use std::{fs::File, io::Read};

use serde::Deserialize;
use x509_cert::{
    attr::AttributeTypeAndValue,
    der::{Decode, Encode, Tag, asn1::Any},
    name::{Name, RdnSequence, RelativeDistinguishedName},
    spki::ObjectIdentifier,
    time::Time,
};

use super::{
    credentials::{CertificateError, IssuerKind, read_metadata},
    error::PkiError,
    request::Request,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Provisioned {
    attestation_id_manufacturer: String,
    attestation_id_model: String,
    device_security_level: u8,
    is_oem_lock: u8,
    #[serde(rename = "OemLockCounter")]
    oem_lock_counter: u8,
    #[serde(default)]
    bootloader_patch_level: String,
}

pub(super) struct Metadata {
    provisioned: Provisioned,
    application_id: String,
    is_root: u8,
    os_patch_level: String,
}

impl Metadata {
    pub(super) fn load() -> Result<Self, PkiError> {
        let json = read_metadata().map_err(|error| match error {
            CertificateError::Io(ref error) if error.kind() != std::io::ErrorKind::InvalidData => {
                PkiError::CredentialsUnavailable
            }
            _ => PkiError::InvalidCredentials,
        })?;
        let provisioned = Provisioned::parse(&json)?;
        let pid = rsbinder::thread_state::get_calling_pid();
        if pid <= 0 {
            return Err(PkiError::NativeContext(-1));
        }
        let mut command_line = Vec::new();
        File::open(format!("/proc/{pid}/cmdline"))
            .and_then(|file| file.take(95).read_to_end(&mut command_line))
            .map_err(|error| PkiError::NativeContext(error.raw_os_error().unwrap_or(-1)))?;
        let application_id = caller_name(&command_line)?;
        let secure = rsproperties::get::<String>("ro.secure").unwrap_or_else(|_| "0".to_owned());
        let os_patch_level = rsproperties::get::<String>("ro.build.version.security_patch")
            .unwrap_or_else(|_| "unknow".to_owned());
        if os_patch_level.len() > 15 || os_patch_level.contains('\0') {
            return Err(PkiError::TooLong);
        }
        Ok(Self {
            provisioned,
            application_id,
            is_root: u8::from(secure != "1"),
            os_patch_level,
        })
    }

    pub(super) fn extension(&self, request: &Request, kind: IssuerKind) -> Vec<u8> {
        let mut output = vec![0xbf];
        for (key, value) in [
            ("nonce", request.nonce.as_str()),
            ("signingKeyAlias", issuer_name(kind)),
            ("signingKeySecurityLevel", "RPMB"),
            ("timestamp", request.timestamp.as_str()),
            (
                "attestationIdManufacturer",
                self.provisioned.attestation_id_manufacturer.as_str(),
            ),
            (
                "attestationIdModel",
                self.provisioned.attestation_id_model.as_str(),
            ),
            ("osPatchLevel", self.os_patch_level.as_str()),
        ] {
            cbor_text_pair(&mut output, key, value);
        }
        if !self.provisioned.bootloader_patch_level.is_empty() {
            cbor_text_pair(
                &mut output,
                "bootloaderPatchLevel",
                &self.provisioned.bootloader_patch_level,
            );
        }
        for (key, value) in [
            ("isRoot", self.is_root),
            ("isOemLock", self.provisioned.is_oem_lock),
            ("OemLockCounter", self.provisioned.oem_lock_counter),
            (
                "deviceSecurityLevel",
                self.provisioned.device_security_level,
            ),
            ("expireDays", request.expire_days),
        ] {
            cbor_text(&mut output, key);
            if value < 24 {
                output.push(value);
            } else {
                output.extend_from_slice(&[0x18, value]);
            }
        }
        if !request.application_customize_data_dgst.is_empty() {
            cbor_text_pair(
                &mut output,
                "applicationCustomizeDataDgst",
                &request.application_customize_data_dgst,
            );
        }
        cbor_text_pair(
            &mut output,
            "applicationKeyAlgorithm",
            &request.application_key_algorithm,
        );
        cbor_text_pair(
            &mut output,
            "applicationKeySecurityLevel",
            &request.application_key_security_level,
        );
        output.push(0xff);
        output
    }

    pub(super) fn subject(&self, request: &Request, kind: IssuerKind) -> Result<Name, PkiError> {
        let mut sequence = RdnSequence::default();
        for (oid, value) in [
            ("2.5.4.3", self.application_id.as_str()),
            ("2.5.4.8", request.application_key_alias.as_str()),
            ("2.5.4.10", issuer_name(kind)),
            ("2.5.4.7", request.app_rotate_device_id.as_str()),
            ("2.5.4.11", request.app_device_id.as_str()),
        ] {
            if value.is_empty() && matches!(oid, "2.5.4.7" | "2.5.4.11") {
                continue;
            }
            let attribute = AttributeTypeAndValue {
                oid: ObjectIdentifier::new(oid).map_err(|_| PkiError::TooLong)?,
                value: Any::new(Tag::Utf8String, value.as_bytes())
                    .map_err(|_| PkiError::TooLong)?,
            };
            let rdn = RelativeDistinguishedName::try_from(vec![attribute])
                .map_err(|_| PkiError::TooLong)?;
            sequence.push(rdn);
        }

        Name::from_der(&sequence.to_der().map_err(|_| PkiError::TooLong)?)
            .map_err(|_| PkiError::TooLong)
    }
}

impl Provisioned {
    fn parse(json: &str) -> Result<Self, PkiError> {
        let provisioned: Self =
            serde_json::from_str(json).map_err(|_| PkiError::InvalidCredentials)?;
        if [
            &provisioned.attestation_id_manufacturer,
            &provisioned.attestation_id_model,
            &provisioned.bootloader_patch_level,
        ]
        .iter()
        .any(|value| value.len() > 15 || value.contains('\0'))
        {
            return Err(PkiError::InvalidCredentials);
        }
        Ok(provisioned)
    }
}

fn caller_name(command_line: &[u8]) -> Result<String, PkiError> {
    let name = command_line
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or_default();
    if name.is_empty() || name.len() > 71 {
        return Err(PkiError::TooLong);
    }
    String::from_utf8(name.to_vec()).map_err(|_| PkiError::TooLong)
}

fn issuer_name(kind: IssuerKind) -> &'static str {
    match kind {
        IssuerKind::User => "uDevice",
        IssuerKind::Group => "gDevice",
    }
}

fn cbor_text_pair(output: &mut Vec<u8>, key: &str, value: &str) {
    cbor_text(output, key);
    cbor_text(output, value);
}

fn cbor_text(output: &mut Vec<u8>, value: &str) {
    let length = u8::try_from(value.len()).expect("validated attestation text fits one byte");
    if length < 24 {
        output.push(0x60 | length);
    } else {
        output.extend_from_slice(&[0x78, length]);
    }
    output.extend_from_slice(value.as_bytes());
}

pub(super) fn parse_time(value: &str) -> Result<Time, PkiError> {
    if value.len() != 14 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PkiError::InvalidValidity);
    }
    let year = value[..4].parse().map_err(|_| PkiError::InvalidValidity)?;
    let mut components = [0; 5];
    for (component, offset) in components.iter_mut().zip((4..14).step_by(2)) {
        *component = value[offset..offset + 2]
            .parse()
            .map_err(|_| PkiError::InvalidValidity)?;
    }
    let [month, day, hour, minute, second] = components;

    let date = x509_cert::der::DateTime::new(year, month, day, hour, minute, second)
        .map_err(|_| PkiError::InvalidValidity)?;
    Ok(date.into())
}
