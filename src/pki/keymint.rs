use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use rsbinder::{ExceptionCode, Strong};
use thiserror::Error;
use x509_cert::{
    Certificate,
    der::{self, Decode, Encode},
    ext::pkix::{BasicConstraints, KeyUsage},
    name::Name,
    spki::{self, DecodePublicKey, EncodePublicKey},
};

use crate::android::{
    hardware::security::keymint::{
        Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, KeyOrigin::KeyOrigin,
        KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose,
        SecurityLevel::SecurityLevel, Tag::Tag,
    },
    system::keystore2::{
        Domain::Domain, IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
        KeyMetadata::KeyMetadata, ResponseCode::ResponseCode,
    },
};

use super::credentials::IssuerKind;

const KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";
const SERVICE_UID: u32 = 1000;

#[derive(Debug, Error)]
pub(crate) enum KeyMintError {
    #[error("Keystore2 transport failed: {0}")]
    Transport(#[from] rsbinder::StatusCode),
    #[error("Keystore2 operation failed: {0}")]
    Binder(#[from] rsbinder::Status),
    #[error("Keystore2 service is unavailable")]
    Unavailable,
    #[error("issuer keys must be accessed as system UID 1000")]
    WrongUid,
    #[error("issuer is not a hardware-generated, unauthenticated P-256 SHA-256 signing key")]
    InvalidMetadata,
    #[error("KeyMint returned an invalid signature")]
    InvalidSignature,
    #[error("issuer certificate encoding is invalid")]
    Encoding,
}

pub(crate) struct KeyMintSigner {
    descriptor: KeyDescriptor,
    public_key: der::Document,
}

impl KeyMintSigner {
    pub(crate) fn load(kind: IssuerKind) -> Result<(Self, Certificate), KeyMintError> {
        let service = connect()?;
        let entry = service.getKeyEntry(&alias_descriptor(kind))?;
        let (signer, certificate) = Self::from_metadata(&entry.metadata)?;
        validate_subject(&certificate, kind)?;
        if !Self::is_ready(&certificate) {
            return Err(KeyMintError::InvalidMetadata);
        }

        signer.sign_sha256(b"cryptoeng issuer availability")?;
        Ok((signer, certificate))
    }

    pub(crate) fn provision_key(kind: IssuerKind) -> Result<(Self, Certificate), KeyMintError> {
        let service = connect()?;
        let alias = alias_descriptor(kind);
        match service.getKeyEntry(&alias) {
            Ok(entry) => {
                let (signer, certificate) = Self::from_metadata(&entry.metadata)?;
                validate_subject(&certificate, kind)?;
                signer.sign_sha256(b"cryptoeng issuer provisioning")?;
                return Ok((signer, certificate));
            }
            Err(error) if key_not_found(&error) => {}
            Err(error) => return Err(error.into()),
        }
        let params = generation_parameters(kind)?;
        let hardware = service.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)?;
        let metadata = hardware.generateKey(&alias, None, &params, 0, &[])?;
        let generated = Self::from_metadata(&metadata).and_then(|(signer, certificate)| {
            signer.sign_sha256(b"cryptoeng issuer provisioning")?;
            Ok((signer, certificate))
        });
        if generated.is_err()
            && metadata.key.domain == Domain::KEY_ID
            && let Err(error) = service.deleteKey(&metadata.key)
        {
            tracing::error!(%error, "failed to remove unusable newly generated issuer key");
        }
        generated
    }

    fn from_metadata(metadata: &KeyMetadata) -> Result<(Self, Certificate), KeyMintError> {
        validate_authorizations(metadata)?;
        let certificate = Certificate::from_der(
            metadata
                .certificate
                .as_deref()
                .ok_or(KeyMintError::InvalidMetadata)?,
        )
        .map_err(|_| KeyMintError::InvalidMetadata)?;
        let public_key = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|_| KeyMintError::InvalidMetadata)?;
        let public_key = p256::PublicKey::from_public_key_der(&public_key)
            .map_err(|_| KeyMintError::InvalidMetadata)?
            .to_public_key_der()
            .map_err(|_| KeyMintError::InvalidMetadata)?;
        Ok((
            Self {
                descriptor: metadata.key.clone(),
                public_key,
            },
            certificate,
        ))
    }

    pub(crate) fn public_der(&self) -> spki::Result<der::Document> {
        Ok(self.public_key.clone())
    }

    pub(crate) fn is_ready(certificate: &Certificate) -> bool {
        let tbs = certificate.tbs_certificate();
        matches!(tbs.get_extension::<BasicConstraints>(), Ok(Some((_, constraints))) if constraints.ca)
            && matches!(tbs.get_extension::<KeyUsage>(), Ok(Some((_, usage))) if usage.key_cert_sign())
    }

    pub(crate) fn sign_sha256(&self, message: &[u8]) -> Result<Vec<u8>, KeyMintError> {
        if message.len() > 32 * 1024 {
            return Err(KeyMintError::InvalidSignature);
        }
        let service = connect()?;

        let entry = service.getKeyEntry(&self.descriptor)?;
        let (current, _) = Self::from_metadata(&entry.metadata)?;
        if current.descriptor != self.descriptor || current.public_key != self.public_key {
            return Err(KeyMintError::InvalidMetadata);
        }
        let hardware = entry.iSecurityLevel.ok_or(KeyMintError::InvalidMetadata)?;
        let operation = hardware.createOperation(
            &self.descriptor,
            &[
                parameter(
                    Tag::PURPOSE,
                    KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
                ),
                parameter(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
            ],
            false,
        )?;
        let handle = operation.iOperation.ok_or(KeyMintError::InvalidMetadata)?;
        if operation.operationChallenge.is_some() {
            let _ = handle.abort();
            return Err(KeyMintError::InvalidMetadata);
        }
        let result = handle.finish(Some(message), None);
        let bytes = match result {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Err(KeyMintError::InvalidSignature),
            Err(error) => {
                let _ = handle.abort();
                return Err(error.into());
            }
        };
        verify_signature(self.public_key.as_bytes(), message, &bytes)?;
        Ok(bytes)
    }

    pub(crate) fn store_certificate(&self, certificate: &Certificate) -> Result<(), KeyMintError> {
        let public = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|_| KeyMintError::Encoding)?;
        if public != self.public_key.as_bytes() {
            return Err(KeyMintError::InvalidMetadata);
        }
        let bytes = certificate.to_der().map_err(|_| KeyMintError::Encoding)?;
        connect()?.updateSubcomponent(&self.descriptor, Some(&bytes), None)?;
        Ok(())
    }
}

fn connect() -> Result<Strong<dyn IKeystoreService>, KeyMintError> {
    if rustix::process::geteuid().as_raw() != SERVICE_UID {
        return Err(KeyMintError::WrongUid);
    }
    rsbinder::hub::try_get_interface(KEYSTORE_SERVICE)?.ok_or(KeyMintError::Unavailable)
}

fn alias_descriptor(kind: IssuerKind) -> KeyDescriptor {
    KeyDescriptor {
        domain: Domain::APP,
        nspace: 0,
        alias: Some(
            match kind {
                IssuerKind::User => "cryptoeng.udevice",
                IssuerKind::Group => "cryptoeng.gdevice",
            }
            .to_owned(),
        ),
        blob: None,
    }
}

fn validate_subject(certificate: &Certificate, kind: IssuerKind) -> Result<(), KeyMintError> {
    let expected = match kind {
        IssuerKind::User => "uDevice",
        IssuerKind::Group => "gDevice",
    };
    if certificate
        .tbs_certificate()
        .subject()
        .common_name()
        .map_err(|_| KeyMintError::InvalidMetadata)?
        .map(String::from)
        .as_deref()
        != Some(expected)
    {
        return Err(KeyMintError::InvalidMetadata);
    }
    Ok(())
}

fn parameter(tag: Tag, value: KeyParameterValue) -> KeyParameter {
    KeyParameter { tag, value }
}

fn generation_parameters(kind: IssuerKind) -> Result<[KeyParameter; 9], KeyMintError> {
    let subject: Name = match kind {
        IssuerKind::User => "CN=uDevice",
        IssuerKind::Group => "CN=gDevice",
    }
    .parse()
    .map_err(|_| KeyMintError::Encoding)?;
    Ok([
        parameter(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::EC)),
        parameter(Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_256)),
        parameter(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
        ),
        parameter(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        parameter(Tag::NO_AUTH_REQUIRED, KeyParameterValue::BoolValue(true)),
        parameter(Tag::CERTIFICATE_SERIAL, KeyParameterValue::Blob(vec![1])),
        parameter(
            Tag::CERTIFICATE_SUBJECT,
            KeyParameterValue::Blob(subject.to_der().map_err(|_| KeyMintError::Encoding)?),
        ),
        parameter(
            Tag::CERTIFICATE_NOT_BEFORE,
            KeyParameterValue::DateTime(1_577_836_800_000),
        ),
        parameter(
            Tag::CERTIFICATE_NOT_AFTER,
            KeyParameterValue::DateTime(2_524_607_999_000),
        ),
    ])
}

fn key_not_found(error: &rsbinder::Status) -> bool {
    error.exception_code() == ExceptionCode::ServiceSpecific
        && error.service_specific_error() == ResponseCode::KEY_NOT_FOUND.0
}

fn validate_authorizations(metadata: &KeyMetadata) -> Result<(), KeyMintError> {
    let level = metadata.keySecurityLevel;
    if !matches!(
        level,
        SecurityLevel::TRUSTED_ENVIRONMENT | SecurityLevel::STRONGBOX
    ) || metadata.key.domain != Domain::KEY_ID
        || metadata.key.alias.is_some()
        || metadata.key.blob.is_some()
    {
        return Err(KeyMintError::InvalidMetadata);
    }
    let required = [
        parameter(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::EC)),
        parameter(Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_256)),
        parameter(Tag::ORIGIN, KeyParameterValue::Origin(KeyOrigin::GENERATED)),
        parameter(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
        ),
        parameter(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        parameter(Tag::NO_AUTH_REQUIRED, KeyParameterValue::BoolValue(true)),
    ];
    if !required.iter().all(|wanted| {
        metadata.authorizations.iter().any(|authorization| {
            authorization.securityLevel == level && authorization.keyParameter == *wanted
        })
    }) {
        return Err(KeyMintError::InvalidMetadata);
    }
    if metadata.authorizations.iter().any(|authorization| {
        let parameter = &authorization.keyParameter;
        (parameter.tag == Tag::PURPOSE
            && parameter.value != KeyParameterValue::KeyPurpose(KeyPurpose::SIGN))
            || matches!(
                parameter.tag,
                Tag::USER_SECURE_ID
                    | Tag::USER_AUTH_TYPE
                    | Tag::AUTH_TIMEOUT
                    | Tag::TRUSTED_USER_PRESENCE_REQUIRED
                    | Tag::TRUSTED_CONFIRMATION_REQUIRED
                    | Tag::UNLOCKED_DEVICE_REQUIRED
            )
    }) {
        return Err(KeyMintError::InvalidMetadata);
    }
    Ok(())
}

fn verify_signature(
    public_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), KeyMintError> {
    let public =
        VerifyingKey::from_public_key_der(public_der).map_err(|_| KeyMintError::InvalidMetadata)?;
    let signature = Signature::from_der(signature).map_err(|_| KeyMintError::InvalidSignature)?;
    public
        .verify(message, &signature)
        .map_err(|_| KeyMintError::InvalidSignature)
}
