use std::{fs::File, io::Read, os::unix::fs::MetadataExt};

use p256::pkcs8::DecodePrivateKey;
use rsa::{RsaPrivateKey, RsaPublicKey, signature::Keypair};
use rustix::fs::{Mode, OFlags, open, openat};
use thiserror::Error;
use x509_cert::{
    Certificate,
    der::{DecodePem, Encode},
    spki::{DecodePublicKey, EncodePublicKey},
};
use zeroize::Zeroizing;

const CREDENTIAL_DIR: &str = "/data/vendor_de/0/cryptoeng/pki";
const MAX_CREDENTIAL_BYTES: u64 = 16_384;

#[derive(Clone, Copy, Debug)]
pub(crate) enum IssuerKind {
    User,
    Group,
}

#[derive(Debug, Error)]
pub(crate) enum CertificateError {
    #[error("issuer credential I/O failed")]
    Io(#[from] std::io::Error),
    #[error("issuer credential file has an untrusted owner, world write access or invalid type")]
    InsecureFile,
    #[error("issuer key or certificate is invalid or mismatched")]
    InvalidIssuer,
    #[error("issuer key algorithm is unsupported")]
    UnsupportedIssuer,
    #[error("application public key is invalid or unsupported")]
    InvalidPublicKey,
    #[error("certificate encoding failed")]
    Encoding,
    #[error("certificate signing failed")]
    Signing,
}

pub(super) enum IssuerKey {
    Rsa(rsa::pkcs1v15::SigningKey<sha2_11::Sha256>),
    P224(p224::ecdsa::SigningKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(p521::ecdsa::SigningKey),
}

pub(crate) struct Issuer {
    pub(super) key: IssuerKey,
    pub(super) certificate: Certificate,
    pub(super) certificate_pem: String,
}

impl Issuer {
    pub(crate) fn load(kind: IssuerKind) -> Result<Self, CertificateError> {
        let directory = open_directory()?;
        let (key_name, cert_name) = match kind {
            IssuerKind::User => ("udevice-key.pem", "udevice-cert.pem"),
            IssuerKind::Group => ("gdevice-key.pem", "gdevice-cert.pem"),
        };
        let key = read_credential(&directory, key_name, true, MAX_CREDENTIAL_BYTES)?;
        let certificate = read_credential(&directory, cert_name, false, MAX_CREDENTIAL_BYTES)?;
        Self::from_pem(&key, &certificate)
    }

    pub(crate) fn from_pem(key: &str, cert: &str) -> Result<Self, CertificateError> {
        if key.len() as u64 > MAX_CREDENTIAL_BYTES || cert.len() as u64 > MAX_CREDENTIAL_BYTES {
            return Err(CertificateError::InvalidIssuer);
        }
        let certificate =
            Certificate::from_pem(cert).map_err(|_| CertificateError::InvalidIssuer)?;
        let public_der = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .to_der()
            .map_err(|_| CertificateError::InvalidIssuer)?;
        let key = if let Ok(private) = RsaPrivateKey::from_pkcs8_pem(key) {
            private
                .validate()
                .map_err(|_| CertificateError::InvalidIssuer)?;
            let public = RsaPublicKey::from_public_key_der(&public_der)
                .map_err(|_| CertificateError::InvalidIssuer)?;
            if public != RsaPublicKey::from(&private) {
                return Err(CertificateError::InvalidIssuer);
            }
            IssuerKey::Rsa(rsa::pkcs1v15::SigningKey::new(private))
        } else if let Ok(private) = p224::SecretKey::from_pkcs8_pem(key) {
            let public = p224::PublicKey::from_public_key_der(&public_der)
                .map_err(|_| CertificateError::InvalidIssuer)?;
            if public != private.public_key() {
                return Err(CertificateError::InvalidIssuer);
            }
            IssuerKey::P224(private.into())
        } else if let Ok(private) = p256::SecretKey::from_pkcs8_pem(key) {
            let public = p256::PublicKey::from_public_key_der(&public_der)
                .map_err(|_| CertificateError::InvalidIssuer)?;
            if public != private.public_key() {
                return Err(CertificateError::InvalidIssuer);
            }
            IssuerKey::P256(private.into())
        } else if let Ok(private) = p384::SecretKey::from_pkcs8_pem(key) {
            let public = p384::PublicKey::from_public_key_der(&public_der)
                .map_err(|_| CertificateError::InvalidIssuer)?;
            if public != private.public_key() {
                return Err(CertificateError::InvalidIssuer);
            }
            IssuerKey::P384(private.into())
        } else if let Ok(private) = p521::SecretKey::from_pkcs8_pem(key) {
            let public = p521::PublicKey::from_public_key_der(&public_der)
                .map_err(|_| CertificateError::InvalidIssuer)?;
            if public != private.public_key() {
                return Err(CertificateError::InvalidIssuer);
            }
            IssuerKey::P521(private.into())
        } else {
            return Err(CertificateError::UnsupportedIssuer);
        };
        Ok(Self {
            key,
            certificate,
            certificate_pem: cert.to_owned(),
        })
    }

    pub(crate) fn common_name(&self) -> Result<String, CertificateError> {
        self.certificate
            .tbs_certificate()
            .subject()
            .common_name()
            .map_err(|_| CertificateError::InvalidIssuer)?
            .map(String::from)
            .filter(|name| !name.is_empty())
            .ok_or(CertificateError::InvalidIssuer)
    }
}

impl IssuerKey {
    pub(super) fn public_der(&self) -> Result<x509_cert::der::Document, x509_cert::spki::Error> {
        match self {
            Self::Rsa(key) => key.verifying_key().to_public_key_der(),
            Self::P224(key) => key.verifying_key().to_public_key_der(),
            Self::P256(key) => key.verifying_key().to_public_key_der(),
            Self::P384(key) => key.verifying_key().to_public_key_der(),
            Self::P521(key) => key.verifying_key().to_public_key_der(),
        }
    }
}

fn trusted_owner(uid: u32) -> bool {
    uid == 0 || uid == rustix::process::geteuid().as_raw()
}

fn open_directory() -> Result<File, CertificateError> {
    let directory: File = open(
        CREDENTIAL_DIR,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let metadata = directory.metadata()?;
    if metadata.mode() & 0o002 != 0 || !trusted_owner(metadata.uid()) {
        return Err(CertificateError::InsecureFile);
    }
    Ok(directory)
}

pub(super) fn read_metadata() -> Result<Zeroizing<String>, CertificateError> {
    read_credential(&open_directory()?, "metadata.json", false, 4096)
}

fn read_credential(
    directory: &File,
    name: &str,
    secret: bool,
    max_bytes: u64,
) -> Result<Zeroizing<String>, CertificateError> {
    let file: File = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?
    .into();
    let metadata = file.metadata()?;
    let forbidden_permissions = if secret { 0o007 } else { 0o002 };
    if !metadata.is_file()
        || metadata.mode() & forbidden_permissions != 0
        || !trusted_owner(metadata.uid())
    {
        return Err(CertificateError::InsecureFile);
    }
    let mut contents = Zeroizing::new(String::new());
    file.take(max_bytes + 1).read_to_string(&mut contents)?;
    if contents.len() as u64 > max_bytes {
        return Err(CertificateError::InvalidIssuer);
    }
    Ok(contents)
}
