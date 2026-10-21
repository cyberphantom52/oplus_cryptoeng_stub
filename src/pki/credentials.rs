use std::{fs::File, io::Read, os::unix::fs::MetadataExt};

use rustix::fs::{Mode, OFlags, open, openat};
use thiserror::Error;
use x509_cert::{
    Certificate,
    der::{EncodePem, pem::LineEnding},
};

use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug)]
pub enum IssuerKind {
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

    #[error("application public key is invalid or unsupported")]
    InvalidPublicKey,
    #[error("application public-key parsing failed with donor status {0}")]
    PublicKeyParsing(i32),
    #[error("certificate encoding failed")]
    Encoding,
    #[error("certificate signing failed")]
    Signing,
    #[error(transparent)]
    KeyMint(#[from] super::keymint::KeyMintError),
}

pub(super) enum IssuerKey {
    KeyMint(super::keymint::KeyMintSigner),
}

pub(crate) struct Issuer {
    pub(super) key: IssuerKey,
    pub(super) certificate: Certificate,
    pub(super) certificate_pem: String,
}

impl Issuer {
    pub(crate) fn load(kind: IssuerKind) -> Result<Self, CertificateError> {
        let (signer, certificate) = super::keymint::KeyMintSigner::load(kind)?;
        let certificate_pem = certificate
            .to_pem(LineEnding::LF)
            .map_err(|_| CertificateError::Encoding)?;
        Ok(Self {
            key: IssuerKey::KeyMint(signer),
            certificate,
            certificate_pem,
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
            Self::KeyMint(signer) => signer.public_der(),
        }
    }
}

fn trusted_owner(uid: u32) -> bool {
    uid == 0 || uid == rustix::process::geteuid().as_raw()
}

fn open_directory() -> Result<File, CertificateError> {
    let directory: File = open(
        crate::storage::STORAGE_DIR,
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
    read_metadata_file(&open_directory()?, "metadata.json", 4096)
}

fn read_metadata_file(
    directory: &File,
    name: &str,
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
    if !metadata.is_file() || metadata.mode() & 0o002 != 0 || !trusted_owner(metadata.uid()) {
        return Err(CertificateError::InsecureFile);
    }
    let mut contents = Zeroizing::new(String::new());
    file.take(max_bytes + 1).read_to_string(&mut contents)?;
    if contents.len() as u64 > max_bytes {
        return Err(CertificateError::InvalidIssuer);
    }
    Ok(contents)
}
