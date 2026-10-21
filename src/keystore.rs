use rsbinder::{ExceptionCode, Strong};
use thiserror::Error;

use crate::android::{
    hardware::security::keymint::{
        KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, Tag::Tag,
    },
    system::keystore2::{IKeystoreService::IKeystoreService, ResponseCode::ResponseCode},
};

const KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";
pub(crate) const SERVICE_UID: u32 = 1000;

#[derive(Debug, Error)]
pub(crate) enum KeyMintError {
    #[error("Keystore2 transport failed: {0}")]
    Transport(#[from] rsbinder::StatusCode),
    #[error("Keystore2 operation failed: {0}")]
    Binder(#[from] rsbinder::Status),
    #[error("Keystore2 service is unavailable")]
    Unavailable,
    #[error("cryptoeng keys must be accessed as system UID 1000")]
    WrongUid,
    #[error("key does not have the required hardware-generated authorizations")]
    InvalidMetadata,
    #[error("KeyMint returned an invalid signature")]
    InvalidSignature,
    #[error("issuer certificate encoding is invalid")]
    Encoding,
    #[error("invalid AES-GCM nonce, ciphertext or operation output")]
    InvalidCiphertext,
}

pub(crate) fn connect() -> Result<Strong<dyn IKeystoreService>, KeyMintError> {
    if rustix::process::geteuid().as_raw() != SERVICE_UID {
        return Err(KeyMintError::WrongUid);
    }
    rsbinder::hub::try_get_interface(KEYSTORE_SERVICE)?.ok_or(KeyMintError::Unavailable)
}

pub(crate) fn parameter(tag: Tag, value: KeyParameterValue) -> KeyParameter {
    KeyParameter { tag, value }
}

pub(crate) fn key_not_found(error: &rsbinder::Status) -> bool {
    error.exception_code() == ExceptionCode::ServiceSpecific
        && error.service_specific_error() == ResponseCode::KEY_NOT_FOUND.0
}
