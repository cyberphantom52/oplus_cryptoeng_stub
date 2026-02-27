//! Error types for the cryptoeng stub service.

use std::sync::PoisonError;
use thiserror::Error;

use crate::{
    SystemType,
    types::{method::MethodType, parameter::MethodParamType},
};

/// Result type alias for cryptoeng operations.
pub type Result<T> = std::result::Result<T, CryptoengError>;

/// Main error type for cryptoeng operations.
#[derive(Debug, Error)]
pub enum CryptoengError {
    /// Request buffer is too short to parse.
    #[error("request buffer too short: got {got} bytes, need at least {min}")]
    BufferTooShort { got: usize, min: usize },

    /// Required parameter is missing from request.
    #[error("missing required parameter: {0:?}")]
    MissingParameter(MethodParamType),

    /// Parameter buffer is too short to parse.
    #[error(
        "parameter buffer too short for {param:?}: expected at least {expected} bytes, got {got}"
    )]
    ParameterBufferTooShort {
        param: MethodParamType,
        expected: usize,
        got: usize,
    },

    /// Parameter contains an unknown/unsupported value.
    #[error("invalid parameter value {value} for {param:?}")]
    InvalidParameterData { param: MethodParamType, value: i32 },

    /// Unknown or unsupported method type.
    #[error("unknown method type: {0:?}")]
    UnknownMethod(MethodType),

    /// Unknown or unsupported native command.
    #[error("unknown native command: {0}")]
    UnknownNativeCommand(u8),

    /// User is not enrolled in the privacy management system.
    #[error("user not enrolled for system type {0:?}")]
    NotEnrolled(SystemType),

    /// Account is locked due to too many failed attempts.
    #[error("account locked for system type {system_type:?}, time remaining: {lock_time}s")]
    AccountLocked {
        system_type: SystemType,
        lock_time: i32,
    },

    /// Password verification failed.
    #[error("verification failed for system type {system_type:?}, retries left: {retries_left}")]
    VerificationFailed {
        system_type: SystemType,
        retries_left: i32,
    },

    /// Challenge token mismatch during modify operation.
    #[error("challenge mismatch for system type {0:?}")]
    ChallengeMismatch(SystemType),

    /// No verify buffer provided when required.
    #[error("no verify buffer provided")]
    NoVerifyBuffer,

    /// Password data not found for user.
    #[error("password data not found for user {0}")]
    PasswordDataNotFound(i32),

    /// Storage I/O error.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// RwLock was poisoned.
    #[error("internal lock poisoned")]
    LockPoisoned,

    /// Parse error for request data.
    #[error("failed to parse request: {0}")]
    ParseError(String),
}

/// Storage-specific errors.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Failed to create storage directory.
    #[error("failed to create storage directory: {0}")]
    CreateDir(std::io::Error),

    /// Failed to read storage file.
    #[error("failed to read storage file: {0}")]
    Read(std::io::Error),

    /// Failed to write storage file.
    #[error("failed to write storage file: {0}")]
    Write(std::io::Error),

    /// Failed to serialize storage data.
    #[error("failed to serialize storage: {0}")]
    Serialize(serde_json::Error),

    /// Failed to deserialize storage data.
    #[error("failed to deserialize storage: {0}")]
    Deserialize(serde_json::Error),

    /// Cryptographic operation failed (encrypt/decrypt).
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl<T> From<PoisonError<T>> for CryptoengError {
    fn from(_: PoisonError<T>) -> Self {
        CryptoengError::LockPoisoned
    }
}

impl CryptoengError {
    /// Returns an appropriate result code for this error.
    /// These codes are returned to the Android client.
    pub fn result_code(&self) -> i32 {
        match self {
            CryptoengError::BufferTooShort { .. } => -1,
            CryptoengError::MissingParameter(_) => -2,
            CryptoengError::ParameterBufferTooShort { .. } => -3,
            CryptoengError::InvalidParameterData { .. } => -3,
            CryptoengError::UnknownMethod(_) => -4,
            CryptoengError::UnknownNativeCommand(_) => -5,
            CryptoengError::NotEnrolled(_) => -10,
            CryptoengError::AccountLocked { .. } => -11,
            CryptoengError::VerificationFailed { .. } => -12,
            CryptoengError::ChallengeMismatch(_) => -13,
            CryptoengError::NoVerifyBuffer => -14,
            CryptoengError::PasswordDataNotFound(_) => -20,
            CryptoengError::Storage(_) => -100,
            CryptoengError::LockPoisoned => -101,
            CryptoengError::ParseError(_) => -1,
        }
    }
}
