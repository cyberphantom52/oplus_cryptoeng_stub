use thiserror::Error;

#[derive(Debug, Error)]
pub(super) enum PkiError {
    #[error("invalid attestation JSON value")]
    InvalidJson,
    #[error("missing attestation field {0}")]
    MissingField(&'static str),
    #[error("attestation field exceeds donor byte limit")]
    TooLong,
    #[error("attestation JSON exceeds donor buffer limit")]
    JsonTooLong,
    #[error("invalid attestation expiration days")]
    InvalidExpiry,
    #[error("unsupported signing key alias")]
    InvalidAlias,
    #[error("unsupported attestation operation")]
    Unsupported,
    #[error("invalid certificate validity")]
    InvalidValidity,
    #[error("missing attestation JSON parameter")]
    MissingParameter,
    #[error("issuer credentials or required metadata unavailable")]
    CredentialsUnavailable,
    #[error("invalid issuer credentials")]
    InvalidCredentials,
    #[error("invalid application public key")]
    InvalidPublicKey,
    #[error("certificate encoding or signing failed")]
    Encoding,
    #[error("native caller context failed with status {0}")]
    NativeContext(i32),
}

impl PkiError {
    pub(super) fn code(&self) -> i32 {
        match self {
            Self::InvalidJson | Self::Encoding => 10010,
            Self::MissingField(key) => match *key {
                "targetFormat" => 20019,
                "applicationKeyAlias" => 2021,
                "applicationPublicKey" => 2022,
                "applicationKeySecurityLevel" => 2023,
                "applicationKeyAlgorithm" => 2024,
                "signingKeyAlias" => 2025,
                "expireDays" => 2026,
                "timestamp" => 2027,
                "notBefore" => 2028,
                "notAfter" => 2029,
                _ => 10010,
            },
            Self::TooLong => 10012,
            Self::JsonTooLong => 10037,
            Self::InvalidExpiry => 1,
            Self::InvalidAlias => 10054,
            Self::Unsupported => 10045,
            Self::InvalidValidity => -10240,
            Self::MissingParameter => 10700,
            Self::CredentialsUnavailable => 10050,
            Self::InvalidCredentials => 10017,
            Self::InvalidPublicKey => -0x3d00,
            Self::NativeContext(status) => *status,
        }
    }
}
