use byteorder::{BigEndian, ByteOrder};
use serde::{Deserialize, Serialize};

use crate::error::{CryptoengError, Result};

/// Length of challenge tokens in bytes.
pub const CHALLENGE_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    ty: MethodParamType,
    value: Value,
}

impl Parameter {
    pub fn new(ty: MethodParamType, data: Vec<u8>) -> Result<Self> {
        Ok(Self {
            ty,
            value: Value::try_from(ty, &data)?,
        })
    }

    /// Create a parameter from an i32 value (big-endian)
    pub fn from_i32(ty: MethodParamType, value: i32) -> Result<Self> {
        let mut data = vec![0u8; 4];
        BigEndian::write_i32(&mut data, value);
        Self::new(ty, data)
    }

    /// Create a parameter from a string value
    pub fn from_str(ty: MethodParamType, value: &str) -> Result<Self> {
        let data = value.as_bytes().to_vec();
        Self::new(ty, data)
    }

    /// Get the raw data
    pub fn data(&self) -> Vec<u8> {
        self.value.as_bytes()
    }

    /// Try to read the data as a big-endian i32
    pub fn as_i32(&self) -> Result<i32> {
        if self.value.as_bytes().len() < 4 {
            return Err(CryptoengError::ParameterBufferTooShort {
                param: self.ty,
                expected: 4,
                got: self.value.as_bytes().len(),
            });
        }
        Ok(BigEndian::read_i32(&self.value.as_bytes()))
    }

    /// Serialize the parameter to big-endian bytes (type + length + data)
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let data_bytes = self.value.as_bytes();
        let mut result = Vec::with_capacity(8 + data_bytes.len());
        let mut buf = [0u8; 4];

        // Param type (4 bytes, big-endian)
        BigEndian::write_i32(&mut buf, self.ty as i32);
        result.extend_from_slice(&buf);

        // Param length (4 bytes, big-endian)
        BigEndian::write_i32(&mut buf, data_bytes.len() as i32);
        result.extend_from_slice(&buf);

        // Param data
        result.extend_from_slice(&data_bytes);

        result
    }
}

impl std::fmt::Display for Parameter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Parameter {{ type: {:?}, value: {} }}",
            self.ty, self.value
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum MethodParamType {
    PmsVersionT = 200,
    PmsTypeT = 201,
    PmsPwdInfoT = 202,
    PmsSecureInfoBufferT = 203,
    PmsVerifyTypeT = 204,
    PmsVerifyBufferT = 205,
    PmsChallengeT = 206,
    PmsInfoTypeT = 207,
    PmsInfoBufferT = 208,
    PmsHandlerT = 209,
    PmsPwdTypeT = 210,
    PmsPwdRetryCountLeftT = 211,
    PmsPwdLockTimeLeftT = 212,
    PmsCommonBuffer0T = 213,
    PmsCommonBuffer1T = 214,
    PmsCommonBuffer2T = 215,
    PmsCommonBuffer3T = 216,
    PmsHideEmailT = 217,
    PmsEncBufferT = 218,
    PmsSecureQuestionRetryCountLeftT = 219,
    PmsSecureQuestionLockTimeLeftT = 220,
    PmsLatestSecureRulesT = 221,
    PmsLockScreenPwdT = 33,
    PmsAccountName = 11,
    PmsPwdUseridT = 500,
    PmsOldPwdTypeT = 501,
    PmsOldPwdLengthT = 502,
    PmsOldPwdBufferT = 503,
    PmsCurrentPwdTypeT = 504,
    PmsCurrentPwdLenT = 505,
    PmsCurrentPwdBufferT = 506,
    PmsPwdSystemTimeT = 507,
    PmsVerifyOldPwdResultT = 508,
    PmsOldPwdTryRemainingCount = 509,
    PmsOldPwdTryRemainingTime = 510,
    PmsOldPasswordType = 512,
    PmsCurrentPasswordBuffer = 513,
    PmsResultValidity = 514,
    PmsCurrentPasswordType = 515,

    Unknown = -1,
}

impl From<i32> for MethodParamType {
    fn from(code: i32) -> Self {
        match code {
            200 => MethodParamType::PmsVersionT,
            201 => MethodParamType::PmsTypeT,
            202 => MethodParamType::PmsPwdInfoT,
            203 => MethodParamType::PmsSecureInfoBufferT,
            204 => MethodParamType::PmsVerifyTypeT,
            205 => MethodParamType::PmsVerifyBufferT,
            206 => MethodParamType::PmsChallengeT,
            207 => MethodParamType::PmsInfoTypeT,
            208 => MethodParamType::PmsInfoBufferT,
            209 => MethodParamType::PmsHandlerT,
            210 => MethodParamType::PmsPwdTypeT,
            211 => MethodParamType::PmsPwdRetryCountLeftT,
            212 => MethodParamType::PmsPwdLockTimeLeftT,
            213 => MethodParamType::PmsCommonBuffer0T,
            214 => MethodParamType::PmsCommonBuffer1T,
            215 => MethodParamType::PmsCommonBuffer2T,
            216 => MethodParamType::PmsCommonBuffer3T,
            217 => MethodParamType::PmsHideEmailT,
            218 => MethodParamType::PmsEncBufferT,
            219 => MethodParamType::PmsSecureQuestionRetryCountLeftT,
            220 => MethodParamType::PmsSecureQuestionLockTimeLeftT,
            221 => MethodParamType::PmsLatestSecureRulesT,
            33 => MethodParamType::PmsLockScreenPwdT,
            11 => MethodParamType::PmsAccountName,
            500 => MethodParamType::PmsPwdUseridT,
            501 => MethodParamType::PmsOldPwdTypeT,
            502 => MethodParamType::PmsOldPwdLengthT,
            503 => MethodParamType::PmsOldPwdBufferT,
            504 => MethodParamType::PmsCurrentPwdTypeT,
            505 => MethodParamType::PmsCurrentPwdLenT,
            506 => MethodParamType::PmsCurrentPwdBufferT,
            507 => MethodParamType::PmsPwdSystemTimeT,
            508 => MethodParamType::PmsVerifyOldPwdResultT,
            509 => MethodParamType::PmsOldPwdTryRemainingCount,
            510 => MethodParamType::PmsOldPwdTryRemainingTime,
            512 => MethodParamType::PmsOldPasswordType,
            513 => MethodParamType::PmsCurrentPasswordBuffer,
            514 => MethodParamType::PmsResultValidity,
            515 => MethodParamType::PmsCurrentPasswordType,
            _ => MethodParamType::Unknown,
        }
    }
}

/// Info type for PMS modify operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum InfoType {
    Password = 1,
    SecurityAnswer = 2,
    Email = 4,
}

impl TryFrom<&[u8]> for InfoType {
    type Error = CryptoengError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() < 4 {
            return Err(CryptoengError::ParameterBufferTooShort {
                param: MethodParamType::PmsInfoTypeT,
                expected: 4,
                got: value.len(),
            });
        }
        let code = BigEndian::read_i32(value);
        match code {
            1 => Ok(InfoType::Password),
            2 => Ok(InfoType::SecurityAnswer),
            4 => Ok(InfoType::Email),
            _ => Err(CryptoengError::InvalidParameterData {
                param: MethodParamType::PmsInfoTypeT,
                value: code,
            }),
        }
    }
}

/// Password quality/complexity type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum PasswordQuality {
    Unspecified = 0,
    NumericFour = 1,
    NumericSix = 2,
    NumericComplex = 3,
    Complex = 4,
    Pattern = 5,
}

impl TryFrom<&[u8]> for PasswordQuality {
    type Error = CryptoengError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() < 4 {
            return Err(CryptoengError::ParameterBufferTooShort {
                param: MethodParamType::PmsPwdTypeT,
                expected: 4,
                got: value.len(),
            });
        }
        let code = BigEndian::read_i32(value);
        match code {
            0 => Ok(PasswordQuality::Unspecified),
            1 => Ok(PasswordQuality::NumericFour),
            2 => Ok(PasswordQuality::NumericSix),
            3 => Ok(PasswordQuality::NumericComplex),
            4 => Ok(PasswordQuality::Complex),
            5 => Ok(PasswordQuality::Pattern),
            _ => Err(CryptoengError::InvalidParameterData {
                param: MethodParamType::PmsPwdTypeT,
                value: code,
            }),
        }
    }
}

/// Verification method type (PmsVerify).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum VerifyType {
    Unspecified = 0,
    Password = 1,
    SecurityQuestion = 2,
    Account = 3,
    Email = 4,
    Fingerprint = 5,
    Face = 6,
    Iris = 7,
    EmailEx1 = 10,
}

impl TryFrom<&[u8]> for VerifyType {
    type Error = CryptoengError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() < 4 {
            return Err(CryptoengError::ParameterBufferTooShort {
                param: MethodParamType::PmsVerifyTypeT,
                expected: 4,
                got: value.len(),
            });
        }
        let code = BigEndian::read_i32(value);
        match code {
            0 => Ok(VerifyType::Unspecified),
            1 => Ok(VerifyType::Password),
            2 => Ok(VerifyType::SecurityQuestion),
            3 => Ok(VerifyType::Account),
            4 => Ok(VerifyType::Email),
            5 => Ok(VerifyType::Fingerprint),
            6 => Ok(VerifyType::Face),
            7 => Ok(VerifyType::Iris),
            10 => Ok(VerifyType::EmailEx1),
            _ => Err(CryptoengError::InvalidParameterData {
                param: MethodParamType::PmsVerifyTypeT,
                value: code,
            }),
        }
    }
}

/// System type for privacy management (PmsType).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(i32)]
pub enum SystemType {
    PrivacyPassword = 1,
    ScreenLock = 2,
}

impl TryFrom<&[u8]> for SystemType {
    type Error = CryptoengError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() < 4 {
            return Err(CryptoengError::ParameterBufferTooShort {
                param: MethodParamType::PmsTypeT,
                expected: 4,
                got: value.len(),
            });
        }
        let code = BigEndian::read_i32(value);
        match code {
            1 => Ok(SystemType::PrivacyPassword),
            2 => Ok(SystemType::ScreenLock),
            _ => Err(CryptoengError::InvalidParameterData {
                param: MethodParamType::PmsTypeT,
                value: code,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    SystemType(SystemType),
    PasswordQuality(PasswordQuality),
    VerifyType(VerifyType),
    Integer(i32),
    Boolean(bool),
    String(String),
    Buffer(Vec<u8>),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::SystemType(t) => write!(f, "{:?}", t),
            Value::PasswordQuality(q) => write!(f, "{:?}", q),
            Value::VerifyType(v) => write!(f, "{:?}", v),
            Value::Integer(i) => write!(f, "{}", i),
            Value::Boolean(b) => write!(f, "{}", b),
            Value::String(s) => write!(f, "{}", s),
            Value::Buffer(buf) => write!(
                f,
                "[{}]",
                buf.iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        }
    }
}

impl Value {
    pub fn try_from(ty: MethodParamType, buf: &[u8]) -> Result<Self> {
        match ty {
            MethodParamType::PmsTypeT => Ok(Value::SystemType(SystemType::try_from(buf)?)),
            MethodParamType::PmsPwdTypeT => {
                Ok(Value::PasswordQuality(PasswordQuality::try_from(buf)?))
            }
            MethodParamType::PmsVerifyTypeT => Ok(Value::VerifyType(VerifyType::try_from(buf)?)),
            MethodParamType::PmsHideEmailT => Ok(Value::Boolean(BigEndian::read_i32(buf) != 0)),
            MethodParamType::PmsAccountName => {
                Ok(Value::String(String::from_utf8_lossy(buf).to_string()))
            }
            _ => Ok(Value::Buffer(buf.to_vec())),
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Value::SystemType(t) => {
                let mut buf = [0u8; 4];
                BigEndian::write_i32(&mut buf, *t as i32);
                buf.to_vec()
            }
            Value::PasswordQuality(q) => {
                let mut buf = [0u8; 4];
                BigEndian::write_i32(&mut buf, *q as i32);
                buf.to_vec()
            }
            Value::VerifyType(v) => {
                let mut buf = [0u8; 4];
                BigEndian::write_i32(&mut buf, *v as i32);
                buf.to_vec()
            }
            Value::Integer(i) => {
                let mut buf = [0u8; 4];
                BigEndian::write_i32(&mut buf, *i);
                buf.to_vec()
            }
            Value::Boolean(b) => {
                let mut buf = [0u8; 4];
                BigEndian::write_i32(&mut buf, if *b { 1 } else { 0 });
                buf.to_vec()
            }
            Value::String(s) => s.as_bytes().to_vec(),
            Value::Buffer(buf) => buf.clone(),
        }
    }
}
