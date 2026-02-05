use byteorder::{BigEndian, ByteOrder};
use serde::{Deserialize, Serialize};

use crate::CryptoengError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    ty: MethodParamType,
    data: Vec<u8>,
}

impl Parameter {
    pub fn new(ty: MethodParamType, data: Vec<u8>) -> Self {
        Self { ty, data }
    }

    /// Create a parameter from an i32 value (big-endian)
    pub fn from_i32(ty: MethodParamType, value: i32) -> Self {
        let mut data = vec![0u8; 4];
        BigEndian::write_i32(&mut data, value);
        Self { ty, data }
    }

    /// Create a parameter from a string value
    pub fn from_str(ty: MethodParamType, value: &str) -> Self {
        Self {
            ty,
            data: value.as_bytes().to_vec(),
        }
    }

    /// Get the raw data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Try to read the data as a big-endian i32
    pub fn as_i32(&self) -> Result<i32, CryptoengError> {
        if self.data.len() >= 4 {
            Ok(BigEndian::read_i32(&self.data))
        } else {
            Err(CryptoengError::InvalidParameterData {
                param: self.ty,
                expected: 4,
                got: self.data.len(),
            })
        }
    }

    /// Serialize the parameter to big-endian bytes (type + length + data)
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(8 + self.data.len());
        let mut buf = [0u8; 4];

        // Param type (4 bytes, big-endian)
        BigEndian::write_i32(&mut buf, self.ty as i32);
        result.extend_from_slice(&buf);

        // Param length (4 bytes, big-endian)
        BigEndian::write_i32(&mut buf, self.data.len() as i32);
        result.extend_from_slice(&buf);

        // Param data
        result.extend_from_slice(&self.data);

        result
    }
}

impl std::fmt::Display for Parameter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ty {
            // Integer parameters - show as decimal
            MethodParamType::PmsTypeT
            | MethodParamType::PmsPwdTypeT
            | MethodParamType::PmsVerifyTypeT
            | MethodParamType::PmsPwdRetryCountLeftT
            | MethodParamType::PmsPwdLockTimeLeftT
            | MethodParamType::PmsSecureQuestionRetryCountLeftT
            | MethodParamType::PmsSecureQuestionLockTimeLeftT
            | MethodParamType::PmsLatestSecureRulesT
            | MethodParamType::PmsPwdUseridT
            | MethodParamType::PmsOldPwdTypeT
            | MethodParamType::PmsOldPwdLengthT
            | MethodParamType::PmsCurrentPwdTypeT
            | MethodParamType::PmsCurrentPwdLenT
            | MethodParamType::PmsVerifyOldPwdResultT
            | MethodParamType::PmsOldPwdTryRemainingCount
            | MethodParamType::PmsOldPwdTryRemainingTime
            | MethodParamType::PmsResultValidity => {
                if self.data.len() >= 4 {
                    write!(f, "{}", BigEndian::read_i32(&self.data))
                } else {
                    write!(f, "<invalid: {} bytes>", self.data.len())
                }
            }
            // Boolean-like parameters
            MethodParamType::PmsHideEmailT => {
                if self.data.len() >= 4 {
                    let val = BigEndian::read_i32(&self.data);
                    write!(f, "{}", val != 0)
                } else {
                    write!(f, "<invalid: {} bytes>", self.data.len())
                }
            }

            // String parameters
            MethodParamType::PmsAccountName => write!(f, "{}", String::from_utf8_lossy(&self.data)),

            // Binary/hash parameters - show as hex with truncation
            MethodParamType::PmsVerifyBufferT
            | MethodParamType::PmsPwdInfoT
            | MethodParamType::PmsSecureInfoBufferT
            | MethodParamType::PmsChallengeT
            | MethodParamType::PmsHandlerT
            | MethodParamType::PmsEncBufferT
            | MethodParamType::PmsOldPwdBufferT
            | MethodParamType::PmsCurrentPwdBufferT
            | MethodParamType::PmsCurrentPasswordBuffer => {
                if self.data.len() <= 16 {
                    write!(
                        f,
                        "[{}]",
                        self.data
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                } else {
                    write!(
                        f,
                        "[{} ... +{} more]",
                        self.data[..8]
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" "),
                        self.data.len() - 8
                    )
                }
            }
            _ => {
                if self.data.len() <= 8 {
                    write!(
                        f,
                        "{} bytes: [{}]",
                        self.data.len(),
                        self.data
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                } else {
                    write!(
                        f,
                        "{} bytes: [{} ...]",
                        self.data.len(),
                        self.data[..4]
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                }
            }
        }
    }
}

/// Info type for PMS modify operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum PmsInfoType {
    Password = 1,
    SecurityAnswer = 2,
    Email = 4,
    Unknown = -1,
}

impl From<i32> for PmsInfoType {
    fn from(code: i32) -> Self {
        match code {
            1 => PmsInfoType::Password,
            2 => PmsInfoType::SecurityAnswer,
            4 => PmsInfoType::Email,
            _ => PmsInfoType::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum MethodType {
    // Privacy Management System commands
    CeCmdPmsFirstCmd = 4000,
    CeCmdPmsEnroll = 4001,
    CeCmdPmsVerify = 4002,
    CeCmdPmsModify = 4003,
    CeCmdPmsDelete = 4004,
    CeCmdPmsGetInfo = 4005,
    CeCmdPmsRequestEncryptData = 4006,
    CeCmdPmsResetAllData = 4007,
    CeCmdPmsMaxCmd = 4008,

    // Lock screen commands
    CeSetLockScreenPwdType = 2019,
    CeCmdGetRpmbValue = 2014,

    // TA commands for password storage
    TaCmdStoreOldPassword = 13001,
    TaCmdRetrievePasswordByOldPwd = 13002,
    TaCmdPasswordRetrieveValidity = 13003,
    TaCmdDeleteOldPassword = 13004,
    TaCmdPasswordVerifyResult = 13005,

    Unknown(i32),
}

impl MethodType {
    /// Returns the method code as i32
    pub fn code(&self) -> i32 {
        match self {
            MethodType::CeCmdPmsFirstCmd => 4000,
            MethodType::CeCmdPmsEnroll => 4001,
            MethodType::CeCmdPmsVerify => 4002,
            MethodType::CeCmdPmsModify => 4003,
            MethodType::CeCmdPmsDelete => 4004,
            MethodType::CeCmdPmsGetInfo => 4005,
            MethodType::CeCmdPmsRequestEncryptData => 4006,
            MethodType::CeCmdPmsResetAllData => 4007,
            MethodType::CeCmdPmsMaxCmd => 4008,
            MethodType::CeSetLockScreenPwdType => 2019,
            MethodType::CeCmdGetRpmbValue => 2014,
            MethodType::TaCmdStoreOldPassword => 13001,
            MethodType::TaCmdRetrievePasswordByOldPwd => 13002,
            MethodType::TaCmdPasswordRetrieveValidity => 13003,
            MethodType::TaCmdDeleteOldPassword => 13004,
            MethodType::TaCmdPasswordVerifyResult => 13005,
            MethodType::Unknown(code) => *code,
        }
    }

    /// Returns the method code as big-endian bytes
    pub fn to_be_bytes(&self) -> [u8; 4] {
        self.code().to_be_bytes()
    }
}

impl From<i32> for MethodType {
    fn from(code: i32) -> Self {
        match code {
            4000 => MethodType::CeCmdPmsFirstCmd,
            4001 => MethodType::CeCmdPmsEnroll,
            4002 => MethodType::CeCmdPmsVerify,
            4003 => MethodType::CeCmdPmsModify,
            4004 => MethodType::CeCmdPmsDelete,
            4005 => MethodType::CeCmdPmsGetInfo,
            4006 => MethodType::CeCmdPmsRequestEncryptData,
            4007 => MethodType::CeCmdPmsResetAllData,
            4008 => MethodType::CeCmdPmsMaxCmd,
            2019 => MethodType::CeSetLockScreenPwdType,
            2014 => MethodType::CeCmdGetRpmbValue,
            13001 => MethodType::TaCmdStoreOldPassword,
            13002 => MethodType::TaCmdRetrievePasswordByOldPwd,
            13003 => MethodType::TaCmdPasswordRetrieveValidity,
            13004 => MethodType::TaCmdDeleteOldPassword,
            13005 => MethodType::TaCmdPasswordVerifyResult,
            _ => MethodType::Unknown(code),
        }
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
