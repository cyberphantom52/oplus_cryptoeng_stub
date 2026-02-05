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
                write!(
                    f,
                    "[{}]",
                    self.data
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
            _ => {
                tracing::error!("Display not implemented for {:?}", self.ty);
                Ok(())
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
    CeCmdGoogleAttestationWrite = 3,
    CeCmdGoogleAttestationVerify = 4,
    CeCmdFindphoneGetStatus = 18,
    CeCmdGeneratePkiCert = 24,
    CeCmdVerifyPkiCert = 25,
    CeCmdPresetDataDec = 26,
    CeCmdGroupPkiVerify = 30,
    CeCmdHdcpKeyWrite = 51,
    CeCmdHdcpKeyVerify = 52,
    CeCmdCleanUp = 53,
    CeCmdGetSecuretype = 54,
    CeCmdWidevineSupport = 59,
    CeCmdCryptoSupport = 60,
    CeCmdEngineer = 90,

    // Find Phone
    CeCmdRunFindphoneGetMemberFromRpmb = 2014,
    CeCmdRunFindphoneResetRpmb = 2015,
    CeCmdRunFindphoneIsSupportUnlockByPasswd = 2018,
    CeCmdRunFindphoneSetPasswdType = 2019,
    CeCmdRunFindphoneGetPasswdType = 2020,
    CeCmdRunFindphoneVerifyPasswd = 2021,
    CeCmdRunFindphoneGetSalt = 2022,

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

    // Rpmb
    CeCmdRpmbStorageReadCustomizeMsg = 5012,
    CeCmdRpmbStorageWriteCustomizeMsg = 5011,

    // Core
    CeCmdRunCoreFirstCmd = 6000,
    CeCmdCoreGetVersion = 6001,
    CeCmdCoreGetFeatureSupport = 6002,
    CeCmdCoreGetDeviceid = 6003,

    // MSE
    CeCmdIdMseEncCmd = 6015,
    CeCmdIdMseDecCmd = 6016,

    // PKI
    CeCmdRunPkiFirstCmd = 10000,
    CeCmdRunPkiHash = 10001,
    CeCmdRunPkiHmac = 10002,
    CeCmdRunPkiHkdf = 10003,
    CeCmdRunPkiAes = 10004,
    CeCmdRunPkiRsa = 10005,
    CeCmdRunPkiEcdh = 10006,
    CeCmdRunPkiEcies = 10007,
    CeCmdRunPkiEcdsa = 10008,
    CeCmdRunPkiCertVerify = 10009,
    CeCmdRunPkiSign = 10010,
    CeCmdRunPkiEciesCertEnc = 10011,
    CeCmdRunPkiEciesCertDec = 10012,
    CeCmdRunPkiPresetDataDec = 10013,
    CeCmdRunPkiBasicAttestation = 10014,
    CeCmdRunPkiCommonIdAttestation = 10015,
    CeCmdRunPkiExportCert = 10020,
    CeCmdRunPkiMax = 10021,

    // TA commands for password storage
    TaCmdStoreOldPassword = 13001,
    TaCmdRetrievePasswordByOldPwd = 13002,
    TaCmdPasswordRetrieveValidity = 13003,
    TaCmdDeleteOldPassword = 13004,
    TaCmdPasswordVerifyResult = 13005,

    // OLock commands
    CeCmdIdOlockFirstCmd = 14000,
    CeCmdIdOlockStateOpen = 14001,
    CeCmdIdOlockStateClose = 14002,
    CeCmdIdOlockSecureLockStateOpen = 14003,
    CeCmdIdOlockSecureLockStateClose = 14004,
    CeCmdIdOlockStateGet = 14005,
    CeCmdIdOlockSecureLockStateGet = 14006,
    CeCmdIdOlockGetPasswdType = 14007,
    CeCmdIdOlockGetSalt = 14008,
    CeCmdIdOlockVerifyPasswd = 14009,
    CeCmdIdOlockMaxCmd = 14010,

    Unknown(i32),
}

impl MethodType {
    /// Returns the method code as i32
    pub fn code(&self) -> i32 {
        match self {
            MethodType::CeCmdPresetDataDec => 26,
            MethodType::CeCmdCleanUp => 53,
            MethodType::CeCmdCryptoSupport => 60,
            MethodType::CeCmdEngineer => 90,
            MethodType::CeCmdFindphoneGetStatus => 18,
            MethodType::CeCmdGeneratePkiCert => 24,
            MethodType::CeCmdGetSecuretype => 54,
            MethodType::CeCmdGoogleAttestationVerify => 4,
            MethodType::CeCmdGoogleAttestationWrite => 3,
            MethodType::CeCmdHdcpKeyVerify => 52,
            MethodType::CeCmdHdcpKeyWrite => 51,
            MethodType::CeCmdVerifyPkiCert => 25,
            MethodType::CeCmdGroupPkiVerify => 30,
            MethodType::CeCmdWidevineSupport => 59,
            MethodType::CeCmdRunFindphoneResetRpmb => 2015,
            MethodType::CeCmdRunFindphoneIsSupportUnlockByPasswd => 2018,
            MethodType::CeCmdRunFindphoneGetPasswdType => 2020,
            MethodType::CeCmdRunFindphoneVerifyPasswd => 2021,
            MethodType::CeCmdRunFindphoneGetSalt => 2022,
            MethodType::CeCmdRunCoreFirstCmd => 6000,

            // OLock
            MethodType::CeCmdIdOlockFirstCmd => 14000,
            MethodType::CeCmdIdOlockStateOpen => 14001,
            MethodType::CeCmdIdOlockStateClose => 14002,
            MethodType::CeCmdIdOlockSecureLockStateOpen => 14003,
            MethodType::CeCmdIdOlockSecureLockStateClose => 14004,
            MethodType::CeCmdIdOlockStateGet => 14005,
            MethodType::CeCmdIdOlockSecureLockStateGet => 14006,
            MethodType::CeCmdIdOlockGetPasswdType => 14007,
            MethodType::CeCmdIdOlockGetSalt => 14008,
            MethodType::CeCmdIdOlockVerifyPasswd => 14009,
            MethodType::CeCmdIdOlockMaxCmd => 14010,

            MethodType::CeCmdPmsFirstCmd => 4000,
            MethodType::CeCmdPmsEnroll => 4001,
            MethodType::CeCmdPmsVerify => 4002,
            MethodType::CeCmdPmsModify => 4003,
            MethodType::CeCmdPmsDelete => 4004,
            MethodType::CeCmdPmsGetInfo => 4005,
            MethodType::CeCmdPmsRequestEncryptData => 4006,
            MethodType::CeCmdPmsResetAllData => 4007,
            MethodType::CeCmdPmsMaxCmd => 4008,
            MethodType::CeCmdRunFindphoneSetPasswdType => 2019,
            MethodType::CeCmdRunFindphoneGetMemberFromRpmb => 2014,
            MethodType::CeCmdCoreGetVersion => 6001,
            MethodType::CeCmdCoreGetFeatureSupport => 6002,
            MethodType::CeCmdCoreGetDeviceid => 6003,
            MethodType::CeCmdIdMseEncCmd => 6015,
            MethodType::CeCmdIdMseDecCmd => 6016,
            MethodType::CeCmdRpmbStorageReadCustomizeMsg => 5012,
            MethodType::CeCmdRpmbStorageWriteCustomizeMsg => 5011,

            // PKI
            MethodType::CeCmdRunPkiFirstCmd => 10000,
            MethodType::CeCmdRunPkiHash => 10001,
            MethodType::CeCmdRunPkiHmac => 10002,
            MethodType::CeCmdRunPkiHkdf => 10003,
            MethodType::CeCmdRunPkiAes => 10004,
            MethodType::CeCmdRunPkiRsa => 10005,
            MethodType::CeCmdRunPkiEcdh => 10006,
            MethodType::CeCmdRunPkiEcies => 10007,
            MethodType::CeCmdRunPkiEcdsa => 10008,
            MethodType::CeCmdRunPkiCertVerify => 10009,
            MethodType::CeCmdRunPkiSign => 10010,
            MethodType::CeCmdRunPkiEciesCertEnc => 10011,
            MethodType::CeCmdRunPkiEciesCertDec => 10012,
            MethodType::CeCmdRunPkiPresetDataDec => 10013,
            MethodType::CeCmdRunPkiBasicAttestation => 10014,
            MethodType::CeCmdRunPkiCommonIdAttestation => 10015,
            MethodType::CeCmdRunPkiExportCert => 10020,
            MethodType::CeCmdRunPkiMax => 10021,

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
            2019 => MethodType::CeCmdRunFindphoneSetPasswdType,
            2014 => MethodType::CeCmdRunFindphoneGetMemberFromRpmb,
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
