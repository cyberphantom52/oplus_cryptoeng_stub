use serde::{Deserialize, Serialize};

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

    Unknown = -1,
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
            _ => MethodType::Unknown,
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
