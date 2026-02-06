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

    // Privacy Management System
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
    CeCmdRpmbStorageWriteCustomizeMsg = 5011,
    CeCmdRpmbStorageReadCustomizeMsg = 5012,

    // Core
    CeCmdRunCoreFirstCmd = 6000,
    CeCmdCoreGetVersion = 6001,
    CeCmdCoreGetFeatureSupport = 6002,
    CeCmdCoreGetDeviceid = 6003,
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

    // TA Password Storage
    TaCmdStoreOldPassword = 13001,
    TaCmdRetrievePasswordByOldPwd = 13002,
    TaCmdPasswordRetrieveValidity = 13003,
    TaCmdDeleteOldPassword = 13004,
    TaCmdPasswordVerifyResult = 13005,

    // OLock
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
            // Base commands (3-90)
            3 => MethodType::CeCmdGoogleAttestationWrite,
            4 => MethodType::CeCmdGoogleAttestationVerify,
            18 => MethodType::CeCmdFindphoneGetStatus,
            24 => MethodType::CeCmdGeneratePkiCert,
            25 => MethodType::CeCmdVerifyPkiCert,
            26 => MethodType::CeCmdPresetDataDec,
            30 => MethodType::CeCmdGroupPkiVerify,
            51 => MethodType::CeCmdHdcpKeyWrite,
            52 => MethodType::CeCmdHdcpKeyVerify,
            53 => MethodType::CeCmdCleanUp,
            54 => MethodType::CeCmdGetSecuretype,
            59 => MethodType::CeCmdWidevineSupport,
            60 => MethodType::CeCmdCryptoSupport,
            90 => MethodType::CeCmdEngineer,

            // Find Phone (2014-2022)
            2014 => MethodType::CeCmdRunFindphoneGetMemberFromRpmb,
            2015 => MethodType::CeCmdRunFindphoneResetRpmb,
            2018 => MethodType::CeCmdRunFindphoneIsSupportUnlockByPasswd,
            2019 => MethodType::CeCmdRunFindphoneSetPasswdType,
            2020 => MethodType::CeCmdRunFindphoneGetPasswdType,
            2021 => MethodType::CeCmdRunFindphoneVerifyPasswd,
            2022 => MethodType::CeCmdRunFindphoneGetSalt,

            // Privacy Management System (4000-4008)
            4000 => MethodType::CeCmdPmsFirstCmd,
            4001 => MethodType::CeCmdPmsEnroll,
            4002 => MethodType::CeCmdPmsVerify,
            4003 => MethodType::CeCmdPmsModify,
            4004 => MethodType::CeCmdPmsDelete,
            4005 => MethodType::CeCmdPmsGetInfo,
            4006 => MethodType::CeCmdPmsRequestEncryptData,
            4007 => MethodType::CeCmdPmsResetAllData,
            4008 => MethodType::CeCmdPmsMaxCmd,

            // Rpmb (5011-5012)
            5011 => MethodType::CeCmdRpmbStorageWriteCustomizeMsg,
            5012 => MethodType::CeCmdRpmbStorageReadCustomizeMsg,

            // Core (6000-6016)
            6000 => MethodType::CeCmdRunCoreFirstCmd,
            6001 => MethodType::CeCmdCoreGetVersion,
            6002 => MethodType::CeCmdCoreGetFeatureSupport,
            6003 => MethodType::CeCmdCoreGetDeviceid,
            6015 => MethodType::CeCmdIdMseEncCmd,
            6016 => MethodType::CeCmdIdMseDecCmd,

            // PKI (10000-10021)
            10000 => MethodType::CeCmdRunPkiFirstCmd,
            10001 => MethodType::CeCmdRunPkiHash,
            10002 => MethodType::CeCmdRunPkiHmac,
            10003 => MethodType::CeCmdRunPkiHkdf,
            10004 => MethodType::CeCmdRunPkiAes,
            10005 => MethodType::CeCmdRunPkiRsa,
            10006 => MethodType::CeCmdRunPkiEcdh,
            10007 => MethodType::CeCmdRunPkiEcies,
            10008 => MethodType::CeCmdRunPkiEcdsa,
            10009 => MethodType::CeCmdRunPkiCertVerify,
            10010 => MethodType::CeCmdRunPkiSign,
            10011 => MethodType::CeCmdRunPkiEciesCertEnc,
            10012 => MethodType::CeCmdRunPkiEciesCertDec,
            10013 => MethodType::CeCmdRunPkiPresetDataDec,
            10014 => MethodType::CeCmdRunPkiBasicAttestation,
            10015 => MethodType::CeCmdRunPkiCommonIdAttestation,
            10020 => MethodType::CeCmdRunPkiExportCert,
            10021 => MethodType::CeCmdRunPkiMax,

            // TA Password Storage (13001-13005)
            13001 => MethodType::TaCmdStoreOldPassword,
            13002 => MethodType::TaCmdRetrievePasswordByOldPwd,
            13003 => MethodType::TaCmdPasswordRetrieveValidity,
            13004 => MethodType::TaCmdDeleteOldPassword,
            13005 => MethodType::TaCmdPasswordVerifyResult,

            // OLock (14000-14010)
            14000 => MethodType::CeCmdIdOlockFirstCmd,
            14001 => MethodType::CeCmdIdOlockStateOpen,
            14002 => MethodType::CeCmdIdOlockStateClose,
            14003 => MethodType::CeCmdIdOlockSecureLockStateOpen,
            14004 => MethodType::CeCmdIdOlockSecureLockStateClose,
            14005 => MethodType::CeCmdIdOlockStateGet,
            14006 => MethodType::CeCmdIdOlockSecureLockStateGet,
            14007 => MethodType::CeCmdIdOlockGetPasswdType,
            14008 => MethodType::CeCmdIdOlockGetSalt,
            14009 => MethodType::CeCmdIdOlockVerifyPasswd,
            14010 => MethodType::CeCmdIdOlockMaxCmd,

            _ => MethodType::Unknown(code),
        }
    }
}
