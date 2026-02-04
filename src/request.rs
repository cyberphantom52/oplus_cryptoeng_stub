use byteorder::{BigEndian, ByteOrder, LittleEndian};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::{
    method::{MethodParamType, MethodType},
    response::{build_native_response, ResponseBuilder},
    storage::Storage,
    utils::generate_random_bytes,
};
use std::collections::HashMap;

/// Request type enum
#[derive(Debug, Clone)]
pub enum Request {
    Standard(StandardRequest),
    Native(NativeRequest),
}

impl Request {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            warn!("Request buffer too short: {} bytes", data.len());
            return None;
        }

        let _cmd_id_le = LittleEndian::read_i32(data);
        let _cmd_id_be = BigEndian::read_i32(data);

        // Check if this is a native command (cmdId <= 100)
        // Native commands use little-endian format and the high bytes are 0
        let _cmd_id_le = LittleEndian::read_i32(data);
        let _cmd_id_be = BigEndian::read_i32(data);

        // If the first byte is a small number and high bytes are 0, it's likely a native command
        if data[1] == 0 && data[2] == 0 && data[3] == 0 && data[0] <= 100 {
            debug!("Detected native command: {}", data[0]);
            return Some(Request::Native(NativeRequest {
                cmd_id: data[0],
                data: data[4..].to_vec(),
            }));
        }

        // Otherwise, parse as standard request (big-endian)
        Self::parse_standard_request(data).map(Request::Standard)
    }

    /// Parse a standard request (cmdId > 100)
    fn parse_standard_request(buffer: &[u8]) -> Option<StandardRequest> {
        if buffer.len() < 12 {
            warn!(
                "Standard request buffer too short: {} bytes (need at least 12)",
                buffer.len()
            );
            return None;
        }

        let method_code = BigEndian::read_i32(&buffer[0..4]);
        let buffer_size = BigEndian::read_i32(&buffer[4..8]);
        let param_count = BigEndian::read_i32(&buffer[8..12]);

        debug!(
            "Parsing standard request: method={}, buffer_size={}, param_count={}",
            method_code, buffer_size, param_count
        );

        let method_type = MethodType::from(method_code);

        let mut params = HashMap::new();
        let mut offset = 12;

        for i in 0..param_count {
            if offset + 8 > buffer.len() {
                warn!(
                    "Buffer too short for param {} header at offset {}",
                    i, offset
                );
                break;
            }

            let param_type = BigEndian::read_i32(&buffer[offset..offset + 4]);
            let param_len = BigEndian::read_i32(&buffer[offset + 4..offset + 8]) as usize;
            offset += 8;

            if offset + param_len > buffer.len() {
                warn!(
                    "Buffer too short for param {} data: need {} bytes at offset {}, have {}",
                    i,
                    param_len,
                    offset,
                    buffer.len()
                );
                break;
            }

            let param_data = buffer[offset..offset + param_len].to_vec();
            offset += param_len;

            debug!(
                "  Param {}: type={} ({:?}), len={}, data={:02x?}",
                i,
                param_type,
                MethodParamType::from(param_type),
                param_len,
                &param_data[..std::cmp::min(32, param_data.len())]
            );

            params.insert(param_type, param_data);
        }

        Some(StandardRequest {
            method_type,
            method_code,
            buffer_size,
            param_count,
            params,
        })
    }
}

/// Parsed standard request (cmdId > 100)
#[derive(Debug, Clone)]
pub struct StandardRequest {
    pub method_type: MethodType,
    pub method_code: i32,
    pub buffer_size: i32,
    pub param_count: i32,
    pub params: HashMap<i32, Vec<u8>>,
}

impl StandardRequest {
    pub fn handle(&self, storage: &mut Storage) -> Vec<u8> {
        info!(
            "Handling standard command: {:?} (code={})",
            self.method_type, self.method_code
        );
        match self.method_type {
            MethodType::CeCmdPmsEnroll => self.handle_pms_enroll(storage),
            MethodType::CeCmdPmsVerify => self.handle_pms_verify(storage),
            MethodType::CeCmdPmsModify => self.handle_pms_modify(storage),
            MethodType::CeCmdPmsDelete => self.handle_pms_delete(storage),
            MethodType::CeCmdPmsGetInfo => self.handle_pms_get_info(storage),
            MethodType::CeCmdPmsRequestEncryptData => self.handle_pms_request_encrypt_data(storage),
            MethodType::CeCmdPmsResetAllData => self.handle_pms_reset_all_data(storage),
            MethodType::CeSetLockScreenPwdType => self.handle_set_lock_screen_pwd_type(storage),
            MethodType::CeCmdGetRpmbValue => self.handle_get_rpmb_value(storage),
            MethodType::TaCmdStoreOldPassword => self.handle_store_old_password(storage),
            MethodType::TaCmdRetrievePasswordByOldPwd => {
                self.handle_retrieve_password_by_old_pwd(storage)
            }
            MethodType::TaCmdPasswordRetrieveValidity => {
                self.handle_password_retrieve_validity(storage)
            }
            MethodType::TaCmdDeleteOldPassword => self.handle_delete_old_password(storage),
            MethodType::TaCmdPasswordVerifyResult => self.handle_password_verify_result(storage),
            _ => {
                warn!(
                    "Unknown standard command: {:?} (code={})",
                    self.method_type, self.method_code
                );
                // Return success with no params for unknown commands
                ResponseBuilder::new(self.method_code).build()
            }
        }
    }

    fn handle_pms_enroll(&self, storage: &mut Storage) -> Vec<u8> {
        info!("PMS Enroll");

        // Get system type from params
        let system_type = self
            .params
            .get(&(MethodParamType::PmsTypeT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let privacy_data = storage.get_privacy_data_mut(system_type);

        // Get password type
        if let Some(pwd_type) = self.params.get(&(MethodParamType::PmsPwdTypeT as i32)) {
            if pwd_type.len() >= 4 {
                privacy_data.password_type = BigEndian::read_i32(pwd_type);
            }
        }

        // Get password info (hash)
        if let Some(pwd_info) = self.params.get(&(MethodParamType::PmsPwdInfoT as i32)) {
            privacy_data.password_hash = pwd_info.clone();
        }

        // Get email
        if let Some(email) = self.params.get(&(MethodParamType::PmsHideEmailT as i32)) {
            privacy_data.email = String::from_utf8_lossy(email).to_string();
        }

        // Generate a handler token (must be exactly 8 bytes for password verification)
        // The verification combines SHA256(password) + handler into a 40-byte buffer
        privacy_data.handler = generate_random_bytes(8);
        privacy_data.enrolled = true;
        privacy_data.retry_count = 5;
        privacy_data.lock_time = 0;

        info!(
            "PMS Enroll: system_type={}, password_type={}, handler_len={}",
            system_type,
            privacy_data.password_type,
            privacy_data.handler.len()
        );

        // Clone the handler before saving to avoid borrow checker issues
        let handler = privacy_data.handler.clone();

        storage.save();

        ResponseBuilder::new(self.method_code)
            .add_param(MethodParamType::PmsHandlerT, handler)
            .build()
    }

    fn handle_pms_verify(&self, storage: &mut Storage) -> Vec<u8> {
        info!("PMS Verify");

        let system_type = self
            .params
            .get(&(MethodParamType::PmsTypeT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let verify_type = self
            .params
            .get(&(MethodParamType::PmsVerifyTypeT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let verify_buffer = self
            .params
            .get(&(MethodParamType::PmsVerifyBufferT as i32))
            .cloned();

        info!(
            "PMS Verify: system_type={}, verify_type={}, has_verify_buffer={}",
            system_type,
            verify_type,
            verify_buffer.is_some()
        );

        if let Some(ref buf) = verify_buffer {
            debug!(
                "  Verify buffer ({} bytes): {:02x?}",
                buf.len(),
                &buf[..std::cmp::min(32, buf.len())]
            );
        }

        let privacy_data = storage.get_privacy_data_mut(system_type);

        // Check if locked
        if privacy_data.lock_time > 0 {
            warn!(
                "PMS Verify: Account is locked for {} seconds",
                privacy_data.lock_time
            );
            return ResponseBuilder::new(self.method_code)
                .result_code(-1)
                .add_param_i32(MethodParamType::PmsPwdLockTimeLeftT, privacy_data.lock_time)
                .build();
        }

        // Check if enrolled
        if !privacy_data.enrolled {
            warn!("PMS Verify: Not enrolled for system_type={}", system_type);
            return ResponseBuilder::new(self.method_code)
                .result_code(-1)
                .build();
        }

        // Verify the password
        // The client sends: SHA256(SHA256(password) + handler)
        // We have stored: SHA256(password) as password_hash and handler
        // So we compute: SHA256(password_hash + handler) and compare

        let verify_buffer = match verify_buffer {
            Some(buf) => buf,
            None => {
                warn!("PMS Verify: No verify buffer provided");
                return ResponseBuilder::new(self.method_code)
                    .result_code(-1)
                    .build();
            }
        };

        // Compute expected hash: SHA256(stored_password_hash + handler)
        let mut combined = Vec::with_capacity(40);
        combined.extend_from_slice(&privacy_data.password_hash);
        combined.extend_from_slice(&privacy_data.handler);

        let mut hasher = Sha256::new();
        hasher.update(&combined);
        let expected_hash = hasher.finalize();

        debug!(
            "  Stored password_hash ({} bytes): {:02x?}",
            privacy_data.password_hash.len(),
            &privacy_data.password_hash[..std::cmp::min(32, privacy_data.password_hash.len())]
        );
        debug!(
            "  Handler ({} bytes): {:02x?}",
            privacy_data.handler.len(),
            &privacy_data.handler
        );
        debug!("  Expected hash: {:02x?}", &expected_hash[..]);
        debug!(
            "  Received hash: {:02x?}",
            &verify_buffer[..std::cmp::min(32, verify_buffer.len())]
        );

        // Compare the hashes
        if verify_buffer.len() == 32 && verify_buffer[..] == expected_hash[..] {
            // Generate a challenge token (32 bytes) for successful verification
            let challenge = generate_random_bytes(32);

            info!("PMS Verify: Password verified successfully!");

            // Reset retry count on success
            privacy_data.retry_count = 5;

            // Clone values before releasing the borrow
            let handler = privacy_data.handler.clone();

            storage.save();

            ResponseBuilder::new(self.method_code)
                .add_param(MethodParamType::PmsChallengeT, challenge)
                .add_param(MethodParamType::PmsHandlerT, handler)
                .build()
        } else {
            // Decrement retry count
            privacy_data.retry_count = (privacy_data.retry_count - 1).max(0);

            warn!(
                "PMS Verify: Password mismatch! Retries left: {}",
                privacy_data.retry_count
            );

            // Lock account if no retries left
            if privacy_data.retry_count == 0 {
                privacy_data.lock_time = 30; // Lock for 30 seconds
                warn!(
                    "PMS Verify: Account locked for {} seconds",
                    privacy_data.lock_time
                );
            }

            let retry_count = privacy_data.retry_count;

            storage.save();

            ResponseBuilder::new(self.method_code)
                .result_code(-1)
                .add_param_i32(MethodParamType::PmsPwdRetryCountLeftT, retry_count)
                .build()
        }
    }

    fn handle_pms_modify(&self, storage: &mut Storage) -> Vec<u8> {
        info!("PMS Modify");

        let system_type = self
            .params
            .get(&(MethodParamType::PmsTypeT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let privacy_data = storage.get_privacy_data_mut(system_type);

        // Update password type if provided
        if let Some(pwd_type) = self.params.get(&(MethodParamType::PmsPwdTypeT as i32)) {
            if pwd_type.len() >= 4 {
                privacy_data.password_type = BigEndian::read_i32(pwd_type);
            }
        }

        // Update password info if provided
        if let Some(pwd_info) = self.params.get(&(MethodParamType::PmsPwdInfoT as i32)) {
            privacy_data.password_hash = pwd_info.clone();
        }

        // Update email if provided
        if let Some(email) = self.params.get(&(MethodParamType::PmsHideEmailT as i32)) {
            privacy_data.email = String::from_utf8_lossy(email).to_string();
        }

        storage.save();

        ResponseBuilder::new(self.method_code).build()
    }

    fn handle_pms_delete(&self, storage: &mut Storage) -> Vec<u8> {
        info!("PMS Delete");

        let system_type = self
            .params
            .get(&(MethodParamType::PmsTypeT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        storage.reset_privacy_data(system_type);
        storage.save();

        ResponseBuilder::new(self.method_code).build()
    }

    fn handle_pms_get_info(&self, storage: &mut Storage) -> Vec<u8> {
        info!("PMS Get Info");

        let system_type = self
            .params
            .get(&(MethodParamType::PmsTypeT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let privacy_data = storage
            .get_privacy_data(system_type)
            .cloned()
            .unwrap_or_default();

        info!(
            "PMS Get Info: system_type={}, password_type={}, enrolled={}, handler_len={}, retry_count={}",
            system_type,
            privacy_data.password_type,
            privacy_data.enrolled,
            privacy_data.handler.len(),
            privacy_data.retry_count
        );

        let mut builder = ResponseBuilder::new(self.method_code)
            .add_param_i32(MethodParamType::PmsPwdTypeT, privacy_data.password_type)
            .add_param_i32(
                MethodParamType::PmsPwdRetryCountLeftT,
                privacy_data.retry_count,
            )
            .add_param_i32(MethodParamType::PmsPwdLockTimeLeftT, privacy_data.lock_time)
            .add_param_i32(
                MethodParamType::PmsSecureQuestionRetryCountLeftT,
                privacy_data.secure_question_retry_count,
            )
            .add_param_i32(
                MethodParamType::PmsSecureQuestionLockTimeLeftT,
                privacy_data.secure_question_lock_time,
            );

        if !privacy_data.handler.is_empty() {
            builder = builder.add_param(MethodParamType::PmsHandlerT, privacy_data.handler.clone());
            debug!("  Added handler: {:02x?}", privacy_data.handler);
        } else {
            warn!("  No handler found for system_type={}", system_type);
        }

        if !privacy_data.email.is_empty() {
            builder = builder.add_param_string(MethodParamType::PmsHideEmailT, &privacy_data.email);
        }

        builder.build()
    }

    fn handle_pms_request_encrypt_data(&self, _storage: &mut Storage) -> Vec<u8> {
        info!("PMS Request Encrypt Data");

        // For stub, return the input data as-is (no actual encryption)
        let encrypted_data = self
            .params
            .get(&(MethodParamType::PmsInfoBufferT as i32))
            .cloned()
            .unwrap_or_default();

        ResponseBuilder::new(self.method_code)
            .add_param(MethodParamType::PmsEncBufferT, encrypted_data)
            .build()
    }

    fn handle_pms_reset_all_data(&self, storage: &mut Storage) -> Vec<u8> {
        info!("PMS Reset All Data");

        let system_type = self
            .params
            .get(&(MethodParamType::PmsTypeT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        storage.reset_privacy_data(system_type);
        storage.save();

        ResponseBuilder::new(self.method_code).build()
    }

    fn handle_set_lock_screen_pwd_type(&self, storage: &mut Storage) -> Vec<u8> {
        info!("Set Lock Screen Password Type");

        let user_id = self
            .params
            .get(&(MethodParamType::PmsPwdUseridT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let pwd_type = self
            .params
            .get(&(MethodParamType::PmsPwdTypeT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        storage.set_lock_screen_pwd_type(user_id, pwd_type);
        storage.save();

        ResponseBuilder::new(self.method_code).build()
    }

    fn handle_get_rpmb_value(&self, storage: &mut Storage) -> Vec<u8> {
        info!("Get RPMB Value");

        let key = self
            .params
            .get(&(MethodParamType::PmsCommonBuffer0T as i32))
            .map(|v| String::from_utf8_lossy(v).to_string())
            .unwrap_or_default();

        let value = storage.get_rpmb_value(&key).cloned().unwrap_or_default();

        ResponseBuilder::new(self.method_code)
            .add_param(MethodParamType::PmsCommonBuffer1T, value)
            .build()
    }

    fn handle_store_old_password(&self, storage: &mut Storage) -> Vec<u8> {
        info!("TA Store Old Password");

        let user_id = self
            .params
            .get(&(MethodParamType::PmsPwdUseridT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let pwd_data = storage.get_password_data_mut(user_id);

        if let Some(old_pwd_type) = self.params.get(&(MethodParamType::PmsOldPwdTypeT as i32)) {
            if old_pwd_type.len() >= 4 {
                pwd_data.old_pwd_type = BigEndian::read_i32(old_pwd_type);
            }
        }

        if let Some(old_pwd_buffer) = self.params.get(&(MethodParamType::PmsOldPwdBufferT as i32)) {
            pwd_data.old_pwd_buffer = old_pwd_buffer.clone();
        }

        if let Some(current_pwd_type) = self
            .params
            .get(&(MethodParamType::PmsCurrentPwdTypeT as i32))
        {
            if current_pwd_type.len() >= 4 {
                pwd_data.current_pwd_type = BigEndian::read_i32(current_pwd_type);
            }
        }

        if let Some(current_pwd_buffer) = self
            .params
            .get(&(MethodParamType::PmsCurrentPwdBufferT as i32))
        {
            pwd_data.current_pwd_buffer = current_pwd_buffer.clone();
        }

        if let Some(system_time) = self
            .params
            .get(&(MethodParamType::PmsPwdSystemTimeT as i32))
        {
            if system_time.len() >= 8 {
                pwd_data.system_time = BigEndian::read_i64(system_time);
            }
        }

        pwd_data.user_id = user_id;
        storage.save();

        ResponseBuilder::new(self.method_code).build()
    }

    fn handle_retrieve_password_by_old_pwd(&self, storage: &mut Storage) -> Vec<u8> {
        info!("TA Retrieve Password By Old Password");

        let user_id = self
            .params
            .get(&(MethodParamType::PmsPwdUseridT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        if let Some(pwd_data) = storage.get_password_data(user_id) {
            ResponseBuilder::new(self.method_code)
                .add_param(
                    MethodParamType::PmsCurrentPasswordBuffer,
                    pwd_data.current_pwd_buffer.clone(),
                )
                .add_param_i32(
                    MethodParamType::PmsCurrentPasswordType,
                    pwd_data.current_pwd_type,
                )
                .add_param_i32(MethodParamType::PmsVerifyOldPwdResultT, 0) // Success
                .build()
        } else {
            ResponseBuilder::new(self.method_code)
                .result_code(-1)
                .build()
        }
    }

    fn handle_password_retrieve_validity(&self, storage: &mut Storage) -> Vec<u8> {
        info!("TA Password Retrieve Validity");

        let user_id = self
            .params
            .get(&(MethodParamType::PmsPwdUseridT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let is_valid = storage.get_password_data(user_id).is_some();

        ResponseBuilder::new(self.method_code)
            .add_param_i32(
                MethodParamType::PmsResultValidity,
                if is_valid { 1 } else { 0 },
            )
            .build()
    }

    fn handle_delete_old_password(&self, storage: &mut Storage) -> Vec<u8> {
        info!("TA Delete Old Password");

        let user_id = self
            .params
            .get(&(MethodParamType::PmsPwdUseridT as i32))
            .map(|v| {
                if v.len() >= 4 {
                    BigEndian::read_i32(v)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        storage.delete_password_data(user_id);
        storage.save();

        ResponseBuilder::new(self.method_code).build()
    }

    fn handle_password_verify_result(&self, _storage: &mut Storage) -> Vec<u8> {
        info!("TA Password Verify Result");

        // For stub, always return success
        ResponseBuilder::new(self.method_code)
            .add_param_i32(MethodParamType::PmsVerifyOldPwdResultT, 0)
            .add_param_i32(MethodParamType::PmsOldPwdTryRemainingCount, 5)
            .build()
    }
}

/// Parsed native request (cmdId <= 100)
#[derive(Debug, Clone)]
pub struct NativeRequest {
    pub cmd_id: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// Native Commands (cmdId <= 100)
pub enum NativeCommand {
    WriteSecret = 8,
    PresetDataDec = 26,
    Unknown = 0,
}

impl From<u8> for NativeCommand {
    fn from(code: u8) -> Self {
        match code {
            8 => NativeCommand::WriteSecret,
            26 => NativeCommand::PresetDataDec,
            _ => NativeCommand::Unknown,
        }
    }
}

impl NativeRequest {
    pub fn handle(&self, storage: &mut Storage) -> Vec<u8> {
        let cmd = NativeCommand::from(self.cmd_id);
        info!("Handling native command: {:?} (id={})", cmd, self.cmd_id);
        match cmd {
            NativeCommand::WriteSecret => self.handle_write_secret(storage),
            NativeCommand::PresetDataDec => self.handle_preset_data_dec(storage),
            NativeCommand::Unknown => {
                warn!("Unknown native command: {}", self.cmd_id);
                build_native_response(0, None)
            }
        }
    }

    fn handle_write_secret(&self, storage: &mut Storage) -> Vec<u8> {
        info!("Native WriteSecret command");

        // Parse the native format:
        // [secret_length: 4 bytes LE][secret: N bytes][token_length: 4 bytes LE][token: M bytes]
        if self.data.len() < 4 {
            warn!("WriteSecret: buffer too short for secret length");
            return build_native_response(-1, None);
        }

        let secret_length = LittleEndian::read_i32(&self.data[0..4]) as usize;
        let mut offset = 4;

        if self.data.len() < offset + secret_length {
            warn!("WriteSecret: buffer too short for secret data");
            return build_native_response(-1, None);
        }

        let secret = &self.data[offset..offset + secret_length];
        offset += secret_length;

        if self.data.len() < offset + 4 {
            warn!("WriteSecret: buffer too short for token length");
            return build_native_response(-1, None);
        }

        let token_length = LittleEndian::read_i32(&self.data[offset..offset + 4]) as usize;
        offset += 4;

        if self.data.len() < offset + token_length {
            warn!("WriteSecret: buffer too short for token data");
            return build_native_response(-1, None);
        }

        let _token = &self.data[offset..offset + token_length];

        debug!(
            "WriteSecret: secret_len={}, token_len={}",
            secret_length, token_length
        );

        // Store the secret
        storage.store_secret(secret_length as i32, secret.to_vec());
        storage.save();

        build_native_response(0, None)
    }

    fn handle_preset_data_dec(&self, _storage: &mut Storage) -> Vec<u8> {
        info!("Native PresetDataDec command");

        // Parse the native format:
        // [aliBuf_len: 4 bytes LE][aliBuf: N bytes][enc_len: 4 bytes LE][enc: M bytes]
        if self.data.len() < 4 {
            warn!("PresetDataDec: buffer too short for aliBuf length");
            return build_native_response(-1, None);
        }

        let ali_buf_len = LittleEndian::read_i32(&self.data[0..4]) as usize;
        let mut offset = 4;

        if self.data.len() < offset + ali_buf_len {
            warn!("PresetDataDec: buffer too short for aliBuf data");
            return build_native_response(-1, None);
        }

        let ali_buf = &self.data[offset..offset + ali_buf_len];
        offset += ali_buf_len;

        if self.data.len() < offset + 4 {
            warn!("PresetDataDec: buffer too short for enc length");
            return build_native_response(-1, None);
        }

        let enc_len = LittleEndian::read_i32(&self.data[offset..offset + 4]) as usize;
        offset += 4;

        if self.data.len() < offset + enc_len {
            warn!("PresetDataDec: buffer too short for enc data");
            return build_native_response(-1, None);
        }

        let enc_data = &self.data[offset..offset + enc_len];

        debug!(
            "PresetDataDec: aliBuf={:?}, enc_len={}",
            String::from_utf8_lossy(ali_buf),
            enc_len
        );

        // For stub, return the encrypted data as-is (no actual decryption)
        build_native_response(0, Some(enc_data))
    }
}
