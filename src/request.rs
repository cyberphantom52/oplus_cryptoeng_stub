use byteorder::{BigEndian, ByteOrder, LittleEndian};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::{
    method::{MethodParamType, MethodType, Parameter, PmsInfoType},
    response::ResponseBuilder,
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
            warn!(len = data.len(), "Request buffer too short");
            return None;
        }

        // If the first byte is a small number and high bytes are 0, it's a native command
        if data[0] <= 100 && data[1..=3] == [0, 0, 0] {
            let request = NativeRequest::from(data);
            debug!(command = ?request.command, "Detected native command:");
            return Some(Request::Native(request));
        }

        // Otherwise, parse as standard request (big-endian)
        StandardRequest::try_from(data).ok().map(Request::Standard)
    }
}

/// Format a parameter value for logging based on its type
fn format_param_value(param_type: &MethodParamType, data: &[u8]) -> String {
    match param_type {
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
            if data.len() >= 4 {
                format!("{}", BigEndian::read_i32(data))
            } else {
                format!("<invalid: {} bytes>", data.len())
            }
        }

        // Boolean-like parameters
        MethodParamType::PmsHideEmailT => {
            if data.len() >= 4 {
                let val = BigEndian::read_i32(data);
                if val == 0 {
                    "false".to_string()
                } else {
                    "true".to_string()
                }
            } else {
                format!("<invalid: {} bytes>", data.len())
            }
        }

        // String parameters
        MethodParamType::PmsAccountName => String::from_utf8_lossy(data).to_string(),

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
            if data.len() <= 16 {
                format!(
                    "[{}]",
                    data.iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            } else {
                format!(
                    "[{} ... +{} more]",
                    data[..8]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" "),
                    data.len() - 8
                )
            }
        }

        // Default: show length and first few bytes
        _ => {
            if data.len() <= 8 {
                format!(
                    "{} bytes: [{}]",
                    data.len(),
                    data.iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            } else {
                format!(
                    "{} bytes: [{} ...]",
                    data.len(),
                    data[..4]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
        }
    }
}

/// Parsed standard request (cmdId > 100)
#[derive(Debug, Clone)]
pub struct StandardRequest {
    pub method_type: MethodType,
    pub params: HashMap<MethodParamType, Vec<u8>>,
}

impl TryFrom<&[u8]> for StandardRequest {
    type Error = &'static str;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        if buffer.len() < 12 {
            warn!(
                len = buffer.len(),
                min = 12,
                "Standard request buffer too short:"
            );
            return Err("Buffer too short");
        }

        let method_type = MethodType::from(BigEndian::read_i32(&buffer[0..4]));
        let param_count = BigEndian::read_i32(&buffer[8..12]);

        debug!(
            method = ?method_type,
            code = method_type.code(),
            param_count,
            "Parsing standard request:"
        );

        let mut params = HashMap::new();
        let mut offset = 12;

        for i in 0..param_count {
            if offset + 8 > buffer.len() {
                warn!(
                    param_index = i,
                    offset,
                    buffer_len = buffer.len(),
                    "Buffer too short for param header:"
                );
                break;
            }

            let param_type_code = BigEndian::read_i32(&buffer[offset..offset + 4]);
            let param_len = BigEndian::read_i32(&buffer[offset + 4..offset + 8]) as usize;
            offset += 8;

            if offset + param_len > buffer.len() {
                warn!(
                    param_index = i,
                    param_len,
                    offset,
                    buffer_len = buffer.len(),
                    "Buffer too short for param data:"
                );
                break;
            }

            let param_data = buffer[offset..offset + param_len].to_vec();
            offset += param_len;

            let param_type = MethodParamType::from(param_type_code);
            let value_preview = format_param_value(&param_type, &param_data);

            debug!(
                param_index = i,
                param_type = ?param_type,
                len = param_len,
                value = %value_preview,
                "  Param:"
            );

            params.insert(param_type, param_data);
        }

        Ok(StandardRequest {
            method_type,
            params,
        })
    }
}

impl StandardRequest {
    pub fn handle(&self, storage: &mut Storage) -> Vec<u8> {
        info!(
            command = ?self.method_type,
            code = self.method_type.code(),
            "Handling command:"
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
            MethodType::CeCmdPmsFirstCmd | MethodType::CeCmdPmsMaxCmd | MethodType::Unknown(_) => {
                let code = self.method_type.code();
                warn!(
                    command = ?self.method_type,
                    code,
                    "Unknown command, returning empty success:"
                );
                ResponseBuilder::standard(self.method_type).build()
            }
        }
    }

    fn handle_pms_enroll(&self, storage: &mut Storage) -> Vec<u8> {
        let system_type = self.get_param_i32(MethodParamType::PmsTypeT).unwrap_or(0);
        let privacy_data = storage.get_privacy_data_mut(system_type);

        // Get password type
        if let Some(pwd_type) = self.get_param_i32(MethodParamType::PmsPwdTypeT) {
            privacy_data.password_type = pwd_type;
        }

        // Get password info (hash)
        if let Some(pwd_info) = self.params.get(&MethodParamType::PmsPwdInfoT) {
            privacy_data.password_hash = pwd_info.clone();
        }

        // Get email
        if let Some(email) = self.params.get(&MethodParamType::PmsHideEmailT) {
            privacy_data.email = String::from_utf8_lossy(email).to_string();
        }

        // Generate a handler token (must be exactly 8 bytes for password verification)
        privacy_data.handler = generate_random_bytes(8);
        privacy_data.enrolled = true;
        privacy_data.retry_count = 5;
        privacy_data.lock_time = 0;

        info!(
            system_type,
            password_type = privacy_data.password_type,
            handler_len = privacy_data.handler.len(),
            "PMS Enroll: User enrolled successfully:"
        );

        let handler = privacy_data.handler.clone();
        storage.save();

        ResponseBuilder::standard(self.method_type)
            .add_param(Parameter::new(MethodParamType::PmsHandlerT, handler))
            .build()
    }

    fn handle_pms_verify(&self, storage: &mut Storage) -> Vec<u8> {
        let system_type = self.get_param_i32(MethodParamType::PmsTypeT).unwrap_or(0);
        let verify_type = self
            .get_param_i32(MethodParamType::PmsVerifyTypeT)
            .unwrap_or(0);
        let verify_buffer = self.params.get(&MethodParamType::PmsVerifyBufferT).cloned();

        debug!(
            system_type,
            verify_type,
            has_verify_buffer = verify_buffer.is_some(),
            "PMS Verify request:"
        );

        let privacy_data = storage.get_privacy_data_mut(system_type);

        // Check if locked
        if privacy_data.lock_time > 0 {
            warn!(
                system_type,
                lock_time = privacy_data.lock_time,
                "PMS Verify: Account is locked:"
            );
            return ResponseBuilder::standard(self.method_type)
                .result_code(-1)
                .add_param(Parameter::from_i32(
                    MethodParamType::PmsPwdLockTimeLeftT,
                    privacy_data.lock_time,
                ))
                .build();
        }

        // Check if enrolled
        if !privacy_data.enrolled {
            warn!(system_type, "PMS Verify: Not enrolled:");
            return ResponseBuilder::standard(self.method_type)
                .result_code(-1)
                .build();
        }

        let verify_buffer = match verify_buffer {
            Some(buf) => buf,
            None => {
                warn!("PMS Verify: No verify buffer provided");
                return ResponseBuilder::standard(self.method_type)
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

        // Compare the hashes
        if verify_buffer.len() == 32 && verify_buffer[..] == expected_hash[..] {
            // Generate a challenge token (64 bytes) for successful verification
            // The challenge must be 64 bytes to match what modifyPasswordByChallenge expects
            let challenge = generate_random_bytes(64);

            info!(
                system_type,
                verify_type, "PMS Verify: Password verified successfully:"
            );

            // Reset retry count on success
            privacy_data.retry_count = 5;

            // Store challenge for modify operation
            debug!(
                challenge_preview = format!(
                    "[{:02x} {:02x} {:02x} {:02x} ...]",
                    challenge[0], challenge[1], challenge[2], challenge[3]
                ),
                challenge_len = challenge.len(),
                "Stored challenge for modify:"
            );

            // Generate new handler to be used after successful modify
            // We store it as pending and DON'T update the actual handler yet
            // This allows subsequent verify calls to still work with the old handler
            let new_handler = generate_random_bytes(8);
            info!(
                handler = format!(
                    "[{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}]",
                    new_handler[0],
                    new_handler[1],
                    new_handler[2],
                    new_handler[3],
                    new_handler[4],
                    new_handler[5],
                    new_handler[6],
                    new_handler[7]
                ),
                "Generated pending handler (will activate after modify):"
            );

            // Store challenge and new handler as pending - DON'T update actual handler yet
            privacy_data.pending_challenge = challenge.clone();
            privacy_data.pending_handler = new_handler.clone();

            storage.save();

            ResponseBuilder::standard(self.method_type)
                .add_param(Parameter::new(MethodParamType::PmsChallengeT, challenge))
                .add_param(Parameter::new(MethodParamType::PmsHandlerT, new_handler))
                .build()
        } else {
            // Decrement retry count
            privacy_data.retry_count = (privacy_data.retry_count - 1).max(0);

            warn!(
                system_type,
                retries_left = privacy_data.retry_count,
                "PMS Verify: Password mismatch:"
            );

            // Lock account if no retries left
            if privacy_data.retry_count == 0 {
                privacy_data.lock_time = 30;
                warn!(
                    system_type,
                    lock_time = privacy_data.lock_time,
                    "PMS Verify: Account locked:"
                );
            }

            let retry_count = privacy_data.retry_count;
            storage.save();

            ResponseBuilder::standard(self.method_type)
                .result_code(-1)
                .add_param(Parameter::from_i32(
                    MethodParamType::PmsPwdRetryCountLeftT,
                    retry_count,
                ))
                .build()
        }
    }

    fn handle_pms_modify(&self, storage: &mut Storage) -> Vec<u8> {
        let system_type = self.get_param_i32(MethodParamType::PmsTypeT).unwrap_or(0);

        // Get the challenge provided in the modify request
        let challenge = self.params.get(&MethodParamType::PmsChallengeT).cloned();

        // Get the info type to determine what we're modifying
        let info_type = PmsInfoType::from(
            self.get_param_i32(MethodParamType::PmsInfoTypeT)
                .unwrap_or(0),
        );

        let privacy_data = storage.get_privacy_data_mut(system_type);

        // Validate challenge
        if let Some(challenge) = &challenge {
            if !privacy_data.pending_challenge.is_empty()
                && *challenge != privacy_data.pending_challenge
            {
                warn!(system_type, "PMS Modify: Challenge mismatch:");
                return ResponseBuilder::standard(self.method_type)
                    .result_code(-1)
                    .build();
            }
            debug!(
                system_type,
                challenge_len = challenge.len(),
                "PMS Modify: Challenge validated:"
            );
        }

        // Update password type if provided
        if let Some(pwd_type) = self.get_param_i32(MethodParamType::PmsPwdTypeT) {
            privacy_data.password_type = pwd_type;
        }

        // Handle different info types
        match info_type {
            PmsInfoType::Password => {
                // Password modification - read from PmsInfoBufferT (208)
                if let Some(pwd_info) = self.params.get(&MethodParamType::PmsInfoBufferT) {
                    privacy_data.password_hash = pwd_info.clone();
                    info!(
                        system_type,
                        password_type = privacy_data.password_type,
                        hash_len = pwd_info.len(),
                        "PMS Modify: Password hash updated:"
                    );
                } else if let Some(pwd_info) = self.params.get(&MethodParamType::PmsPwdInfoT) {
                    // Fallback to old param type for compatibility
                    privacy_data.password_hash = pwd_info.clone();
                    info!(
                        system_type,
                        password_type = privacy_data.password_type,
                        hash_len = pwd_info.len(),
                        "PMS Modify: Password hash updated (via PmsPwdInfoT):"
                    );
                }
            }
            PmsInfoType::SecurityAnswer => {
                // Security answer modification
                if let Some(answer_info) = self.params.get(&MethodParamType::PmsInfoBufferT) {
                    debug!(
                        system_type,
                        answer_len = answer_info.len(),
                        "PMS Modify: Security answer updated:"
                    );
                    // Store security answer if needed (currently not implemented)
                }
            }
            PmsInfoType::Email => {
                // Email modification
                if let Some(email) = self.params.get(&MethodParamType::PmsInfoBufferT) {
                    privacy_data.email = String::from_utf8_lossy(email).to_string();
                    info!(system_type, "PMS Modify: Email updated:");
                }
            }
            PmsInfoType::Unknown => {
                // Legacy handling: try to update based on what params are present
                if let Some(pwd_info) = self.params.get(&MethodParamType::PmsPwdInfoT) {
                    privacy_data.password_hash = pwd_info.clone();
                }
                if let Some(email) = self.params.get(&MethodParamType::PmsHideEmailT) {
                    privacy_data.email = String::from_utf8_lossy(email).to_string();
                }
                info!(
                    system_type,
                    ?info_type,
                    "PMS Modify: Updated with legacy params:"
                );
            }
        }

        // Update the handler to the pending handler (generated during verify)
        // and clear the pending state
        let new_handler = if !privacy_data.pending_handler.is_empty() {
            let handler = privacy_data.pending_handler.clone();
            privacy_data.handler = handler.clone();
            privacy_data.pending_handler.clear();
            privacy_data.pending_challenge.clear();
            info!(
                system_type,
                handler_preview = format!(
                    "[{:02x} {:02x} {:02x} {:02x} ...]",
                    handler[0], handler[1], handler[2], handler[3]
                ),
                "PMS Modify: Handler activated from pending:"
            );
            handler
        } else {
            // Generate a new handler if no pending one exists
            let handler = generate_random_bytes(8);
            privacy_data.handler = handler.clone();
            info!(system_type, "PMS Modify: Generated new handler:");
            handler
        };

        storage.save();

        // Return success with new handler
        ResponseBuilder::standard(self.method_type)
            .add_param(Parameter::new(MethodParamType::PmsHandlerT, new_handler))
            .build()
    }

    fn handle_pms_delete(&self, storage: &mut Storage) -> Vec<u8> {
        let system_type = self.get_param_i32(MethodParamType::PmsTypeT).unwrap_or(0);

        storage.reset_privacy_data(system_type);
        storage.save();

        info!(system_type, "PMS Delete: Privacy data deleted:");
        ResponseBuilder::standard(self.method_type).build()
    }

    fn handle_pms_get_info(&self, storage: &mut Storage) -> Vec<u8> {
        let system_type = self.get_param_i32(MethodParamType::PmsTypeT).unwrap_or(0);

        let privacy_data = storage
            .get_privacy_data(system_type)
            .cloned()
            .unwrap_or_default();

        info!(
            system_type,
            enrolled = privacy_data.enrolled,
            password_type = privacy_data.password_type,
            retry_count = privacy_data.retry_count,
            lock_time = privacy_data.lock_time,
            has_handler = !privacy_data.handler.is_empty(),
            "PMS GetInfo:"
        );

        let mut builder = ResponseBuilder::standard(self.method_type)
            .add_param(Parameter::from_i32(
                MethodParamType::PmsPwdTypeT,
                privacy_data.password_type,
            ))
            .add_param(Parameter::from_i32(
                MethodParamType::PmsPwdRetryCountLeftT,
                privacy_data.retry_count,
            ))
            .add_param(Parameter::from_i32(
                MethodParamType::PmsPwdLockTimeLeftT,
                privacy_data.lock_time,
            ))
            .add_param(Parameter::from_i32(
                MethodParamType::PmsSecureQuestionRetryCountLeftT,
                privacy_data.secure_question_retry_count,
            ))
            .add_param(Parameter::from_i32(
                MethodParamType::PmsSecureQuestionLockTimeLeftT,
                privacy_data.secure_question_lock_time,
            ));

        if !privacy_data.handler.is_empty() {
            builder = builder.add_param(Parameter::new(
                MethodParamType::PmsHandlerT,
                privacy_data.handler.clone(),
            ));
        }

        if !privacy_data.email.is_empty() {
            builder = builder.add_param(Parameter::from_str(
                MethodParamType::PmsHideEmailT,
                &privacy_data.email,
            ));
        }

        builder.build()
    }

    fn handle_pms_request_encrypt_data(&self, _storage: &mut Storage) -> Vec<u8> {
        let encrypted_data = self
            .params
            .get(&MethodParamType::PmsInfoBufferT)
            .cloned()
            .unwrap_or_default();

        info!(
            data_len = encrypted_data.len(),
            "PMS RequestEncryptData: Returning data as-is (stub):"
        );

        ResponseBuilder::standard(self.method_type)
            .add_param(Parameter::new(
                MethodParamType::PmsEncBufferT,
                encrypted_data,
            ))
            .build()
    }

    fn handle_pms_reset_all_data(&self, storage: &mut Storage) -> Vec<u8> {
        let system_type = self.get_param_i32(MethodParamType::PmsTypeT).unwrap_or(0);

        storage.reset_privacy_data(system_type);
        storage.save();

        info!(system_type, "PMS ResetAllData: All data reset:");
        ResponseBuilder::standard(self.method_type).build()
    }

    fn handle_set_lock_screen_pwd_type(&self, storage: &mut Storage) -> Vec<u8> {
        let user_id = self
            .get_param_i32(MethodParamType::PmsPwdUseridT)
            .unwrap_or(0);
        let pwd_type = self
            .get_param_i32(MethodParamType::PmsPwdTypeT)
            .unwrap_or(0);

        storage.set_lock_screen_pwd_type(user_id, pwd_type);
        storage.save();

        info!(
            user_id,
            pwd_type, "SetLockScreenPwdType: Password type set:"
        );
        ResponseBuilder::standard(self.method_type).build()
    }

    fn handle_get_rpmb_value(&self, storage: &mut Storage) -> Vec<u8> {
        let key = self
            .params
            .get(&MethodParamType::PmsCommonBuffer0T)
            .map(|v| String::from_utf8_lossy(v).to_string())
            .unwrap_or_default();

        let value = storage.get_rpmb_value(&key).cloned().unwrap_or_default();

        info!(
            key = %key,
            value_len = value.len(),
            "GetRpmbValue:"
        );

        ResponseBuilder::standard(self.method_type)
            .add_param(Parameter::new(MethodParamType::PmsCommonBuffer1T, value))
            .build()
    }

    fn handle_store_old_password(&self, storage: &mut Storage) -> Vec<u8> {
        let user_id = self
            .get_param_i32(MethodParamType::PmsPwdUseridT)
            .unwrap_or(0);
        let pwd_data = storage.get_password_data_mut(user_id);

        if let Some(old_pwd_type) = self.get_param_i32(MethodParamType::PmsOldPwdTypeT) {
            pwd_data.old_pwd_type = old_pwd_type;
        }

        if let Some(old_pwd_buffer) = self.params.get(&MethodParamType::PmsOldPwdBufferT) {
            pwd_data.old_pwd_buffer = old_pwd_buffer.clone();
        }

        if let Some(current_pwd_type) = self.get_param_i32(MethodParamType::PmsCurrentPwdTypeT) {
            pwd_data.current_pwd_type = current_pwd_type;
        }

        if let Some(current_pwd_buffer) = self.params.get(&MethodParamType::PmsCurrentPwdBufferT) {
            pwd_data.current_pwd_buffer = current_pwd_buffer.clone();
        }

        if let Some(system_time) = self.params.get(&MethodParamType::PmsPwdSystemTimeT) {
            if system_time.len() >= 8 {
                pwd_data.system_time = BigEndian::read_i64(system_time);
            }
        }

        pwd_data.user_id = user_id;

        // Capture values before releasing the mutable borrow
        let old_pwd_type = pwd_data.old_pwd_type;
        let current_pwd_type = pwd_data.current_pwd_type;

        storage.save();

        info!(
            user_id,
            old_pwd_type, current_pwd_type, "TA StoreOldPassword: Password stored:"
        );

        ResponseBuilder::standard(self.method_type).build()
    }

    fn handle_retrieve_password_by_old_pwd(&self, storage: &mut Storage) -> Vec<u8> {
        let user_id = self
            .get_param_i32(MethodParamType::PmsPwdUseridT)
            .unwrap_or(0);

        if let Some(pwd_data) = storage.get_password_data(user_id) {
            info!(
                user_id,
                current_pwd_type = pwd_data.current_pwd_type,
                buffer_len = pwd_data.current_pwd_buffer.len(),
                "TA RetrievePasswordByOldPwd: Found:"
            );

            ResponseBuilder::standard(self.method_type)
                .add_param(Parameter::new(
                    MethodParamType::PmsCurrentPasswordBuffer,
                    pwd_data.current_pwd_buffer.clone(),
                ))
                .add_param(Parameter::from_i32(
                    MethodParamType::PmsCurrentPasswordType,
                    pwd_data.current_pwd_type,
                ))
                .add_param(Parameter::from_i32(
                    MethodParamType::PmsVerifyOldPwdResultT,
                    0,
                ))
                .build()
        } else {
            warn!(user_id, "TA RetrievePasswordByOldPwd: Not found:");
            ResponseBuilder::standard(self.method_type)
                .result_code(-1)
                .build()
        }
    }

    fn handle_password_retrieve_validity(&self, storage: &mut Storage) -> Vec<u8> {
        let user_id = self
            .get_param_i32(MethodParamType::PmsPwdUseridT)
            .unwrap_or(0);
        let is_valid = storage.get_password_data(user_id).is_some();

        info!(user_id, is_valid, "TA PasswordRetrieveValidity:");

        ResponseBuilder::standard(self.method_type)
            .add_param(Parameter::from_i32(
                MethodParamType::PmsResultValidity,
                if is_valid { 1 } else { 0 },
            ))
            .build()
    }

    fn handle_delete_old_password(&self, storage: &mut Storage) -> Vec<u8> {
        let user_id = self
            .get_param_i32(MethodParamType::PmsPwdUseridT)
            .unwrap_or(0);

        storage.delete_password_data(user_id);
        storage.save();

        info!(user_id, "TA DeleteOldPassword: Deleted:");
        ResponseBuilder::standard(self.method_type).build()
    }

    fn handle_password_verify_result(&self, _storage: &mut Storage) -> Vec<u8> {
        info!("TA PasswordVerifyResult: Returning success (stub):");

        ResponseBuilder::standard(self.method_type)
            .add_param(Parameter::from_i32(
                MethodParamType::PmsVerifyOldPwdResultT,
                0,
            ))
            .add_param(Parameter::from_i32(
                MethodParamType::PmsOldPwdTryRemainingCount,
                5,
            ))
            .build()
    }

    /// Helper to get an i32 parameter
    fn get_param_i32(&self, param_type: MethodParamType) -> Option<i32> {
        self.params.get(&param_type).and_then(|v| {
            if v.len() >= 4 {
                Some(BigEndian::read_i32(v))
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// Native Commands (cmdId <= 100)
pub enum NativeCommand {
    WriteSecret = 8,
    PresetDataDec = 26,
    Unknown(u8),
}

impl From<u8> for NativeCommand {
    fn from(code: u8) -> Self {
        match code {
            8 => NativeCommand::WriteSecret,
            26 => NativeCommand::PresetDataDec,
            _ => NativeCommand::Unknown(code),
        }
    }
}

/// Parsed native request (cmdId <= 100)
#[derive(Debug, Clone)]
pub struct NativeRequest {
    pub command: NativeCommand,
    pub data: Vec<u8>,
}

impl From<&[u8]> for NativeRequest {
    fn from(data: &[u8]) -> Self {
        Self {
            command: NativeCommand::from(data[0]),
            data: data[4..].to_vec(),
        }
    }
}

impl NativeRequest {
    pub fn handle(&self, storage: &mut Storage) -> Vec<u8> {
        info!(
            command = ?self.command,
            data_len = self.data.len(),
            "Handling native command:"
        );
        match self.command {
            NativeCommand::WriteSecret => self.handle_write_secret(storage),
            NativeCommand::PresetDataDec => self.handle_preset_data_dec(storage),
            NativeCommand::Unknown(cmd_id) => {
                warn!(cmd_id, "Unknown native command:");
                ResponseBuilder::native().build()
            }
        }
    }

    fn handle_write_secret(&self, storage: &mut Storage) -> Vec<u8> {
        // Parse: [secret_length: 4 bytes LE][secret: N bytes][token_length: 4 bytes LE][token: M bytes]
        if self.data.len() < 4 {
            warn!(
                data_len = self.data.len(),
                "WriteSecret: Buffer too short for secret length:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let secret_length = LittleEndian::read_i32(&self.data[0..4]) as usize;
        let mut offset = 4;

        if self.data.len() < offset + secret_length {
            warn!(
                data_len = self.data.len(),
                expected = offset + secret_length,
                "WriteSecret: Buffer too short for secret data:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let secret = &self.data[offset..offset + secret_length];
        offset += secret_length;

        if self.data.len() < offset + 4 {
            warn!(
                data_len = self.data.len(),
                expected = offset + 4,
                "WriteSecret: Buffer too short for token length:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let token_length = LittleEndian::read_i32(&self.data[offset..offset + 4]) as usize;
        offset += 4;

        if self.data.len() < offset + token_length {
            warn!(
                data_len = self.data.len(),
                expected = offset + token_length,
                "WriteSecret: Buffer too short for token data:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        info!(
            secret_len = secret_length,
            token_len = token_length,
            "WriteSecret: Stored secret:"
        );

        storage.store_secret(secret_length as i32, secret.to_vec());
        storage.save();

        ResponseBuilder::native().build()
    }

    fn handle_preset_data_dec(&self, _storage: &mut Storage) -> Vec<u8> {
        // Parse: [aliBuf_len: 4 bytes LE][aliBuf: N bytes][enc_len: 4 bytes LE][enc: M bytes]
        if self.data.len() < 4 {
            warn!(
                data_len = self.data.len(),
                "PresetDataDec: Buffer too short for aliBuf length:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let ali_buf_len = LittleEndian::read_i32(&self.data[0..4]) as usize;
        let mut offset = 4;

        if self.data.len() < offset + ali_buf_len {
            warn!(
                data_len = self.data.len(),
                expected = offset + ali_buf_len,
                "PresetDataDec: Buffer too short for aliBuf data:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let ali_buf = &self.data[offset..offset + ali_buf_len];
        offset += ali_buf_len;

        if self.data.len() < offset + 4 {
            warn!(
                data_len = self.data.len(),
                expected = offset + 4,
                "PresetDataDec: Buffer too short for enc length:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let enc_len = LittleEndian::read_i32(&self.data[offset..offset + 4]) as usize;
        offset += 4;

        if self.data.len() < offset + enc_len {
            warn!(
                data_len = self.data.len(),
                expected = offset + enc_len,
                "PresetDataDec: Buffer too short for enc data:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let enc_data = &self.data[offset..offset + enc_len];

        info!(
            ali_buf = %String::from_utf8_lossy(ali_buf),
            enc_len,
            "PresetDataDec: Returning data as-is (stub):"
        );

        ResponseBuilder::native()
            .extra_data(enc_data.to_vec())
            .build()
    }
}
