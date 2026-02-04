use byteorder::{BigEndian, ByteOrder, LittleEndian};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::{
    method::{MethodParamType, MethodType},
    request::{NativeRequest, StandardRequest},
    response::{build_native_response, ResponseBuilder},
    storage::Storage,
    utils::generate_random_bytes,
};

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

/// Handle a standard command (cmdId > 100)
pub fn handle_standard_command(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    info!(
        "Handling standard command: {:?} (code={})",
        request.method_type, request.method_code
    );

    match request.method_type {
        MethodType::CeCmdPmsEnroll => handle_pms_enroll(request, storage),
        MethodType::CeCmdPmsVerify => handle_pms_verify(request, storage),
        MethodType::CeCmdPmsModify => handle_pms_modify(request, storage),
        MethodType::CeCmdPmsDelete => handle_pms_delete(request, storage),
        MethodType::CeCmdPmsGetInfo => handle_pms_get_info(request, storage),
        MethodType::CeCmdPmsRequestEncryptData => handle_pms_request_encrypt_data(request, storage),
        MethodType::CeCmdPmsResetAllData => handle_pms_reset_all_data(request, storage),
        MethodType::CeSetLockScreenPwdType => handle_set_lock_screen_pwd_type(request, storage),
        MethodType::CeCmdGetRpmbValue => handle_get_rpmb_value(request, storage),
        MethodType::TaCmdStoreOldPassword => handle_store_old_password(request, storage),
        MethodType::TaCmdRetrievePasswordByOldPwd => {
            handle_retrieve_password_by_old_pwd(request, storage)
        }
        MethodType::TaCmdPasswordRetrieveValidity => {
            handle_password_retrieve_validity(request, storage)
        }
        MethodType::TaCmdDeleteOldPassword => handle_delete_old_password(request, storage),
        MethodType::TaCmdPasswordVerifyResult => handle_password_verify_result(request, storage),
        _ => {
            warn!(
                "Unknown standard command: {:?} (code={})",
                request.method_type, request.method_code
            );
            // Return success with no params for unknown commands
            ResponseBuilder::new(request.method_code).build()
        }
    }
}

/// Handle a native command (cmdId <= 100)
pub fn handle_native_command(request: &NativeRequest, storage: &mut Storage) -> Vec<u8> {
    let cmd = NativeCommand::from(request.cmd_id);
    info!("Handling native command: {:?} (id={})", cmd, request.cmd_id);

    match cmd {
        NativeCommand::WriteSecret => handle_write_secret(request, storage),
        NativeCommand::PresetDataDec => handle_preset_data_dec(request, storage),
        NativeCommand::Unknown => {
            warn!("Unknown native command: {}", request.cmd_id);
            build_native_response(0, None)
        }
    }
}

pub fn handle_pms_enroll(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    info!("PMS Enroll");

    // Get system type from params
    let system_type = request
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
    if let Some(pwd_type) = request.params.get(&(MethodParamType::PmsPwdTypeT as i32)) {
        if pwd_type.len() >= 4 {
            privacy_data.password_type = BigEndian::read_i32(pwd_type);
        }
    }

    // Get password info (hash)
    if let Some(pwd_info) = request.params.get(&(MethodParamType::PmsPwdInfoT as i32)) {
        privacy_data.password_hash = pwd_info.clone();
    }

    // Get email
    if let Some(email) = request.params.get(&(MethodParamType::PmsHideEmailT as i32)) {
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

    ResponseBuilder::new(request.method_code)
        .add_param(MethodParamType::PmsHandlerT, handler)
        .build()
}

fn handle_pms_verify(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    info!("PMS Verify");

    let system_type = request
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

    let verify_type = request
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

    let verify_buffer = request
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
        return ResponseBuilder::new(request.method_code)
            .result_code(-1)
            .add_param_i32(MethodParamType::PmsPwdLockTimeLeftT, privacy_data.lock_time)
            .build();
    }

    // Check if enrolled
    if !privacy_data.enrolled {
        warn!("PMS Verify: Not enrolled for system_type={}", system_type);
        return ResponseBuilder::new(request.method_code)
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
            return ResponseBuilder::new(request.method_code)
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

        ResponseBuilder::new(request.method_code)
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

        ResponseBuilder::new(request.method_code)
            .result_code(-1)
            .add_param_i32(MethodParamType::PmsPwdRetryCountLeftT, retry_count)
            .build()
    }
}

fn handle_pms_modify(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    info!("PMS Modify");

    let system_type = request
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
    if let Some(pwd_type) = request.params.get(&(MethodParamType::PmsPwdTypeT as i32)) {
        if pwd_type.len() >= 4 {
            privacy_data.password_type = BigEndian::read_i32(pwd_type);
        }
    }

    // Update password info if provided
    if let Some(pwd_info) = request.params.get(&(MethodParamType::PmsPwdInfoT as i32)) {
        privacy_data.password_hash = pwd_info.clone();
    }

    // Update email if provided
    if let Some(email) = request.params.get(&(MethodParamType::PmsHideEmailT as i32)) {
        privacy_data.email = String::from_utf8_lossy(email).to_string();
    }

    storage.save();

    ResponseBuilder::new(request.method_code).build()
}

fn handle_pms_delete(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    info!("PMS Delete");

    let system_type = request
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

    ResponseBuilder::new(request.method_code).build()
}

fn handle_pms_get_info(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    info!("PMS Get Info");

    let system_type = request
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

    let mut builder = ResponseBuilder::new(request.method_code)
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

fn handle_pms_request_encrypt_data(request: &StandardRequest, _storage: &mut Storage) -> Vec<u8> {
    info!("PMS Request Encrypt Data");

    // For stub, return the input data as-is (no actual encryption)
    let encrypted_data = request
        .params
        .get(&(MethodParamType::PmsInfoBufferT as i32))
        .cloned()
        .unwrap_or_default();

    ResponseBuilder::new(request.method_code)
        .add_param(MethodParamType::PmsEncBufferT, encrypted_data)
        .build()
}

fn handle_pms_reset_all_data(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    info!("PMS Reset All Data");

    let system_type = request
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

    ResponseBuilder::new(request.method_code).build()
}

fn handle_set_lock_screen_pwd_type(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    info!("Set Lock Screen Password Type");

    let user_id = request
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

    let pwd_type = request
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

    ResponseBuilder::new(request.method_code).build()
}

fn handle_get_rpmb_value(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    info!("Get RPMB Value");

    let key = request
        .params
        .get(&(MethodParamType::PmsCommonBuffer0T as i32))
        .map(|v| String::from_utf8_lossy(v).to_string())
        .unwrap_or_default();

    let value = storage.get_rpmb_value(&key).cloned().unwrap_or_default();

    ResponseBuilder::new(request.method_code)
        .add_param(MethodParamType::PmsCommonBuffer1T, value)
        .build()
}

fn handle_store_old_password(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    info!("TA Store Old Password");

    let user_id = request
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

    if let Some(old_pwd_type) = request
        .params
        .get(&(MethodParamType::PmsOldPwdTypeT as i32))
    {
        if old_pwd_type.len() >= 4 {
            pwd_data.old_pwd_type = BigEndian::read_i32(old_pwd_type);
        }
    }

    if let Some(old_pwd_buffer) = request
        .params
        .get(&(MethodParamType::PmsOldPwdBufferT as i32))
    {
        pwd_data.old_pwd_buffer = old_pwd_buffer.clone();
    }

    if let Some(current_pwd_type) = request
        .params
        .get(&(MethodParamType::PmsCurrentPwdTypeT as i32))
    {
        if current_pwd_type.len() >= 4 {
            pwd_data.current_pwd_type = BigEndian::read_i32(current_pwd_type);
        }
    }

    if let Some(current_pwd_buffer) = request
        .params
        .get(&(MethodParamType::PmsCurrentPwdBufferT as i32))
    {
        pwd_data.current_pwd_buffer = current_pwd_buffer.clone();
    }

    if let Some(system_time) = request
        .params
        .get(&(MethodParamType::PmsPwdSystemTimeT as i32))
    {
        if system_time.len() >= 8 {
            pwd_data.system_time = BigEndian::read_i64(system_time);
        }
    }

    pwd_data.user_id = user_id;
    storage.save();

    ResponseBuilder::new(request.method_code).build()
}

fn handle_retrieve_password_by_old_pwd(
    request: &StandardRequest,
    storage: &mut Storage,
) -> Vec<u8> {
    info!("TA Retrieve Password By Old Password");

    let user_id = request
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
        ResponseBuilder::new(request.method_code)
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
        ResponseBuilder::new(request.method_code)
            .result_code(-1)
            .build()
    }
}

fn handle_password_retrieve_validity(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    info!("TA Password Retrieve Validity");

    let user_id = request
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

    ResponseBuilder::new(request.method_code)
        .add_param_i32(
            MethodParamType::PmsResultValidity,
            if is_valid { 1 } else { 0 },
        )
        .build()
}

fn handle_delete_old_password(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    info!("TA Delete Old Password");

    let user_id = request
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

    ResponseBuilder::new(request.method_code).build()
}

fn handle_password_verify_result(request: &StandardRequest, _storage: &mut Storage) -> Vec<u8> {
    info!("TA Password Verify Result");

    // For stub, always return success
    ResponseBuilder::new(request.method_code)
        .add_param_i32(MethodParamType::PmsVerifyOldPwdResultT, 0)
        .add_param_i32(MethodParamType::PmsOldPwdTryRemainingCount, 5)
        .build()
}

fn handle_write_secret(request: &NativeRequest, storage: &mut Storage) -> Vec<u8> {
    info!("Native WriteSecret command");

    // Parse the native format:
    // [secret_length: 4 bytes LE][secret: N bytes][token_length: 4 bytes LE][token: M bytes]
    if request.data.len() < 4 {
        warn!("WriteSecret: buffer too short for secret length");
        return build_native_response(-1, None);
    }

    let secret_length = LittleEndian::read_i32(&request.data[0..4]) as usize;
    let mut offset = 4;

    if request.data.len() < offset + secret_length {
        warn!("WriteSecret: buffer too short for secret data");
        return build_native_response(-1, None);
    }

    let secret = &request.data[offset..offset + secret_length];
    offset += secret_length;

    if request.data.len() < offset + 4 {
        warn!("WriteSecret: buffer too short for token length");
        return build_native_response(-1, None);
    }

    let token_length = LittleEndian::read_i32(&request.data[offset..offset + 4]) as usize;
    offset += 4;

    if request.data.len() < offset + token_length {
        warn!("WriteSecret: buffer too short for token data");
        return build_native_response(-1, None);
    }

    let _token = &request.data[offset..offset + token_length];

    debug!(
        "WriteSecret: secret_len={}, token_len={}",
        secret_length, token_length
    );

    // Store the secret
    storage.store_secret(secret_length as i32, secret.to_vec());
    storage.save();

    build_native_response(0, None)
}

fn handle_preset_data_dec(request: &NativeRequest, _storage: &mut Storage) -> Vec<u8> {
    info!("Native PresetDataDec command");

    // Parse the native format:
    // [aliBuf_len: 4 bytes LE][aliBuf: N bytes][enc_len: 4 bytes LE][enc: M bytes]
    if request.data.len() < 4 {
        warn!("PresetDataDec: buffer too short for aliBuf length");
        return build_native_response(-1, None);
    }

    let ali_buf_len = LittleEndian::read_i32(&request.data[0..4]) as usize;
    let mut offset = 4;

    if request.data.len() < offset + ali_buf_len {
        warn!("PresetDataDec: buffer too short for aliBuf data");
        return build_native_response(-1, None);
    }

    let ali_buf = &request.data[offset..offset + ali_buf_len];
    offset += ali_buf_len;

    if request.data.len() < offset + 4 {
        warn!("PresetDataDec: buffer too short for enc length");
        return build_native_response(-1, None);
    }

    let enc_len = LittleEndian::read_i32(&request.data[offset..offset + 4]) as usize;
    offset += 4;

    if request.data.len() < offset + enc_len {
        warn!("PresetDataDec: buffer too short for enc data");
        return build_native_response(-1, None);
    }

    let enc_data = &request.data[offset..offset + enc_len];

    debug!(
        "PresetDataDec: aliBuf={:?}, enc_len={}",
        String::from_utf8_lossy(ali_buf),
        enc_len
    );

    // For stub, return the encrypted data as-is (no actual decryption)
    build_native_response(0, Some(enc_data))
}
