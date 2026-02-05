use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::method::{MethodParamType, MethodType, Parameter, PmsInfoType};
use crate::register_handler;
use crate::request::StandardRequest;
use crate::response::ResponseBuilder;
use crate::storage::Storage;
use crate::utils::generate_random_bytes;

register_handler!(MethodType::CeCmdPmsEnroll, handle_pms_enroll);
register_handler!(MethodType::CeCmdPmsVerify, handle_pms_verify);
register_handler!(MethodType::CeCmdPmsModify, handle_pms_modify);
register_handler!(MethodType::CeCmdPmsDelete, handle_pms_delete);
register_handler!(MethodType::CeCmdPmsGetInfo, handle_pms_get_info);
register_handler!(
    MethodType::CeCmdPmsRequestEncryptData,
    handle_pms_request_encrypt_data
);
register_handler!(MethodType::CeCmdPmsResetAllData, handle_pms_reset_all_data);

fn handle_pms_enroll(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    let system_type = request
        .get_param(MethodParamType::PmsTypeT)
        .and_then(|p| p.as_i32())
        .unwrap_or(0);
    let privacy_data = storage.get_privacy_data_mut(system_type);

    // Get password type
    if let Some(pwd_type) = request
        .get_param(MethodParamType::PmsPwdTypeT)
        .and_then(|p| p.as_i32())
    {
        privacy_data.password_type = pwd_type;
    }

    // Get password info (hash)
    if let Some(pwd_info) = request.get_param(MethodParamType::PmsPwdInfoT) {
        privacy_data.password_hash = pwd_info.data().to_vec();
    }

    // Get email
    if let Some(email) = request.get_param(MethodParamType::PmsHideEmailT) {
        privacy_data.email = String::from_utf8_lossy(email.data()).to_string();
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

    ResponseBuilder::standard(request.method_type)
        .add_param(Parameter::new(MethodParamType::PmsHandlerT, handler))
        .build()
}

fn handle_pms_verify(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    let system_type = request
        .get_param(MethodParamType::PmsTypeT)
        .and_then(|p| p.as_i32())
        .unwrap_or(0);
    let verify_type = request
        .get_param(MethodParamType::PmsVerifyTypeT)
        .and_then(|p| p.as_i32())
        .unwrap_or(0);
    let verify_buffer = request
        .get_param(MethodParamType::PmsVerifyBufferT)
        .map(|p| p.data().to_vec());

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
        return ResponseBuilder::standard(request.method_type)
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
        return ResponseBuilder::standard(request.method_type)
            .result_code(-1)
            .build();
    }

    let verify_buffer = match verify_buffer {
        Some(buf) => buf,
        None => {
            warn!("PMS Verify: No verify buffer provided");
            return ResponseBuilder::standard(request.method_type)
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

        ResponseBuilder::standard(request.method_type)
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

        ResponseBuilder::standard(request.method_type)
            .result_code(-1)
            .add_param(Parameter::from_i32(
                MethodParamType::PmsPwdRetryCountLeftT,
                retry_count,
            ))
            .build()
    }
}

fn handle_pms_modify(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    let system_type = request
        .get_param(MethodParamType::PmsTypeT)
        .and_then(|p| p.as_i32())
        .unwrap_or(0);

    // Get the challenge provided in the modify request
    let challenge = request
        .get_param(MethodParamType::PmsChallengeT)
        .map(|p| p.data().to_vec());

    // Get the info type to determine what we're modifying
    let info_type = PmsInfoType::from(
        request
            .get_param(MethodParamType::PmsInfoTypeT)
            .and_then(|p| p.as_i32())
            .unwrap_or(0),
    );

    let privacy_data = storage.get_privacy_data_mut(system_type);

    // Validate challenge
    if let Some(challenge) = &challenge {
        if !privacy_data.pending_challenge.is_empty()
            && *challenge != privacy_data.pending_challenge
        {
            warn!(system_type, "PMS Modify: Challenge mismatch:");
            return ResponseBuilder::standard(request.method_type)
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
    if let Some(pwd_type) = request
        .get_param(MethodParamType::PmsPwdTypeT)
        .and_then(|p| p.as_i32())
    {
        privacy_data.password_type = pwd_type;
    }

    // Handle different info types
    match info_type {
        PmsInfoType::Password => {
            // Password modification - read from PmsInfoBufferT (208)
            if let Some(pwd_info) = request.get_param(MethodParamType::PmsInfoBufferT) {
                privacy_data.password_hash = pwd_info.data().to_vec();
                info!(
                    system_type,
                    password_type = privacy_data.password_type,
                    hash_len = pwd_info.data().len(),
                    "PMS Modify: Password hash updated:"
                );
            } else if let Some(pwd_info) = request.get_param(MethodParamType::PmsPwdInfoT) {
                // Fallback to old param type for compatibility
                privacy_data.password_hash = pwd_info.data().to_vec();
                info!(
                    system_type,
                    password_type = privacy_data.password_type,
                    hash_len = pwd_info.data().len(),
                    "PMS Modify: Password hash updated (via PmsPwdInfoT):"
                );
            }
        }
        PmsInfoType::SecurityAnswer => {
            // Security answer modification
            if let Some(answer_info) = request.get_param(MethodParamType::PmsInfoBufferT) {
                debug!(
                    system_type,
                    answer_len = answer_info.data().len(),
                    "PMS Modify: Security answer updated:"
                );
                // Store security answer if needed (currently not implemented)
            }
        }
        PmsInfoType::Email => {
            // Email modification
            if let Some(email) = request.get_param(MethodParamType::PmsInfoBufferT) {
                privacy_data.email = String::from_utf8_lossy(email.data()).to_string();
                info!(system_type, "PMS Modify: Email updated:");
            }
        }
        PmsInfoType::Unknown => {
            // Legacy handling: try to update based on what params are present
            if let Some(pwd_info) = request.get_param(MethodParamType::PmsPwdInfoT) {
                privacy_data.password_hash = pwd_info.data().to_vec();
            }
            if let Some(email) = request.get_param(MethodParamType::PmsHideEmailT) {
                privacy_data.email = String::from_utf8_lossy(email.data()).to_string();
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
    ResponseBuilder::standard(request.method_type)
        .add_param(Parameter::new(MethodParamType::PmsHandlerT, new_handler))
        .build()
}

fn handle_pms_delete(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    let system_type = request
        .get_param(MethodParamType::PmsTypeT)
        .and_then(|p| p.as_i32())
        .unwrap_or(0);

    storage.reset_privacy_data(system_type);
    storage.save();

    info!(system_type, "PMS Delete: Privacy data deleted:");
    ResponseBuilder::standard(request.method_type).build()
}

fn handle_pms_get_info(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    let system_type = request
        .get_param(MethodParamType::PmsTypeT)
        .and_then(|p| p.as_i32())
        .unwrap_or(0);

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

    let mut builder = ResponseBuilder::standard(request.method_type)
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

fn handle_pms_request_encrypt_data(request: &StandardRequest, _storage: &mut Storage) -> Vec<u8> {
    let encrypted_data = request
        .get_param(MethodParamType::PmsInfoBufferT)
        .map(|p| p.data().to_vec())
        .unwrap_or_default();

    info!(
        data_len = encrypted_data.len(),
        "PMS RequestEncryptData: Returning data as-is (stub):"
    );

    ResponseBuilder::standard(request.method_type)
        .add_param(Parameter::new(
            MethodParamType::PmsEncBufferT,
            encrypted_data,
        ))
        .build()
}

fn handle_pms_reset_all_data(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    let system_type = request
        .get_param(MethodParamType::PmsTypeT)
        .and_then(|p| p.as_i32())
        .unwrap_or(0);

    storage.reset_privacy_data(system_type);
    storage.save();

    info!(system_type, "PMS ResetAllData: All data reset:");
    ResponseBuilder::standard(request.method_type).build()
}
