use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::error::{CryptoengError, Result};
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

fn handle_pms_enroll(request: &StandardRequest, storage: &mut Storage) -> Result<Vec<u8>> {
    let system_type = request.get_param(MethodParamType::PmsTypeT)?.as_i32()?;
    let privacy_data = storage.get_privacy_data_mut(system_type);

    // Get password type (required for enrollment)
    let pwd_type = request.get_param(MethodParamType::PmsPwdTypeT)?.as_i32()?;
    privacy_data.password_type = pwd_type;

    // Get password info (hash) - required for enrollment
    let pwd_info = request.get_param(MethodParamType::PmsPwdInfoT)?;
    privacy_data.password_hash = pwd_info.data().to_vec();

    // Get email (optional)
    if let Ok(email) = request.get_param(MethodParamType::PmsHideEmailT) {
        privacy_data.email = String::from_utf8_lossy(email.data()).to_string();
    }

    // Generate a handler token (must be exactly 8 bytes for password verification)
    privacy_data.handler = generate_random_bytes(8);
    privacy_data.enrolled = true;
    privacy_data.retry_count = 5;
    privacy_data.lock_time = 0;

    info!(system_type, password_type = pwd_type, "User enrolled");

    let handler = privacy_data.handler.clone();
    storage.save()?;

    Ok(ResponseBuilder::standard(request.method_type)
        .add_param(Parameter::new(MethodParamType::PmsHandlerT, handler))
        .build())
}

fn handle_pms_verify(request: &StandardRequest, storage: &mut Storage) -> Result<Vec<u8>> {
    let system_type = request.get_param(MethodParamType::PmsTypeT)?.as_i32()?;
    let verify_type = request
        .get_param(MethodParamType::PmsVerifyTypeT)?
        .as_i32()?;

    let privacy_data = storage.get_privacy_data_mut(system_type);

    // Check if locked
    if privacy_data.lock_time > 0 {
        warn!(
            system_type,
            lock_time = privacy_data.lock_time,
            "Account is locked"
        );
        return Err(CryptoengError::AccountLocked {
            system_type,
            lock_time: privacy_data.lock_time,
        });
    }

    // Check if enrolled
    if !privacy_data.enrolled {
        warn!(system_type, "Not enrolled");
        return Err(CryptoengError::NotEnrolled(system_type));
    }

    let verify_buffer = request.get_param(MethodParamType::PmsVerifyBufferT)?;
    let verify_data = verify_buffer.data().to_vec();

    // Compute expected hash: SHA256(stored_password_hash + handler)
    let mut combined = Vec::with_capacity(40);
    combined.extend_from_slice(&privacy_data.password_hash);
    combined.extend_from_slice(&privacy_data.handler);

    let mut hasher = Sha256::new();
    hasher.update(&combined);
    let expected_hash = hasher.finalize();

    // Compare the hashes
    if verify_data.len() == 32 && verify_data[..] == expected_hash[..] {
        // Generate a challenge token (64 bytes) for successful verification
        // The challenge must be 64 bytes to match what modifyPasswordByChallenge expects
        let challenge = generate_random_bytes(64);

        info!(system_type, verify_type, "Password verified");

        // Reset retry count on success
        privacy_data.retry_count = 5;

        // Generate new handler to be used after successful modify
        // We store it as pending and DON'T update the actual handler yet
        // This allows subsequent verify calls to still work with the old handler
        let new_handler = generate_random_bytes(8);

        // Store challenge and new handler as pending - DON'T update actual handler yet
        privacy_data.pending_challenge = challenge.clone();
        privacy_data.pending_handler = new_handler.clone();

        storage.save()?;

        Ok(ResponseBuilder::standard(request.method_type)
            .add_param(Parameter::new(MethodParamType::PmsChallengeT, challenge))
            .add_param(Parameter::new(MethodParamType::PmsHandlerT, new_handler))
            .build())
    } else {
        // Decrement retry count
        privacy_data.retry_count = (privacy_data.retry_count - 1).max(0);

        warn!(
            system_type,
            retries_left = privacy_data.retry_count,
            "Password mismatch"
        );

        // Lock account if no retries left
        if privacy_data.retry_count == 0 {
            privacy_data.lock_time = 30;
            warn!(
                system_type,
                lock_time = privacy_data.lock_time,
                "Account locked"
            );
        }

        let retries_left = privacy_data.retry_count;
        storage.save()?;

        Err(CryptoengError::VerificationFailed {
            system_type,
            retries_left,
        })
    }
}

fn handle_pms_modify(request: &StandardRequest, storage: &mut Storage) -> Result<Vec<u8>> {
    let system_type = request.get_param(MethodParamType::PmsTypeT)?.as_i32()?;

    // Get the challenge provided in the modify request (optional for some flows)
    let challenge = request
        .get_param(MethodParamType::PmsChallengeT)
        .map(|p| p.data().to_vec());

    // Get the info type to determine what we're modifying
    let info_type = PmsInfoType::from(request.get_param(MethodParamType::PmsInfoTypeT)?.as_i32()?);

    let privacy_data = storage.get_privacy_data_mut(system_type);

    // Validate challenge if one was provided and we have a pending one
    if let Ok(challenge) = &challenge {
        if !privacy_data.pending_challenge.is_empty()
            && *challenge != privacy_data.pending_challenge
        {
            warn!(system_type, "Challenge mismatch");
            return Err(CryptoengError::ChallengeMismatch(system_type));
        }
    }

    // Update password type if provided
    if let Ok(pwd_type) = request
        .get_param(MethodParamType::PmsPwdTypeT)
        .and_then(|p| p.as_i32())
    {
        privacy_data.password_type = pwd_type;
    }

    // Handle different info types
    match info_type {
        PmsInfoType::Password => {
            // Password modification - read from PmsInfoBufferT (208)
            if let Ok(pwd_info) = request.get_param(MethodParamType::PmsInfoBufferT) {
                privacy_data.password_hash = pwd_info.data().to_vec();
                info!(
                    system_type,
                    password_type = privacy_data.password_type,
                    "Password updated"
                );
            } else if let Ok(pwd_info) = request.get_param(MethodParamType::PmsPwdInfoT) {
                // Fallback to old param type for compatibility
                privacy_data.password_hash = pwd_info.data().to_vec();
                info!(
                    system_type,
                    password_type = privacy_data.password_type,
                    "Password updated"
                );
            }
        }
        PmsInfoType::SecurityAnswer => {
            // Security answer modification
            if let Ok(_answer_info) = request.get_param(MethodParamType::PmsInfoBufferT) {
                unimplemented!("Storing security answer not implemented")
            }
        }
        PmsInfoType::Email => {
            // Email modification
            if let Ok(email) = request.get_param(MethodParamType::PmsInfoBufferT) {
                privacy_data.email = String::from_utf8_lossy(email.data()).to_string();
                info!(system_type, "Email updated");
            }
        }
        PmsInfoType::Unknown => {
            // Legacy handling: try to update based on what params are present
            if let Ok(pwd_info) = request.get_param(MethodParamType::PmsPwdInfoT) {
                privacy_data.password_hash = pwd_info.data().to_vec();
            }
            if let Ok(email) = request.get_param(MethodParamType::PmsHideEmailT) {
                privacy_data.email = String::from_utf8_lossy(email.data()).to_string();
            }
            info!(system_type, "Modified (legacy)");
        }
    }

    // Update the handler to the pending handler (generated during verify)
    // and clear the pending state
    let new_handler = if !privacy_data.pending_handler.is_empty() {
        let handler = privacy_data.pending_handler.clone();
        privacy_data.handler = handler.clone();
        privacy_data.pending_handler.clear();
        privacy_data.pending_challenge.clear();
        handler
    } else {
        // Generate a new handler if no pending one exists
        let handler = generate_random_bytes(8);
        privacy_data.handler = handler.clone();
        handler
    };

    storage.save()?;

    // Return success with new handler
    Ok(ResponseBuilder::standard(request.method_type)
        .add_param(Parameter::new(MethodParamType::PmsHandlerT, new_handler))
        .build())
}

fn handle_pms_delete(request: &StandardRequest, storage: &mut Storage) -> Result<Vec<u8>> {
    let system_type = request.get_param(MethodParamType::PmsTypeT)?.as_i32()?;

    storage.reset_privacy_data(system_type);
    storage.save()?;

    info!(system_type, "Privacy data deleted");
    Ok(ResponseBuilder::standard(request.method_type).build())
}

fn handle_pms_get_info(request: &StandardRequest, storage: &mut Storage) -> Result<Vec<u8>> {
    let system_type = request.get_param(MethodParamType::PmsTypeT)?.as_i32()?;

    let privacy_data = storage
        .get_privacy_data(system_type)
        .cloned()
        .unwrap_or_default();

    info!(
        system_type,
        enrolled = privacy_data.enrolled,
        password_type = privacy_data.password_type,
        retry_count = privacy_data.retry_count,
        "GetInfo"
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

    Ok(builder.build())
}

fn handle_pms_request_encrypt_data(
    request: &StandardRequest,
    _storage: &mut Storage,
) -> Result<Vec<u8>> {
    let encrypted_data = request.get_param(MethodParamType::PmsInfoBufferT)?;
    let data = encrypted_data.data().to_vec();

    Ok(ResponseBuilder::standard(request.method_type)
        .add_param(Parameter::new(MethodParamType::PmsEncBufferT, data))
        .build())
}

fn handle_pms_reset_all_data(request: &StandardRequest, storage: &mut Storage) -> Result<Vec<u8>> {
    let system_type = request.get_param(MethodParamType::PmsTypeT)?.as_i32()?;

    storage.reset_privacy_data(system_type);
    storage.save()?;

    info!(system_type, "All data reset");
    Ok(ResponseBuilder::standard(request.method_type).build())
}
