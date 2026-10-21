use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::error::{CryptoengError, Result};
use crate::register_handler;
use crate::request::CryptoengRequest;
use crate::response::ResponseBuilder;
use crate::storage::{RuntimeState, Storage};
use crate::types::method::MethodType;
use crate::types::parameter::{InfoType, MethodParamType, Parameter, Value};
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

fn handle_pms_enroll(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    _runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let system_type = match request.get_param(MethodParamType::PmsTypeT)?.value() {
        Value::SystemType(ty) => *ty,
        _ => {
            return Err(CryptoengError::ParseError(
                "Invalid system type parameter".to_string(),
            ));
        }
    };
    let privacy_data = storage.get_privacy_data_mut(system_type);

    // Get password type (required for enrollment)
    let password_type = match request.get_param(MethodParamType::PmsPwdTypeT)?.value() {
        Value::PasswordQuality(q) => *q,
        _ => {
            return Err(CryptoengError::ParseError(
                "Invalid password type parameter".to_string(),
            ));
        }
    };
    privacy_data.password_type = password_type;

    // Get password info (hash) - required for enrollment
    let pwd_info = request.get_param(MethodParamType::PmsPwdInfoT)?;
    privacy_data.password_hash = pwd_info.value().as_bytes().to_vec();

    // Parse email from PmsSecureInfoBufferT if present
    if let Ok(secure_info) = request.get_param(MethodParamType::PmsSecureInfoBufferT)
        && let Value::SecureBuffer(secure_buffer) = secure_info.value()
    {
        let mut email_first: Option<String> = None;
        let mut email_continuation: Option<String> = None;

        for entry in secure_buffer.entries.iter() {
            match (&entry.ty, &entry.value) {
                (InfoType::Email, Value::String(s)) => {
                    email_first = Some(s.trim_end_matches('\0').to_string());
                }
                (InfoType::EmailEx1, Value::String(s)) => {
                    email_continuation = Some(s.trim_end_matches('\0').to_string());
                }
                _ => continue,
            }
        }

        if let Some(first) = email_first {
            privacy_data.email = match email_continuation {
                Some(cont) => format!("{}{}", first, cont),
                None => first,
            };
            info!(email = %privacy_data.email, "Email saved during enroll");
        }
    }

    // Generate a handler token (must be exactly 8 bytes for password verification)
    privacy_data.handler = generate_random_bytes(8);
    privacy_data.enrolled = true;
    privacy_data.retry_count = 5;
    privacy_data.lock_until = None;

    info!(?system_type, ?password_type, "User enrolled");

    let handler = privacy_data.handler.clone();
    storage.save()?;

    Ok(ResponseBuilder::standard(request.method_type())
        .add_param(Parameter::new(MethodParamType::PmsHandlerT, &handler)?)
        .build())
}

fn handle_pms_verify(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let system_type = match request.get_param(MethodParamType::PmsTypeT)?.value() {
        Value::SystemType(ty) => *ty,
        _ => {
            return Err(CryptoengError::ParseError(
                "Invalid system type parameter".to_string(),
            ));
        }
    };

    let verify_type = match request.get_param(MethodParamType::PmsVerifyTypeT)?.value() {
        Value::InfoType(ty) => *ty,
        _ => {
            return Err(CryptoengError::ParseError(
                "Invalid verify info type parameter".to_string(),
            ));
        }
    };

    let privacy_data = storage.get_privacy_data_mut(system_type);

    // Check if locked using the new method
    if privacy_data.is_locked() {
        let lock_time = privacy_data.lock_time_remaining();
        warn!(?system_type, lock_time, "Account is locked");
        return Err(CryptoengError::AccountLocked {
            system_type,
            lock_time,
        });
    }

    // Check if enrolled
    if !privacy_data.enrolled {
        warn!(?system_type, "Not enrolled");
        return Err(CryptoengError::NotEnrolled(system_type));
    }

    let verify_buffer = request.get_param(MethodParamType::PmsVerifyBufferT)?;
    let verify_data = verify_buffer.value().as_bytes();

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

        info!(?system_type, ?verify_type, "Password verified");

        privacy_data.retry_count = 5;

        // Generate new handler to be used after successful modify
        let new_handler = generate_random_bytes(8);

        // Store challenge and new handler in RuntimeState (not persisted)
        runtime.set_pending(system_type, challenge.clone(), new_handler.clone());

        storage.save()?;

        Ok(ResponseBuilder::standard(request.method_type())
            .add_param(Parameter::new(MethodParamType::PmsChallengeT, &challenge)?)
            .add_param(Parameter::new(MethodParamType::PmsHandlerT, &new_handler)?)
            .build())
    } else {
        // Decrement retry count
        privacy_data.retry_count = (privacy_data.retry_count - 1).max(0);

        warn!(
            ?system_type,
            retries_left = privacy_data.retry_count,
            "Password mismatch"
        );

        // Lock account if no retries left
        if privacy_data.retry_count == 0 {
            privacy_data.set_lock(30);
            warn!(?system_type, lock_time = 30, "Account locked");
        }

        let retries_left = privacy_data.retry_count;
        storage.save()?;

        Err(CryptoengError::VerificationFailed {
            system_type,
            retries_left,
        })
    }
}

fn handle_pms_modify(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let system_type = match request.get_param(MethodParamType::PmsTypeT)?.value() {
        Value::SystemType(ty) => *ty,
        _ => {
            return Err(CryptoengError::ParseError(
                "Invalid system type parameter".to_string(),
            ));
        }
    };

    // Get the challenge provided in the modify request (optional for some flows)
    let challenge = request
        .get_param(MethodParamType::PmsChallengeT)
        .map(|p| p.value().as_bytes());

    let info_type = match request.get_param(MethodParamType::PmsInfoTypeT)?.value() {
        Value::InfoType(ty) => *ty,
        _ => {
            return Err(CryptoengError::ParseError(
                "Invalid info type parameter".to_string(),
            ));
        }
    };

    // Validate challenge if one was provided and we have a pending one
    let pending = runtime.get_pending(system_type);
    if let Ok(challenge) = &challenge {
        if let Some(pending) = pending {
            if *challenge != pending.challenge {
                warn!(?system_type, "Challenge mismatch");
                return Err(CryptoengError::ChallengeMismatch(system_type));
            }
        }
    }

    let privacy_data = storage.get_privacy_data_mut(system_type);

    // Update password type if provided
    if let Ok(pwd_type) = request.get_param(MethodParamType::PmsPwdTypeT)
        && let Value::PasswordQuality(pwd_type) = pwd_type.value()
    {
        privacy_data.password_type = *pwd_type;
    }

    // Handle different info types
    match info_type {
        InfoType::Password => {
            let pwd_info = request.get_param(MethodParamType::PmsInfoBufferT)?;
            privacy_data.password_hash = pwd_info.value().as_bytes().to_vec();
            info!(
                ?system_type,
                password_type = ?privacy_data.password_type,
                "Password updated"
            );
        }
        InfoType::SecurityQuestion => {
            tracing::error!("Storing security answer not implemented")
        }
        InfoType::Email => {
            if let Ok(email) = request.get_param(MethodParamType::PmsInfoBufferT) {
                privacy_data.email =
                    String::from_utf8_lossy(&*email.value().as_bytes()).to_string();
                info!(?system_type, "Email updated");
            }
        }
        _ => {
            warn!(?system_type, info_type = ?info_type, "Unsupported info type for modify");
            return Err(CryptoengError::ParseError(format!(
                "Unsupported info type for modify: {:?}",
                info_type
            )));
        }
    }

    // Take the pending verification from runtime state and update handler
    let new_handler = if let Some(pending) = runtime.take_pending(system_type) {
        privacy_data.handler = pending.pending_handler.clone();
        pending.pending_handler
    } else {
        // Generate a new handler if no pending one exists
        let handler = generate_random_bytes(8);
        privacy_data.handler = handler.clone();
        handler
    };

    storage.save()?;

    Ok(ResponseBuilder::standard(request.method_type())
        .add_param(Parameter::new(MethodParamType::PmsHandlerT, &new_handler)?)
        .build())
}

fn handle_pms_delete(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    _runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let system_type = match request.get_param(MethodParamType::PmsTypeT)?.value() {
        Value::SystemType(ty) => *ty,
        _ => {
            return Err(CryptoengError::ParseError(
                "Invalid system type parameter".to_string(),
            ));
        }
    };
    storage.reset_privacy_data(system_type);
    storage.save()?;

    info!(?system_type, "Privacy data deleted");
    Ok(ResponseBuilder::standard(request.method_type()).build())
}

fn handle_pms_get_info(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    _runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let system_type = match request.get_param(MethodParamType::PmsTypeT)?.value() {
        Value::SystemType(ty) => *ty,
        _ => {
            return Err(CryptoengError::ParseError(
                "Invalid system type parameter".to_string(),
            ));
        }
    };

    let privacy_data = storage
        .get_privacy_data(system_type)
        .cloned()
        .unwrap_or_default();

    info!(
        ?system_type,
        enrolled = privacy_data.enrolled,
        password_type = ?privacy_data.password_type,
        retry_count = privacy_data.retry_count,
        "GetInfo"
    );

    let mut builder = ResponseBuilder::standard(request.method_type())
        .add_param(Parameter::new(
            MethodParamType::PmsPwdTypeT,
            &(privacy_data.password_type as i32).to_be_bytes(),
        )?)
        .add_param(Parameter::new(
            MethodParamType::PmsPwdRetryCountLeftT,
            &privacy_data.retry_count.to_be_bytes(),
        )?)
        .add_param(Parameter::new(
            MethodParamType::PmsPwdLockTimeLeftT,
            &privacy_data.lock_time_remaining().to_be_bytes(),
        )?)
        .add_param(Parameter::new(
            MethodParamType::PmsSecureQuestionRetryCountLeftT,
            &privacy_data.secure_question_retry_count.to_be_bytes(),
        )?)
        .add_param(Parameter::new(
            MethodParamType::PmsSecureQuestionLockTimeLeftT,
            &privacy_data
                .secure_question_lock_time_remaining()
                .to_be_bytes(),
        )?);

    if !privacy_data.handler.is_empty() {
        builder = builder.add_param(Parameter::new(
            MethodParamType::PmsHandlerT,
            &privacy_data.handler,
        )?);
    }

    if !privacy_data.email.is_empty() {
        builder = builder.add_param(Parameter::new(
            MethodParamType::PmsHideEmailT,
            privacy_data.email.as_bytes(),
        )?);
    }

    Ok(builder.build())
}

fn handle_pms_request_encrypt_data(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    _runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let plaintext = request.get_param(MethodParamType::PmsInfoBufferT)?;
    let plaintext_bytes = plaintext.value().as_bytes();

    // Encrypt using AES-256-GCM with the storage key
    let encrypted = storage.encrypt(&plaintext_bytes)?;

    Ok(ResponseBuilder::standard(request.method_type())
        .add_param(Parameter::new(MethodParamType::PmsEncBufferT, &encrypted)?)
        .build())
}

fn handle_pms_reset_all_data(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    _runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let system_type = match request.get_param(MethodParamType::PmsTypeT)?.value() {
        Value::SystemType(ty) => *ty,
        _ => {
            return Err(CryptoengError::ParseError(
                "Invalid system type parameter".to_string(),
            ));
        }
    };

    storage.reset_privacy_data(system_type);
    storage.save()?;

    info!(?system_type, "All data reset");
    Ok(ResponseBuilder::standard(request.method_type()).build())
}
