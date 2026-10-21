use std::collections::HashSet;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{info, warn};

use crate::error::{CryptoengError, Result};
use crate::register_handler;
use crate::request::CryptoengRequest;
use crate::response::ResponseBuilder;
use crate::storage::{BootTimestamp, PendingVerification, RuntimeState, Storage};
use crate::types::method::MethodType;
use crate::types::parameter::{InfoType, MethodParamType, Parameter, Value};
use crate::utils::generate_random_bytes;

register_handler!(MethodType::CeCmdPmsEnroll, handle_pms_enroll);
register_handler!(MethodType::CeCmdPmsVerify, handle_pms_verify);
register_handler!(MethodType::CeCmdPmsModify, handle_pms_modify);
register_handler!(MethodType::CeCmdPmsDelete, handle_pms_delete);
register_handler!(MethodType::CeCmdPmsGetInfo, handle_pms_get_info);

fn handle_pms_enroll(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let response = enroll(request, storage, runtime)?;
    storage.save()?;
    Ok(response)
}

fn enroll(
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
    require_privacy_system(system_type)?;

    let password_type = match request.get_param(MethodParamType::PmsPwdTypeT)?.value() {
        Value::PasswordQuality(q) => *q,
        _ => {
            return Err(CryptoengError::ParseError(
                "Invalid password type parameter".to_string(),
            ));
        }
    };

    // Get password info (hash) - required for enrollment
    let pwd_info = request.get_param(MethodParamType::PmsPwdInfoT)?;
    if password_type == crate::PasswordQuality::Unspecified
        || pwd_info.value().as_bytes().len() != 32
    {
        return Err(CryptoengError::ParseError(
            "invalid password enrollment".into(),
        ));
    }
    let secure_info = request.get_param(MethodParamType::PmsSecureInfoBufferT)?;
    let Value::SecureBuffer(buffer) = secure_info.value() else {
        return Err(CryptoengError::ParseError(
            "invalid recovery records".into(),
        ));
    };
    if buffer.entries.is_empty()
        || buffer.entries.len() > 6
        || !buffer.entries.iter().any(|entry| {
            entry.ty == InfoType::SecurityQuestion && entry.value.as_bytes().len() == 32
        })
        || buffer.entries.iter().any(|entry| {
            !matches!(
                entry.ty,
                InfoType::Email | InfoType::EmailEx1 | InfoType::SecurityQuestion
            ) || entry.value.as_bytes().is_empty()
                || (entry.ty == InfoType::SecurityQuestion && entry.value.as_bytes().len() != 32)
        })
    {
        return Err(CryptoengError::ParseError(
            "invalid recovery records".into(),
        ));
    }

    let mut seen = HashSet::new();
    if buffer.entries.iter().any(|entry| !seen.insert(entry.ty))
        || (seen.contains(&InfoType::EmailEx1) && !seen.contains(&InfoType::Email))
    {
        return Err(CryptoengError::ParseError(
            "duplicate or orphaned recovery records".into(),
        ));
    }
    let privacy_data = storage.get_privacy_data_mut(system_type);
    if privacy_data.enrolled {
        return Err(CryptoengError::AlreadyEnrolled(system_type));
    }
    privacy_data.password_type = password_type;
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
                (InfoType::SecurityQuestion, Value::Buffer(answer)) if answer.len() == 32 => {
                    privacy_data.security_answer_hash = answer.clone();
                }
                _ => continue,
            }
        }

        if let Some(first) = email_first {
            privacy_data.email = match email_continuation {
                Some(cont) => format!("{}{}", first, cont),
                None => first,
            };
            info!("Email saved during enroll");
        }
    }

    privacy_data.handler = generate_random_bytes(8);
    privacy_data.enrolled = true;
    privacy_data.reset_retries();

    info!(?system_type, ?password_type, "User enrolled");

    let handler = privacy_data.handler.clone();
    privacy_data.authorization = None;
    Ok(ResponseBuilder::standard(request.method_type())
        .add_param(Parameter::new(MethodParamType::PmsHandlerT, &handler)?)
        .build())
}

fn handle_pms_verify(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let response = verify(request, storage, runtime);

    if response.is_ok() || matches!(&response, Err(CryptoengError::VerificationFailed { .. })) {
        storage.save()?;
    }
    response
}

fn verify(
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

    require_privacy_system(system_type)?;
    let verify_type = match request.get_param(MethodParamType::PmsVerifyTypeT)?.value() {
        Value::InfoType(ty) => *ty,
        _ => {
            return Err(CryptoengError::ParseError(
                "Invalid verify info type parameter".to_string(),
            ));
        }
    };

    if verify_type == InfoType::Unspecified {
        return Err(CryptoengError::ParseError(
            "invalid verification type".into(),
        ));
    }
    if !matches!(verify_type, InfoType::Password | InfoType::SecurityQuestion) {
        return Err(CryptoengError::UnsupportedOperation);
    }
    let privacy_data = storage.get_privacy_data_mut(system_type);

    if !privacy_data.enrolled {
        warn!(?system_type, "Not enrolled");
        return Err(CryptoengError::NotEnrolled(system_type));
    }

    let verify_buffer = request.get_param(MethodParamType::PmsVerifyBufferT)?;
    let verify_data = verify_buffer.value().as_bytes();
    if verify_data.len() != 32 {
        return Err(CryptoengError::ParseError("invalid proof length".into()));
    }
    let now = runtime.now()?;

    if credential_matches(privacy_data, verify_type, &verify_data) {
        // Generate a challenge token (64 bytes) for successful verification
        // The challenge must be 64 bytes to match what modifyPasswordByChallenge expects
        let challenge = generate_random_bytes(64);

        info!(?system_type, ?verify_type, "Password verified");

        privacy_data.reset_retries();
        privacy_data.authorization = Some(PendingVerification {
            challenge: challenge.clone(),
            issued_at: now.clone(),
        });

        Ok(ResponseBuilder::standard(request.method_type())
            .add_param(Parameter::new(MethodParamType::PmsChallengeT, &challenge)?)
            .build())
    } else {
        let retries_left = privacy_data.record_failure(verify_type, &now);
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
    let response = modify(request, storage, runtime)?;
    storage.save()?;
    Ok(response)
}

fn modify(
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

    require_privacy_system(system_type)?;
    let challenge = request
        .get_param(MethodParamType::PmsChallengeT)?
        .value()
        .as_bytes();
    if challenge.len() != crate::CHALLENGE_LENGTH {
        return Err(CryptoengError::ParseError(
            "invalid challenge length".into(),
        ));
    }
    let password_type = match request.get_param(MethodParamType::PmsPwdTypeT)?.value() {
        Value::PasswordQuality(quality) if *quality != crate::PasswordQuality::Unspecified => {
            *quality
        }
        _ => {
            return Err(CryptoengError::ParseError(
                "invalid password quality".into(),
            ));
        }
    };
    let info_type = match request.get_param(MethodParamType::PmsInfoTypeT)?.value() {
        Value::InfoType(ty) => *ty,
        _ => {
            return Err(CryptoengError::ParseError(
                "invalid modification type".into(),
            ));
        }
    };
    if info_type == InfoType::Unspecified {
        return Err(CryptoengError::ParseError(
            "invalid modification type".into(),
        ));
    }
    if !matches!(
        info_type,
        InfoType::Password | InfoType::SecurityQuestion | InfoType::Email
    ) {
        return Err(CryptoengError::UnsupportedOperation);
    }
    let information = request
        .get_param(MethodParamType::PmsInfoBufferT)?
        .value()
        .as_bytes();
    let pending = storage
        .get_privacy_data(system_type)
        .and_then(|data| data.authorization.as_ref())
        .ok_or(CryptoengError::ChallengeMismatch(system_type))?;
    validate_challenge(&challenge, pending, system_type, &runtime.now()?, 300_000)?;
    let email = // Handle different info types
match info_type {
        InfoType::Password | InfoType::SecurityQuestion if information.len() == 32 => None,
        InfoType::Email if information.len() <= 64 => Some(
            std::str::from_utf8(&information)
                .map_err(|_| CryptoengError::ParseError("invalid email encoding".into()))?
                .to_owned(),
        ),
        _ => {
            return Err(CryptoengError::ParseError(
                "unsupported modification information".into(),
            ));
        }
    };
    let privacy_data = storage.get_privacy_data_mut(system_type);
    if !privacy_data.enrolled {
        return Err(CryptoengError::NotEnrolled(system_type));
    }
    if info_type == InfoType::Password {
        privacy_data.password_type = password_type;
    }
    if let Some(email) = email {
        privacy_data.email = email;
    } else if info_type == InfoType::SecurityQuestion {
        privacy_data.security_answer_hash = information.into_owned();
    } else {
        privacy_data.password_hash = information.into_owned();
    }
    privacy_data.reset_retries();
    let mut response = ResponseBuilder::standard(request.method_type());
    if info_type == InfoType::Password {
        privacy_data.handler = generate_random_bytes(8);
        response = response.add_param(Parameter::new(
            MethodParamType::PmsHandlerT,
            &privacy_data.handler,
        )?);
    }
    Ok(response.build())
}

fn handle_pms_delete(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let response = delete(request, storage, runtime)?;
    storage.save()?;
    Ok(response)
}

fn delete(
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
    require_privacy_system(system_type)?;
    let challenge = request
        .get_param(MethodParamType::PmsChallengeT)?
        .value()
        .as_bytes();
    if challenge.len() != crate::CHALLENGE_LENGTH {
        return Err(CryptoengError::ParseError(
            "invalid challenge length".into(),
        ));
    }
    let pending = storage
        .get_privacy_data(system_type)
        .and_then(|data| data.authorization.as_ref())
        .ok_or(CryptoengError::ChallengeMismatch(system_type))?;
    validate_challenge(&challenge, pending, system_type, &runtime.now()?, 60_000)?;
    storage.reset_privacy_data(system_type);

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
    require_privacy_system(system_type)?;

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

fn credential_matches(data: &crate::storage::PrivacyData, kind: InfoType, provided: &[u8]) -> bool {
    if provided.len() != 32 {
        return false;
    }
    match kind {
        InfoType::Password if data.password_hash.len() == 32 && data.handler.len() == 8 => {
            let mut hasher = Sha256::new();
            hasher.update(&data.password_hash);
            hasher.update(&data.handler);
            bool::from(provided.ct_eq(hasher.finalize().as_slice()))
        }
        InfoType::SecurityQuestion => {
            data.security_answer_hash.len() == 32
                && bool::from(provided.ct_eq(&data.security_answer_hash))
        }
        _ => false,
    }
}

fn validate_challenge(
    provided: &[u8],
    pending: &PendingVerification,
    system_type: crate::SystemType,
    now: &BootTimestamp,
    lifetime_ms: u64,
) -> Result<()> {
    if provided.len() != crate::CHALLENGE_LENGTH || !bool::from(provided.ct_eq(&pending.challenge))
    {
        return Err(CryptoengError::ChallengeMismatch(system_type));
    }
    if pending.is_expired(now, lifetime_ms) {
        return Err(CryptoengError::ChallengeExpired);
    }
    Ok(())
}

fn require_privacy_system(system: crate::SystemType) -> Result<()> {
    if system == crate::SystemType::PrivacyPassword {
        Ok(())
    } else {
        Err(CryptoengError::UnsupportedOperation)
    }
}
