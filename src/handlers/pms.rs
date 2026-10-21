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
        || !buffer
            .entries
            .iter()
            .any(|entry| entry.ty == InfoType::SecurityQuestion as i32)
        || buffer
            .entries
            .iter()
            .any(|entry| entry.ty == 0 || entry.declared_len == 0)
    {
        return Err(CryptoengError::ParseError(
            "invalid recovery records".into(),
        ));
    }
    let privacy_data = storage.get_privacy_data_mut(system_type);
    if privacy_data.enrolled {
        return Err(CryptoengError::AlreadyEnrolled(system_type));
    }
    privacy_data.password_type = password_type;
    privacy_data.password_hash = pwd_info.value().as_bytes().to_vec();

    privacy_data.recovery_records = buffer.entries.clone();

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
    let challenge_parameter = request.get_param(MethodParamType::PmsChallengeT)?;
    let challenge = challenge_parameter.value().as_bytes();
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
    let information_parameter = request.get_param(MethodParamType::PmsInfoBufferT)?;
    let information = information_parameter.value().as_bytes();
    let pending = storage
        .get_privacy_data(system_type)
        .and_then(|data| data.authorization.as_ref())
        .ok_or(CryptoengError::ChallengeMismatch(system_type))?;
    validate_challenge(&challenge, pending, system_type, &runtime.now()?, 300_000)?;
    // Handle different info types
    match info_type {
        InfoType::Password if information.len() == 32 => {}
        InfoType::SecurityQuestion if (1..=32).contains(&information.len()) => {}
        InfoType::Email if (1..=64).contains(&information.len()) => {}
        _ => {
            return Err(CryptoengError::ParseError(
                "unsupported modification information".into(),
            ));
        }
    }
    let privacy_data = storage.get_privacy_data_mut(system_type);
    if !privacy_data.enrolled {
        return Err(CryptoengError::NotEnrolled(system_type));
    }
    if info_type == InfoType::Password {
        privacy_data.password_type = password_type;
    }
    if matches!(info_type, InfoType::SecurityQuestion | InfoType::Email) {
        privacy_data.modify_recovery_info(info_type, &information)?;
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
    let challenge_parameter = request.get_param(MethodParamType::PmsChallengeT)?;
    let challenge = challenge_parameter.value().as_bytes();
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
    if !storage
        .get_privacy_data(system_type)
        .is_some_and(|data| data.enrolled)
    {
        return Ok(ResponseBuilder::standard(request.method_type())
            .add_param(Parameter::new(
                MethodParamType::PmsPwdTypeT,
                &0i32.to_be_bytes(),
            )?)
            .build());
    }
    let latest = optional_word(request, MethodParamType::PmsLatestSecureRulesT) == Some(10000);
    let now = runtime.now()?;
    let privacy_data = storage.get_privacy_data_mut(system_type);
    let mut builder = ResponseBuilder::standard(request.method_type())
        .add_param(Parameter::new(
            MethodParamType::PmsPwdTypeT,
            &(privacy_data.password_type as i32).to_be_bytes(),
        )?)
        .add_param(Parameter::new(
            MethodParamType::PmsHandlerT,
            &privacy_data.handler,
        )?);
    if let Some(email) = privacy_data.recovery_email() {
        let email = email.split(|byte| *byte == 0).next().unwrap_or_default();
        let hide_email = optional_word(request, MethodParamType::PmsHideEmailT) != Some(0);
        let email = if hide_email {
            hidden_email(email)?
        } else {
            validate_email(email)?;
            email.to_vec()
        };
        builder = builder.add_param(Parameter::new(MethodParamType::PmsHideEmailT, &email)?);
    }

    let changed = !latest && privacy_data.refresh_legacy_retries(&now);
    let (password_retries, password_lock) =
        privacy_data.retry_status(InfoType::Password, &now, latest);
    let (answer_retries, answer_lock) =
        privacy_data.retry_status(InfoType::SecurityQuestion, &now, latest);
    if !latest || password_lock > 0 {
        builder = builder.add_param(Parameter::new(
            MethodParamType::PmsPwdLockTimeLeftT,
            &lock_time_bytes(password_lock),
        )?);
    }
    if latest && answer_lock > 0 {
        builder = builder.add_param(Parameter::new(
            MethodParamType::PmsSecureQuestionLockTimeLeftT,
            &lock_time_bytes(answer_lock),
        )?);
    }
    builder = builder.add_param(Parameter::new(
        MethodParamType::PmsPwdRetryCountLeftT,
        &password_retries.to_be_bytes(),
    )?);
    if latest {
        builder = builder.add_param(Parameter::new(
            MethodParamType::PmsSecureQuestionRetryCountLeftT,
            &answer_retries.to_be_bytes(),
        )?);
    }
    let response = builder.build();
    if changed {
        storage.save()?;
    }
    Ok(response)
}

fn optional_word(request: &dyn CryptoengRequest, kind: MethodParamType) -> Option<i32> {
    let parameter = request.get_param(kind).ok()?;
    let bytes = parameter.value().as_bytes();
    let mut word = [0; 4];
    let count = bytes.len().min(word.len());
    word[..count].copy_from_slice(&bytes[..count]);
    Some(i32::from_be_bytes(word))
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
        InfoType::SecurityQuestion if !data.recovery_records.is_empty() => data
            .recovery_records
            .iter()
            .filter(|entry| entry.ty == InfoType::SecurityQuestion as i32)
            .fold(false, |matched, entry| {
                matched | bool::from(provided.ct_eq(&entry.payload))
            }),
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

fn lock_time_bytes(seconds: i32) -> [u8; 8] {
    let mut bytes = [0; 8];
    bytes[..4].copy_from_slice(&seconds.to_be_bytes());
    bytes
}

fn validate_email(email: &[u8]) -> Result<usize> {
    let prefix = email
        .iter()
        .position(|byte| *byte == b'@')
        .ok_or(CryptoengError::InvalidEmail)?;
    if prefix == 0 || prefix + 1 == email.len() || email[prefix + 1..].contains(&b'@') {
        return Err(CryptoengError::InvalidEmail);
    }
    Ok(prefix)
}

fn hidden_email(email: &[u8]) -> Result<Vec<u8>> {
    let prefix = validate_email(email)?;
    if prefix < 2 {
        return Ok(Vec::new());
    }
    let mut hidden = email.to_vec();
    hidden[prefix / 4 + 1..prefix].fill(b'*');
    Ok(hidden)
}

fn require_privacy_system(system: crate::SystemType) -> Result<()> {
    if system == crate::SystemType::PrivacyPassword {
        Ok(())
    } else {
        Err(CryptoengError::UnsupportedOperation)
    }
}
