use byteorder::{BigEndian, ByteOrder};
use tracing::info;

use crate::error::{CryptoengError, Result};
use crate::method::{MethodParamType, MethodType, Parameter};
use crate::register_handler;
use crate::request::StandardRequest;
use crate::response::ResponseBuilder;
use crate::storage::Storage;

// Register all TA handlers
register_handler!(MethodType::TaCmdStoreOldPassword, handle_store_old_password);
register_handler!(
    MethodType::TaCmdRetrievePasswordByOldPwd,
    handle_retrieve_password_by_old_pwd
);
register_handler!(
    MethodType::TaCmdPasswordRetrieveValidity,
    handle_password_retrieve_validity
);
register_handler!(
    MethodType::TaCmdDeleteOldPassword,
    handle_delete_old_password
);
register_handler!(
    MethodType::TaCmdPasswordVerifyResult,
    handle_password_verify_result
);

fn handle_store_old_password(request: &StandardRequest, storage: &mut Storage) -> Result<Vec<u8>> {
    let user_id = request
        .get_param(MethodParamType::PmsPwdUseridT)?
        .as_i32()?;
    let pwd_data = storage.get_password_data_mut(user_id);

    if let Ok(old_pwd_type) = request
        .get_param(MethodParamType::PmsOldPwdTypeT)
        .and_then(|p| p.as_i32())
    {
        pwd_data.old_pwd_type = old_pwd_type;
    }

    if let Ok(old_pwd_buffer) = request.get_param(MethodParamType::PmsOldPwdBufferT) {
        pwd_data.old_pwd_buffer = old_pwd_buffer.data().to_vec();
    }

    if let Ok(current_pwd_type) = request
        .get_param(MethodParamType::PmsCurrentPwdTypeT)
        .and_then(|p| p.as_i32())
    {
        pwd_data.current_pwd_type = current_pwd_type;
    }

    if let Ok(current_pwd_buffer) = request.get_param(MethodParamType::PmsCurrentPwdBufferT) {
        pwd_data.current_pwd_buffer = current_pwd_buffer.data().to_vec();
    }

    if let Ok(system_time) = request.get_param(MethodParamType::PmsPwdSystemTimeT) {
        if system_time.data().len() >= 8 {
            pwd_data.system_time = BigEndian::read_i64(system_time.data());
        }
    }

    pwd_data.user_id = user_id;

    // Capture values before releasing the mutable borrow
    let old_pwd_type = pwd_data.old_pwd_type;
    let current_pwd_type = pwd_data.current_pwd_type;

    storage.save()?;

    info!(
        user_id,
        old_pwd_type, current_pwd_type, "TA StoreOldPassword: Password stored:"
    );

    Ok(ResponseBuilder::standard(request.method_type).build())
}

fn handle_retrieve_password_by_old_pwd(
    request: &StandardRequest,
    storage: &mut Storage,
) -> Result<Vec<u8>> {
    let user_id = request
        .get_param(MethodParamType::PmsPwdUseridT)?
        .as_i32()?;

    if let Some(pwd_data) = storage.get_password_data(user_id) {
        info!(
            user_id,
            current_pwd_type = pwd_data.current_pwd_type,
            buffer_len = pwd_data.current_pwd_buffer.len(),
            "TA RetrievePasswordByOldPwd: Found:"
        );

        Ok(ResponseBuilder::standard(request.method_type)
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
            .build())
    } else {
        tracing::warn!(user_id, "TA RetrievePasswordByOldPwd: Not found:");
        Err(CryptoengError::PasswordDataNotFound(user_id))
    }
}

fn handle_password_retrieve_validity(
    request: &StandardRequest,
    storage: &mut Storage,
) -> Result<Vec<u8>> {
    let user_id = request
        .get_param(MethodParamType::PmsPwdUseridT)?
        .as_i32()?;
    let is_valid = storage.get_password_data(user_id).is_some();

    info!(user_id, is_valid, "TA PasswordRetrieveValidity:");

    Ok(ResponseBuilder::standard(request.method_type)
        .add_param(Parameter::from_i32(
            MethodParamType::PmsResultValidity,
            if is_valid { 1 } else { 0 },
        ))
        .build())
}

fn handle_delete_old_password(request: &StandardRequest, storage: &mut Storage) -> Result<Vec<u8>> {
    let user_id = request
        .get_param(MethodParamType::PmsPwdUseridT)?
        .as_i32()?;

    storage.delete_password_data(user_id);
    storage.save()?;

    info!(user_id, "TA DeleteOldPassword: Deleted:");
    Ok(ResponseBuilder::standard(request.method_type).build())
}

fn handle_password_verify_result(
    request: &StandardRequest,
    _storage: &mut Storage,
) -> Result<Vec<u8>> {
    info!("TA PasswordVerifyResult: Returning success (stub):");

    Ok(ResponseBuilder::standard(request.method_type)
        .add_param(Parameter::from_i32(
            MethodParamType::PmsVerifyOldPwdResultT,
            0,
        ))
        .add_param(Parameter::from_i32(
            MethodParamType::PmsOldPwdTryRemainingCount,
            5,
        ))
        .build())
}
