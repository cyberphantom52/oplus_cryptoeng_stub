use byteorder::{BigEndian, ByteOrder};
use tracing::info;

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

fn handle_store_old_password(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    let user_id = request
        .get_param_i32(MethodParamType::PmsPwdUseridT)
        .unwrap_or(0);
    let pwd_data = storage.get_password_data_mut(user_id);

    if let Some(old_pwd_type) = request.get_param_i32(MethodParamType::PmsOldPwdTypeT) {
        pwd_data.old_pwd_type = old_pwd_type;
    }

    if let Some(old_pwd_buffer) = request.params.get(&MethodParamType::PmsOldPwdBufferT) {
        pwd_data.old_pwd_buffer = old_pwd_buffer.clone();
    }

    if let Some(current_pwd_type) = request.get_param_i32(MethodParamType::PmsCurrentPwdTypeT) {
        pwd_data.current_pwd_type = current_pwd_type;
    }

    if let Some(current_pwd_buffer) = request.params.get(&MethodParamType::PmsCurrentPwdBufferT) {
        pwd_data.current_pwd_buffer = current_pwd_buffer.clone();
    }

    if let Some(system_time) = request.params.get(&MethodParamType::PmsPwdSystemTimeT) {
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

    ResponseBuilder::standard(request.method_type).build()
}

fn handle_retrieve_password_by_old_pwd(
    request: &StandardRequest,
    storage: &mut Storage,
) -> Vec<u8> {
    let user_id = request
        .get_param_i32(MethodParamType::PmsPwdUseridT)
        .unwrap_or(0);

    if let Some(pwd_data) = storage.get_password_data(user_id) {
        info!(
            user_id,
            current_pwd_type = pwd_data.current_pwd_type,
            buffer_len = pwd_data.current_pwd_buffer.len(),
            "TA RetrievePasswordByOldPwd: Found:"
        );

        ResponseBuilder::standard(request.method_type)
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
        tracing::warn!(user_id, "TA RetrievePasswordByOldPwd: Not found:");
        ResponseBuilder::standard(request.method_type)
            .result_code(-1)
            .build()
    }
}

fn handle_password_retrieve_validity(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    let user_id = request
        .get_param_i32(MethodParamType::PmsPwdUseridT)
        .unwrap_or(0);
    let is_valid = storage.get_password_data(user_id).is_some();

    info!(user_id, is_valid, "TA PasswordRetrieveValidity:");

    ResponseBuilder::standard(request.method_type)
        .add_param(Parameter::from_i32(
            MethodParamType::PmsResultValidity,
            if is_valid { 1 } else { 0 },
        ))
        .build()
}

fn handle_delete_old_password(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    let user_id = request
        .get_param_i32(MethodParamType::PmsPwdUseridT)
        .unwrap_or(0);

    storage.delete_password_data(user_id);
    storage.save();

    info!(user_id, "TA DeleteOldPassword: Deleted:");
    ResponseBuilder::standard(request.method_type).build()
}

fn handle_password_verify_result(request: &StandardRequest, _storage: &mut Storage) -> Vec<u8> {
    info!("TA PasswordVerifyResult: Returning success (stub):");

    ResponseBuilder::standard(request.method_type)
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
