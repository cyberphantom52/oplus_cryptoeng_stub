use tracing::info;

use crate::method::{MethodParamType, MethodType, Parameter};
use crate::register_handler;
use crate::request::StandardRequest;
use crate::response::ResponseBuilder;
use crate::storage::Storage;

register_handler!(
    MethodType::CeSetLockScreenPwdType,
    handle_set_lock_screen_pwd_type
);
register_handler!(MethodType::CeCmdGetRpmbValue, handle_get_rpmb_value);

fn handle_set_lock_screen_pwd_type(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    let user_id = request
        .get_param_i32(MethodParamType::PmsPwdUseridT)
        .unwrap_or(0);
    let pwd_type = request
        .get_param_i32(MethodParamType::PmsPwdTypeT)
        .unwrap_or(0);

    storage.set_lock_screen_pwd_type(user_id, pwd_type);
    storage.save();

    info!(
        user_id,
        pwd_type, "SetLockScreenPwdType: Password type set:"
    );
    ResponseBuilder::standard(request.method_type).build()
}

fn handle_get_rpmb_value(request: &StandardRequest, storage: &mut Storage) -> Vec<u8> {
    let key = request
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

    ResponseBuilder::standard(request.method_type)
        .add_param(Parameter::new(MethodParamType::PmsCommonBuffer1T, value))
        .build()
}
