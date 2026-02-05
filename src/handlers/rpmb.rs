use tracing::info;

use crate::error::Result;
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

fn handle_set_lock_screen_pwd_type(
    request: &StandardRequest,
    storage: &mut Storage,
) -> Result<Vec<u8>> {
    let user_id = request
        .get_param(MethodParamType::PmsPwdUseridT)?
        .as_i32()?;
    let pwd_type = request.get_param(MethodParamType::PmsPwdTypeT)?.as_i32()?;

    storage.set_lock_screen_pwd_type(user_id, pwd_type);
    storage.save()?;

    info!(user_id, pwd_type, "Lock screen password type set");
    Ok(ResponseBuilder::standard(request.method_type).build())
}

fn handle_get_rpmb_value(request: &StandardRequest, storage: &mut Storage) -> Result<Vec<u8>> {
    let key_param = request.get_param(MethodParamType::PmsCommonBuffer0T)?;
    let key = String::from_utf8_lossy(key_param.data()).to_string();

    let value = storage.get_rpmb_value(&key).cloned().unwrap_or_default();

    Ok(ResponseBuilder::standard(request.method_type)
        .add_param(Parameter::new(MethodParamType::PmsCommonBuffer1T, value))
        .build())
}
