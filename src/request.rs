use crate::method::MethodType;
use std::collections::HashMap;

/// Request type enum
#[derive(Debug, Clone)]
pub enum Request {
    Standard(StandardRequest),
    Native(NativeRequest),
}

/// Parsed standard request (cmdId > 100)
#[derive(Debug, Clone)]
pub struct StandardRequest {
    pub method_type: MethodType,
    pub method_code: i32,
    pub buffer_size: i32,
    pub param_count: i32,
    pub params: HashMap<i32, Vec<u8>>,
}

/// Parsed native request (cmdId <= 100)
#[derive(Debug, Clone)]
pub struct NativeRequest {
    pub cmd_id: u8,
    pub data: Vec<u8>,
}
