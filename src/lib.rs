mod error;
mod handlers;
mod pki;
mod request;
mod response;
mod storage;
mod types;
mod utils;

use rsbinder::*;
use std::sync::{Arc, RwLock};
use tracing::error;

include!(concat!(env!("OUT_DIR"), "/cryptoeng.rs"));

pub use crate::error::{CryptoengError, Result, StorageError};
use crate::response::ResponseBuilder;
use crate::storage::{RuntimeState, Storage};
pub use crate::types::parameter::{CHALLENGE_LENGTH, InfoType, PasswordQuality, SystemType};
pub use crate::vendor::oplus::hardware::cryptoeng::ICryptoeng::BnCryptoeng;
pub use crate::vendor::oplus::hardware::cryptoeng::ICryptoeng::ICryptoeng;

/// Main cryptoeng service with storage backend
pub struct CryptoengService {
    storage: Arc<RwLock<Storage>>,
    runtime: Arc<RwLock<RuntimeState>>,
}

impl CryptoengService {
    pub fn new() -> Result<Self> {
        Ok(Self {
            storage: Arc::new(RwLock::new(Storage::load().unwrap_or_else(|error| {
                error!(%error, "PMS storage unavailable; preserving files for recovery");
                Storage::unavailable()
            }))),
            runtime: Arc::new(RwLock::new(RuntimeState::new())),
        })
    }

    fn handle_request(&self, request: &dyn request::CryptoengRequest) -> Result<Vec<u8>> {
        if let Some(response) = pki::dispatch(request) {
            return Ok(response);
        }
        let mut storage = self.storage.write()?;
        storage.ensure_available()?;
        let mut runtime = self.runtime.write()?;
        handlers::dispatch(request, &mut storage, &mut runtime)
    }
}

impl Interface for CryptoengService {}

impl ICryptoeng for CryptoengService {
    fn cryptoeng_invoke_command(&self, request: &[u8]) -> rsbinder::BinderResult<Vec<u8>> {
        if request.starts_with(&10014i32.to_be_bytes()) && request.len() > 4096 {
            return Ok(ResponseBuilder::standard(
                types::method::MethodType::CeCmdRunPkiBasicAttestation,
            )
            .result_code(10037)
            .build());
        }
        let response = match request::parse(request) {
            Ok(parsed) => match self.handle_request(parsed.as_ref()) {
                Ok(response) => response,
                Err(error) => {
                    error!(%error, method = parsed.method_type().code(), "request handling failed");
                    response::failure(parsed.method_type(), error.result_code())
                }
            },
            Err(error) => {
                error!(%error, "invalid cryptoeng request");
                if let Some(method) = request::parameter_error_method(request, &error) {
                    response::failure(method, error.result_code())
                } else {
                    ResponseBuilder::native().result_code(-1).build()
                }
            }
        };

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::types::{
        method::MethodType,
        parameter::{MethodParamType, Parameter},
    };

    use byteorder::{BigEndian, ByteOrder};

    #[test]
    fn test_parse_native_command() {
        // Native command format (big-endian): [0][0][0][cmd_id][data...]
        let data = vec![0u8, 0, 0, 8, 0, 0, 0, 0];
        let parsed = request::parse(&data);
        assert!(parsed.is_ok());
        let request = parsed.unwrap();
        assert_eq!(request.method_type(), MethodType::CeCmdWriteSecret);
    }

    #[test]
    fn test_parse_standard_command() {
        // Standard command format: [method_type BE][buffer_size BE][param_count BE][params...]
        let mut data = Vec::new();

        // Method type = 4005 (CeCmdPmsGetInfo)
        data.extend_from_slice(&4005i32.to_be_bytes());

        // Buffer size = 10000
        data.extend_from_slice(&10000i32.to_be_bytes());

        data.extend_from_slice(&1i32.to_be_bytes());

        // Param type = 201 (PmsTypeT)
        data.extend_from_slice(&201i32.to_be_bytes());

        // Param length = 4
        data.extend_from_slice(&4i32.to_be_bytes());

        data.extend_from_slice(&1i32.to_be_bytes());

        let parsed = request::parse(&data);
        assert!(parsed.is_ok(), "Parse failed: {:?}", parsed.err());
        let request = parsed.unwrap();
        assert_eq!(request.method_type(), MethodType::CeCmdPmsGetInfo);
    }

    #[test]
    fn test_response_builder() {
        let response = ResponseBuilder::standard(MethodType::CeCmdPmsGetInfo)
            .result_code(0)
            .add_param(Parameter::new(MethodParamType::PmsPwdTypeT, &1i32.to_be_bytes()).unwrap())
            .build();

        // Check header
        assert_eq!(BigEndian::read_i32(&response[0..4]), 4005); // method type

        assert_eq!(BigEndian::read_i32(&response[4..8]), 0); // result code

        assert_eq!(BigEndian::read_i32(&response[8..12]), 1); // param count
    }

    #[test]
    fn test_native_response() {
        let response = ResponseBuilder::native().result_code(-1).build();
        assert_eq!(response, (-1i32).to_be_bytes());
    }
}
