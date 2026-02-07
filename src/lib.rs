mod error;
mod handlers;
mod request;
mod response;
mod storage;
mod types;
mod utils;

use rsbinder::*;
use std::sync::{Arc, RwLock};
use tracing::{debug, error};

include!(concat!(env!("OUT_DIR"), "/cryptoeng.rs"));

pub use crate::error::{CryptoengError, Result, StorageError};
use crate::response::ResponseBuilder;
use crate::storage::{RuntimeState, Storage};
pub use crate::types::parameter::{InfoType, PasswordQuality, SystemType, CHALLENGE_LENGTH};
pub use crate::vendor::oplus::hardware::cryptoeng::ICryptoeng::BnCryptoeng;
pub use crate::vendor::oplus::hardware::cryptoeng::ICryptoeng::ICryptoeng;

/// Interface version and hash from the original AIDL
pub const INTERFACE_VERSION: i32 = 1;
pub const INTERFACE_HASH: &str = "765136eb397eb5b85ee1e089d8fec72c15e266b3";

/// Buffer size constant used in the protocol
#[allow(dead_code)]
const BUFFER_SIZE: i32 = 10000;

/// Main cryptoeng service with storage backend
pub struct CryptoengService {
    storage: Arc<RwLock<Storage>>,
    runtime: Arc<RwLock<RuntimeState>>,
}

impl CryptoengService {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(Storage::load())),
            runtime: Arc::new(RwLock::new(RuntimeState::new())),
        }
    }

    fn handle_request(&self, data: &[u8]) -> Result<Vec<u8>> {
        let request = request::parse(data)?;

        let mut storage = self.storage.write()?;
        let mut runtime = self.runtime.write()?;

        handlers::dispatch(request.as_ref(), &mut storage, &mut runtime)
    }
}

impl Default for CryptoengService {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for CryptoengService {}

impl ICryptoeng for CryptoengService {
    fn cryptoeng_invoke_command(&self, request: &[u8]) -> rsbinder::status::Result<Vec<u8>> {
        let response = match self.handle_request(request) {
            Ok(response) => response,
            Err(e) => {
                error!(error = %e, "Request handling failed");
                debug!(
                    hex = format!("{:02x?}", &request[..std::cmp::min(64, request.len())]),
                    "Raw request data"
                );
                // Return an error response with the appropriate code
                ResponseBuilder::native()
                    .result_code(e.result_code())
                    .build()
            }
        };

        Ok(response)
    }

    fn getInterfaceVersion(&self) -> rsbinder::status::Result<i32> {
        Ok(INTERFACE_VERSION)
    }

    fn getInterfaceHash(&self) -> rsbinder::status::Result<String> {
        Ok(INTERFACE_HASH.to_string())
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{BigEndian, ByteOrder};
    use crate::types::{method::MethodType, parameter::{MethodParamType, Parameter}};
    use super::*;

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
        // Param count = 1
        data.extend_from_slice(&1i32.to_be_bytes());
        // Param type = 201 (PmsTypeT)
        data.extend_from_slice(&201i32.to_be_bytes());
        // Param length = 4
        data.extend_from_slice(&4i32.to_be_bytes());
        // Param data = 1 (PrivacyPassword)
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
        let response = ResponseBuilder::native()
            .result_code(0)
            .extra_data(vec![1, 2, 3, 4])
            .build();
        assert_eq!(response.len(), 8);
        assert_eq!(BigEndian::read_i32(&response[0..4]), 0);
        assert_eq!(&response[4..8], &[1, 2, 3, 4]);
    }
}
