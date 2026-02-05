mod error;
mod handlers;
mod method;
mod request;
mod response;
mod storage;
mod utils;

use rsbinder::*;
use std::sync::{Arc, RwLock};
use tracing::{debug, error};

include!(concat!(env!("OUT_DIR"), "/cryptoeng.rs"));

pub use crate::error::{CryptoengError, Result, StorageError};
use crate::request::Request;
use crate::response::ResponseBuilder;
use crate::storage::Storage;
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
}

impl CryptoengService {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(Storage::load())),
        }
    }

    fn handle_request(&self, request: &[u8]) -> Result<Vec<u8>> {
        let parsed = Request::parse(request)?;

        let mut storage = self.storage.write()?;

        match parsed {
            Request::Standard(req) => req.handle(&mut storage),
            Request::Native(req) => req.handle(&mut storage),
        }
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
    use byteorder::{BigEndian, ByteOrder, LittleEndian};

    use crate::{
        method::{MethodParamType, MethodType, Parameter},
        request::NativeCommand,
        response::ResponseBuilder,
    };

    use super::*;

    #[test]
    fn test_parse_native_command() {
        // Native command format: [cmd_id][0][0][0][data...]
        let request = vec![8u8, 0, 0, 0, 0, 0, 0, 0];
        let parsed = Request::parse(&request);
        assert!(parsed.is_ok());
        if let Ok(Request::Native(req)) = parsed {
            assert_eq!(req.command, NativeCommand::WriteSecret);
        } else {
            panic!("Expected Native request");
        }
    }

    #[test]
    fn test_parse_standard_command() {
        // Standard command format: [method_type BE][buffer_size BE][param_count BE][params...]
        let mut request = Vec::new();
        // Method type = 4005 (CeCmdPmsGetInfo)
        request.extend_from_slice(&4005i32.to_be_bytes());
        // Buffer size = 10000
        request.extend_from_slice(&10000i32.to_be_bytes());
        // Param count = 1
        request.extend_from_slice(&1i32.to_be_bytes());
        // Param type = 201 (PmsTypeT)
        request.extend_from_slice(&201i32.to_be_bytes());
        // Param length = 4
        request.extend_from_slice(&4i32.to_be_bytes());
        // Param data = 0
        request.extend_from_slice(&0i32.to_be_bytes());

        let parsed = Request::parse(&request);
        assert!(parsed.is_ok());
        if let Ok(Request::Standard(req)) = parsed {
            assert_eq!(req.method_type, MethodType::CeCmdPmsGetInfo);
            assert_eq!(req.params.len(), 1);
        } else {
            panic!("Expected Standard request");
        }
    }

    #[test]
    fn test_response_builder() {
        let response = ResponseBuilder::standard(MethodType::CeCmdPmsGetInfo)
            .result_code(0)
            .add_param(Parameter::from_i32(MethodParamType::PmsPwdTypeT, 1))
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
        assert_eq!(LittleEndian::read_i32(&response[0..4]), 0);
        assert_eq!(&response[4..8], &[1, 2, 3, 4]);
    }
}
