mod method;
mod request;
mod response;
mod storage;
mod utils;

use rsbinder::*;
use std::io::Write;
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info, warn};

include!(concat!(env!("OUT_DIR"), "/cryptoeng.rs"));

use crate::request::Request;
use crate::response::build_native_response;
use crate::storage::{Storage, STORAGE_DIR};
pub use crate::vendor::oplus::hardware::cryptoeng::ICryptoeng::BnCryptoeng;
pub use crate::vendor::oplus::hardware::cryptoeng::ICryptoeng::ICryptoeng;

/// Interface version and hash from the original AIDL
pub const INTERFACE_VERSION: i32 = 1;
pub const INTERFACE_HASH: &str = "765136eb397eb5b85ee1e089d8fec72c15e266b3";

/// Buffer size constant used in the protocol
#[allow(dead_code)]
const BUFFER_SIZE: i32 = 10000;

// ============================================================================
// Cryptoeng Service Implementation
// ============================================================================

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
}

impl Default for CryptoengService {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for CryptoengService {}

impl ICryptoeng for CryptoengService {
    fn cryptoeng_invoke_command(&self, request: &[u8]) -> rsbinder::status::Result<Vec<u8>> {
        debug!("cryptoeng_invoke_command: received {} bytes", request.len());
        debug!(
            "Request hex: {:02x?}",
            &request[..std::cmp::min(64, request.len())]
        );

        let response = match Request::parse(request) {
            Some(Request::Standard(req)) => {
                let mut storage = self.storage.write().unwrap();
                req.handle(&mut storage)
            }
            Some(Request::Native(req)) => {
                let mut storage = self.storage.write().unwrap();
                req.handle(&mut storage)
            }
            None => {
                warn!("Failed to parse request");
                // Return a generic error response
                build_native_response(-1, None)
            }
        };

        debug!(
            "Response hex: {:02x?}",
            &response[..std::cmp::min(64, response.len())]
        );
        Ok(response)
    }

    fn getInterfaceVersion(&self) -> rsbinder::status::Result<i32> {
        info!(
            "getInterfaceVersion called, returning {}",
            INTERFACE_VERSION
        );
        Ok(INTERFACE_VERSION)
    }

    fn getInterfaceHash(&self) -> rsbinder::status::Result<String> {
        info!("getInterfaceHash called, returning {}", INTERFACE_HASH);
        Ok(INTERFACE_HASH.to_string())
    }
}

// ============================================================================
// Debug Service Implementation
// ============================================================================

/// Debug service that logs all incoming binder transactions.
pub struct DebugCryptoengService {
    inner: CryptoengService,
}

impl DebugCryptoengService {
    pub fn new() -> Self {
        Self {
            inner: CryptoengService::new(),
        }
    }
}

impl Default for DebugCryptoengService {
    fn default() -> Self {
        Self::new()
    }
}

impl Interface for DebugCryptoengService {}

impl Remotable for DebugCryptoengService {
    fn descriptor() -> &'static str
    where
        Self: Sized,
    {
        "vendor.oplus.hardware.cryptoeng.ICryptoeng"
    }

    fn on_transact(
        &self,
        code: TransactionCode,
        reader: &mut Parcel,
        reply: &mut Parcel,
    ) -> Result<()> {
        let data_len = reader.data_size();
        warn!(
            code = code,
            code_hex = format!("0x{:x}", code),
            data_len = data_len,
            "BINDER TRANSACTION"
        );

        // Log hex dump for debugging
        let data = unsafe { std::slice::from_raw_parts(reader.as_ptr(), data_len) };
        let hex: String = data
            .iter()
            .take(256)
            .map(|b| format!("{:02x}", b))
            .collect();
        debug!(hex = %hex, "parcel data (first 256 bytes)");

        match code {
            // Transaction 1 = cryptoeng_invoke_command
            1 => {
                // Read the byte array from the parcel
                let request: Vec<u8> = reader.read()?;
                info!("cryptoeng_invoke_command: {} bytes", request.len());

                // Process the command
                match self.inner.cryptoeng_invoke_command(&request) {
                    Ok(response) => {
                        info!("Response: {} bytes", response.len());
                        reply.write(&0i32)?; // Status OK
                        reply.write(&response)?;
                        Ok(())
                    }
                    Err(e) => {
                        error!("Command failed: {:?}", e);
                        Err(e.into())
                    }
                }
            }
            // Transaction 16777214 = getInterfaceHash
            16777214 => {
                info!("getInterfaceHash - returning {}", INTERFACE_HASH);
                reply.write(&0i32)?;
                reply.write(&INTERFACE_HASH.to_string())?;
                Ok(())
            }
            // Transaction 16777215 = getInterfaceVersion
            16777215 => {
                info!("getInterfaceVersion - returning {}", INTERFACE_VERSION);
                reply.write(&0i32)?;
                reply.write(&INTERFACE_VERSION)?;
                Ok(())
            }
            _ => {
                warn!(code = code, "unknown transaction code");
                Err(StatusCode::UnknownTransaction.into())
            }
        }
    }

    fn on_dump(&self, writer: &mut dyn Write, _args: &[String]) -> Result<()> {
        writeln!(writer, "DebugCryptoengService - logs all transactions").ok();
        writeln!(writer, "Storage: {}/", STORAGE_DIR).ok();
        writeln!(writer, "Supported commands:").ok();
        writeln!(writer, "  - PMS Enroll/Verify/Modify/Delete/GetInfo").ok();
        writeln!(writer, "  - Set Lock Screen Password Type").ok();
        writeln!(writer, "  - Get RPMB Value").ok();
        writeln!(writer, "  - TA Password Storage commands").ok();
        writeln!(writer, "  - Native WriteSecret/PresetDataDec").ok();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{BigEndian, ByteOrder, LittleEndian};

    use crate::{
        method::{MethodParamType, MethodType},
        response::ResponseBuilder,
    };

    use super::*;

    #[test]
    fn test_parse_native_command() {
        // Native command format: [cmd_id][0][0][0][data...]
        let request = vec![8u8, 0, 0, 0, 0, 0, 0, 0];
        let parsed = Request::parse(&request);
        assert!(matches!(parsed, Some(Request::Native(_))));
        if let Some(Request::Native(req)) = parsed {
            assert_eq!(req.cmd_id, 8);
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
        assert!(matches!(parsed, Some(Request::Standard(_))));
        if let Some(Request::Standard(req)) = parsed {
            assert_eq!(req.method_type, MethodType::CeCmdPmsGetInfo);
            assert_eq!(req.param_count, 1);
        }
    }

    #[test]
    fn test_response_builder() {
        let response = ResponseBuilder::new(4005)
            .result_code(0)
            .add_param_i32(MethodParamType::PmsPwdTypeT, 1)
            .build();

        // Check header
        assert_eq!(BigEndian::read_i32(&response[0..4]), 4005); // method type
        assert_eq!(BigEndian::read_i32(&response[4..8]), 0); // result code
        assert_eq!(BigEndian::read_i32(&response[8..12]), 1); // param count
    }

    #[test]
    fn test_native_response() {
        let response = build_native_response(0, Some(&[1, 2, 3, 4]));
        assert_eq!(response.len(), 8);
        assert_eq!(LittleEndian::read_i32(&response[0..4]), 0);
        assert_eq!(&response[4..8], &[1, 2, 3, 4]);
    }
}
