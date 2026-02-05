use byteorder::{BigEndian, ByteOrder, LittleEndian};
use tracing::{debug, info, warn};

use crate::{
    handlers,
    method::{MethodParamType, MethodType},
    response::ResponseBuilder,
    storage::Storage,
};
use std::collections::HashMap;

/// Request type enum
#[derive(Debug, Clone)]
pub enum Request {
    Standard(StandardRequest),
    Native(NativeRequest),
}

impl Request {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            warn!(len = data.len(), "Request buffer too short");
            return None;
        }

        // If the first byte is a small number and high bytes are 0, it's a native command
        if data[0] <= 100 && data[1..=3] == [0, 0, 0] {
            let request = NativeRequest::from(data);
            debug!(command = ?request.command, "Detected native command:");
            return Some(Request::Native(request));
        }

        // Otherwise, parse as standard request (big-endian)
        StandardRequest::try_from(data).ok().map(Request::Standard)
    }
}

/// Format a parameter value for logging based on its type
fn format_param_value(param_type: &MethodParamType, data: &[u8]) -> String {
    match param_type {
        // Integer parameters - show as decimal
        MethodParamType::PmsTypeT
        | MethodParamType::PmsPwdTypeT
        | MethodParamType::PmsVerifyTypeT
        | MethodParamType::PmsPwdRetryCountLeftT
        | MethodParamType::PmsPwdLockTimeLeftT
        | MethodParamType::PmsSecureQuestionRetryCountLeftT
        | MethodParamType::PmsSecureQuestionLockTimeLeftT
        | MethodParamType::PmsLatestSecureRulesT
        | MethodParamType::PmsPwdUseridT
        | MethodParamType::PmsOldPwdTypeT
        | MethodParamType::PmsOldPwdLengthT
        | MethodParamType::PmsCurrentPwdTypeT
        | MethodParamType::PmsCurrentPwdLenT
        | MethodParamType::PmsVerifyOldPwdResultT
        | MethodParamType::PmsOldPwdTryRemainingCount
        | MethodParamType::PmsOldPwdTryRemainingTime
        | MethodParamType::PmsResultValidity => {
            if data.len() >= 4 {
                format!("{}", BigEndian::read_i32(data))
            } else {
                format!("<invalid: {} bytes>", data.len())
            }
        }

        // Boolean-like parameters
        MethodParamType::PmsHideEmailT => {
            if data.len() >= 4 {
                let val = BigEndian::read_i32(data);
                if val == 0 {
                    "false".to_string()
                } else {
                    "true".to_string()
                }
            } else {
                format!("<invalid: {} bytes>", data.len())
            }
        }

        // String parameters
        MethodParamType::PmsAccountName => String::from_utf8_lossy(data).to_string(),

        // Binary/hash parameters - show as hex with truncation
        MethodParamType::PmsVerifyBufferT
        | MethodParamType::PmsPwdInfoT
        | MethodParamType::PmsSecureInfoBufferT
        | MethodParamType::PmsChallengeT
        | MethodParamType::PmsHandlerT
        | MethodParamType::PmsEncBufferT
        | MethodParamType::PmsOldPwdBufferT
        | MethodParamType::PmsCurrentPwdBufferT
        | MethodParamType::PmsCurrentPasswordBuffer => {
            if data.len() <= 16 {
                format!(
                    "[{}]",
                    data.iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            } else {
                format!(
                    "[{} ... +{} more]",
                    data[..8]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" "),
                    data.len() - 8
                )
            }
        }

        // Default: show length and first few bytes
        _ => {
            if data.len() <= 8 {
                format!(
                    "{} bytes: [{}]",
                    data.len(),
                    data.iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            } else {
                format!(
                    "{} bytes: [{} ...]",
                    data.len(),
                    data[..4]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
        }
    }
}

/// Parsed standard request (cmdId > 100)
#[derive(Debug, Clone)]
pub struct StandardRequest {
    pub method_type: MethodType,
    pub params: HashMap<MethodParamType, Vec<u8>>,
}

impl TryFrom<&[u8]> for StandardRequest {
    type Error = &'static str;

    fn try_from(buffer: &[u8]) -> Result<Self, Self::Error> {
        if buffer.len() < 12 {
            warn!(
                len = buffer.len(),
                min = 12,
                "Standard request buffer too short:"
            );
            return Err("Buffer too short");
        }

        let method_type = MethodType::from(BigEndian::read_i32(&buffer[0..4]));
        let param_count = BigEndian::read_i32(&buffer[8..12]);

        debug!(
            method = ?method_type,
            code = method_type.code(),
            param_count,
            "Parsing standard request:"
        );

        let mut params = HashMap::new();
        let mut offset = 12;

        for i in 0..param_count {
            if offset + 8 > buffer.len() {
                warn!(
                    param_index = i,
                    offset,
                    buffer_len = buffer.len(),
                    "Buffer too short for param header:"
                );
                break;
            }

            let param_type_code = BigEndian::read_i32(&buffer[offset..offset + 4]);
            let param_len = BigEndian::read_i32(&buffer[offset + 4..offset + 8]) as usize;
            offset += 8;

            if offset + param_len > buffer.len() {
                warn!(
                    param_index = i,
                    param_len,
                    offset,
                    buffer_len = buffer.len(),
                    "Buffer too short for param data:"
                );
                break;
            }

            let param_data = buffer[offset..offset + param_len].to_vec();
            offset += param_len;

            let param_type = MethodParamType::from(param_type_code);
            let value_preview = format_param_value(&param_type, &param_data);

            debug!(
                param_index = i,
                param_type = ?param_type,
                len = param_len,
                value = %value_preview,
                "  Param:"
            );

            params.insert(param_type, param_data);
        }

        Ok(StandardRequest {
            method_type,
            params,
        })
    }
}

impl StandardRequest {
    pub fn handle(&self, storage: &mut Storage) -> Vec<u8> {
        info!(
            command = ?self.method_type,
            code = self.method_type.code(),
            "Handling command:"
        );

        // Try to dispatch to a registered handler
        if let Some(response) = handlers::dispatch(self, storage) {
            return response;
        }

        // No handler found - return empty success for unknown commands
        let code = self.method_type.code();
        warn!(
            command = ?self.method_type,
            code,
            "Unknown command, returning empty success:"
        );
        ResponseBuilder::standard(self.method_type).build()
    }

    /// Helper to get an i32 parameter
    pub fn get_param_i32(&self, param_type: MethodParamType) -> Option<i32> {
        self.params.get(&param_type).and_then(|v| {
            if v.len() >= 4 {
                Some(BigEndian::read_i32(v))
            } else {
                None
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// Native Commands (cmdId <= 100)
pub enum NativeCommand {
    WriteSecret = 8,
    PresetDataDec = 26,
    Unknown(u8),
}

impl From<u8> for NativeCommand {
    fn from(code: u8) -> Self {
        match code {
            8 => NativeCommand::WriteSecret,
            26 => NativeCommand::PresetDataDec,
            _ => NativeCommand::Unknown(code),
        }
    }
}

/// Parsed native request (cmdId <= 100)
#[derive(Debug, Clone)]
pub struct NativeRequest {
    pub command: NativeCommand,
    pub data: Vec<u8>,
}

impl From<&[u8]> for NativeRequest {
    fn from(data: &[u8]) -> Self {
        Self {
            command: NativeCommand::from(data[0]),
            data: data[4..].to_vec(),
        }
    }
}

impl NativeRequest {
    pub fn handle(&self, storage: &mut Storage) -> Vec<u8> {
        info!(
            command = ?self.command,
            data_len = self.data.len(),
            "Handling native command:"
        );
        match self.command {
            NativeCommand::WriteSecret => self.handle_write_secret(storage),
            NativeCommand::PresetDataDec => self.handle_preset_data_dec(storage),
            NativeCommand::Unknown(cmd_id) => {
                warn!(cmd_id, "Unknown native command:");
                ResponseBuilder::native().build()
            }
        }
    }

    fn handle_write_secret(&self, storage: &mut Storage) -> Vec<u8> {
        // Parse: [secret_length: 4 bytes LE][secret: N bytes][token_length: 4 bytes LE][token: M bytes]
        if self.data.len() < 4 {
            warn!(
                data_len = self.data.len(),
                "WriteSecret: Buffer too short for secret length:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let secret_length = LittleEndian::read_i32(&self.data[0..4]) as usize;
        let mut offset = 4;

        if self.data.len() < offset + secret_length {
            warn!(
                data_len = self.data.len(),
                expected = offset + secret_length,
                "WriteSecret: Buffer too short for secret data:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let secret = &self.data[offset..offset + secret_length];
        offset += secret_length;

        if self.data.len() < offset + 4 {
            warn!(
                data_len = self.data.len(),
                expected = offset + 4,
                "WriteSecret: Buffer too short for token length:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let token_length = LittleEndian::read_i32(&self.data[offset..offset + 4]) as usize;
        offset += 4;

        if self.data.len() < offset + token_length {
            warn!(
                data_len = self.data.len(),
                expected = offset + token_length,
                "WriteSecret: Buffer too short for token data:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        info!(
            secret_len = secret_length,
            token_len = token_length,
            "WriteSecret: Stored secret:"
        );

        storage.store_secret(secret_length as i32, secret.to_vec());
        storage.save();

        ResponseBuilder::native().build()
    }

    fn handle_preset_data_dec(&self, _storage: &mut Storage) -> Vec<u8> {
        // Parse: [aliBuf_len: 4 bytes LE][aliBuf: N bytes][enc_len: 4 bytes LE][enc: M bytes]
        if self.data.len() < 4 {
            warn!(
                data_len = self.data.len(),
                "PresetDataDec: Buffer too short for aliBuf length:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let ali_buf_len = LittleEndian::read_i32(&self.data[0..4]) as usize;
        let mut offset = 4;

        if self.data.len() < offset + ali_buf_len {
            warn!(
                data_len = self.data.len(),
                expected = offset + ali_buf_len,
                "PresetDataDec: Buffer too short for aliBuf data:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let ali_buf = &self.data[offset..offset + ali_buf_len];
        offset += ali_buf_len;

        if self.data.len() < offset + 4 {
            warn!(
                data_len = self.data.len(),
                expected = offset + 4,
                "PresetDataDec: Buffer too short for enc length:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let enc_len = LittleEndian::read_i32(&self.data[offset..offset + 4]) as usize;
        offset += 4;

        if self.data.len() < offset + enc_len {
            warn!(
                data_len = self.data.len(),
                expected = offset + enc_len,
                "PresetDataDec: Buffer too short for enc data:"
            );
            return ResponseBuilder::native().result_code(-1).build();
        }

        let enc_data = &self.data[offset..offset + enc_len];

        info!(
            ali_buf = %String::from_utf8_lossy(ali_buf),
            enc_len,
            "PresetDataDec: Returning data as-is (stub):"
        );

        ResponseBuilder::native()
            .extra_data(enc_data.to_vec())
            .build()
    }
}
