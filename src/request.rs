use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::collections::HashMap;
use std::fmt;
use tracing::{debug, info, warn};

use crate::{
    error::{CryptoengError, Result},
    handlers,
    response::ResponseBuilder,
    storage::Storage,
    types::method::MethodType,
    types::parameter::{MethodParamType, Parameter},
};

/// Request type enum
#[derive(Debug, Clone)]
pub enum Request {
    Standard(StandardRequest),
    Native(NativeRequest),
}

impl Request {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(CryptoengError::BufferTooShort {
                got: data.len(),
                min: 4,
            });
        }

        // If the first byte is a small number and high bytes are 0, it's a native command
        if data[0] <= 100 && data[1..=3] == [0, 0, 0] {
            let request = NativeRequest::try_from(data)?;
            return Ok(Request::Native(request));
        }

        // Otherwise, parse as standard request (big-endian)
        StandardRequest::try_from(data).map(Request::Standard)
    }
}

/// Parsed standard request (cmdId > 100)
#[derive(Debug, Clone)]
pub struct StandardRequest {
    pub method_type: MethodType,
    pub params: HashMap<MethodParamType, Parameter>,
}

impl fmt::Display for StandardRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.method_type)?;
        if !self.params.is_empty() {
            write!(f, " {{")?;
            let mut first = true;
            for (_, v) in &self.params {
                if !first {
                    write!(f, ",")?;
                }
                first = false;
                write!(f, " {}", v)?;
            }
            write!(f, " }}")?;
        }
        Ok(())
    }
}

impl TryFrom<&[u8]> for StandardRequest {
    type Error = CryptoengError;

    fn try_from(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < 12 {
            warn!(
                len = buffer.len(),
                min = 12,
                "Standard request buffer too short"
            );
            return Err(CryptoengError::BufferTooShort {
                got: buffer.len(),
                min: 12,
            });
        }

        let method_type = MethodType::from(BigEndian::read_i32(&buffer[0..4]));
        let param_count = BigEndian::read_i32(&buffer[8..12]);

        let mut params = HashMap::new();
        let mut offset = 12;

        for i in 0..param_count {
            if offset + 8 > buffer.len() {
                warn!(
                    param_index = i,
                    offset,
                    buffer_len = buffer.len(),
                    "Buffer too short for param header"
                );
                return Err(CryptoengError::BufferTooShort {
                    got: buffer.len(),
                    min: offset + 8,
                });
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
                    "Buffer too short for param data"
                );
                return Err(CryptoengError::BufferTooShort {
                    got: buffer.len(),
                    min: offset + param_len,
                });
            }

            let param_data = buffer[offset..offset + param_len].to_vec();
            offset += param_len;

            let param_type = MethodParamType::from(param_type_code);
            let parameter = Parameter::new(param_type, param_data)?;

            params.insert(param_type, parameter);
        }

        let request = StandardRequest {
            method_type,
            params,
        };

        debug!(request = %request, "Recieved Request");

        Ok(request)
    }
}

impl StandardRequest {
    pub fn handle(&self, storage: &mut Storage) -> Result<Vec<u8>> {
        info!(
            command = ?self.method_type,
            code = self.method_type.code(),
            "Handling command"
        );

        // Try to dispatch to a registered handler
        handlers::dispatch(self, storage)
    }

    /// Get a parameter by type
    pub fn get_param(&self, param_type: MethodParamType) -> Result<&Parameter> {
        self.params
            .get(&param_type)
            .ok_or(CryptoengError::MissingParameter(param_type))
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

impl TryFrom<&[u8]> for NativeRequest {
    type Error = CryptoengError;

    fn try_from(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(CryptoengError::BufferTooShort {
                got: data.len(),
                min: 4,
            });
        }

        Ok(Self {
            command: NativeCommand::from(data[0]),
            data: data[4..].to_vec(),
        })
    }
}

impl NativeRequest {
    pub fn handle(&self, storage: &mut Storage) -> Result<Vec<u8>> {
        match self.command {
            NativeCommand::WriteSecret => self.handle_write_secret(storage),
            NativeCommand::PresetDataDec => self.handle_preset_data_dec(storage),
            NativeCommand::Unknown(cmd_id) => {
                warn!(cmd_id, "Unknown native command");
                Err(CryptoengError::UnknownNativeCommand(cmd_id))
            }
        }
    }

    fn handle_write_secret(&self, storage: &mut Storage) -> Result<Vec<u8>> {
        // Parse: [secret_length: 4 bytes LE][secret: N bytes][token_length: 4 bytes LE][token: M bytes]
        if self.data.len() < 4 {
            return Err(CryptoengError::BufferTooShort {
                got: self.data.len(),
                min: 4,
            });
        }

        let secret_length = LittleEndian::read_i32(&self.data[0..4]) as usize;
        let mut offset = 4;

        if self.data.len() < offset + secret_length {
            return Err(CryptoengError::BufferTooShort {
                got: self.data.len(),
                min: offset + secret_length,
            });
        }

        let secret = &self.data[offset..offset + secret_length];
        offset += secret_length;

        if self.data.len() < offset + 4 {
            return Err(CryptoengError::BufferTooShort {
                got: self.data.len(),
                min: offset + 4,
            });
        }

        let token_length = LittleEndian::read_i32(&self.data[offset..offset + 4]) as usize;
        offset += 4;

        if self.data.len() < offset + token_length {
            return Err(CryptoengError::BufferTooShort {
                got: self.data.len(),
                min: offset + token_length,
            });
        }

        storage.store_secret(secret_length as i32, secret.to_vec());
        storage.save()?;

        Ok(ResponseBuilder::native().build())
    }

    fn handle_preset_data_dec(&self, _storage: &mut Storage) -> Result<Vec<u8>> {
        // Parse: [aliBuf_len: 4 bytes LE][aliBuf: N bytes][enc_len: 4 bytes LE][enc: M bytes]
        if self.data.len() < 4 {
            return Err(CryptoengError::BufferTooShort {
                got: self.data.len(),
                min: 4,
            });
        }

        let ali_buf_len = LittleEndian::read_i32(&self.data[0..4]) as usize;
        let mut offset = 4;

        if self.data.len() < offset + ali_buf_len {
            return Err(CryptoengError::BufferTooShort {
                got: self.data.len(),
                min: offset + ali_buf_len,
            });
        }

        let _ali_buf = &self.data[offset..offset + ali_buf_len];
        offset += ali_buf_len;

        if self.data.len() < offset + 4 {
            return Err(CryptoengError::BufferTooShort {
                got: self.data.len(),
                min: offset + 4,
            });
        }

        let enc_len = LittleEndian::read_i32(&self.data[offset..offset + 4]) as usize;
        offset += 4;

        if self.data.len() < offset + enc_len {
            return Err(CryptoengError::BufferTooShort {
                got: self.data.len(),
                min: offset + enc_len,
            });
        }

        let enc_data = &self.data[offset..offset + enc_len];

        Ok(ResponseBuilder::native()
            .extra_data(enc_data.to_vec())
            .build())
    }
}
