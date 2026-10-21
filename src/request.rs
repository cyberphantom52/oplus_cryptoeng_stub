use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::{collections::HashMap, fmt, marker::PhantomData};

use crate::{
    error::{CryptoengError, Result},
    types::method::MethodType,
    types::parameter::{MethodParamType, Parameter},
};

pub const MAX_REQUEST_SIZE: usize = 0x5800;

/// Marker type for native request format (cmdId <= 100)
#[derive(Debug, Clone, Copy)]
pub struct Native;

/// Marker type for standard request format (cmdId > 100)
#[derive(Debug, Clone, Copy)]
pub struct Standard;

/// Trait that requests must implement
pub trait CryptoengRequest: fmt::Debug {
    fn method_type(&self) -> MethodType;

    fn get_param(&self, param_type: MethodParamType) -> Result<&Parameter>;
}

#[derive(Debug, Clone)]
pub struct Request<T> {
    pub method_type: MethodType,

    /// Parsed parameters (only populated for Standard requests)
    pub params: HashMap<MethodParamType, Parameter>,
    _marker: PhantomData<T>,
}

// Implement HandleRequest for Request<Native>
impl CryptoengRequest for Request<Native> {
    fn method_type(&self) -> MethodType {
        self.method_type
    }

    fn get_param(&self, param_type: MethodParamType) -> Result<&Parameter> {
        Err(CryptoengError::MissingParameter(param_type))
    }
}

// Implement HandleRequest for Request<Standard>
impl CryptoengRequest for Request<Standard> {
    fn method_type(&self) -> MethodType {
        self.method_type
    }

    fn get_param(&self, param_type: MethodParamType) -> Result<&Parameter> {
        self.params
            .get(&param_type)
            .ok_or(CryptoengError::MissingParameter(param_type))
    }
}

/// Parse incoming request data into the appropriate Request type
pub fn parse(data: &[u8]) -> Result<Box<dyn CryptoengRequest>> {
    if data.len() > MAX_REQUEST_SIZE {
        return Err(CryptoengError::ParseError(
            "request exceeds backend buffer limit".into(),
        ));
    }
    if data.len() < 4 {
        return Err(CryptoengError::BufferTooShort {
            got: data.len(),
            min: 4,
        });
    }

    let method_type = method_type(data);

    if method_type.code() < 0 {
        return Err(CryptoengError::ParseError("negative command code".into()));
    }
    if method_type.is_native() {
        Ok(Box::new(Request::<Native>::parse(data)?))
    } else {
        Ok(Box::new(Request::<Standard>::parse(data)?))
    }
}

fn method_type(data: &[u8]) -> MethodType {
    let little_endian = LittleEndian::read_i32(data);
    if (0..=100).contains(&little_endian) {
        MethodType::from(little_endian)
    } else {
        MethodType::from(BigEndian::read_i32(data))
    }
}

impl Request<Native> {
    fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(CryptoengError::BufferTooShort {
                got: data.len(),
                min: 4,
            });
        }

        let method_type = method_type(data);

        let request = Self {
            method_type,
            params: HashMap::new(),
            _marker: PhantomData,
        };

        Ok(request)
    }
}

impl Request<Standard> {
    fn parse(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < 12 {
            return Err(CryptoengError::BufferTooShort {
                got: buffer.len(),
                min: 12,
            });
        }

        let method_type = MethodType::from(BigEndian::read_i32(&buffer[0..4]));
        if (4000..=4012).contains(&method_type.code()) && buffer.len() > 0x1000 {
            return Err(CryptoengError::ParseError(
                "PMS command exceeds TA limit".into(),
            ));
        }

        let param_count = usize::try_from(BigEndian::read_i32(&buffer[8..12]))
            .map_err(|_| CryptoengError::ParseError("negative parameter count".into()))?;
        if param_count > (buffer.len() - 12) / 8 {
            return Err(CryptoengError::ParseError(
                "parameter count exceeds buffer".into(),
            ));
        }

        let mut params = HashMap::with_capacity(param_count);
        let mut remaining = &buffer[12..];
        for _ in 0..param_count {
            if remaining.len() < 8 {
                return Err(CryptoengError::BufferTooShort {
                    got: remaining.len(),
                    min: 8,
                });
            }
            let param_type = MethodParamType::from(BigEndian::read_i32(&remaining[..4]));
            let param_len = usize::try_from(BigEndian::read_i32(&remaining[4..8]))
                .map_err(|_| CryptoengError::ParseError("negative parameter length".into()))?;
            remaining = &remaining[8..];
            if param_len > remaining.len() {
                return Err(CryptoengError::BufferTooShort {
                    got: remaining.len(),
                    min: param_len,
                });
            }
            if param_type != MethodParamType::Unknown && !params.contains_key(&param_type) {
                let parameter = Parameter::new(param_type, &remaining[..param_len])?;
                params.insert(param_type, parameter);
            }
            remaining = &remaining[param_len..];
        }

        Ok(Self {
            method_type,
            params,
            _marker: PhantomData,
        })
    }
}
