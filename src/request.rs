use byteorder::{BigEndian, ByteOrder};
use std::{collections::HashMap, fmt, marker::PhantomData};
use tracing::{debug, warn};

use crate::{
    error::{CryptoengError, Result},
    types::method::MethodType,
    types::parameter::{MethodParamType, Parameter},
};

/// Marker type for native request format (cmdId <= 100)
#[derive(Debug, Clone, Copy)]
pub struct Native;

/// Marker type for standard request format (cmdId > 100)
#[derive(Debug, Clone, Copy)]
pub struct Standard;

/// Trait that requests must implement
pub trait CryptoengRequest: fmt::Debug {
    /// Get the method type
    fn method_type(&self) -> MethodType;
    
    /// Get a parameter by type (returns error for Native requests)
    fn get_param(&self, param_type: MethodParamType) -> Result<&Parameter>;
    
    /// Get raw data payload (empty for Standard requests)
    fn data(&self) -> &[u8];
}

#[derive(Debug, Clone)]
pub struct Request<T> {
    pub method_type: MethodType,
    /// Parsed parameters (only populated for Standard requests)
    pub params: HashMap<MethodParamType, Parameter>,
    /// Raw data payload (only populated for Native requests)
    pub data: Vec<u8>,
    _marker: PhantomData<T>,
}

impl<T> fmt::Display for Request<T> {
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

// Implement HandleRequest for Request<Native>
impl CryptoengRequest for Request<Native> {
    fn method_type(&self) -> MethodType {
        self.method_type
    }
    
    fn get_param(&self, param_type: MethodParamType) -> Result<&Parameter> {
        Err(CryptoengError::MissingParameter(param_type))
    }
    
    fn data(&self) -> &[u8] {
        &self.data
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
    
    fn data(&self) -> &[u8] {
        &[]
    }
}

/// Parse incoming request data into the appropriate Request type
pub fn parse(data: &[u8]) -> Result<Box<dyn CryptoengRequest>> {
    if data.len() < 4 {
        return Err(CryptoengError::BufferTooShort {
            got: data.len(),
            min: 4,
        });
    }

    let method_code = BigEndian::read_i32(data);
    let method_type = MethodType::from(method_code);

    if method_type.is_native() {
        Ok(Box::new(Request::<Native>::parse(data)?))
    } else {
        Ok(Box::new(Request::<Standard>::parse(data)?))
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

        let method_code = BigEndian::read_i32(data);
        let method_type = MethodType::from(method_code);

        let request = Self {
            method_type,
            params: HashMap::new(),
            data: data[4..].to_vec(),
            _marker: PhantomData,
        };

        debug!(request = %request, "Received Native Request");
        Ok(request)
    }
}

impl Request<Standard> {
    fn parse(buffer: &[u8]) -> Result<Self> {
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
        let _buffer_size = BigEndian::read_i32(&buffer[4..8]);
        let param_count = BigEndian::read_i32(&buffer[8..12]) as usize;

        let mut params = HashMap::with_capacity(param_count);
        let mut offset = 12;

        for i in 0..param_count {
            if buffer.len() < offset + 8 {
                warn!(
                    param_index = i,
                    offset = offset,
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

            if buffer.len() < offset + param_len {
                warn!(
                    param_index = i,
                    param_len = param_len,
                    offset = offset,
                    buffer_len = buffer.len(),
                    "Buffer too short for param data"
                );
                return Err(CryptoengError::BufferTooShort {
                    got: buffer.len(),
                    min: offset + param_len,
                });
            }

            let param_data = &buffer[offset..offset + param_len];
            offset += param_len;

            let param_type = MethodParamType::from(param_type_code);
            let parameter = Parameter::new(param_type, param_data)?;

            params.insert(param_type, parameter);
        }

        let request = Self {
            method_type,
            params,
            data: Vec::new(),
            _marker: PhantomData,
        };

        debug!(request = %request, "Received Standard Request");
        Ok(request)
    }
}
