use std::marker::PhantomData;

use byteorder::{BigEndian, ByteOrder, LittleEndian};

use crate::method::{MethodType, Parameter};

/// Marker type for standard response format (cmdId > 100)
pub struct Standard;

/// Marker type for native response format (cmdId <= 100)
pub struct Native;

pub struct ResponseBuilder<T> {
    method_type: Option<MethodType>,
    result_code: i32,
    parameters: Vec<Parameter>,
    extra_data: Option<Vec<u8>>,
    _marker: PhantomData<T>,
}

impl ResponseBuilder<Standard> {
    /// Create a new standard response builder
    pub fn standard(method_type: MethodType) -> Self {
        Self {
            method_type: Some(method_type),
            result_code: 0,
            parameters: Vec::new(),
            extra_data: None,
            _marker: PhantomData,
        }
    }

    /// Set the result code
    #[allow(dead_code)]
    pub fn result_code(mut self, code: i32) -> Self {
        self.result_code = code;
        self
    }

    /// Add a parameter
    pub fn add_param(mut self, param: Parameter) -> Self {
        self.parameters.push(param);
        self
    }

    /// Build the standard response bytes
    pub fn build(self) -> Vec<u8> {
        let mut result = Vec::new();
        let mut buf = [0u8; 4];

        // Method type (4 bytes)
        result.extend_from_slice(&self.method_type.unwrap().to_be_bytes());

        // Result code (4 bytes)
        BigEndian::write_i32(&mut buf, self.result_code);
        result.extend_from_slice(&buf);

        // Param count (4 bytes)
        BigEndian::write_i32(&mut buf, self.parameters.len() as i32);
        result.extend_from_slice(&buf);

        // Params
        for param in self.parameters {
            result.extend_from_slice(&param.to_be_bytes());
        }

        result
    }
}

impl ResponseBuilder<Native> {
    /// Create a new native response builder
    pub fn native() -> Self {
        Self {
            method_type: None,
            result_code: 0,
            parameters: Vec::new(),
            extra_data: None,
            _marker: PhantomData,
        }
    }

    /// Set the result code
    pub fn result_code(mut self, code: i32) -> Self {
        self.result_code = code;
        self
    }

    /// Set extra data
    pub fn extra_data(mut self, data: Vec<u8>) -> Self {
        self.extra_data = Some(data);
        self
    }

    /// Build the native response bytes
    pub fn build(self) -> Vec<u8> {
        let mut result = vec![0u8; 4];
        LittleEndian::write_i32(&mut result, self.result_code);

        if let Some(data) = self.extra_data {
            result.extend_from_slice(&data);
        }

        result
    }
}
