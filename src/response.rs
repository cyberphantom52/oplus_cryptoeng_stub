use std::marker::PhantomData;

use byteorder::{BigEndian, ByteOrder};

use crate::request::{Native, Standard};
use crate::types::{method::MethodType, parameter::Parameter};

pub struct ResponseBuilder<T> {
    method_type: Option<MethodType>,
    result_code: i32,
    parameters: Vec<Parameter>,
    _marker: PhantomData<T>,
}

impl ResponseBuilder<Standard> {
    /// Create a new standard response builder
    pub fn standard(method_type: MethodType) -> Self {
        Self {
            method_type: Some(method_type),
            result_code: 0,
            parameters: Vec::new(),
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
            _marker: PhantomData,
        }
    }

    pub fn result_code(mut self, code: i32) -> Self {
        self.result_code = code;
        self
    }

    pub fn build(self) -> Vec<u8> {
        let mut result = vec![0u8; 4];
        BigEndian::write_i32(&mut result, self.result_code);

        result
    }
}

pub fn failure(method_type: MethodType, result_code: Option<i32>) -> Vec<u8> {
    if let Some(result_code) = result_code.filter(|_| !method_type.is_native()) {
        ResponseBuilder::standard(method_type)
            .result_code(result_code)
            .build()
    } else {
        ResponseBuilder::native().result_code(-1).build()
    }
}
