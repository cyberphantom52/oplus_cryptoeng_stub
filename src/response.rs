use byteorder::{BigEndian, ByteOrder, LittleEndian};

use crate::method::MethodParamType;

/// Builder for standard responses
pub struct ResponseBuilder {
    method_code: i32,
    result_code: i32,
    params: Vec<(i32, Vec<u8>)>,
}

impl ResponseBuilder {
    pub fn new(method_code: i32) -> Self {
        Self {
            method_code,
            result_code: 0,
            params: Vec::new(),
        }
    }

    pub fn result_code(mut self, code: i32) -> Self {
        self.result_code = code;
        self
    }

    pub fn add_param(mut self, param_type: MethodParamType, data: Vec<u8>) -> Self {
        self.params.push((param_type as i32, data));
        self
    }

    pub fn add_param_i32(mut self, param_type: MethodParamType, value: i32) -> Self {
        let mut data = vec![0u8; 4];
        BigEndian::write_i32(&mut data, value);
        self.params.push((param_type as i32, data));
        self
    }

    pub fn add_param_string(mut self, param_type: MethodParamType, value: &str) -> Self {
        self.params
            .push((param_type as i32, value.as_bytes().to_vec()));
        self
    }

    pub fn build(self) -> Vec<u8> {
        let mut result = Vec::new();

        // Method type (4 bytes)
        let mut buf = [0u8; 4];
        BigEndian::write_i32(&mut buf, self.method_code);
        result.extend_from_slice(&buf);

        // Result code (4 bytes)
        BigEndian::write_i32(&mut buf, self.result_code);
        result.extend_from_slice(&buf);

        // Param count (4 bytes)
        BigEndian::write_i32(&mut buf, self.params.len() as i32);
        result.extend_from_slice(&buf);

        // Params
        for (param_type, data) in self.params {
            // Param type (4 bytes)
            BigEndian::write_i32(&mut buf, param_type);
            result.extend_from_slice(&buf);

            // Param length (4 bytes)
            BigEndian::write_i32(&mut buf, data.len() as i32);
            result.extend_from_slice(&buf);

            // Param data
            result.extend_from_slice(&data);
        }

        result
    }
}

/// Build a native response (for cmdId <= 100)
pub fn build_native_response(result_code: i32, extra_data: Option<&[u8]>) -> Vec<u8> {
    let mut result = vec![0u8; 4];
    LittleEndian::write_i32(&mut result, result_code);
    if let Some(data) = extra_data {
        result.extend_from_slice(data);
    }
    result
}
