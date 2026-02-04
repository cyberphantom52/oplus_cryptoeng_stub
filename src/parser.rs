use std::collections::HashMap;

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use tracing::{debug, warn};

use crate::{
    method::{MethodParamType, MethodType},
    request::{NativeRequest, Request, StandardRequest},
};

/// Parsed parameter from a request/response
#[derive(Debug, Clone)]
pub struct ParsedParam {
    pub param_type: i32,
    pub data: Vec<u8>,
}

/// Parse a request buffer
pub fn parse_request(buffer: &[u8]) -> Option<Request> {
    if buffer.len() < 4 {
        warn!("Request buffer too short: {} bytes", buffer.len());
        return None;
    }

    // Check if this is a native command (cmdId <= 100)
    // Native commands use little-endian format and the high bytes are 0
    let _cmd_id_le = LittleEndian::read_i32(buffer);
    let _cmd_id_be = BigEndian::read_i32(buffer);

    // If the first byte is a small number and high bytes are 0, it's likely a native command
    if buffer[1] == 0 && buffer[2] == 0 && buffer[3] == 0 && buffer[0] <= 100 {
        debug!("Detected native command: {}", buffer[0]);
        return Some(Request::Native(NativeRequest {
            cmd_id: buffer[0],
            data: buffer[4..].to_vec(),
        }));
    }

    // Otherwise, parse as standard request (big-endian)
    parse_standard_request(buffer).map(Request::Standard)
}

/// Parse a standard request (cmdId > 100)
fn parse_standard_request(buffer: &[u8]) -> Option<StandardRequest> {
    if buffer.len() < 12 {
        warn!(
            "Standard request buffer too short: {} bytes (need at least 12)",
            buffer.len()
        );
        return None;
    }

    let method_code = BigEndian::read_i32(&buffer[0..4]);
    let buffer_size = BigEndian::read_i32(&buffer[4..8]);
    let param_count = BigEndian::read_i32(&buffer[8..12]);

    debug!(
        "Parsing standard request: method={}, buffer_size={}, param_count={}",
        method_code, buffer_size, param_count
    );

    let method_type = MethodType::from(method_code);

    let mut params = HashMap::new();
    let mut offset = 12;

    for i in 0..param_count {
        if offset + 8 > buffer.len() {
            warn!(
                "Buffer too short for param {} header at offset {}",
                i, offset
            );
            break;
        }

        let param_type = BigEndian::read_i32(&buffer[offset..offset + 4]);
        let param_len = BigEndian::read_i32(&buffer[offset + 4..offset + 8]) as usize;
        offset += 8;

        if offset + param_len > buffer.len() {
            warn!(
                "Buffer too short for param {} data: need {} bytes at offset {}, have {}",
                i,
                param_len,
                offset,
                buffer.len()
            );
            break;
        }

        let param_data = buffer[offset..offset + param_len].to_vec();
        offset += param_len;

        debug!(
            "  Param {}: type={} ({:?}), len={}, data={:02x?}",
            i,
            param_type,
            MethodParamType::from(param_type),
            param_len,
            &param_data[..std::cmp::min(32, param_data.len())]
        );

        params.insert(param_type, param_data);
    }

    Some(StandardRequest {
        method_type,
        method_code,
        buffer_size,
        param_count,
        params,
    })
}
