//! Native command handlers
use byteorder::{ByteOrder, LittleEndian};

use crate::error::{CryptoengError, Result};
use crate::register_handler;
use crate::request::CryptoengRequest;
use crate::response::ResponseBuilder;
use crate::storage::{RuntimeState, Storage};
use crate::types::method::MethodType;

register_handler!(MethodType::CeCmdWriteSecret, handle_write_secret);
register_handler!(MethodType::CeCmdPresetDataDec, handle_preset_data_dec);

fn handle_write_secret(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    _runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let data = request.data();

    if data.len() < 4 {
        return Err(CryptoengError::BufferTooShort {
            got: data.len(),
            min: 4,
        });
    }

    let secret_length = LittleEndian::read_i32(&data[0..4]) as usize;
    let mut offset = 4;

    if data.len() < offset + secret_length {
        return Err(CryptoengError::BufferTooShort {
            got: data.len(),
            min: offset + secret_length,
        });
    }

    let secret = &data[offset..offset + secret_length];
    offset += secret_length;

    if data.len() < offset + 4 {
        return Err(CryptoengError::BufferTooShort {
            got: data.len(),
            min: offset + 4,
        });
    }

    let _token_length = LittleEndian::read_i32(&data[offset..offset + 4]) as usize;

    storage.store_secret(secret_length as i32, secret.to_vec());
    storage.save()?;

    Ok(ResponseBuilder::native().build())
}

fn handle_preset_data_dec(
    request: &dyn CryptoengRequest,
    storage: &mut Storage,
    _runtime: &mut RuntimeState,
) -> Result<Vec<u8>> {
    let data = request.data();

    if data.len() < 4 {
        return Err(CryptoengError::BufferTooShort {
            got: data.len(),
            min: 4,
        });
    }

    let ali_buf_len = LittleEndian::read_i32(&data[0..4]) as usize;
    let mut offset = 4;

    if data.len() < offset + ali_buf_len {
        return Err(CryptoengError::BufferTooShort {
            got: data.len(),
            min: offset + ali_buf_len,
        });
    }

    let _ali_buf = &data[offset..offset + ali_buf_len];
    offset += ali_buf_len;

    if data.len() < offset + 4 {
        return Err(CryptoengError::BufferTooShort {
            got: data.len(),
            min: offset + 4,
        });
    }

    let enc_len = LittleEndian::read_i32(&data[offset..offset + 4]) as usize;
    offset += 4;

    if data.len() < offset + enc_len {
        return Err(CryptoengError::BufferTooShort {
            got: data.len(),
            min: offset + enc_len,
        });
    }

    let enc_data = &data[offset..offset + enc_len];

    let decrypted = storage.decrypt(enc_data)?;

    Ok(ResponseBuilder::native().extra_data(decrypted).build())
}
