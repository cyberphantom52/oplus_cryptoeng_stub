use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use serde_json::Value;

#[derive(Debug)]
struct Object(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for Object {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = Object;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an attestation object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Object, M::Error> {
                let mut members = Vec::new();
                while let Some(member) = map.next_entry()? {
                    members.push(member);
                }
                Ok(Object(members))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

impl Object {
    fn get(&self, key: &str) -> Option<&Value> {
        self.0
            .iter()
            .find(|(name, _)| c_string(name).eq_ignore_ascii_case(key))
            .map(|(_, value)| value)
    }
}

fn c_string(value: &str) -> &str {
    value.split('\0').next().unwrap_or_default()
}

use super::error::PkiError;

#[derive(Debug)]
pub(super) struct Request {
    pub nonce: String,
    pub app_device_id: String,
    pub app_rotate_device_id: String,
    pub application_key_alias: String,
    pub application_public_key: String,
    pub application_key_security_level: String,
    pub application_key_algorithm: String,
    pub application_customize_data_dgst: String,
    pub alias: u8,
    pub expire_days: u8,
    pub timestamp: String,
    pub not_before: String,
    pub not_after: String,
}

impl Request {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, PkiError> {
        if bytes.is_empty() {
            return Err(PkiError::MissingParameter);
        }
        if bytes.len() > 4096 {
            return Err(PkiError::JsonTooLong);
        }

        let json = serde_json::Deserializer::from_slice(bytes)
            .into_iter::<Object>()
            .next()
            .ok_or(PkiError::InvalidJson)?
            .map_err(|_| {
                if serde_json::Deserializer::from_slice(bytes)
                    .into_iter::<Value>()
                    .next()
                    .is_some_and(|value| value.is_ok())
                {
                    PkiError::MissingField("targetFormat")
                } else {
                    PkiError::InvalidJson
                }
            })?;
        let json = &json;
        let target = string(json, "targetFormat", usize::MAX, true)?;
        if target.starts_with("raw") {
            return Err(PkiError::Unsupported);
        }
        let nonce = if json.get("nonce").is_some() {
            string(json, "nonce", 64, false)?
        } else {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            crate::utils::generate_random_bytes(32)
                .into_iter()
                .flat_map(|byte| {
                    [
                        char::from(HEX[usize::from(byte >> 4)]),
                        char::from(HEX[usize::from(byte & 15)]),
                    ]
                })
                .collect()
        };
        let app_device_id = string(json, "appDeviceId", 64, false)?;
        let app_rotate_device_id = string(json, "appRotateDeviceId", 64, false)?;
        let application_key_alias = string(json, "applicationKeyAlias", 15, true)?;
        let application_public_key = string(json, "applicationPublicKey", 1023, true)?;
        let application_key_security_level = string(json, "applicationKeySecurityLevel", 15, true)?;
        let application_key_algorithm = string(json, "applicationKeyAlgorithm", 15, true)?;
        let application_customize_data_dgst =
            string(json, "applicationCustomizeDataDgst", 64, false)?;
        let alias = byte(json, "signingKeyAlias")?;
        let expire_days = match byte(json, "expireDays")? {
            0 => 30,
            days @ 1..=90 => days,
            _ => return Err(PkiError::InvalidExpiry),
        };
        let timestamp = string(json, "timestamp", 31, true)?;
        let not_before = string(json, "notBefore", 15, true)?;
        let not_after = string(json, "notAfter", 15, true)?;
        Ok(Self {
            nonce,
            app_device_id,
            app_rotate_device_id,
            application_key_alias,
            application_public_key,
            application_key_security_level,
            application_key_algorithm,
            application_customize_data_dgst,
            alias,
            expire_days,
            timestamp,
            not_before,
            not_after,
        })
    }
}

fn string(
    json: &Object,
    key: &'static str,
    max_bytes: usize,
    required: bool,
) -> Result<String, PkiError> {
    let Some(value) = json.get(key) else {
        return if required {
            Err(PkiError::MissingField(key))
        } else {
            Ok(String::new())
        };
    };
    let value = c_string(value.as_str().ok_or(PkiError::InvalidJson)?);
    if value.len() > max_bytes {
        return Err(PkiError::TooLong);
    }
    Ok(value.to_owned())
}

fn byte(json: &Object, key: &'static str) -> Result<u8, PkiError> {
    let value = match json.get(key).ok_or(PkiError::MissingField(key))? {
        Value::Number(value) => value.as_f64().unwrap_or(0.0),
        Value::Bool(true) => 1.0,
        _ => 0.0,
    };

    Ok(value as i32 as u8)
}
