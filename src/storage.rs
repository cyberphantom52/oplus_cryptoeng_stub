use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::PathBuf};
use tracing::{debug, info, warn};

use crate::error::{Result, StorageError};

/// Storage directory for persistent data
pub const STORAGE_DIR: &str = "/data/vendor/cryptoeng";

/// Stored privacy data for a system type
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrivacyData {
    pub password_type: i32,
    pub password_hash: Vec<u8>,
    pub email: String,
    pub handler: Vec<u8>,
    pub retry_count: i32,
    pub lock_time: i32,
    pub secure_question_retry_count: i32,
    pub secure_question_lock_time: i32,
    pub enrolled: bool,
    /// Challenge generated after successful verify, used to authorize modify operations
    #[serde(default)]
    pub pending_challenge: Vec<u8>,
    /// New handler to be set after successful modify (generated during verify)
    #[serde(default)]
    pub pending_handler: Vec<u8>,
}

/// Stored password data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PasswordData {
    pub user_id: i32,
    pub old_pwd_type: i32,
    pub old_pwd_buffer: Vec<u8>,
    pub current_pwd_type: i32,
    pub current_pwd_buffer: Vec<u8>,
    pub system_time: i64,
}

/// Storage backend for the cryptoeng stub
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Storage {
    /// Privacy data keyed by system type
    privacy_data: HashMap<i32, PrivacyData>,
    /// Password data keyed by user ID
    password_data: HashMap<i32, PasswordData>,
    /// Generic key-value store for RPMB values
    rpmb_values: HashMap<String, Vec<u8>>,
    /// Lock screen password types keyed by user ID
    lock_screen_pwd_types: HashMap<i32, i32>,
    /// Secrets stored by writeSecret command
    secrets: HashMap<i32, Vec<u8>>,
}

impl Storage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Self {
        let path = PathBuf::from(STORAGE_DIR).join("storage.json");
        if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str(&content) {
                    Ok(storage) => {
                        info!(path = %path.display(), "Loaded storage:");
                        return storage;
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "Failed to parse storage file:");
                    }
                },
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to read storage file:");
                }
            }
        }
        info!(path = %path.display(), "Creating new storage:");
        Self::new()
    }

    pub fn save(&self) -> Result<()> {
        let path = PathBuf::from(STORAGE_DIR);
        fs::create_dir_all(&path).map_err(StorageError::CreateDir)?;

        let file_path = path.join("storage.json");
        let content = serde_json::to_string_pretty(self).map_err(StorageError::Serialize)?;
        fs::write(&file_path, content).map_err(StorageError::Write)?;

        debug!(path = %file_path.display(), "Saved storage:");
        Ok(())
    }

    pub fn get_privacy_data(&self, system_type: i32) -> Option<&PrivacyData> {
        self.privacy_data.get(&system_type)
    }

    pub fn get_privacy_data_mut(&mut self, system_type: i32) -> &mut PrivacyData {
        self.privacy_data.entry(system_type).or_default()
    }

    pub fn get_password_data(&self, user_id: i32) -> Option<&PasswordData> {
        self.password_data.get(&user_id)
    }

    pub fn get_password_data_mut(&mut self, user_id: i32) -> &mut PasswordData {
        self.password_data.entry(user_id).or_default()
    }

    pub fn delete_password_data(&mut self, user_id: i32) {
        self.password_data.remove(&user_id);
    }

    #[allow(dead_code)]
    pub fn set_rpmb_value(&mut self, key: String, value: Vec<u8>) {
        self.rpmb_values.insert(key, value);
    }

    pub fn get_rpmb_value(&self, key: &str) -> Option<&Vec<u8>> {
        self.rpmb_values.get(key)
    }

    pub fn set_lock_screen_pwd_type(&mut self, user_id: i32, pwd_type: i32) {
        self.lock_screen_pwd_types.insert(user_id, pwd_type);
    }

    #[allow(dead_code)]
    pub fn get_lock_screen_pwd_type(&self, user_id: i32) -> Option<i32> {
        self.lock_screen_pwd_types.get(&user_id).copied()
    }

    pub fn store_secret(&mut self, length: i32, secret: Vec<u8>) {
        self.secrets.insert(length, secret);
    }

    pub fn reset_privacy_data(&mut self, system_type: i32) {
        self.privacy_data.remove(&system_type);
    }
}
