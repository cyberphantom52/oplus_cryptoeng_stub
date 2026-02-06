use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::PathBuf};
use tracing::info;

use crate::{
    PasswordQuality, SystemType,
    error::{Result, StorageError},
};

/// Storage directory for persistent data
pub const STORAGE_DIR: &str = "/data/vendor/cryptoeng";

/// Stored privacy data for a system type
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrivacyData {
    pub password_type: PasswordQuality,
    pub password_hash: Vec<u8>,
    pub email: String,
    pub handler: Vec<u8>,
    pub retry_count: i32,
    pub secure_question_retry_count: i32,
    pub enrolled: bool,
    /// Timestamp when password lock expires (None = not locked)
    #[serde(default)]
    pub lock_until: Option<DateTime<Utc>>,
    /// Timestamp when secure question lock expires (None = not locked)
    #[serde(default)]
    pub secure_question_lock_until: Option<DateTime<Utc>>,
}

impl PrivacyData {
    /// Returns the remaining lock time in seconds, or 0 if not locked
    pub fn lock_time_remaining(&self) -> i32 {
        self.lock_until
            .map(|until| (until - Utc::now()).num_seconds().max(0) as i32)
            .unwrap_or(0)
    }

    /// Returns the remaining secure question lock time in seconds, or 0 if not locked
    pub fn secure_question_lock_time_remaining(&self) -> i32 {
        self.secure_question_lock_until
            .map(|until| (until - Utc::now()).num_seconds().max(0) as i32)
            .unwrap_or(0)
    }

    /// Sets the password lock for the given duration in seconds
    pub fn set_lock(&mut self, seconds: i32) {
        if seconds > 0 {
            self.lock_until = Some(Utc::now() + Duration::seconds(seconds as i64));
        } else {
            self.lock_until = None;
        }
    }

    /// Sets the secure question lock for the given duration in seconds
    #[allow(dead_code)]
    pub fn set_secure_question_lock(&mut self, seconds: i32) {
        if seconds > 0 {
            self.secure_question_lock_until = Some(Utc::now() + Duration::seconds(seconds as i64));
        } else {
            self.secure_question_lock_until = None;
        }
    }

    /// Returns true if the account is locked
    pub fn is_locked(&self) -> bool {
        self.lock_time_remaining() > 0
    }

    /// Returns true if secure question is locked
    #[allow(dead_code)]
    pub fn is_secure_question_locked(&self) -> bool {
        self.secure_question_lock_time_remaining() > 0
    }
}

/// Pending verification state for verify->modify flow (runtime only, not persisted)
#[derive(Debug, Clone, Default)]
pub struct PendingVerification {
    pub challenge: Vec<u8>,
    pub pending_handler: Vec<u8>,
}

/// Runtime state that is NOT persisted to disk
#[derive(Debug, Default)]
pub struct RuntimeState {
    /// Pending verifications keyed by system type
    pub pending: HashMap<SystemType, PendingVerification>,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a pending verification for the given system type
    pub fn set_pending(&mut self, system_type: SystemType, challenge: Vec<u8>, pending_handler: Vec<u8>) {
        self.pending.insert(system_type, PendingVerification {
            challenge,
            pending_handler,
        });
    }

    /// Get pending verification for the given system type
    pub fn get_pending(&self, system_type: SystemType) -> Option<&PendingVerification> {
        self.pending.get(&system_type)
    }

    /// Take and remove pending verification for the given system type
    pub fn take_pending(&mut self, system_type: SystemType) -> Option<PendingVerification> {
        self.pending.remove(&system_type)
    }
}

/// Storage backend for the cryptoeng stub
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Storage {
    /// Privacy data keyed by system type
    privacy_data: HashMap<i32, PrivacyData>,
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
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(storage) = serde_json::from_str(&content) {
                    info!(path = %path.display(), "Loaded storage");
                    return storage;
                }
            }
        }
        info!(path = %path.display(), "Creating new storage");
        Self::new()
    }

    pub fn save(&self) -> Result<()> {
        let path = PathBuf::from(STORAGE_DIR);
        fs::create_dir_all(&path).map_err(StorageError::CreateDir)?;

        let file_path = path.join("storage.json");
        let content = serde_json::to_string_pretty(self).map_err(StorageError::Serialize)?;
        fs::write(&file_path, content).map_err(StorageError::Write)?;

        Ok(())
    }

    pub fn get_privacy_data(&self, system_type: SystemType) -> Option<&PrivacyData> {
        self.privacy_data.get(&(system_type as i32))
    }

    pub fn get_privacy_data_mut(&mut self, system_type: SystemType) -> &mut PrivacyData {
        self.privacy_data.entry(system_type as i32).or_default()
    }

    pub fn store_secret(&mut self, length: i32, secret: Vec<u8>) {
        self.secrets.insert(length, secret);
    }

    pub fn reset_privacy_data(&mut self, system_type: SystemType) {
        self.privacy_data.remove(&(system_type as i32));
    }
}
