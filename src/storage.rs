use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::PathBuf};
use tracing::{info, warn};

use crate::{
    PasswordQuality, SystemType,
    error::{Result, StorageError},
    utils::generate_random_bytes,
};

/// Storage directory for persistent data
pub const STORAGE_DIR: &str = "/data/vendor_de/0/cryptoeng";

/// AES-256-GCM nonce size in bytes (96 bits)
const NONCE_SIZE: usize = 12;
/// AES-256 key size in bytes (256 bits)
const KEY_SIZE: usize = 32;

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
    pub fn set_pending(
        &mut self,
        system_type: SystemType,
        challenge: Vec<u8>,
        pending_handler: Vec<u8>,
    ) {
        self.pending.insert(
            system_type,
            PendingVerification {
                challenge,
                pending_handler,
            },
        );
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

/// Encryption key manager — loads or generates the AES-256 key
fn load_or_create_key() -> std::result::Result<Key<Aes256Gcm>, StorageError> {
    let key_path = PathBuf::from(STORAGE_DIR).join("storage.key");

    if key_path.exists() {
        let key_bytes = fs::read(&key_path).map_err(StorageError::Read)?;
        if key_bytes.len() != KEY_SIZE {
            warn!("Corrupt storage key (wrong size), regenerating");
            let key = generate_and_save_key(&key_path)?;
            return Ok(key);
        }
        Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
    } else {
        info!(path = %key_path.display(), "Generating new storage encryption key");
        let key = generate_and_save_key(&key_path)?;
        Ok(key)
    }
}

fn generate_and_save_key(path: &PathBuf) -> std::result::Result<Key<Aes256Gcm>, StorageError> {
    let key_bytes = generate_random_bytes(KEY_SIZE);
    fs::create_dir_all(STORAGE_DIR).map_err(StorageError::CreateDir)?;
    fs::write(path, &key_bytes).map_err(StorageError::Write)?;
    Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
}

pub fn encrypt_data(
    key: &Key<Aes256Gcm>,
    plaintext: &[u8],
) -> std::result::Result<Vec<u8>, StorageError> {
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = generate_random_bytes(NONCE_SIZE);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| StorageError::Crypto(format!("encryption failed: {e}")))?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend(ciphertext);
    Ok(output)
}

pub fn decrypt_data(
    key: &Key<Aes256Gcm>,
    data: &[u8],
) -> std::result::Result<Vec<u8>, StorageError> {
    if data.len() < NONCE_SIZE {
        return Err(StorageError::Crypto(
            "encrypted data too short for nonce".into(),
        ));
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| StorageError::Crypto(format!("decryption failed: {e}")))
}

/// Storage backend for the cryptoeng stub — encrypted at rest with AES-256-GCM
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Storage {
    /// Privacy data keyed by system type
    privacy_data: HashMap<i32, PrivacyData>,
    /// Secrets stored by writeSecret command
    secrets: HashMap<i32, Vec<u8>>,
    /// Encryption key (not serialized — loaded separately)
    #[serde(skip)]
    encryption_key: Option<Key<Aes256Gcm>>,
}

impl Storage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the encryption key, loading/creating it if needed
    pub fn key(&mut self) -> std::result::Result<&Key<Aes256Gcm>, StorageError> {
        if self.encryption_key.is_none() {
            self.encryption_key = Some(load_or_create_key()?);
        }
        Ok(self.encryption_key.as_ref().unwrap())
    }

    pub fn load() -> Self {
        let key = match load_or_create_key() {
            Ok(k) => k,
            Err(e) => {
                warn!(error = %e, "Failed to load encryption key, starting fresh");
                return Self::new();
            }
        };

        // Try encrypted format first (storage.dat)
        let dat_path = PathBuf::from(STORAGE_DIR).join("storage.dat");
        if dat_path.exists() {
            if let Ok(encrypted) = fs::read(&dat_path) {
                match decrypt_data(&key, &encrypted) {
                    Ok(plaintext) => {
                        if let Ok(mut storage) = serde_json::from_slice::<Storage>(&plaintext) {
                            storage.encryption_key = Some(key);
                            info!(path = %dat_path.display(), "Loaded encrypted storage");
                            return storage;
                        }
                    }
                    Err(e) => warn!(error = %e, "Failed to decrypt storage.dat"),
                }
            }
        }

        // Migrate from legacy plaintext format (storage.json)
        let json_path = PathBuf::from(STORAGE_DIR).join("storage.json");
        if json_path.exists() {
            if let Ok(content) = fs::read_to_string(&json_path) {
                if let Ok(mut storage) = serde_json::from_str::<Storage>(&content) {
                    storage.encryption_key = Some(key);
                    info!("Migrating plaintext storage.json → encrypted storage.dat");
                    if let Err(e) = storage.save() {
                        warn!(error = %e, "Failed to save migrated storage");
                    }
                    // Remove old plaintext file after successful migration
                    let _ = fs::remove_file(&json_path);
                    return storage;
                }
            }
        }

        info!("Creating new encrypted storage");
        let mut storage = Self::new();
        storage.encryption_key = Some(key);
        storage
    }

    pub fn save(&mut self) -> Result<()> {
        let dir = PathBuf::from(STORAGE_DIR);
        fs::create_dir_all(&dir).map_err(StorageError::CreateDir)?;

        // Serialize first (immutable borrow), then get key (mutable borrow)
        let json = serde_json::to_string_pretty(&*self).map_err(StorageError::Serialize)?;
        let key = self.key()?;
        let encrypted = encrypt_data(key, json.as_bytes())?;

        let file_path = dir.join("storage.dat");
        fs::write(&file_path, encrypted).map_err(StorageError::Write)?;

        Ok(())
    }

    /// Encrypt arbitrary data using the storage key
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = self.key()?;
        Ok(encrypt_data(key, plaintext)?)
    }

    /// Decrypt arbitrary data using the storage key
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.key()?;
        Ok(decrypt_data(key, data)?)
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
