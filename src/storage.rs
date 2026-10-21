use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use tracing::info;

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
    #[serde(default)]
    pub security_answer_hash: Vec<u8>,
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
    pub fn reset_retries(&mut self) {
        self.retry_count = 5;
        self.secure_question_retry_count = 5;
        self.lock_until = None;
        self.secure_question_lock_until = None;
    }

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
    match fs::read(&key_path) {
        Ok(key_bytes) => {
            if key_bytes.len() != KEY_SIZE {
                return Err(StorageError::Crypto("invalid storage key length".into()));
            }
            Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fs::read(Path::new(STORAGE_DIR).join("storage.dat")) {
                Ok(_) => {
                    return Err(StorageError::Crypto(
                        "storage.key missing for existing encrypted storage".into(),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(StorageError::Read(error)),
            }
            info!(path = %key_path.display(), "Generating new storage encryption key");
            generate_and_save_key(&key_path)
        }
        Err(error) => Err(StorageError::Read(error)),
    }
}

fn generate_and_save_key(path: &Path) -> std::result::Result<Key<Aes256Gcm>, StorageError> {
    let key_bytes = generate_random_bytes(KEY_SIZE);
    fs::create_dir_all(STORAGE_DIR).map_err(StorageError::CreateDir)?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(StorageError::Write)?;
    file.write_all(&key_bytes).map_err(StorageError::Write)?;
    file.sync_all().map_err(StorageError::Write)?;
    File::open(STORAGE_DIR)
        .and_then(|directory| directory.sync_all())
        .map_err(StorageError::Write)?;
    Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::other("storage path has no parent"))?;
    let temporary_path = directory.join(format!(".storage-{:032x}.tmp", rand::random::<u128>()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary_path)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary_path, path)?;
        File::open(directory)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
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

    #[serde(skip)]
    persistence_failed: bool,
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

    pub fn load() -> Result<Self> {
        let key = load_or_create_key()?;

        // Try encrypted format first (storage.dat)
        let dat_path = PathBuf::from(STORAGE_DIR).join("storage.dat");
        match fs::read(&dat_path) {
            Ok(encrypted) => {
                let storage = Self::decode(key, &encrypted)?;
                info!(path = %dat_path.display(), "Loaded encrypted storage");
                return Ok(storage);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(StorageError::Read(error).into()),
        }

        // Migrate from legacy plaintext format (storage.json)
        let json_path = PathBuf::from(STORAGE_DIR).join("storage.json");
        match fs::read(&json_path) {
            Ok(content) => {
                let mut storage: Self =
                    serde_json::from_slice(&content).map_err(StorageError::Deserialize)?;
                storage.encryption_key = Some(key);
                info!("Migrating plaintext storage.json → encrypted storage.dat");
                storage.save()?;
                fs::remove_file(&json_path).map_err(StorageError::Write)?;
                File::open(STORAGE_DIR)
                    .and_then(|directory| directory.sync_all())
                    .map_err(StorageError::Write)?;
                return Ok(storage);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(StorageError::Read(error).into()),
        }

        info!("Creating new encrypted storage");
        let mut storage = Self::new();
        storage.encryption_key = Some(key);
        Ok(storage)
    }

    pub fn save(&mut self) -> Result<()> {
        self.ensure_available()?;

        self.persistence_failed = true;
        let result = self.save_inner();
        if result.is_ok() {
            self.persistence_failed = false;
        }
        result
    }

    pub fn ensure_available(&self) -> Result<()> {
        if self.persistence_failed {
            return Err(StorageError::Write(io::Error::other(
                "storage unavailable after failed save; restart required",
            ))
            .into());
        }
        Ok(())
    }

    fn save_inner(&mut self) -> Result<()> {
        let dir = PathBuf::from(STORAGE_DIR);
        fs::create_dir_all(&dir).map_err(StorageError::CreateDir)?;

        let encrypted = self.encode()?;

        let file_path = dir.join("storage.dat");
        atomic_write(&file_path, &encrypted).map_err(StorageError::Write)?;

        Ok(())
    }

    fn encode(&mut self) -> Result<Vec<u8>> {
        let json = serde_json::to_vec_pretty(&*self).map_err(StorageError::Serialize)?;
        Ok(encrypt_data(self.key()?, &json)?)
    }

    fn decode(key: Key<Aes256Gcm>, encrypted: &[u8]) -> Result<Self> {
        let plaintext = decrypt_data(&key, encrypted)?;
        let mut storage: Self =
            serde_json::from_slice(&plaintext).map_err(StorageError::Deserialize)?;
        storage.encryption_key = Some(key);
        Ok(storage)
    }

    pub fn get_privacy_data(&self, system_type: SystemType) -> Option<&PrivacyData> {
        self.privacy_data.get(&(system_type as i32))
    }

    pub fn get_privacy_data_mut(&mut self, system_type: SystemType) -> &mut PrivacyData {
        self.privacy_data.entry(system_type as i32).or_default()
    }

    pub fn reset_privacy_data(&mut self, system_type: SystemType) {
        self.privacy_data.remove(&(system_type as i32));
    }
}
