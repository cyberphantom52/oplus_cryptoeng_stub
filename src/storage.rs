mod files;
mod keymint;

use files::StorageFiles;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, io, path::Path};
use tracing::info;
use zeroize::Zeroizing;

use crate::{
    PasswordQuality, SystemType,
    error::{Result, StorageError},
    types::parameter::{InfoType, SecureBufferEntry},
};

/// Storage directory for persistent data
pub const STORAGE_DIR: &str = "/data/vendor_de/0/cryptoeng";

/// AES-256-GCM nonce size in bytes (96 bits)
const NONCE_SIZE: usize = 12;

const STORAGE_HEADER: &[u8] = b"CEKM\x00\x00\x00\x01";

/// Stored privacy data for a system type
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrivacyData {
    pub password_type: PasswordQuality,
    pub password_hash: Vec<u8>,
    #[serde(default)]
    pub security_answer_hash: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_records: Vec<SecureBufferEntry>,
    pub email: String,
    pub handler: Vec<u8>,
    pub retry_count: i32,
    pub secure_question_retry_count: i32,
    pub enrolled: bool,
    #[serde(default)]
    pub authorization: Option<PendingVerification>,
    #[serde(default)]
    password_retry: Option<RetryRecord>,
    #[serde(default)]
    question_retry: Option<RetryRecord>,

    /// Timestamp when password lock expires (None = not locked)
    #[serde(default)]
    pub lock_until: Option<DateTime<Utc>>,

    /// Timestamp when secure question lock expires (None = not locked)
    #[serde(default)]
    pub secure_question_lock_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootTimestamp {
    pub boot_id: String,
    pub milliseconds: u64,
}

impl BootTimestamp {
    fn elapsed_since(&self, earlier: &Self) -> Option<u64> {
        (self.boot_id == earlier.boot_id)
            .then(|| self.milliseconds.checked_sub(earlier.milliseconds))
            .flatten()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RetryRecord {
    failures: u32,
    last_failed: Option<BootTimestamp>,
}

impl RetryRecord {
    fn status(&self, now: &BootTimestamp, latest: bool) -> (i32, i32) {
        let delay: u64 = if latest {
            match self.failures {
                5 => 60_000,
                10 => 600_000,
                15 => 1_800_000,
                20.. => 3_600_000,
                _ => 0,
            }
        } else if self.failures > 0 && self.failures.is_multiple_of(5) {
            30_000
        } else {
            0
        };

        let elapsed = self
            .last_failed
            .as_ref()
            .and_then(|previous| now.elapsed_since(previous));
        let remaining = delay.saturating_sub(elapsed.unwrap_or(now.milliseconds));
        let locked = remaining > 0;
        let retries = if latest {
            match self.failures {
                0..=4 => 5 - self.failures,
                5 | 10 | 15 => {
                    if locked {
                        0
                    } else {
                        5
                    }
                }
                6..=9 => 10 - self.failures,
                11..=14 => self.failures ^ 15,
                16..=20 => 20 - self.failures,
                _ => 0,
            }
        } else {
            5u32.saturating_sub(self.failures)
        };
        (
            retries as i32,
            if locked {
                (remaining / 1000 + 1) as i32
            } else {
                0
            },
        )
    }
}

impl PrivacyData {
    pub fn recovery_email(&self) -> Option<Vec<u8>> {
        if self.recovery_records.is_empty() {
            return (!self.email.is_empty()).then(|| self.email.as_bytes().to_vec());
        }
        let first = self
            .recovery_records
            .iter()
            .find(|entry| entry.ty == InfoType::Email as i32)?;
        let mut email = first.payload.to_vec();
        if let Some(continuation) = self
            .recovery_records
            .iter()
            .find(|entry| entry.ty == InfoType::EmailEx1 as i32)
        {
            email.extend_from_slice(&continuation.payload);
        }
        Some(email)
    }

    pub fn modify_recovery_info(&mut self, kind: InfoType, information: &[u8]) -> Result<()> {
        let mut records = self.recovery_records.clone();
        if records.is_empty() {
            if self.security_answer_hash.len() == 32 {
                records.push(recovery_record(
                    InfoType::SecurityQuestion,
                    &self.security_answer_hash,
                ));
            }
            for (index, bytes) in self.email.as_bytes().chunks(32).enumerate() {
                records.push(recovery_record(
                    if index == 0 {
                        InfoType::Email
                    } else {
                        InfoType::EmailEx1
                    },
                    bytes,
                ));
            }
        }
        let slot = |records: &mut Vec<SecureBufferEntry>, kind: InfoType| -> Result<usize> {
            if let Some(index) = records
                .iter()
                .position(|entry| entry.ty == 0 || entry.ty == kind as i32)
            {
                return Ok(index);
            }
            if records.len() == 6 {
                return Err(if kind == InfoType::SecurityQuestion {
                    crate::error::CryptoengError::ParseError("no recovery slot available".into())
                } else {
                    crate::error::CryptoengError::RecoverySlotsFull
                });
            }
            records.push(SecureBufferEntry {
                ty: 0,
                declared_len: 0,
                payload: [0; 32],
            });
            Ok(records.len() - 1)
        };
        let index = slot(&mut records, kind)?;
        records[index] = recovery_record(kind, &information[..information.len().min(32)]);
        if kind == InfoType::Email {
            let continuation = slot(&mut records, InfoType::EmailEx1)?;
            records[continuation] = if information.len() > 32 {
                recovery_record(InfoType::EmailEx1, &information[32..])
            } else {
                SecureBufferEntry {
                    ty: 0,
                    declared_len: 0,
                    payload: [0; 32],
                }
            };
        }
        self.recovery_records = records;
        Ok(())
    }

    pub fn refresh_legacy_retries(&mut self, now: &BootTimestamp) -> bool {
        let password = self.retry(InfoType::Password, now);
        if password.failures >= 5 && password.status(now, false).1 == 0 {
            password.failures %= 5;
            self.retry_count = 5 - password.failures as i32;
            self.question_retry = Some(RetryRecord::default());
            self.secure_question_retry_count = 5;
            self.lock_until = None;
            self.secure_question_lock_until = None;
            true
        } else {
            false
        }
    }

    pub fn retry_status(
        &mut self,
        kind: InfoType,
        now: &BootTimestamp,
        latest: bool,
    ) -> (i32, i32) {
        self.retry(kind, now).status(now, latest)
    }

    pub fn record_failure(&mut self, kind: InfoType, now: &BootTimestamp) -> i32 {
        let record = self.retry(kind, now);
        record.failures = record.failures.saturating_add(1);
        record.last_failed = Some(now.clone());
        let retries_left = record.status(now, true).0;
        if kind == InfoType::Password {
            self.retry_count = retries_left;
        } else {
            self.secure_question_retry_count = retries_left;
        }
        retries_left
    }

    fn retry(&mut self, kind: InfoType, now: &BootTimestamp) -> &mut RetryRecord {
        let (record, retries_left, old_until) = if kind == InfoType::Password {
            (&mut self.password_retry, self.retry_count, self.lock_until)
        } else {
            (
                &mut self.question_retry,
                self.secure_question_retry_count,
                self.secure_question_lock_until,
            )
        };
        record.get_or_insert_with(|| {
            let remaining = old_until
                .map(|until| (until - Utc::now()).num_milliseconds().clamp(0, 30_000) as u64);
            RetryRecord {
                failures: (5i64 - i64::from(retries_left)).clamp(0, 5) as u32,
                last_failed: remaining.map(|remaining| BootTimestamp {
                    boot_id: now.boot_id.clone(),
                    milliseconds: now.milliseconds.saturating_sub(30_000 - remaining),
                }),
            }
        })
    }

    pub fn reset_retries(&mut self) {
        self.password_retry = Some(RetryRecord::default());
        self.question_retry = Some(RetryRecord::default());
        self.retry_count = 5;
        self.secure_question_retry_count = 5;
        self.lock_until = None;
        self.secure_question_lock_until = None;
    }
}

fn recovery_record(kind: InfoType, bytes: &[u8]) -> SecureBufferEntry {
    let mut payload = [0; 32];
    payload[..bytes.len()].copy_from_slice(bytes);
    SecureBufferEntry {
        ty: kind as i32,
        declared_len: bytes.len() as u32,
        payload,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingVerification {
    pub challenge: Vec<u8>,
    pub issued_at: BootTimestamp,
}

#[derive(Debug)]
pub struct RuntimeState {
    boot_id: Option<String>,
}

impl RuntimeState {
    pub fn new() -> Self {
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| {
                value.len() == 36
                    && value.bytes().enumerate().all(|(index, byte)| {
                        if matches!(index, 8 | 13 | 18 | 23) {
                            byte == b'-'
                        } else {
                            byte.is_ascii_hexdigit()
                        }
                    })
            });
        Self { boot_id }
    }

    pub fn now(&self) -> Result<BootTimestamp> {
        let boot_id = self
            .boot_id
            .as_ref()
            .ok_or(crate::CryptoengError::ClockUnavailable)?;
        let time = rustix::time::clock_gettime_dynamic(rustix::time::DynamicClockId::Boottime)
            .map_err(|_| crate::CryptoengError::ClockUnavailable)?;
        let seconds =
            u64::try_from(time.tv_sec).map_err(|_| crate::CryptoengError::ClockUnavailable)?;
        let nanoseconds =
            u64::try_from(time.tv_nsec).map_err(|_| crate::CryptoengError::ClockUnavailable)?;
        let milliseconds = seconds
            .checked_mul(1000)
            .and_then(|value| value.checked_add(nanoseconds / 1_000_000))
            .ok_or(crate::CryptoengError::ClockUnavailable)?;
        Ok(BootTimestamp {
            boot_id: boot_id.clone(),
            milliseconds,
        })
    }
}

impl PendingVerification {
    pub fn is_expired(&self, now: &BootTimestamp, lifetime_ms: u64) -> bool {
        now.elapsed_since(&self.issued_at)
            .is_none_or(|elapsed| elapsed >= lifetime_ms)
    }
}

fn decrypt_legacy(
    key: &[u8],
    encrypted: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, StorageError> {
    if encrypted.len() < NONCE_SIZE + 16 {
        return Err(StorageError::Crypto(
            "legacy encrypted data is truncated".into(),
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| StorageError::Crypto("invalid legacy storage key length".into()))?;
    cipher
        .decrypt(
            Nonce::from_slice(&encrypted[..NONCE_SIZE]),
            &encrypted[NONCE_SIZE..],
        )
        .map(Zeroizing::new)
        .map_err(|_| StorageError::Crypto("legacy storage authentication failed".into()))
}

#[derive(Debug)]
enum EncryptionKey {
    Hardware(keymint::StorageCipher),
}

impl EncryptionKey {
    fn encrypt(&self, plaintext: &[u8]) -> std::result::Result<Vec<u8>, StorageError> {
        let encrypted = match self {
            Self::Hardware(cipher) => cipher.encrypt(plaintext)?,
        };
        let mut output = STORAGE_HEADER.to_vec();
        output.extend(encrypted);
        Ok(output)
    }

    fn decrypt(&self, envelope: &[u8]) -> std::result::Result<Zeroizing<Vec<u8>>, StorageError> {
        if !envelope.starts_with(STORAGE_HEADER)
            || envelope.len() < STORAGE_HEADER.len() + NONCE_SIZE + 16
        {
            return Err(StorageError::Crypto(
                "invalid hardware storage envelope".into(),
            ));
        }
        let encrypted = &envelope[STORAGE_HEADER.len()..];
        match self {
            Self::Hardware(cipher) => Ok(cipher.decrypt(encrypted)?),
        }
    }
}

enum StorageSource {
    Hardware(Zeroizing<Vec<u8>>),
    Legacy(Storage),
}

#[derive(Debug, Default)]
enum PersistenceState {
    #[default]
    Ready,
    PendingInitialization,
    Failed,
}

/// Storage backend for the cryptoeng stub — encrypted at rest with AES-256-GCM
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Storage {
    /// Privacy data keyed by system type
    privacy_data: HashMap<i32, PrivacyData>,

    /// Secrets stored by writeSecret command
    secrets: HashMap<i32, Vec<u8>>,
    #[serde(skip)]
    encryption_key: Option<EncryptionKey>,
    #[serde(skip)]
    files: Option<StorageFiles>,

    #[serde(skip)]
    persistence: PersistenceState,
}

impl Storage {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn unavailable() -> Self {
        Self {
            persistence: PersistenceState::PendingInitialization,
            ..Self::default()
        }
    }

    pub fn load() -> Result<Self> {
        if rustix::process::geteuid().as_raw() != crate::keystore::SERVICE_UID {
            return Err(StorageError::from(crate::keystore::KeyMintError::WrongUid).into());
        }
        let files = StorageFiles::open(Path::new(STORAGE_DIR))?;
        let source = files.source()?;
        let create = matches!(&source, StorageSource::Legacy(_));
        let cipher = EncryptionKey::Hardware(
            keymint::StorageCipher::load(create).map_err(StorageError::from)?,
        );
        Self::load_source(files, source, cipher)
    }

    fn load_source(
        files: StorageFiles,
        source: StorageSource,
        cipher: EncryptionKey,
    ) -> Result<Self> {
        let mut storage = match source {
            StorageSource::Hardware(encrypted) => {
                let storage = Self::decode(cipher, &encrypted)?;
                files.cleanup_legacy()?;
                info!("Loaded hardware-encrypted PMS storage");
                storage
            }
            StorageSource::Legacy(mut storage) => {
                let plaintext = Zeroizing::new(
                    serde_json::to_vec_pretty(&storage).map_err(StorageError::Serialize)?,
                );
                files.commit_migration(&cipher, &plaintext)?;
                storage.encryption_key = Some(cipher);
                info!("Committed hardware-encrypted PMS storage");
                storage
            }
        };
        storage.files = Some(files);
        Ok(storage)
    }

    pub fn save(&mut self) -> Result<()> {
        self.ensure_available()?;

        self.persistence = PersistenceState::Failed;
        let result = self.save_inner();
        if result.is_ok() {
            self.persistence = PersistenceState::Ready;
        }
        result
    }

    pub(crate) fn initialize_if_needed(&mut self) -> Result<()> {
        if matches!(self.persistence, PersistenceState::PendingInitialization) {
            *self = Self::load()?;
        } else if matches!(self.persistence, PersistenceState::Failed) {
            let encrypted = self
                .files
                .as_ref()
                .ok_or_else(|| StorageError::Crypto("storage is not initialized".into()))?
                .committed()?;
            let plaintext = self
                .encryption_key
                .as_ref()
                .ok_or_else(|| StorageError::Crypto("storage key is unavailable".into()))?
                .decrypt(&encrypted)?;
            let committed: Self =
                serde_json::from_slice(&plaintext).map_err(StorageError::Deserialize)?;
            self.privacy_data = committed.privacy_data;
            self.secrets = committed.secrets;
            self.persistence = PersistenceState::Ready;
        }
        Ok(())
    }

    pub fn ensure_available(&self) -> Result<()> {
        match self.persistence {
            PersistenceState::Ready => Ok(()),
            PersistenceState::PendingInitialization => Err(StorageError::Write(io::Error::other(
                "storage initialization is pending",
            ))
            .into()),
            PersistenceState::Failed => Err(StorageError::Write(io::Error::other(
                "storage unavailable until committed state can be recovered",
            ))
            .into()),
        }
    }

    fn save_inner(&self) -> Result<()> {
        let encrypted = self.encode()?;
        self.files
            .as_ref()
            .ok_or_else(|| StorageError::Crypto("storage is not initialized".into()))?
            .write(&encrypted)?;
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let json =
            Zeroizing::new(serde_json::to_vec_pretty(self).map_err(StorageError::Serialize)?);
        Ok(self
            .encryption_key
            .as_ref()
            .ok_or_else(|| StorageError::Crypto("storage key is unavailable".into()))?
            .encrypt(&json)?)
    }

    fn decode(key: EncryptionKey, encrypted: &[u8]) -> Result<Self> {
        let plaintext = key.decrypt(encrypted)?;
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
