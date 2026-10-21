use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, flock, open, openat, renameat, unlinkat};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::Path,
};
use zeroize::Zeroizing;

use super::{EncryptionKey, Storage, StorageSource, decrypt_legacy};
use crate::error::{Result, StorageError};

#[derive(Debug)]
pub(super) struct StorageFiles {
    directory: File,
    _lock: File,
}

fn trusted_owner(uid: u32) -> bool {
    uid == 0 || uid == rustix::process::geteuid().as_raw()
}

impl StorageFiles {
    pub(super) fn open(path: &Path) -> std::result::Result<Self, StorageError> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o770)
            .create(path)
            .map_err(StorageError::CreateDir)?;
        let directory: File = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)
        .map_err(StorageError::Read)?
        .into();
        let metadata = directory.metadata().map_err(StorageError::Read)?;

        if !trusted_owner(metadata.uid()) || metadata.mode() & 0o002 != 0 {
            return Err(StorageError::Crypto("insecure PMS directory".into()));
        }
        let lock: File = openat(
            &directory,
            "storage.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io::Error::from)
        .map_err(StorageError::Write)?
        .into();
        let metadata = lock.metadata().map_err(StorageError::Read)?;
        if !metadata.is_file() || !trusted_owner(metadata.uid()) || metadata.mode() & 0o002 != 0 {
            return Err(StorageError::Crypto("insecure PMS lock file".into()));
        }
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(io::Error::from)
            .map_err(StorageError::Write)?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }

    fn read(
        &self,
        name: &str,
        secret: bool,
    ) -> std::result::Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        let file = match openat(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => File::from(file),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(StorageError::Read(error.into())),
        };
        let metadata = file.metadata().map_err(StorageError::Read)?;
        let forbidden = if secret { 0o007 } else { 0o002 };
        if !metadata.is_file() || !trusted_owner(metadata.uid()) || metadata.mode() & forbidden != 0
        {
            return Err(StorageError::Crypto("insecure PMS storage file".into()));
        }
        if secret && metadata.len() != 32 {
            return Err(StorageError::Crypto(
                "invalid legacy storage key length".into(),
            ));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        let mut file = file;
        file.read_to_end(&mut bytes).map_err(StorageError::Read)?;
        Ok(Some(bytes))
    }

    pub(super) fn source(&self) -> Result<StorageSource> {
        if let Some(encrypted) = self.read("storage.km", false)? {
            return Ok(StorageSource::Hardware(encrypted));
        }
        let plaintext = if let Some(encrypted) = self.read("storage.dat", false)? {
            let key = self.read("storage.key", true)?.ok_or_else(|| {
                StorageError::Crypto("storage.key missing for legacy encrypted storage".into())
            })?;
            decrypt_legacy(&key, &encrypted)?
        } else if let Some(plaintext) = self.read("storage.json", false)? {
            plaintext
        } else {
            return Ok(StorageSource::Legacy(Storage::new()));
        };

        Ok(StorageSource::Legacy(
            serde_json::from_slice(&plaintext).map_err(StorageError::Deserialize)?,
        ))
    }

    pub(super) fn write(&self, bytes: &[u8]) -> std::result::Result<(), StorageError> {
        let name = format!(".storage-{:032x}.tmp", rand::random::<u128>());
        let mut file: File = openat(
            &self.directory,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io::Error::from)
        .map_err(StorageError::Write)?
        .into();
        let result = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            renameat(&self.directory, &name, &self.directory, "storage.km")
                .map_err(io::Error::from)?;
            self.directory.sync_all()
        })();
        if result.is_err() {
            let _ = unlinkat(&self.directory, &name, AtFlags::empty());
        }
        result.map_err(StorageError::Write)
    }

    pub(super) fn committed(&self) -> std::result::Result<Zeroizing<Vec<u8>>, StorageError> {
        self.directory.sync_all().map_err(StorageError::Write)?;
        self.read("storage.km", false)?
            .ok_or_else(|| StorageError::Crypto("committed PMS storage is missing".into()))
    }

    pub(super) fn commit_migration(&self, cipher: &EncryptionKey, plaintext: &[u8]) -> Result<()> {
        self.write(&cipher.encrypt(plaintext)?)?;
        self.verify_migration(cipher, plaintext)
    }

    pub(super) fn verify_migration(&self, cipher: &EncryptionKey, plaintext: &[u8]) -> Result<()> {
        let saved = self.read("storage.km", false)?.ok_or_else(|| {
            StorageError::Crypto("new storage disappeared during migration".into())
        })?;
        if cipher.decrypt(&saved)?.as_slice() != plaintext {
            return Err(
                StorageError::Crypto("new storage failed migration readback".into()).into(),
            );
        }
        self.cleanup_legacy()?;
        Ok(())
    }

    pub(super) fn cleanup_legacy(&self) -> std::result::Result<(), StorageError> {
        self.directory.sync_all().map_err(StorageError::Write)?;
        for name in ["storage.dat", "storage.json"] {
            self.remove(name)?;
        }
        self.directory.sync_all().map_err(StorageError::Write)?;
        self.remove("storage.key")?;
        self.directory.sync_all().map_err(StorageError::Write)
    }

    fn remove(&self, name: &str) -> std::result::Result<(), StorageError> {
        match unlinkat(&self.directory, name, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(error) => Err(StorageError::Write(error.into())),
        }
    }
}
