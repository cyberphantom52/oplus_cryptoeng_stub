use std::fmt;

use rsbinder::Strong;
use zeroize::Zeroizing;

use crate::{
    android::{
        hardware::security::keymint::{
            Algorithm::Algorithm, BlockMode::BlockMode, KeyOrigin::KeyOrigin,
            KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue,
            KeyPurpose::KeyPurpose, PaddingMode::PaddingMode, SecurityLevel::SecurityLevel,
            Tag::Tag,
        },
        system::keystore2::{
            Domain::Domain, IKeystoreOperation::IKeystoreOperation, KeyDescriptor::KeyDescriptor,
            KeyMetadata::KeyMetadata, KeyParameters::KeyParameters,
        },
    },
    keystore::{KeyMintError, connect, key_not_found, parameter},
};

const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const CHUNK_LENGTH: usize = 32 * 1024;

pub(super) struct StorageCipher {
    descriptor: KeyDescriptor,
}

impl fmt::Debug for StorageCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageCipher")
            .finish_non_exhaustive()
    }
}

impl StorageCipher {
    pub(super) fn load(create_if_missing: bool) -> Result<Self, KeyMintError> {
        let service = connect()?;
        let alias = KeyDescriptor {
            domain: Domain::APP,
            alias: Some("cryptoeng.pms.storage".into()),
            ..Default::default()
        };
        match service.getKeyEntry(&alias) {
            Ok(entry) => Self::from_metadata(&entry.metadata),
            Err(error) if create_if_missing && key_not_found(&error) => {
                let hardware = service.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)?;
                let metadata =
                    hardware.generateKey(&alias, None, &generation_parameters(), 0, &[])?;
                let cipher = Self::from_metadata(&metadata);
                if cipher.is_err()
                    && metadata.key.domain == Domain::KEY_ID
                    && let Err(error) = service.deleteKey(&metadata.key)
                {
                    tracing::error!(%error, "failed to remove unusable new PMS key");
                }
                cipher
            }
            Err(error) => Err(error.into()),
        }
    }

    fn from_metadata(metadata: &KeyMetadata) -> Result<Self, KeyMintError> {
        validate_authorizations(metadata)?;
        Ok(Self {
            descriptor: metadata.key.clone(),
        })
    }

    pub(super) fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, KeyMintError> {
        let expected = plaintext
            .len()
            .checked_add(TAG_LENGTH)
            .ok_or(KeyMintError::InvalidCiphertext)?;
        let (operation, nonce) = self.begin(KeyPurpose::ENCRYPT, None)?;
        let ciphertext = operation.process(plaintext, expected)?;
        let mut output = nonce;
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    pub(super) fn decrypt(&self, encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeyMintError> {
        if encrypted.len() < NONCE_LENGTH + TAG_LENGTH {
            return Err(KeyMintError::InvalidCiphertext);
        }
        let (nonce, ciphertext) = encrypted.split_at(NONCE_LENGTH);
        let (operation, _) = self.begin(KeyPurpose::DECRYPT, Some(nonce))?;
        operation.process(ciphertext, ciphertext.len() - TAG_LENGTH)
    }

    fn begin(
        &self,
        purpose: KeyPurpose,
        nonce: Option<&[u8]>,
    ) -> Result<(Operation, Vec<u8>), KeyMintError> {
        let entry = connect()?.getKeyEntry(&self.descriptor)?;
        validate_authorizations(&entry.metadata)?;
        if entry.metadata.key != self.descriptor {
            return Err(KeyMintError::InvalidMetadata);
        }
        let hardware = entry.iSecurityLevel.ok_or(KeyMintError::InvalidMetadata)?;
        let mut params = vec![
            parameter(Tag::PURPOSE, KeyParameterValue::KeyPurpose(purpose)),
            parameter(
                Tag::BLOCK_MODE,
                KeyParameterValue::BlockMode(BlockMode::GCM),
            ),
            parameter(
                Tag::PADDING,
                KeyParameterValue::PaddingMode(PaddingMode::NONE),
            ),
            parameter(Tag::MAC_LENGTH, KeyParameterValue::Integer(128)),
        ];
        if let Some(nonce) = nonce {
            params.push(parameter(
                Tag::NONCE,
                KeyParameterValue::Blob(nonce.to_vec()),
            ));
        }
        let response = hardware.createOperation(&self.descriptor, &params, false)?;
        let operation = Operation {
            handle: response.iOperation.ok_or(KeyMintError::InvalidMetadata)?,
            finished: false,
        };
        if response.operationChallenge.is_some() || response.upgradedBlob.is_some() {
            return Err(KeyMintError::InvalidMetadata);
        }
        let nonce = operation_nonce(response.parameters.as_ref(), nonce)?;
        operation.handle.updateAad(super::STORAGE_HEADER)?;
        Ok((operation, nonce))
    }
}

struct Operation {
    handle: Strong<dyn IKeystoreOperation>,
    finished: bool,
}

impl Operation {
    fn process(
        mut self,
        input: &[u8],
        expected_length: usize,
    ) -> Result<Zeroizing<Vec<u8>>, KeyMintError> {
        let mut output = Zeroizing::new(Vec::with_capacity(expected_length));
        for chunk in input.chunks(CHUNK_LENGTH) {
            if let Some(bytes) = self.handle.update(chunk)? {
                append_output(&mut output, Zeroizing::new(bytes), expected_length)?;
            }
        }
        let final_bytes = self.handle.finish(None, None)?;
        self.finished = true;
        if let Some(bytes) = final_bytes {
            append_output(&mut output, Zeroizing::new(bytes), expected_length)?;
        }
        if output.len() != expected_length {
            return Err(KeyMintError::InvalidCiphertext);
        }
        Ok(output)
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.handle.abort();
        }
    }
}

fn append_output(
    output: &mut Vec<u8>,
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
) -> Result<(), KeyMintError> {
    if bytes.len() > limit.saturating_sub(output.len()) {
        return Err(KeyMintError::InvalidCiphertext);
    }
    output.extend_from_slice(&bytes);
    Ok(())
}

fn operation_nonce(
    parameters: Option<&KeyParameters>,
    supplied: Option<&[u8]>,
) -> Result<Vec<u8>, KeyMintError> {
    if supplied.is_some_and(|nonce| nonce.len() != NONCE_LENGTH) {
        return Err(KeyMintError::InvalidCiphertext);
    }
    let mut nonces = parameters
        .into_iter()
        .flat_map(|parameters| &parameters.keyParameter)
        .filter(|parameter| parameter.tag == Tag::NONCE);
    let nonce = match nonces.next() {
        Some(KeyParameter {
            value: KeyParameterValue::Blob(bytes),
            ..
        }) if bytes.len() == NONCE_LENGTH => bytes.as_slice(),
        Some(_) => return Err(KeyMintError::InvalidCiphertext),
        None => {
            return supplied
                .map(<[u8]>::to_vec)
                .ok_or(KeyMintError::InvalidCiphertext);
        }
    };
    if nonces.next().is_some() || supplied.is_some_and(|supplied| supplied != nonce) {
        return Err(KeyMintError::InvalidCiphertext);
    }
    Ok(nonce.to_vec())
}

fn generation_parameters() -> [KeyParameter; 8] {
    [
        parameter(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::AES)),
        parameter(Tag::KEY_SIZE, KeyParameterValue::Integer(256)),
        parameter(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
        ),
        parameter(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT),
        ),
        parameter(
            Tag::BLOCK_MODE,
            KeyParameterValue::BlockMode(BlockMode::GCM),
        ),
        parameter(
            Tag::PADDING,
            KeyParameterValue::PaddingMode(PaddingMode::NONE),
        ),
        parameter(Tag::MIN_MAC_LENGTH, KeyParameterValue::Integer(128)),
        parameter(Tag::NO_AUTH_REQUIRED, KeyParameterValue::BoolValue(true)),
    ]
}

fn validate_authorizations(metadata: &KeyMetadata) -> Result<(), KeyMintError> {
    let level = metadata.keySecurityLevel;
    if !matches!(
        level,
        SecurityLevel::TRUSTED_ENVIRONMENT | SecurityLevel::STRONGBOX
    ) || metadata.key.domain != Domain::KEY_ID
        || metadata.key.alias.is_some()
        || metadata.key.blob.is_some()
    {
        return Err(KeyMintError::InvalidMetadata);
    }
    let mut required = generation_parameters().to_vec();
    required.push(parameter(
        Tag::ORIGIN,
        KeyParameterValue::Origin(KeyOrigin::GENERATED),
    ));
    if !required.iter().all(|wanted| {
        metadata.authorizations.iter().any(|authorization| {
            authorization.securityLevel == level && authorization.keyParameter == *wanted
        })
    }) {
        return Err(KeyMintError::InvalidMetadata);
    }
    if metadata.authorizations.iter().any(|authorization| {
        let parameter = &authorization.keyParameter;
        match parameter.tag {
            Tag::PURPOSE => !matches!(
                parameter.value,
                KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT | KeyPurpose::DECRYPT)
            ),
            Tag::BLOCK_MODE => parameter.value != KeyParameterValue::BlockMode(BlockMode::GCM),
            Tag::PADDING => parameter.value != KeyParameterValue::PaddingMode(PaddingMode::NONE),
            Tag::ALGORITHM => parameter.value != KeyParameterValue::Algorithm(Algorithm::AES),
            Tag::KEY_SIZE => parameter.value != KeyParameterValue::Integer(256),
            Tag::MIN_MAC_LENGTH => parameter.value != KeyParameterValue::Integer(128),
            Tag::ORIGIN => parameter.value != KeyParameterValue::Origin(KeyOrigin::GENERATED),
            Tag::NO_AUTH_REQUIRED => parameter.value != KeyParameterValue::BoolValue(true),
            Tag::CALLER_NONCE
            | Tag::USER_SECURE_ID
            | Tag::USER_AUTH_TYPE
            | Tag::AUTH_TIMEOUT
            | Tag::TRUSTED_USER_PRESENCE_REQUIRED
            | Tag::TRUSTED_CONFIRMATION_REQUIRED
            | Tag::UNLOCKED_DEVICE_REQUIRED => true,
            _ => false,
        }
    }) {
        return Err(KeyMintError::InvalidMetadata);
    }
    Ok(())
}
