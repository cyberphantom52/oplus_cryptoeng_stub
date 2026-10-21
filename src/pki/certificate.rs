use rsa::signature::{Keypair, RandomizedSigner, rand_core::TryCryptoRng};

use sha1::{Digest, Sha1};

use x509_cert::{
    SubjectPublicKeyInfo, TbsCertificate,
    builder::{Builder, CertificateBuilder, profile::BuilderProfile},
    der::{
        self, Decode, Encode, EncodePem, Tag,
        asn1::{Any, BitString, OctetString, Uint},
        pem::LineEnding,
    },
    ext::Extension,
    name::Name,
    serial_number::SerialNumber,
    spki::{
        self, AlgorithmIdentifierOwned, DecodePublicKey, DynSignatureAlgorithmIdentifier,
        EncodePublicKey, ObjectIdentifier, SignatureBitStringEncoding, SubjectPublicKeyInfoRef,
    },
    time::{Time, Validity},
};

use super::credentials::{CertificateError, Issuer, IssuerKey};

const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");
const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const ATTESTATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.25");

const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

impl Issuer {
    pub(super) fn self_signed(
        key: IssuerKey,
        subject: Name,
        not_before: Time,
        not_after: Time,
    ) -> Result<Self, CertificateError> {
        let public_der = key
            .public_der()
            .map_err(|_| CertificateError::InvalidIssuer)?;
        let public_key = SubjectPublicKeyInfo::from_der(public_der.as_bytes())
            .map_err(|_| CertificateError::InvalidIssuer)?;
        let subject_id = Sha1::digest(public_key.subject_public_key.raw_bytes());
        let extensions = (|| {
            Ok::<_, der::Error>(vec![
                extension(BASIC_CONSTRAINTS, true, &[0x30, 0x03, 0x01, 0x01, 0xff])?,
                extension(KEY_USAGE, true, &[0x03, 0x02, 0x02, 0x04])?,
                extension(
                    SUBJECT_KEY_IDENTIFIER,
                    false,
                    &OctetString::new(subject_id.as_slice())?.to_der()?,
                )?,
            ])
        })()
        .map_err(|_| CertificateError::Encoding)?;
        let profile = CertificateProfile {
            issuer: subject.clone(),
            subject,
            extensions,
        };
        let certificate = CertificateBuilder::new(
            profile,
            SerialNumber::from(1u32),
            Validity::new(not_before, not_after),
            public_key,
        )
        .map_err(|_| CertificateError::Encoding)?
        .build_with_rng::<_, CertificateSignature, _>(&key, &mut rand::rng())
        .map_err(|_| CertificateError::Signing)?;
        let certificate_pem = certificate
            .to_pem(LineEnding::LF)
            .map_err(|_| CertificateError::Encoding)?;
        Ok(Self {
            key,
            certificate,
            certificate_pem,
        })
    }

    pub(super) fn issue_parsed(
        &self,
        app_public_pem: &str,
        public_key: SubjectPublicKeyInfo,
        subject: &Name,
        validity: [Any; 2],
        extension_cbor: &[u8],
    ) -> Result<(String, String), CertificateError> {
        let issuer_public_der = self
            .key
            .public_der()
            .map_err(|_| CertificateError::InvalidIssuer)?;
        let issuer_public_key = SubjectPublicKeyInfo::from_der(issuer_public_der.as_bytes())
            .map_err(|_| CertificateError::InvalidIssuer)?;
        let serial = donor_serial(app_public_pem).map_err(|_| CertificateError::Encoding)?;
        let extensions = donor_extensions(&public_key, &issuer_public_key, extension_cbor)
            .map_err(|_| CertificateError::Encoding)?;
        let encode = || -> der::Result<Vec<u8>> {
            let signature_algorithm = self
                .key
                .signature_algorithm_identifier()
                .map_err(|_| der::Error::from(der::ErrorKind::Failed))?;

            let tbs = vec![
                Any::new(
                    Tag::ContextSpecific {
                        constructed: true,
                        number: der::TagNumber(0),
                    },
                    vec![2, 1, 2],
                )?,
                Any::encode_from(&serial)?,
                Any::encode_from(&signature_algorithm)?,
                Any::encode_from(self.certificate.tbs_certificate().subject())?,
                Any::encode_from(&Vec::from(validity))?,
                Any::encode_from(subject)?,
                Any::encode_from(&public_key)?,
                Any::new(
                    Tag::ContextSpecific {
                        constructed: true,
                        number: der::TagNumber(3),
                    },
                    extensions.to_der()?,
                )?,
            ];
            let body = tbs.to_der()?;
            let signature: CertificateSignature = self
                .key
                .try_sign_with_rng(&mut rand::rng(), &body)
                .map_err(|_| der::Error::from(der::ErrorKind::Failed))?;
            vec![
                Any::encode_from(&tbs)?,
                Any::encode_from(&signature_algorithm)?,
                Any::encode_from(&signature.to_bitstring()?)?,
            ]
            .to_der()
        };
        let certificate = encode().map_err(|_| CertificateError::Signing)?;
        let pem = der::pem::encode_string("CERTIFICATE", LineEnding::LF, &certificate)
            .map_err(|_| CertificateError::Encoding)?;
        if pem.len() >= 0xc00 {
            return Err(CertificateError::Encoding);
        }
        Ok((self.certificate_pem.clone(), pem))
    }
}

pub(crate) fn parse_public_key(pem: &str) -> Result<SubjectPublicKeyInfo, CertificateError> {
    use rsa::pkcs1::DecodeRsaPublicKey;

    let mut decoder = der::pem::Decoder::new_detect_wrap(pem.as_bytes())
        .map_err(|_| CertificateError::InvalidPublicKey)?;
    let mut decoded = Vec::new();
    decoder
        .decode_to_end(&mut decoded)
        .map_err(|_| CertificateError::InvalidPublicKey)?;
    let normalized = der::pem::encode_string(decoder.type_label(), LineEnding::LF, &decoded)
        .map_err(|_| CertificateError::InvalidPublicKey)?;
    let pem = normalized.as_str();

    if !matches!(decoder.type_label(), "PUBLIC KEY" | "RSA PUBLIC KEY") {
        return Err(CertificateError::InvalidPublicKey);
    }
    super::key_parse::validate_der(&decoded, decoder.type_label() == "RSA PUBLIC KEY")
        .map_err(CertificateError::PublicKeyParsing)?;

    let decoded_spki = SubjectPublicKeyInfo::from_der(&decoded).ok();
    if let Some(key) = &decoded_spki
        && key.algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")
    {
        super::public_key::point_format(key).map_err(CertificateError::PublicKeyParsing)?;
    }

    if decoder.type_label() == "PUBLIC KEY"
        && let Ok(key) = SubjectPublicKeyInfo::from_der(&decoded)
        && super::public_key::validate(&key)
    {
        return Ok(key);
    }

    let public_der = if let Ok(key) = rsa::RsaPublicKey::from_public_key_pem(pem) {
        key.to_public_key_der()
    } else if let Ok(key) = rsa::RsaPublicKey::from_pkcs1_pem(pem) {
        key.to_public_key_der()
    } else if let Ok(key) = p224::PublicKey::from_public_key_pem(pem) {
        key.to_public_key_der()
    } else if let Ok(key) = p256::PublicKey::from_public_key_pem(pem) {
        key.to_public_key_der()
    } else if let Ok(key) = p384::PublicKey::from_public_key_pem(pem) {
        key.to_public_key_der()
    } else if let Ok(key) = p521::PublicKey::from_public_key_pem(pem) {
        key.to_public_key_der()
    } else {
        let status = if decoder.type_label() == "RSA PUBLIC KEY"
            || decoded_spki.as_ref().is_some_and(|key| {
                key.algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")
            }) {
            super::key_parse::INVALID_RSA
        } else {
            -0x4c80
        };
        return Err(CertificateError::PublicKeyParsing(status));
    }
    .map_err(|_| CertificateError::InvalidPublicKey)?;
    SubjectPublicKeyInfo::from_der(public_der.as_bytes())
        .map_err(|_| CertificateError::InvalidPublicKey)
}

fn donor_serial(public_pem: &str) -> der::Result<SerialNumber> {
    let digest = Sha1::new()
        .chain_update(public_pem.as_bytes())
        .chain_update([0])
        .finalize();

    SerialNumber::from_der(&Uint::new(&digest)?.to_der()?)
}

fn extension(oid: ObjectIdentifier, critical: bool, value: &[u8]) -> der::Result<Extension> {
    Ok(Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value)?,
    })
}

fn donor_extensions(
    subject: &SubjectPublicKeyInfo,
    issuer: &SubjectPublicKeyInfo,
    cbor: &[u8],
) -> der::Result<Vec<Extension>> {
    let subject_id = Sha1::digest(subject.subject_public_key.raw_bytes());
    let issuer_id = Sha1::digest(issuer.subject_public_key.raw_bytes());
    let mut authority_id = vec![0x30, 0x16, 0x80, 0x14];
    authority_id.extend_from_slice(&issuer_id);
    Ok(vec![
        extension(BASIC_CONSTRAINTS, false, &[0x30, 0])?,
        extension(
            SUBJECT_KEY_IDENTIFIER,
            false,
            &OctetString::new(subject_id.as_slice())?.to_der()?,
        )?,
        extension(AUTHORITY_KEY_IDENTIFIER, false, &authority_id)?,
        extension(KEY_USAGE, true, &[0x03, 0x02, 0x04, 0xf0])?,
        extension(ATTESTATION, false, cbor)?,
    ])
}

struct CertificateProfile {
    issuer: Name,
    subject: Name,
    extensions: Vec<Extension>,
}

impl BuilderProfile for CertificateProfile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _subject: SubjectPublicKeyInfoRef<'_>,
        _issuer: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(self.extensions.clone())
    }
}

impl DynSignatureAlgorithmIdentifier for IssuerKey {
    fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        Ok(AlgorithmIdentifierOwned {
            oid: ECDSA_SHA256,
            parameters: None,
        })
    }
}

#[derive(Clone)]
pub(super) struct IssuerPublicKey(der::Document);

impl EncodePublicKey for IssuerPublicKey {
    fn to_public_key_der(&self) -> spki::Result<der::Document> {
        Ok(self.0.clone())
    }
}

impl Keypair for IssuerKey {
    type VerifyingKey = IssuerPublicKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        IssuerPublicKey(self.public_der().expect("validated issuer public key"))
    }
}

struct CertificateSignature(Vec<u8>);

impl SignatureBitStringEncoding for CertificateSignature {
    fn to_bitstring(&self) -> der::Result<BitString> {
        BitString::new(0, self.0.clone())
    }
}

impl RandomizedSigner<CertificateSignature> for IssuerKey {
    fn try_sign_with_rng<R: TryCryptoRng + ?Sized>(
        &self,
        _rng: &mut R,
        message: &[u8],
    ) -> rsa::signature::Result<CertificateSignature> {
        let signature = match self {
            Self::KeyMint(key) => key
                .sign_sha256(message)
                .map_err(|_| rsa::signature::Error::new())?,
        };
        Ok(CertificateSignature(signature))
    }
}
