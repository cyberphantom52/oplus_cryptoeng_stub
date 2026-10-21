const OUT_OF_DATA: i32 = -0x60;
const UNEXPECTED_TAG: i32 = -0x62;
const INVALID_LENGTH: i32 = -0x64;
const LENGTH_MISMATCH: i32 = -0x66;
const INVALID_DATA: i32 = -0x68;
const INVALID_FORMAT: i32 = -0x3d00;
const INVALID_ALGORITHM: i32 = -0x3a80;
pub(super) const INVALID_RSA: i32 = -0x3b00;

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn value(&mut self, tag: u8) -> Result<&'a [u8], i32> {
        let (&actual, remaining) = self.0.split_first().ok_or(OUT_OF_DATA)?;
        if actual != tag {
            return Err(UNEXPECTED_TAG);
        }
        let (&first, mut remaining) = remaining.split_first().ok_or(OUT_OF_DATA)?;
        let length = if first < 128 {
            usize::from(first)
        } else {
            let count = usize::from(first & 127);
            if count == 0 || count > 4 {
                return Err(INVALID_LENGTH);
            }
            let bytes = remaining.get(..count).ok_or(OUT_OF_DATA)?;
            remaining = &remaining[count..];
            bytes
                .iter()
                .fold(0usize, |length, byte| (length << 8) | usize::from(*byte))
        };
        let value = remaining.get(..length).ok_or(OUT_OF_DATA)?;
        self.0 = &remaining[length..];
        Ok(value)
    }

    fn finish(&self) -> Result<(), i32> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(LENGTH_MISMATCH)
        }
    }
}

fn rsa_public(bytes: &[u8]) -> Result<(), i32> {
    let mut outer = Reader(bytes);
    let mut key = Reader(outer.value(0x30).map_err(|error| INVALID_RSA + error)?);
    outer.finish().map_err(|error| INVALID_RSA + error)?;
    key.value(2).map_err(|error| INVALID_RSA + error)?;
    key.value(2).map_err(|error| INVALID_RSA + error)?;
    key.finish().map_err(|error| INVALID_RSA + error)
}

pub(super) fn validate_der(bytes: &[u8], rsa_pkcs1: bool) -> Result<(), i32> {
    if rsa_pkcs1 {
        return rsa_public(bytes);
    }
    let mut outer = Reader(bytes);
    let mut spki = Reader(outer.value(0x30).map_err(|error| INVALID_FORMAT + error)?);
    let mut algorithm = Reader(
        spki.value(0x30)
            .map_err(|error| INVALID_ALGORITHM + error)?,
    );
    let oid = algorithm
        .value(6)
        .map_err(|error| INVALID_ALGORITHM + error)?;
    let is_rsa = oid == b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
    let is_ec = oid == b"\x2a\x86\x48\xce\x3d\x02\x01" || oid == b"\x2b\x81\x04\x01\x0c";
    let parameter = if let Some(&tag) = algorithm.0.first() {
        let value = algorithm
            .value(tag)
            .map_err(|error| INVALID_ALGORITHM + error)?;
        Some((tag, value))
    } else {
        None
    };
    algorithm
        .finish()
        .map_err(|error| INVALID_ALGORITHM + error)?;
    if !is_rsa && !is_ec {
        return Err(-0x3c80);
    }
    if is_rsa && parameter.is_some_and(|(tag, value)| tag != 5 || !value.is_empty()) {
        return Err(INVALID_ALGORITHM);
    }
    let bits = spki.value(3).map_err(|error| INVALID_RSA + error)?;
    if bits.first() != Some(&0) {
        return Err(INVALID_RSA + INVALID_DATA);
    }
    spki.finish().map_err(|error| INVALID_RSA + error)?;
    if is_rsa {
        rsa_public(&bits[1..])?;
    }
    Ok(())
}
