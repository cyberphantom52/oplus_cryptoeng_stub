use p256::elliptic_curve::bigint::BoxedUint;
use x509_cert::{
    SubjectPublicKeyInfo,
    der::{Decode, Encode},
    spki::ObjectIdentifier,
};

struct Curve {
    oid: ObjectIdentifier,
    prime: &'static str,
    a: &'static str,
    b: &'static str,
}

const CURVES: &[Curve] = &[
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.1"),
        prime: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
        a: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
        b: "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.132.0.31"),
        prime: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37",
        a: "000000000000000000000000000000000000000000000000",
        b: "000000000000000000000000000000000000000000000003",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.132.0.32"),
        prime: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",
        a: "00000000000000000000000000000000000000000000000000000000",
        b: "00000000000000000000000000000000000000000000000000000005",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.132.0.10"),
        prime: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        a: "0000000000000000000000000000000000000000000000000000000000000000",
        b: "0000000000000000000000000000000000000000000000000000000000000007",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7"),
        prime: "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
        a: "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
        b: "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.11"),
        prime: "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
        a: "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
        b: "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.13"),
        prime: "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
        a: "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
        b: "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
    },
];

pub(super) fn point_format(key: &SubjectPublicKeyInfo) -> Result<(), i32> {
    let oid = key
        .algorithm
        .parameters
        .as_ref()
        .and_then(|value| ObjectIdentifier::from_der(&value.to_der().ok()?).ok())
        .ok_or(-0x3d00)?;
    let width = match oid.to_string().as_str() {
        "1.3.132.0.33" => 28,
        "1.2.840.10045.3.1.7" => 32,
        "1.3.132.0.34" => 48,
        "1.3.132.0.35" => 66,
        _ => CURVES
            .iter()
            .find(|curve| curve.oid == oid)
            .map(|curve| curve.prime.len() / 2)
            .ok_or(-0x3a2e)?,
    };
    let point = key.subject_public_key.as_bytes().ok_or(-0x3b68)?;
    if point.first() == Some(&0) && point.len() == 1 {
        return Err(-0x4c80);
    }
    if point.is_empty() || (point[0] == 4 && point.len() != 1 + 2 * width) {
        return Err(-0x4f80);
    }
    if point[0] != 4 {
        return Err(-0x4e80);
    }
    Ok(())
}

pub(super) fn validate(key: &SubjectPublicKeyInfo) -> bool {
    if key.algorithm.oid != ObjectIdentifier::new_unwrap("1.2.840.10045.2.1") {
        return false;
    }
    let Some(oid) = key
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| ObjectIdentifier::from_der(&p.to_der().ok()?).ok())
    else {
        return false;
    };
    let Some(curve) = CURVES.iter().find(|curve| curve.oid == oid) else {
        return false;
    };
    let Some(point) = key.subject_public_key.as_bytes() else {
        return false;
    };
    let width = curve.prime.len() / 2;

    if point.len() != 1 + 2 * width || point[0] != 4 {
        return false;
    }
    let Ok(prime) = BoxedUint::from_str_radix_vartime(curve.prime, 16) else {
        return false;
    };
    let precision = prime.bits_precision();
    let number = |bytes| BoxedUint::from_be_slice(bytes, precision).ok();
    let Some(x) = number(&point[1..1 + width]) else {
        return false;
    };
    let Some(y) = number(&point[1 + width..]) else {
        return false;
    };
    if x >= prime || y >= prime {
        return false;
    }
    let Some(modulus) = prime.as_nz_vartime() else {
        return false;
    };
    let Ok(a) = BoxedUint::from_str_radix_with_precision_vartime(curve.a, 16, precision) else {
        return false;
    };
    let Ok(b) = BoxedUint::from_str_radix_with_precision_vartime(curve.b, 16, precision) else {
        return false;
    };
    let rhs = x
        .square_mod(modulus)
        .mul_mod(&x, modulus)
        .add_mod(&a.mul_mod(&x, modulus), modulus)
        .add_mod(&b, modulus);
    y.square_mod(modulus) == rhs
}
