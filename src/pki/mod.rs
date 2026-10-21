mod certificate;
mod credentials;
mod error;
mod metadata;
mod request;

use credentials::{CertificateError, Issuer, IssuerKind};
use error::PkiError;
use metadata::{Metadata, parse_time};

use crate::{
    request::CryptoengRequest,
    response::ResponseBuilder,
    types::{
        method::MethodType,
        parameter::{MethodParamType, Parameter},
    },
};

pub(crate) fn dispatch(command: &dyn CryptoengRequest) -> Option<Vec<u8>> {
    use MethodType::*;
    match command.method_type() {
        CeCmdVerifyPkiCert | CeCmdGroupPkiVerify => {
            let kind = if command.method_type() == CeCmdVerifyPkiCert {
                IssuerKind::User
            } else {
                IssuerKind::Group
            };
            Some(capability_response(Issuer::load(kind)))
        }
        CeCmdRunPkiBasicAttestation => Some(match attest(command) {
            Ok(response) => response,
            Err(error) => ResponseBuilder::standard(CeCmdRunPkiBasicAttestation)
                .result_code(error.code())
                .build(),
        }),
        _ => None,
    }
}

fn load_issuer(kind: IssuerKind) -> Result<Issuer, PkiError> {
    Issuer::load(kind).map_err(certificate_status)
}

fn capability_response(issuer: Result<Issuer, CertificateError>) -> Vec<u8> {
    let status = issuer
        .and_then(|issuer| issuer.common_name())
        .map_or_else(|error| certificate_status(error).code(), |_| 0);
    status.to_le_bytes().to_vec()
}

fn attest(command: &dyn CryptoengRequest) -> Result<Vec<u8>, PkiError> {
    let parameter = command
        .get_param(MethodParamType::PkiCalculationT)
        .map_err(|_| PkiError::MissingParameter)?;
    let request = request::Request::parse(parameter.value().as_bytes().as_ref())?;
    let metadata = Metadata::load()?;
    let (kind, issuer) = match request.alias {
        0 => match load_issuer(IssuerKind::User) {
            Ok(issuer) => (IssuerKind::User, issuer),
            Err(_) => (IssuerKind::Group, load_issuer(IssuerKind::Group)?),
        },
        1 => (IssuerKind::User, load_issuer(IssuerKind::User)?),
        2 => (IssuerKind::Group, load_issuer(IssuerKind::Group)?),
        _ => return Err(PkiError::InvalidAlias),
    };
    issue(&request, &metadata, kind, &issuer)
}

fn issue(
    request: &request::Request,
    metadata: &Metadata,
    kind: IssuerKind,
    issuer: &Issuer,
) -> Result<Vec<u8>, PkiError> {
    let subject = metadata.subject(request, kind)?;
    let (signing_cert, attest_cert) = issuer
        .issue(
            &request.application_public_key,
            &subject,
            parse_time(&request.not_before)?,
            parse_time(&request.not_after)?,
            &metadata.extension(request, kind),
        )
        .map_err(certificate_status)?;
    let json = serde_json::to_vec(&serde_json::json!({
        "signingCert": signing_cert,
        "attestCert": attest_cert,
    }))
    .map_err(|_| PkiError::Encoding)?;

    if json.len() > 4096 - 20 {
        return Err(PkiError::Encoding);
    }
    let parameter =
        Parameter::new(MethodParamType::PkiResponseT, &json).map_err(|_| PkiError::Encoding)?;
    Ok(
        ResponseBuilder::standard(MethodType::CeCmdRunPkiBasicAttestation)
            .add_param(parameter)
            .build(),
    )
}

fn certificate_status(error: CertificateError) -> PkiError {
    match error {
        CertificateError::Io(_) | CertificateError::InsecureFile => {
            PkiError::CredentialsUnavailable
        }
        CertificateError::InvalidIssuer => PkiError::InvalidCredentials,
        CertificateError::UnsupportedIssuer => PkiError::Unsupported,

        CertificateError::InvalidPublicKey => PkiError::InvalidPublicKey,
        CertificateError::Encoding | CertificateError::Signing => PkiError::Encoding,
    }
}
