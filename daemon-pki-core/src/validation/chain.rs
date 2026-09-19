use super::certificate::{
    CertificateValidationError,
    CertificateValidity,
    IdentityRequirement,
};

use super::trust::TrustStore;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// A certificate represented as validation input.
///
/// DER remains the source of cryptographic truth. The metadata
/// fields make policy decisions explicit and testable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateValidationInput {
    pub der: Vec<u8>,
    pub validity: CertificateValidity,

    pub is_ca: bool,

    pub digital_signature: bool,
    pub key_cert_sign: bool,

    pub server_auth: bool,
    pub client_auth: bool,

    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<std::net::IpAddr>,

    pub issuer: String,
    pub subject: String,
}

/// Result of successful certificate validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub trusted: bool,
    pub chain_depth: usize,
    pub trust_anchor_id: Option<Uuid>,
}

/// Explicit chain-validation failures.
#[derive(Debug, Error)]
pub enum ChainValidationError {
    #[error("certificate validation failed: {0}")]
    Certificate(#[from] CertificateValidationError),

    #[error("no trusted anchor is configured")]
    NoTrustAnchor,

    #[error("certificate chain is empty")]
    EmptyChain,

    #[error("issuer relationship is invalid")]
    InvalidIssuer,

    #[error("CA certificate is missing key-cert-sign usage")]
    InvalidCaUsage,

    #[error("leaf certificate is incorrectly marked as a CA")]
    LeafIsCa,

    #[error("required identity was not found in certificate")]
    IdentityMismatch,

    #[error("revocation status is not acceptable")]
    Revoked,

    #[error("certificate could not be parsed as X.509")]
    InvalidCertificate,

    #[error("certificate signature verification failed")]
    InvalidSignature,

    #[error("certificate signature algorithm is unsupported")]
    UnsupportedSignatureAlgorithm,
}

/// Validates certificate chains against explicit trust anchors.
pub struct ChainValidator;

impl ChainValidator {
    /// Existing policy/metadata validator.
    ///
    /// This remains useful for callers that already possess validated
    /// certificate metadata.
    pub fn validate_leaf(
        certificate: &CertificateValidationInput,
        trust_store: &TrustStore,
        identity: Option<&IdentityRequirement>,
    ) -> Result<ValidationResult, ChainValidationError> {
        let now = OffsetDateTime::now_utc();

        certificate.validity.validate(now)?;

        if certificate.is_ca {
            return Err(ChainValidationError::LeafIsCa);
        }

        if !certificate.digital_signature {
            return Err(ChainValidationError::Certificate(
                CertificateValidationError::MissingKeyUsage,
            ));
        }

        if let Some(requirement) = identity {
            Self::validate_identity(certificate, requirement)?;
        }

        let anchor = trust_store
            .enabled()
            .next()
            .ok_or(ChainValidationError::NoTrustAnchor)?;

        Ok(ValidationResult {
            trusted: true,
            chain_depth: 1,
            trust_anchor_id: Some(anchor.id),
        })
    }

    /// Validate a CA certificate's basic CA properties.
    pub fn validate_ca(
        certificate: &CertificateValidationInput,
    ) -> Result<(), ChainValidationError> {
        let now = OffsetDateTime::now_utc();

        certificate.validity.validate(now)?;

        if !certificate.is_ca {
            return Err(ChainValidationError::Certificate(
                CertificateValidationError::NotACa,
            ));
        }

        if !certificate.key_cert_sign {
            return Err(ChainValidationError::InvalidCaUsage);
        }

        Ok(())
    }

    /// Validate a DER certificate chain while explicitly enforcing
    /// the caller-supplied revocation status of the leaf certificate.
    ///
    /// The revocation state is deliberately supplied by the caller because
    /// the core crate must remain independent of the API persistence layer.
    pub fn validate_der_chain_with_revocation(
        leaf_der: &[u8],
        intermediate_der: &[u8],
        root_der: &[u8],
        trust_store: &TrustStore,
        leaf_revoked: bool,
    ) -> Result<ValidationResult, ChainValidationError> {
        if leaf_revoked {
            return Err(ChainValidationError::Revoked);
        }

        Self::validate_der_chain(
            leaf_der,
            intermediate_der,
            root_der,
            trust_store,
        )
    }
    /// Cryptographically validate:
    ///
    /// Root CA
    ///     -> Intermediate CA
    ///         -> Leaf certificate
    ///
    /// The supplied root must also exist as an enabled trust anchor.
    ///
    /// This performs actual X.509 signature verification using
    /// x509-parser's verification support.
    pub fn validate_der_chain(
        leaf_der: &[u8],
        intermediate_der: &[u8],
        root_der: &[u8],
        trust_store: &TrustStore,
    ) -> Result<ValidationResult, ChainValidationError> {
        if leaf_der.is_empty()
            || intermediate_der.is_empty()
            || root_der.is_empty()
        {
            return Err(ChainValidationError::EmptyChain);
        }

        let (_, leaf) =
            x509_parser::parse_x509_certificate(leaf_der)
                .map_err(|_| ChainValidationError::InvalidCertificate)?;

        let (_, intermediate) =
            x509_parser::parse_x509_certificate(intermediate_der)
                .map_err(|_| ChainValidationError::InvalidCertificate)?;

        let (_, root) =
            x509_parser::parse_x509_certificate(root_der)
                .map_err(|_| ChainValidationError::InvalidCertificate)?;

        // --------------------------------------------------------
        // The supplied root must be explicitly trusted.
        // --------------------------------------------------------
        let anchor = trust_store
            .enabled()
            .find(|candidate| candidate.certificate_der == root_der)
            .ok_or(ChainValidationError::NoTrustAnchor)?;

        // --------------------------------------------------------
        // Verify issuer relationships.
        // --------------------------------------------------------
        if leaf.issuer() != intermediate.subject() {
            return Err(ChainValidationError::InvalidIssuer);
        }

        if intermediate.issuer() != root.subject() {
            return Err(ChainValidationError::InvalidIssuer);
        }

        // --------------------------------------------------------
        // Verify CA constraints.
        // --------------------------------------------------------
        if !intermediate.is_ca() {
            return Err(ChainValidationError::Certificate(
                CertificateValidationError::NotACa,
            ));
        }

        if !root.is_ca() {
            return Err(ChainValidationError::Certificate(
                CertificateValidationError::NotACa,
            ));
        }

        let intermediate_key_usage = intermediate
            .key_usage()
            .map_err(|_| ChainValidationError::InvalidCertificate)?;

        if !intermediate_key_usage
            .map(|extension| extension.value.key_cert_sign())
            .unwrap_or(false)
        {
            return Err(ChainValidationError::InvalidCaUsage);
        }

        let root_key_usage = root
            .key_usage()
            .map_err(|_| ChainValidationError::InvalidCertificate)?;

        if !root_key_usage
            .map(|extension| extension.value.key_cert_sign())
            .unwrap_or(false)
        {
            return Err(ChainValidationError::InvalidCaUsage);
        }

        // --------------------------------------------------------
        // Verify certificate signatures.
        //
        // Leaf signed by Intermediate.
        // Intermediate signed by Root.
        // Root is self-signed.
        // --------------------------------------------------------
        leaf.verify_signature(Some(intermediate.public_key()))
            .map_err(|error| {
                let _ = error;
                ChainValidationError::InvalidSignature
            })?;

        intermediate
            .verify_signature(Some(root.public_key()))
            .map_err(|error| {
                let _ = error;
                ChainValidationError::InvalidSignature
            })?;

        root.verify_signature(None).map_err(|error| {
            let _ = error;
            ChainValidationError::InvalidSignature
        })?;

        // --------------------------------------------------------
        // Verify current validity windows.
        // --------------------------------------------------------
        let now = OffsetDateTime::now_utc();

        let leaf_validity = CertificateValidity {
            not_before: leaf.validity().not_before.to_datetime(),
            not_after: leaf.validity().not_after.to_datetime(),
        };

        leaf_validity.validate(now)?;

        let intermediate_validity = CertificateValidity {
            not_before: intermediate.validity().not_before.to_datetime(),
            not_after: intermediate.validity().not_after.to_datetime(),
        };

        intermediate_validity.validate(now)?;

        let root_validity = CertificateValidity {
            not_before: root.validity().not_before.to_datetime(),
            not_after: root.validity().not_after.to_datetime(),
        };

        root_validity.validate(now)?;

        // --------------------------------------------------------
        // Leaf must not be a CA.
        // --------------------------------------------------------
        if leaf.is_ca() {
            return Err(ChainValidationError::LeafIsCa);
        }

        // --------------------------------------------------------
        // Leaf must contain Digital Signature usage.
        // --------------------------------------------------------
        let leaf_key_usage = leaf
            .key_usage()
            .map_err(|_| ChainValidationError::InvalidCertificate)?;

        if !leaf_key_usage
            .map(|extension| extension.value.digital_signature())
            .unwrap_or(false)
        {
            return Err(ChainValidationError::Certificate(
                CertificateValidationError::MissingKeyUsage,
            ));
        }

        Ok(ValidationResult {
            trusted: true,
            chain_depth: 3,
            trust_anchor_id: Some(anchor.id),
        })
    }

    fn validate_identity(
        certificate: &CertificateValidationInput,
        requirement: &IdentityRequirement,
    ) -> Result<(), ChainValidationError> {
        if let Some(name) = &requirement.dns_name {
            let matched = certificate
                .dns_names
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(name));

            if !matched {
                return Err(ChainValidationError::IdentityMismatch);
            }
        }

        if let Some(address) = requirement.ip_address {
            if !certificate.ip_addresses.contains(&address) {
                return Err(ChainValidationError::IdentityMismatch);
            }
        }

        if requirement.require_server_auth
            && !certificate.server_auth
        {
            return Err(ChainValidationError::Certificate(
                CertificateValidationError::MissingExtendedKeyUsage,
            ));
        }

        if requirement.require_client_auth
            && !certificate.client_auth
        {
            return Err(ChainValidationError::Certificate(
                CertificateValidationError::MissingExtendedKeyUsage,
            ));
        }

        Ok(())
    }
}
