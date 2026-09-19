use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use thiserror::Error;

/// Explicit certificate validation failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CertificateValidationError {
    #[error("certificate is not yet valid")]
    NotYetValid,

    #[error("certificate has expired")]
    Expired,

    #[error("certificate is not permitted to act as a CA")]
    NotACa,

    #[error("certificate is missing required key usage")]
    MissingKeyUsage,

    #[error("certificate is missing required extended key usage")]
    MissingExtendedKeyUsage,

    #[error("certificate identity does not match requested identity")]
    IdentityMismatch,

    #[error("certificate has no usable identity")]
    MissingIdentity,

    #[error("certificate has been revoked")]
    Revoked,
}

/// Identity requested during certificate validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRequirement {
    pub dns_name: Option<String>,
    pub ip_address: Option<std::net::IpAddr>,
    pub require_server_auth: bool,
    pub require_client_auth: bool,
}

impl IdentityRequirement {
    pub fn dns(name: impl Into<String>) -> Self {
        Self {
            dns_name: Some(name.into()),
            ip_address: None,
            require_server_auth: true,
            require_client_auth: false,
        }
    }

    pub fn ip(address: std::net::IpAddr) -> Self {
        Self {
            dns_name: None,
            ip_address: Some(address),
            require_server_auth: true,
            require_client_auth: false,
        }
    }
}

/// Basic certificate validity information used by the validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateValidity {
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl CertificateValidity {
    pub fn validate(
        &self,
        now: OffsetDateTime,
    ) -> Result<(), CertificateValidationError> {
        if now < self.not_before {
            return Err(CertificateValidationError::NotYetValid);
        }

        if now > self.not_after {
            return Err(CertificateValidationError::Expired);
        }

        Ok(())
    }
}
