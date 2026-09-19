use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};

use crate::ca::IntermediateCa;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IssuanceError {
    #[error("certificate generation failed: {0}")]
    Certificate(#[from] rcgen::Error),

    #[error("certificate request rejected: {0}")]
    Policy(String),
}

#[derive(Debug, Clone)]
pub struct CertificateRequest {
    pub common_name: String,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<std::net::IpAddr>,
    pub client_auth: bool,
    pub server_auth: bool,
}

impl CertificateRequest {
    pub fn new(common_name: impl Into<String>) -> Self {
        Self {
            common_name: common_name.into(),
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            client_auth: true,
            server_auth: true,
        }
    }

    pub fn with_dns_name(mut self, name: impl Into<String>) -> Self {
        self.dns_names.push(name.into());
        self
    }

    pub fn with_ip_address(mut self, address: std::net::IpAddr) -> Self {
        self.ip_addresses.push(address);
        self
    }
}

pub struct CertificateIssuer;

impl CertificateIssuer {
    pub fn issue(
        ca: &IntermediateCa,
        request: CertificateRequest,
    ) -> Result<(Certificate, KeyPair), IssuanceError> {
        Self::validate_request(&request)?;

        let mut params = CertificateParams::default();

        params.distinguished_name = DistinguishedName::new();

        if !request.common_name.trim().is_empty() {
            params
                .distinguished_name
                .push(DnType::CommonName, request.common_name.clone());
        }

        for dns_name in &request.dns_names {
            params
                .subject_alt_names
                .push(SanType::DnsName(dns_name.clone().try_into().map_err(
                    |_| IssuanceError::Policy("invalid DNS subject alternative name".to_string()),
                )?));
        }

        for ip in &request.ip_addresses {
            params.subject_alt_names.push(SanType::IpAddress(*ip));
        }

        params.is_ca = IsCa::NoCa;

        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        let mut eku = Vec::new();

        if request.server_auth {
            eku.push(ExtendedKeyUsagePurpose::ServerAuth);
        }

        if request.client_auth {
            eku.push(ExtendedKeyUsagePurpose::ClientAuth);
        }

        params.extended_key_usages = eku;

        params.use_authority_key_identifier_extension = true;

        let key = KeyPair::generate()?;

        let certificate = params.signed_by(&key, &ca.issuer)?;

        Ok((certificate, key))
    }

    fn validate_request(request: &CertificateRequest) -> Result<(), IssuanceError> {
        if request.common_name.trim().is_empty()
            && request.dns_names.is_empty()
            && request.ip_addresses.is_empty()
        {
            return Err(IssuanceError::Policy(
                "certificate must contain a subject identity".to_string(),
            ));
        }

        if request.common_name.len() > 253 {
            return Err(IssuanceError::Policy(
                "common name exceeds maximum length".to_string(),
            ));
        }

        if request.dns_names.len() > 100 {
            return Err(IssuanceError::Policy(
                "too many DNS subject alternative names".to_string(),
            ));
        }

        if request.ip_addresses.len() > 100 {
            return Err(IssuanceError::Policy(
                "too many IP subject alternative names".to_string(),
            ));
        }

        if !request.server_auth && !request.client_auth {
            return Err(IssuanceError::Policy(
                "certificate must have at least one permitted extended key usage".to_string(),
            ));
        }

        Ok(())
    }
}
