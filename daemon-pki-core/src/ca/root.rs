use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    IsCa, KeyPair, KeyUsagePurpose,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CaError {
    #[error("cryptographic operation failed: {0}")]
    Crypto(#[from] rcgen::Error),

    #[error("invalid CA configuration: {0}")]
    Configuration(String),
}

pub struct RootCa {
    pub issuer: CertifiedIssuer<'static, KeyPair>,
}

impl RootCa {
    pub fn generate(common_name: &str) -> Result<Self, CaError> {
        if common_name.trim().is_empty() {
            return Err(CaError::Configuration(
                "root CA common name cannot be empty".to_string(),
            ));
        }

        let mut params = CertificateParams::default();

        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);

        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        params.use_authority_key_identifier_extension = true;

        let key = KeyPair::generate()?;
        let issuer = CertifiedIssuer::self_signed(params, key)?;

        Ok(Self { issuer })
    }

    pub fn certificate_pem(&self) -> String {
        self.issuer.pem()
    }

    pub fn certificate_der(&self) -> Vec<u8> {
        self.issuer.der().to_vec()
    }


}

pub struct IntermediateCa {
    pub issuer: CertifiedIssuer<'static, KeyPair>,
}

impl IntermediateCa {
    pub fn generate(root: &RootCa, common_name: &str) -> Result<Self, CaError> {
        if common_name.trim().is_empty() {
            return Err(CaError::Configuration(
                "intermediate CA common name cannot be empty".to_string(),
            ));
        }

        let mut params = CertificateParams::default();

        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);

        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));

        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        params.use_authority_key_identifier_extension = true;

        let key = KeyPair::generate()?;

        let issuer = CertifiedIssuer::signed_by(params, key, &root.issuer)?;

        Ok(Self { issuer })
    }

    pub fn certificate_pem(&self) -> String {
        self.issuer.pem()
    }

    pub fn certificate_der(&self) -> Vec<u8> {
        self.issuer.der().to_vec()
    }
}


