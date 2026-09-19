use rcgen::{
    BasicConstraints,
    CertificateParams,
    DistinguishedName,
    DnType,
    IsCa,
    Issuer,
    KeyPair,
    KeyUsagePurpose,
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
    pub issuer: Issuer<'static, KeyPair>,
    certificate_pem: String,
    certificate_der: Vec<u8>,
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

        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        params.use_authority_key_identifier_extension = true;

        let key = KeyPair::generate()?;

        let certificate = params.self_signed(&key)?;

        let certificate_pem = certificate.pem();
        let certificate_der = certificate.der().to_vec();

        let issuer = Issuer::new(params, key);

        Ok(Self {
            issuer,
            certificate_pem,
            certificate_der,
        })
    }

    pub fn from_pem(
        certificate_pem: &str,
        private_key_pem: &str,
    ) -> Result<Self, CaError> {
        if certificate_pem.trim().is_empty() {
            return Err(CaError::Configuration(
                "root CA certificate is empty".to_string(),
            ));
        }

        if private_key_pem.trim().is_empty() {
            return Err(CaError::Configuration(
                "root CA private key is empty".to_string(),
            ));
        }

        let key = KeyPair::from_pem(private_key_pem)?;

        let issuer =
            Issuer::from_ca_cert_pem(certificate_pem, key)?;

        let certificate_der =
            pem::parse(certificate_pem)
                .map_err(|_| rcgen::Error::CouldNotParseCertificate)?
                .contents()
                .to_vec();

        Ok(Self {
            issuer,
            certificate_pem: certificate_pem.to_string(),
            certificate_der,
        })
    }

    pub fn certificate_pem(&self) -> String {
        self.certificate_pem.clone()
    }

    pub fn certificate_der(&self) -> Vec<u8> {
        self.certificate_der.clone()
    }

    pub fn private_key_pem(&self) -> String {
        self.issuer.key().serialize_pem()
    }
}

pub struct IntermediateCa {
    pub issuer: Issuer<'static, KeyPair>,
    certificate_pem: String,
    certificate_der: Vec<u8>,
}

impl IntermediateCa {
    pub fn generate(
        root: &RootCa,
        common_name: &str,
    ) -> Result<Self, CaError> {
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

        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];

        params.use_authority_key_identifier_extension = true;

        let key = KeyPair::generate()?;

        let certificate =
            params.signed_by(&key, &root.issuer)?;

        let certificate_pem = certificate.pem();
        let certificate_der = certificate.der().to_vec();

        let issuer = Issuer::new(params, key);

        Ok(Self {
            issuer,
            certificate_pem,
            certificate_der,
        })
    }

    pub fn from_pem(
        certificate_pem: &str,
        private_key_pem: &str,
    ) -> Result<Self, CaError> {
        if certificate_pem.trim().is_empty() {
            return Err(CaError::Configuration(
                "intermediate CA certificate is empty".to_string(),
            ));
        }

        if private_key_pem.trim().is_empty() {
            return Err(CaError::Configuration(
                "intermediate CA private key is empty".to_string(),
            ));
        }

        let key = KeyPair::from_pem(private_key_pem)?;

        let issuer =
            Issuer::from_ca_cert_pem(certificate_pem, key)?;

        let certificate_der =
            pem::parse(certificate_pem)
                .map_err(|_| rcgen::Error::CouldNotParseCertificate)?
                .contents()
                .to_vec();

        Ok(Self {
            issuer,
            certificate_pem: certificate_pem.to_string(),
            certificate_der,
        })
    }

    pub fn certificate_pem(&self) -> String {
        self.certificate_pem.clone()
    }

    pub fn certificate_der(&self) -> Vec<u8> {
        self.certificate_der.clone()
    }

    pub fn private_key_pem(&self) -> String {
        self.issuer.key().serialize_pem()
    }
}
