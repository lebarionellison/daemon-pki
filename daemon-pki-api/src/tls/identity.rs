use anyhow::{Context, Result};
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x509_parser::prelude::*;

#[derive(Debug, Clone)]
pub struct MtlsIdentity {
    pub id: Uuid,
    pub name: String,
    pub serial_number: String,
    pub fingerprint_sha256: String,
}

pub fn identity_from_client_certificate(
    certificate: &CertificateDer<'_>,
) -> Result<MtlsIdentity> {
    let (_, parsed) =
        X509Certificate::from_der(certificate.as_ref())
            .context("failed to parse client certificate")?;

    let name = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|value| value.as_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| "unknown-mtls-client".to_string());

    let serial_number = parsed
        .raw_serial()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    let fingerprint =
        Sha256::digest(certificate.as_ref());

    let fingerprint_sha256 =
        fingerprint
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

    let id =
        Uuid::from_bytes(
            fingerprint[..16]
                .try_into()
                .expect("SHA-256 digest is at least 16 bytes"),
        );

    Ok(MtlsIdentity {
        id,
        name,
        serial_number,
        fingerprint_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use daemon_pki_core::ca::RootCa;
    use rcgen::{
        BasicConstraints,
        CertificateParams,
        DistinguishedName,
        DnType,
        IsCa,
        KeyPair,
    };

    fn test_certificate() -> CertificateDer<'static> {
        let mut params =
            CertificateParams::new(
                vec![
                    "identity-test.internal".to_string()
                ],
            )
            .expect(
                "certificate parameters should be valid",
            );

        let mut distinguished_name =
            DistinguishedName::new();

        distinguished_name.push(
            DnType::CommonName,
            "identity-test.internal",
        );

        params.distinguished_name =
            distinguished_name;

        params.is_ca =
            rcgen::IsCa::Ca(
                rcgen::BasicConstraints::Unconstrained
            );

        let key_pair =
            KeyPair::generate()
                .expect(
                    "test key generation should succeed",
                );

        let root =
            RootCa::generate(
                "Daemon PKI Identity Test Root",
            )
            .expect(
                "root generation should succeed",
            );

        let certificate =
            params
                .self_signed(&key_pair)
                .expect(
                    "test certificate generation should succeed",
                );

        let _ = root;

        CertificateDer::from(
            certificate.der().to_vec(),
        )
    }

    #[test]
    fn certificate_identity_is_stable() {
        let certificate =
            test_certificate();

        let first =
            identity_from_client_certificate(
                &certificate,
            )
            .expect(
                "identity extraction should succeed",
            );

        let second =
            identity_from_client_certificate(
                &certificate,
            )
            .expect(
                "identity extraction should succeed",
            );

        assert_eq!(
            first.id,
            second.id
        );

        assert_eq!(
            first.fingerprint_sha256,
            second.fingerprint_sha256
        );

        assert_eq!(
            first.name,
            second.name
        );

        assert_eq!(
            first.serial_number,
            second.serial_number
        );
    }

    #[test]
    fn different_certificates_have_different_identities() {
        let first_certificate =
            test_certificate();

        let second_certificate =
            test_certificate();

        let first =
            identity_from_client_certificate(
                &first_certificate,
            )
            .expect(
                "first identity extraction should succeed",
            );

        let second =
            identity_from_client_certificate(
                &second_certificate,
            )
            .expect(
                "second identity extraction should succeed",
            );

        assert_ne!(
            first.id,
            second.id
        );

        assert_ne!(
            first.fingerprint_sha256,
            second.fingerprint_sha256
        );
    }
}


