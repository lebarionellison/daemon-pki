use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{
    CertificateDer,
    PrivateKeyDer,
};
use rustls::{
    RootCertStore,
    ServerConfig,
};

pub fn build_mtls_server_config(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<Arc<ServerConfig>> {
    let certificates = rustls_pemfile::certs(
        &mut BufReader::new(certificate_pem),
    )
    .collect::<Result<Vec<_>, _>>()
    .context("failed to parse server certificate")?;

    if certificates.is_empty() {
        anyhow::bail!("server certificate chain is empty");
    }

    let private_key = rustls_pemfile::private_key(
        &mut BufReader::new(private_key_pem),
    )
    .context("failed to parse server private key")?
    .context("server private key was not found")?;

    let client_certs = rustls_pemfile::certs(
        &mut BufReader::new(client_ca_pem),
    )
    .collect::<Result<Vec<_>, _>>()
    .context("failed to parse client CA certificate")?;

    if client_certs.is_empty() {
        anyhow::bail!("client CA certificate is empty");
    }

    let mut roots = RootCertStore::empty();

    for certificate in client_certs {
        roots
            .add(CertificateDer::from_slice(certificate.as_ref()))
            .context("failed to add client CA trust anchor")?;
    }

    let client_auth =
        rustls::server::WebPkiClientVerifier::builder(
            Arc::new(roots),
        )
        .build()
        .context("failed to build mTLS client verifier")?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(
            certificates,
            PrivateKeyDer::try_from(private_key)
                .context("invalid server private key")?,
        )
        .context("failed to build TLS server configuration")?;

    Ok(Arc::new(config))
}

