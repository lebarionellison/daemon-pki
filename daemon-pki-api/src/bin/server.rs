use std::{
    env,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};

use daemon_pki_api::{
    http::{AuthorizationPolicy, HttpApi},
    issuance::{IssuancePolicy, IssuanceService},
    tls::server::build_mtls_server_config,
};

use daemon_pki_core::{
    ca::{IntermediateCa, RootCa},
    certificate::{CertificateIssuer, CertificateRequest},
};

fn load_or_create_root(data_dir: &Path) -> Result<RootCa> {
    let cert_path = data_dir.join("root-ca.pem");
    let key_path = data_dir.join("root-ca-key.pem");

    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {
            let certificate = fs::read_to_string(&cert_path)
                .with_context(|| format!("failed to read {}", cert_path.display()))?;

            let private_key = fs::read_to_string(&key_path)
                .with_context(|| format!("failed to read {}", key_path.display()))?;

            RootCa::from_pem(&certificate, &private_key)
                .context("failed to load persisted root CA")
        }

        (false, false) => {
            let root = RootCa::generate("Daemon PKI Root CA")
                .context("failed to generate root CA")?;

            fs::write(&cert_path, root.certificate_pem())
                .with_context(|| format!("failed to write {}", cert_path.display()))?;

            fs::write(&key_path, root.private_key_pem())
                .with_context(|| format!("failed to write {}", key_path.display()))?;

            Ok(root)
        }

        _ => anyhow::bail!(
            "root CA storage is incomplete: both root-ca.pem and root-ca-key.pem must exist"
        ),
    }
}

fn load_or_create_intermediate(
    data_dir: &Path,
    root: &RootCa,
) -> Result<IntermediateCa> {
    let cert_path = data_dir.join("intermediate-ca.pem");
    let key_path = data_dir.join("intermediate-ca-key.pem");

    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {
            let certificate = fs::read_to_string(&cert_path)
                .with_context(|| format!("failed to read {}", cert_path.display()))?;

            let private_key = fs::read_to_string(&key_path)
                .with_context(|| format!("failed to read {}", key_path.display()))?;

            IntermediateCa::from_pem(&certificate, &private_key)
                .context("failed to load persisted intermediate CA")
        }

        (false, false) => {
            let intermediate =
                IntermediateCa::generate(root, "Daemon PKI Workload CA")
                    .context("failed to generate intermediate CA")?;

            fs::write(&cert_path, intermediate.certificate_pem())
                .with_context(|| format!("failed to write {}", cert_path.display()))?;

            fs::write(&key_path, intermediate.private_key_pem())
                .with_context(|| format!("failed to write {}", key_path.display()))?;

            Ok(intermediate)
        }

        _ => anyhow::bail!(
            "intermediate CA storage is incomplete: both intermediate-ca.pem and intermediate-ca-key.pem must exist"
        ),
    }
}

fn load_or_create_server_certificate(
    data_dir: &Path,
    intermediate: &IntermediateCa,
) -> Result<(String, String)> {
    let cert_path = data_dir.join("server-cert.pem");
    let key_path = data_dir.join("server-key.pem");

    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {
            let certificate = fs::read_to_string(&cert_path)
                .with_context(|| format!("failed to read {}", cert_path.display()))?;

            let private_key = fs::read_to_string(&key_path)
                .with_context(|| format!("failed to read {}", key_path.display()))?;

            Ok((certificate, private_key))
        }

        (false, false) => {
            let request =
                CertificateRequest::new("daemon-pki-api.internal")
                    .with_dns_name("daemon-pki-api.internal");

            let (certificate, key) =
                CertificateIssuer::issue(
                    intermediate,
                    request,
                )
                .context("failed to issue API server certificate")?;

            let certificate_pem = certificate.pem();
            let private_key_pem = key.serialize_pem();

            fs::write(&cert_path, &certificate_pem)
                .with_context(|| format!("failed to write {}", cert_path.display()))?;

            fs::write(&key_path, &private_key_pem)
                .with_context(|| format!("failed to write {}", key_path.display()))?;

            Ok((certificate_pem, private_key_pem))
        }

        _ => anyhow::bail!(
            "server certificate storage is incomplete: both server-cert.pem and server-key.pem must exist"
        ),
    }
}

fn authorization_policy() -> AuthorizationPolicy {
    let mut policy = AuthorizationPolicy::new();

    if let Ok(value) = env::var("DAEMON_PKI_ISSUE_FINGERPRINTS") {
        for fingerprint in value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            policy =
                policy.allow_certificate_issuance(
                    fingerprint.to_string(),
                );
        }
    }

    policy
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("Daemon PKI API starting");

    let data_dir = PathBuf::from(
        env::var("DAEMON_PKI_DATA_DIR")
            .unwrap_or_else(|_| "data/pki".to_string()),
    );

    fs::create_dir_all(&data_dir)
        .with_context(|| {
            format!(
                "failed to create {}",
                data_dir.display()
            )
        })?;

    let root = load_or_create_root(&data_dir)?;

    let intermediate =
        load_or_create_intermediate(
            &data_dir,
            &root,
        )?;

    let (server_certificate_pem, server_private_key_pem) =
        load_or_create_server_certificate(
            &data_dir,
            &intermediate,
        )?;

    let client_ca_pem = root.certificate_pem();

    let tls_config =
        build_mtls_server_config(
            server_certificate_pem.as_bytes(),
            server_private_key_pem.as_bytes(),
            client_ca_pem.as_bytes(),
        )
        .context(
            "failed to build mTLS server configuration",
        )?;

    let issuance =
        Arc::new(
            IssuanceService::new(
                IssuancePolicy::default(),
            ),
        );

    let authorization = authorization_policy();

    let api =
        HttpApi::new(
            issuance,
            Arc::new(intermediate),
            tokio_rustls::TlsAcceptor::from(
                tls_config,
            ),
            authorization,
        );

    let bind_address =
        env::var("DAEMON_PKI_BIND")
            .unwrap_or_else(|_| {
                "127.0.0.1:8443".to_string()
            });

    println!("Root CA: persistent");
    println!("Intermediate CA: persistent");
    println!("API server certificate: persistent");
    println!(
        "CA storage: {}",
        data_dir.display()
    );
    println!(
        "mTLS client verification: enabled"
    );
    println!(
        "API bind address: {}",
        bind_address
    );

    if env::var(
        "DAEMON_PKI_ISSUE_FINGERPRINTS",
    )
    .is_ok()
    {
        println!(
            "Certificate issuance authorization: configured"
        );
    } else {
        println!(
            "Certificate issuance authorization: no identities configured"
        );
    }

    println!("Daemon PKI API ready");

    api.run(&bind_address).await
}
