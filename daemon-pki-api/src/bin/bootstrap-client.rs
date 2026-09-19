use std::{
    env,
    fs,
    path::PathBuf,
};

use anyhow::{Context, Result};
use daemon_pki_core::{
    ca::IntermediateCa,
    certificate::{
        CertificateIssuer,
        CertificateRequest,
    },
};
use sha2::{Digest, Sha256};

fn main() -> Result<()> {
    println!("Daemon PKI bootstrap client");

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

    let intermediate_cert_path =
        data_dir.join("intermediate-ca.pem");

    let intermediate_key_path =
        data_dir.join("intermediate-ca-key.pem");

    let client_cert_path =
        data_dir.join("bootstrap-client-cert.pem");

    let client_key_path =
        data_dir.join("bootstrap-client-key.pem");

    let intermediate_certificate =
        fs::read_to_string(&intermediate_cert_path)
            .with_context(|| {
                format!(
                    "failed to read {}",
                    intermediate_cert_path.display()
                )
            })?;

    let intermediate_private_key =
        fs::read_to_string(&intermediate_key_path)
            .with_context(|| {
                format!(
                    "failed to read {}",
                    intermediate_key_path.display()
                )
            })?;

    let intermediate =
        IntermediateCa::from_pem(
            &intermediate_certificate,
            &intermediate_private_key,
        )
        .context(
            "failed to load persisted intermediate CA",
        )?;

    let request =
        CertificateRequest::new(
            "daemon-pki-bootstrap-client",
        );

    let (certificate, private_key) =
        CertificateIssuer::issue(
            &intermediate,
            request,
        )
        .context(
            "failed to issue bootstrap client certificate",
        )?;

    let certificate_der =
        certificate.der();

    let fingerprint =
        Sha256::digest(certificate_der);

    let fingerprint_sha256 =
        fingerprint
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

    let certificate_pem =
        certificate.pem();

    let private_key_pem =
        private_key.serialize_pem();

    fs::write(
        &client_cert_path,
        &certificate_pem,
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            client_cert_path.display()
        )
    })?;

    fs::write(
        &client_key_path,
        &private_key_pem,
    )
    .with_context(|| {
        format!(
            "failed to write {}",
            client_key_path.display()
        )
    })?;

    println!();
    println!("Bootstrap client certificate: created");
    println!(
        "Certificate: {}",
        client_cert_path.display()
    );
    println!(
        "Private key: {}",
        client_key_path.display()
    );
    println!();
    println!(
        "SHA-256 fingerprint:"
    );
    println!("{}", fingerprint_sha256);
    println!();
    println!(
        "Set this environment variable before starting the API:"
    );
    println!(
        "DAEMON_PKI_ISSUE_FINGERPRINTS={}",
        fingerprint_sha256
    );
    println!();
    println!(
        "Bootstrap client certificate includes:"
    );
    println!("  Client authentication: enabled");
    println!("  Server authentication: enabled");
    println!();
    println!(
        "Private key saved under the local PKI data directory."
    );

    Ok(())
}
