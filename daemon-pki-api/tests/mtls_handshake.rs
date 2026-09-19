use std::sync::Arc;

use daemon_pki_api::tls::server::build_mtls_server_config;
use daemon_pki_core::{
    ca::{IntermediateCa, RootCa},
    certificate::{CertificateIssuer, CertificateRequest},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn pem_private_key(key_der: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();

    output.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\n");

    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        key_der,
    );

    for chunk in encoded.as_bytes().chunks(64) {
        output.extend_from_slice(chunk);
        output.push(b'\n');
    }

    output.extend_from_slice(b"-----END PRIVATE KEY-----\n");

    output
}

fn pem_certificate(cert_der: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();

    output.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");

    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        cert_der,
    );

    for chunk in encoded.as_bytes().chunks(64) {
        output.extend_from_slice(chunk);
        output.push(b'\n');
    }

    output.extend_from_slice(b"-----END CERTIFICATE-----\n");

    output
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_pki_real_mtls_handshake(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let root = RootCa::generate("Daemon PKI Test Root CA")?;

    let intermediate =
        IntermediateCa::generate(&root, "Daemon PKI Test Workload CA")?;

    let server_request =
        CertificateRequest::new("server.daemon.internal")
            .with_dns_name("server.daemon.internal");

    let (server_cert, server_key) =
        CertificateIssuer::issue(&intermediate, server_request)?;

    let client_request =
        CertificateRequest::new("client.daemon.internal")
            .with_dns_name("client.daemon.internal");

    let (client_cert, client_key) =
        CertificateIssuer::issue(&intermediate, client_request)?;

    /*
     * TLS peers must receive the complete certificate chain:
     *
     *   Leaf -> Intermediate -> Root trust anchor
     *
     * The root itself is trusted separately and is not sent
     * as part of the TLS certificate chain.
     */
    let server_cert_pem = format!(
        "{}{}",
        String::from_utf8(pem_certificate(server_cert.der()))?,
        String::from_utf8(
            pem_certificate(&intermediate.certificate_der())
        )?
    )
    .into_bytes();

    let server_key_der = server_key.serialize_der();
    let server_key_pem = pem_private_key(&server_key_der);

    let root_der = root.certificate_der();
    let root_cert_pem = pem_certificate(&root_der);

    let server_config = build_mtls_server_config(
        &server_cert_pem,
        &server_key_pem,
        &root_cert_pem,
        None,
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    let acceptor = TlsAcceptor::from(server_config);

    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;

        let mut tls_stream =
            acceptor.accept(stream).await?;

        let mut request = [0u8; 4];
        tls_stream.read_exact(&mut request).await?;

        if &request != b"PING" {
            return Err::<(), Box<dyn std::error::Error + Send + Sync>>(
                "unexpected client payload".into(),
            );
        }

        tls_stream.write_all(b"PONG").await?;

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });

    let mut roots = RootCertStore::empty();

    roots.add(
        CertificateDer::from(root_der.clone()),
    )?;

    let client_key_der = client_key.serialize_der();

    let client_cert_chain = vec![
        CertificateDer::from(
            client_cert.der().to_vec()
        ),
        CertificateDer::from(
            intermediate.certificate_der()
        ),
    ];

    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            client_cert_chain,
            PrivateKeyDer::try_from(client_key_der)?,
        )?;

    let connector =
        TlsConnector::from(Arc::new(client_config));

    let stream =
        tokio::net::TcpStream::connect(address).await?;

    let server_name =
        ServerName::try_from("server.daemon.internal")?;

    let mut tls_stream =
        connector.connect(server_name, stream).await?;

    tls_stream.write_all(b"PING").await?;

    let mut response = [0u8; 4];

    tls_stream.read_exact(&mut response).await?;

    assert_eq!(&response, b"PONG");

    server_task.await??;

    println!("Daemon PKI real mTLS handshake: PASSED");
    println!("Server certificate: VERIFIED");
    println!("Client certificate: VERIFIED");
    println!("Root trust: VERIFIED");
    println!("Certificate chains: VERIFIED");
    println!("Encrypted application data: VERIFIED");

    Ok(())
}
