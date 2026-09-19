use std::io::BufReader;
use std::sync::Arc;

use anyhow::{Context, Result};
use daemon_pki_api::issuance::{
    AuthenticatedPrincipal,
    IssuancePolicy,
    IssuanceService,
    IssueCertificateRequest,
};
use daemon_pki_api::tls::server::build_mtls_server_config;
use daemon_pki_core::ca::{IntermediateCa, RootCa};
use daemon_pki_core::certificate::{
    CertificateIssuer,
    CertificateRequest,
};
use rustls::client::danger::{
    HandshakeSignatureValid,
    ServerCertVerified,
    ServerCertVerifier,
};
use rustls::pki_types::{
    CertificateDer,
    PrivateKeyDer,
    ServerName,
    UnixTime,
};
use rustls::{
    ClientConfig,
    DigitallySignedStruct,
    RootCertStore,
    SignatureScheme,
};
use rustls_pemfile::certs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Debug)]
struct TrustAllServerVerifier;

impl ServerCertVerifier for TrustAllServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(
        &self,
    ) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn certificate_chain_pem(
    leaf_pem: &str,
    intermediate_pem: &str,
) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(leaf_pem.as_bytes());
    result.extend_from_slice(intermediate_pem.as_bytes());
    result
}

#[tokio::test]
async fn end_to_end_mtls_http_certificate_issuance() -> Result<()> {
    let root =
        RootCa::generate("Daemon PKI Test Root")?;

    let intermediate =
        IntermediateCa::generate(
            &root,
            "Daemon PKI Test Intermediate",
        )?;

    let mut server_request =
        CertificateRequest::new(
            "daemon-pki-api.internal",
        )
        .with_dns_name(
            "daemon-pki-api.internal",
        );

    server_request.server_auth = true;

    let (server_certificate, server_key) =
        CertificateIssuer::issue(
            &intermediate,
            server_request,
        )?;

    let mut client_request =
        CertificateRequest::new(
            "daemon-pki-test-client.internal",
        )
        .with_dns_name(
            "daemon-pki-test-client.internal",
        );

    client_request.client_auth = true;

    let (client_certificate, client_key) =
        CertificateIssuer::issue(
            &intermediate,
            client_request,
        )?;

    let server_chain = certificate_chain_pem(
        &server_certificate.pem(),
        &intermediate.certificate_pem(),
    );

    let client_chain = certificate_chain_pem(
        &client_certificate.pem(),
        &intermediate.certificate_pem(),
    );

    let server_key_pem =
        server_key.serialize_pem();

    let root_pem =
        root.certificate_pem();

    let server_config =
        build_mtls_server_config(
            &server_chain,
            server_key_pem.as_bytes(),
            root_pem.as_bytes(),
        )?;

    let listener =
        TcpListener::bind(
            "127.0.0.1:0",
        )
        .await?;

    let address =
        listener.local_addr()?;

    let acceptor =
        TlsAcceptor::from(server_config);

    let issuance = Arc::new(
        IssuanceService::new(
            IssuancePolicy::default(),
        ),
    );

    let intermediate =
        Arc::new(intermediate);

    let server_task =
        tokio::spawn(async move {
            let (stream, _) =
                listener.accept().await?;

            let mut tls_stream =
                acceptor.accept(stream).await?;

            let peer_certificates =
                tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .context(
                        "client certificate missing",
                    )?;

            let client_certificate =
                peer_certificates
                    .first()
                    .context(
                        "client certificate chain empty",
                    )?;

            let identity =
                daemon_pki_api::tls::identity::
                    identity_from_client_certificate(
                        client_certificate,
                    )?;

            assert_eq!(
                identity.name,
                "daemon-pki-test-client.internal"
            );

            let mut request_buffer =
                vec![0u8; 8192];

            let size =
                tls_stream
                    .read(&mut request_buffer)
                    .await?;

            let request_text =
                String::from_utf8_lossy(
                    &request_buffer[..size],
                );

            assert!(
                request_text.starts_with(
                    "POST /v1/certificates/issue HTTP/1.1"
                )
            );

            let body =
                request_text
                    .split("\r\n\r\n")
                    .nth(1)
                    .context(
                        "HTTP request body missing",
                    )?;

            let request:
                IssueCertificateRequest =
                serde_json::from_str(body)?;

            let principal =
                AuthenticatedPrincipal {
                    id: identity.id,
                    name: identity.name,
                    roles: vec![
                        "certificate:issue"
                            .to_string(),
                    ],
                };

            let (response, audit) =
                issuance.issue(
                    &principal,
                    &intermediate,
                    request,
                )?;

            assert!(audit.success);

            assert_eq!(
                audit.principal_name,
                "daemon-pki-test-client.internal"
            );

            assert!(
                response
                    .certificate_pem
                    .contains(
                        "BEGIN CERTIFICATE"
                    )
            );

            let response_body =
                serde_json::to_string(
                    &response,
                )?;

            let http_response =
                format!(
                    "HTTP/1.1 201 Created\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {}",
                    response_body.len(),
                    response_body,
                );

            tls_stream
                .write_all(
                    http_response.as_bytes(),
                )
                .await?;

            Ok::<(), anyhow::Error>(())
        });

    let mut roots =
        RootCertStore::empty();

    roots.add(
        CertificateDer::from(
            root.certificate_der()
                .to_vec(),
        ),
    )?;

    let client_key_pem =
        client_key.serialize_pem();

    let client_certificates =
        certs(
            &mut BufReader::new(
                client_chain.as_slice(),
            ),
        )
        .collect::<Result<Vec<_>, _>>()?;

    let client_private_key =
        rustls_pemfile::private_key(
            &mut BufReader::new(
                client_key_pem.as_bytes(),
            ),
        )?
        .context(
            "client private key missing",
        )?;

    let client_config =
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(
                Arc::new(
                    TrustAllServerVerifier,
                ),
            )
            .with_client_auth_cert(
                client_certificates,
                PrivateKeyDer::try_from(
                    client_private_key,
                )?,
            )?;

    let connector =
        TlsConnector::from(
            Arc::new(client_config),
        );

    let stream =
        tokio::net::TcpStream::connect(
            address,
        )
        .await?;

    let server_name =
        ServerName::try_from(
            "daemon-pki-api.internal",
        )?;

    let mut tls_stream =
        connector
            .connect(
                server_name,
                stream,
            )
            .await?;

    let body =
        serde_json::to_string(
            &IssueCertificateRequest {
                common_name:
                    "issued-workload.internal"
                        .to_string(),
                dns_names: vec![
                    "issued-workload.internal"
                        .to_string(),
                ],
                ip_addresses:
                    Vec::new(),
                client_auth: false,
                server_auth: true,
            },
        )?;

    let request =
        format!(
            "POST /v1/certificates/issue HTTP/1.1\r\n\
             Host: daemon-pki-api.internal\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            body.len(),
            body,
        );

    tls_stream
        .write_all(
            request.as_bytes(),
        )
        .await?;

    let mut response =
        Vec::new();

    loop {
        let mut buffer = [0u8; 4096];

        match tls_stream.read(&mut buffer).await {
            Ok(0) => break,
            Ok(size) => {
                response.extend_from_slice(&buffer[..size]);
            }
            Err(error)
                if error.to_string().contains(
                    "peer closed connection without sending TLS close_notify"
                ) =>
            {
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }

    let response_text =
        String::from_utf8(
            response,
        )?;

    assert!(
        response_text.starts_with(
            "HTTP/1.1 201 Created"
        ),
        "unexpected response: {response_text}"
    );

    assert!(
        response_text.contains(
            "issued-workload.internal"
        )
    );

    server_task.await??;

    println!(
        "Daemon PKI end-to-end mTLS HTTP issuance: PASSED"
    );

    Ok(())
}



