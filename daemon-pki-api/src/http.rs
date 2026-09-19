use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::issuance::{
    AuthenticatedPrincipal,
    IssueCertificateRequest,
    IssuanceService,
};

use crate::tls::identity::{
    identity_from_client_certificate,
    MtlsIdentity,
};

use daemon_pki_core::ca::IntermediateCa;
use rustls::pki_types::CertificateDer;

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Deserialize)]
struct IssueRequest {
    common_name: String,
    dns_names: Vec<String>,
    ip_addresses: Vec<String>,
    client_auth: bool,
    server_auth: bool,
}

/// Explicit authorization policy for mTLS identities.
///
/// Authentication proves that a client possesses a trusted
/// certificate. Authorization separately determines what that
/// authenticated identity is allowed to do.
#[derive(Debug, Clone)]
pub struct AuthorizationPolicy {
    certificate_issue_identities: Vec<String>,
}

impl AuthorizationPolicy {
    pub fn new() -> Self {
        Self {
            certificate_issue_identities: Vec::new(),
        }
    }

    /// Allow a specific certificate fingerprint to issue certificates.
    ///
    /// Authorization is bound to the cryptographic identity of the
    /// certificate rather than its human-readable common name.
    pub fn allow_certificate_issuance(
        mut self,
        fingerprint_sha256: impl Into<String>,
    ) -> Self {
        self.certificate_issue_identities
            .push(fingerprint_sha256.into());

        self
    }

    pub fn can_issue_certificates(
        &self,
        identity: &MtlsIdentity,
    ) -> bool {
        self.certificate_issue_identities
            .iter()
            .any(|allowed| {
                allowed == &identity.fingerprint_sha256
            })
    }

    fn roles_for(
        &self,
        identity: &MtlsIdentity,
    ) -> Vec<String> {
        let mut roles = Vec::new();

        if self.can_issue_certificates(identity) {
            roles.push(
                "certificate:issue".to_string(),
            );
        }

        roles
    }
}

impl Default for AuthorizationPolicy {
    fn default() -> Self {
        Self::new()
    }
}

pub struct HttpApi {
    issuance: Arc<IssuanceService>,
    intermediate_ca: Arc<IntermediateCa>,
    tls_acceptor: TlsAcceptor,
    authorization: AuthorizationPolicy,
}

impl HttpApi {
    pub fn new(
        issuance: Arc<IssuanceService>,
        intermediate_ca: Arc<IntermediateCa>,
        tls_acceptor: TlsAcceptor,
        authorization: AuthorizationPolicy,
    ) -> Self {
        Self {
            issuance,
            intermediate_ca,
            tls_acceptor,
            authorization,
        }
    }

    pub async fn run(
        self,
        bind_address: &str,
    ) -> Result<()> {
        let listener = TcpListener::bind(bind_address)
            .await
            .context(
                "failed to bind mTLS HTTP API listener",
            )?;

        println!(
            "Daemon PKI mTLS HTTP API listening on {bind_address}"
        );

        let service = Arc::new(self);

        loop {
            let (stream, peer) = listener
                .accept()
                .await
                .context("failed to accept TCP connection")?;

            let service = Arc::clone(&service);

            tokio::spawn(async move {
                let tls_result =
                    service.tls_acceptor.accept(stream).await;

                let mut tls_stream = match tls_result {
                    Ok(stream) => stream,

                    Err(error) => {
                        eprintln!(
                            "mTLS handshake failed from {peer}: {error}"
                        );
                        return;
                    }
                };

                let client_certificate =
                    match tls_stream
                        .get_ref()
                        .1
                        .peer_certificates()
                    {
                        Some(certificates)
                            if !certificates.is_empty() =>
                        {
                            CertificateDer::from(
                                certificates[0].as_ref().to_vec()
                            )
                        }

                        _ => {
                            eprintln!(
                                "mTLS connection from {peer} did not \
                                 provide a client certificate"
                            );
                            return;
                        }
                    };

                let identity =
                    match identity_from_client_certificate(
                        &client_certificate,
                    ) {
                        Ok(identity) => identity,

                        Err(error) => {
                            eprintln!(
                                "failed to extract mTLS identity \
                                 from {peer}: {error}"
                            );
                            return;
                        }
                    };

                if let Err(error) = service
                    .handle_connection(
                        &mut tls_stream,
                        identity,
                    )
                    .await
                {
                    eprintln!(
                        "HTTP API request failed from {peer}: {error}"
                    );
                }
            });
        }
    }

    async fn handle_connection(
        &self,
        stream: &mut tokio_rustls::server::TlsStream<
            tokio::net::TcpStream,
        >,
        identity: MtlsIdentity,
    ) -> Result<()> {
        let mut buffer = vec![0u8; 64 * 1024];

        let bytes_read = stream
            .read(&mut buffer)
            .await
            .context("failed to read HTTP request")?;

        if bytes_read == 0 {
            return Ok(());
        }

        let request_bytes = &buffer[..bytes_read];

        let mut headers =
            [httparse::EMPTY_HEADER; 32];

        let mut request =
            httparse::Request::new(&mut headers);

        let status = request
            .parse(request_bytes)
            .context("failed to parse HTTP request")?;

        if !status.is_complete() {
            self.write_json(
                stream,
                400,
                &ErrorResponse {
                    error:
                        "incomplete HTTP request".to_string(),
                },
            )
            .await?;

            return Ok(());
        }

        let method =
            request.method.unwrap_or_default();

        let path =
            request.path.unwrap_or_default();

        let body_offset =
            status.unwrap();

        let body =
            &request_bytes[body_offset..];

        match (method, path) {
            ("GET", "/health") => {
                self.write_json(
                    stream,
                    200,
                    &HealthResponse {
                        status: "ok",
                        service: "daemon-pki",
                    },
                )
                .await?;
            }

            ("POST", "/v1/certificates/issue") => {
                self.handle_issue(
                    stream,
                    body,
                    identity,
                )
                .await?;
            }

            _ => {
                self.write_json(
                    stream,
                    404,
                    &ErrorResponse {
                        error:
                            "endpoint not found".to_string(),
                    },
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn handle_issue(
        &self,
        stream: &mut tokio_rustls::server::TlsStream<
            tokio::net::TcpStream,
        >,
        body: &[u8],
        identity: MtlsIdentity,
    ) -> Result<()> {
        let request: IssueRequest =
            match serde_json::from_slice(body) {
                Ok(value) => value,

                Err(_) => {
                    self.write_json(
                        stream,
                        400,
                        &ErrorResponse {
                            error:
                                "invalid JSON request body"
                                    .to_string(),
                        },
                    )
                    .await?;

                    return Ok(());
                }
            };

        let roles =
            self.authorization.roles_for(&identity);

        let principal =
            AuthenticatedPrincipal {
                id: identity.id,
                name: identity.name,
                roles,
            };

        let issuance_request =
            IssueCertificateRequest {
                common_name: request.common_name,
                dns_names: request.dns_names,
                ip_addresses: request.ip_addresses,
                client_auth: request.client_auth,
                server_auth: request.server_auth,
            };

        match self.issuance.issue(
            &principal,
            &self.intermediate_ca,
            issuance_request,
        ) {
            Ok((response, _audit)) => {
                self.write_json(
                    stream,
                    201,
                    &response,
                )
                .await?;
            }

            Err(error) => {
                let status_code =
                    if matches!(
                        error,
                        crate::issuance::IssuanceServiceError::Unauthorized
                    ) {
                        403
                    } else {
                        400
                    };

                self.write_json(
                    stream,
                    status_code,
                    &ErrorResponse {
                        error: error.to_string(),
                    },
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn write_json<T: Serialize>(
        &self,
        stream: &mut tokio_rustls::server::TlsStream<
            tokio::net::TcpStream,
        >,
        status_code: u16,
        value: &T,
    ) -> Result<()> {
        let body =
            serde_json::to_vec(value)
                .context(
                    "failed to serialize JSON response",
                )?;

        let reason = match status_code {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            _ => "Internal Server Error",
        };

        let response = format!(
            "HTTP/1.1 {status_code} {reason}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body.len()
        );

        stream
            .write_all(response.as_bytes())
            .await?;

        stream
            .write_all(&body)
            .await?;

        stream.shutdown().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_identity(
        name: &str,
        fingerprint: &str,
    ) -> MtlsIdentity {
        MtlsIdentity {
            id: Uuid::new_v4(),
            name: name.to_string(),
            serial_number: "test-serial".to_string(),
            fingerprint_sha256:
                fingerprint.to_string(),
        }
    }

    #[test]
    fn authorized_identity_receives_certificate_issue_role() {
        let policy =
            AuthorizationPolicy::new()
                .allow_certificate_issuance(
                    "authorized-fingerprint",
                );

        let identity =
            test_identity(
                "authorized-client.internal",
                "authorized-fingerprint",
            );

        assert!(
            policy.can_issue_certificates(&identity)
        );

        let roles =
            policy.roles_for(&identity);

        assert_eq!(
            roles,
            vec![
                "certificate:issue".to_string()
            ]
        );
    }

    #[test]
    fn unauthorized_identity_receives_no_roles() {
        let policy =
            AuthorizationPolicy::new()
                .allow_certificate_issuance(
                    "authorized-fingerprint",
                );

        let identity =
            test_identity(
                "unauthorized-client.internal",
                "unauthorized-fingerprint",
            );

        assert!(
            !policy.can_issue_certificates(&identity)
        );

        let roles =
            policy.roles_for(&identity);

        assert!(
            roles.is_empty()
        );
    }

    #[test]
    fn authorization_is_based_on_certificate_fingerprint() {
        let policy =
            AuthorizationPolicy::new()
                .allow_certificate_issuance(
                    "authorized-fingerprint",
                );

        let matching_identity =
            test_identity(
                "authorized-client.internal",
                "authorized-fingerprint",
            );

        let same_name_different_certificate =
            test_identity(
                "authorized-client.internal",
                "different-fingerprint",
            );

        assert!(
            policy.can_issue_certificates(
                &matching_identity
            )
        );

        assert!(
            !policy.can_issue_certificates(
                &same_name_different_certificate
            )
        );
    }
}




