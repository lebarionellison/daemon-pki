use std::sync::Arc;

use crate::audit::{
    AuditEvent,
    AuditEventType,
    AuditOutcome,
    AuditStore,
};

use crate::certificates::{
    CertificateRecord,
    CertificateStore,
};

use x509_parser::prelude::*;

use daemon_pki_core::{
    ca::IntermediateCa,
    certificate::{
        CertificateIssuer,
        CertificateRequest,
        IssuanceError,
    },
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedPrincipal {
    pub id: Uuid,
    pub name: String,
    pub roles: Vec<String>,
}

impl AuthenticatedPrincipal {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|item| item == role)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuancePolicy {
    pub max_dns_names: usize,
    pub max_ip_addresses: usize,
    pub max_common_name_length: usize,
    pub require_server_auth: bool,
    pub require_client_auth: bool,
}

impl Default for IssuancePolicy {
    fn default() -> Self {
        Self {
            max_dns_names: 100,
            max_ip_addresses: 100,
            max_common_name_length: 253,
            require_server_auth: false,
            require_client_auth: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueCertificateRequest {
    pub common_name: String,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub client_auth: bool,
    pub server_auth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueCertificateResponse {
    pub certificate_pem: String,
    pub issuer: String,
    pub common_name: String,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub client_auth: bool,
    pub server_auth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuanceAuditEvent {
    pub event_id: Uuid,
    pub principal_id: Uuid,
    pub principal_name: String,
    pub common_name: String,
    pub success: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Error)]
pub enum IssuanceServiceError {
    #[error("certificate store error: {0}")]
    CertificateStore(String),
    #[error("caller is not authorized to issue certificates")]
    Unauthorized,

    #[error("certificate request is invalid: {0}")]
    InvalidRequest(String),

    #[error("certificate issuance failed: {0}")]
    Issuance(#[from] IssuanceError),
}

pub struct IssuanceService {
    policy: IssuancePolicy,
    audit_store: Arc<AuditStore>,
    certificate_store: Arc<CertificateStore>,
}

impl IssuanceService {
    pub fn new(policy: IssuancePolicy) -> Self {
        Self {
            policy,
            audit_store: Arc::new(AuditStore::new()),
            certificate_store: Arc::new(CertificateStore::new()),
        }
    }

    pub fn with_audit_store(
        policy: IssuancePolicy,
        audit_store: Arc<AuditStore>,
    ) -> Self {
        Self {
            policy,
            audit_store,
            certificate_store: Arc::new(CertificateStore::new()),
        }
    }

    pub fn with_certificate_store(
        policy: IssuancePolicy,
        audit_store: Arc<AuditStore>,
        certificate_store: Arc<CertificateStore>,
    ) -> Self {
        Self {
            policy,
            audit_store,
            certificate_store,
        }
    }

    pub fn policy(&self) -> &IssuancePolicy {
        &self.policy
    }

    pub fn audit_store(&self) -> Arc<AuditStore> {
        Arc::clone(&self.audit_store)
    }

    pub fn certificate_store(&self) -> Arc<CertificateStore> {
        Arc::clone(&self.certificate_store)
    }

    fn record_event(
        &self,
        event_type: AuditEventType,
        outcome: AuditOutcome,
        principal: &AuthenticatedPrincipal,
        common_name: &str,
        reason: Option<String>,
    ) {
        let mut event = AuditEvent::new(
            event_type,
            outcome,
            "certificate.issue",
        )
        .with_principal(
            principal.id,
            principal.name.clone(),
        )
        .with_resource("certificate");

        if !common_name.is_empty() {
            event = event.with_metadata(
                serde_json::json!({
                    "common_name": common_name,
                }),
            );
        }

        if let Some(reason) = reason {
            event = event.with_reason(reason);
        }

        self.audit_store.record(event);
    }

    pub fn issue(
        &self,
        principal: &AuthenticatedPrincipal,
        ca: &IntermediateCa,
        request: IssueCertificateRequest,
    ) -> Result<
        (IssueCertificateResponse, IssuanceAuditEvent),
        IssuanceServiceError,
    > {
        if !principal.has_role("certificate:issue") {
            let reason =
                "caller is not authorized to issue certificates"
                    .to_string();

            self.record_event(
                AuditEventType::AuthorizationDenied,
                AuditOutcome::Denied,
                principal,
                &request.common_name,
                Some(reason.clone()),
            );

            return Err(
                IssuanceServiceError::Unauthorized,
            );
        }

        if let Err(error) =
            self.validate_request(&request)
        {
            let reason = error.to_string();

            self.record_event(
                AuditEventType::PolicyDenied,
                AuditOutcome::Denied,
                principal,
                &request.common_name,
                Some(reason.clone()),
            );

            return Err(error);
        }

        let mut certificate_request =
            CertificateRequest::new(&request.common_name);

        for dns_name in &request.dns_names {
            certificate_request =
                certificate_request.with_dns_name(dns_name);
        }

        for ip_address in &request.ip_addresses {
            let parsed = ip_address.parse().map_err(|_| {
                let reason =
                    format!("invalid IP address: {ip_address}");

                self.record_event(
                    AuditEventType::PolicyDenied,
                    AuditOutcome::Denied,
                    principal,
                    &request.common_name,
                    Some(reason.clone()),
                );

                IssuanceServiceError::InvalidRequest(
                    reason,
                )
            })?;

            certificate_request =
                certificate_request.with_ip_address(parsed);
        }

        certificate_request.client_auth =
            request.client_auth;

        certificate_request.server_auth =
            request.server_auth;

        let (certificate, _private_key) =
            match CertificateIssuer::issue(
                ca,
                certificate_request,
            ) {
                Ok(result) => result,

                Err(error) => {
                    let reason = error.to_string();

                    self.record_event(
                        AuditEventType::CertificateIssued,
                        AuditOutcome::Failure,
                        principal,
                        &request.common_name,
                        Some(reason),
                    );

                    return Err(
                        IssuanceServiceError::Issuance(error),
                    );
                }
            };

        let certificate_pem = certificate.pem();
        let certificate_der = certificate.der();

        let (_, parsed_certificate) =
            X509Certificate::from_der(certificate_der)
                .map_err(|error| {
                    IssuanceServiceError::CertificateStore(
                        format!(
                            "failed to parse issued certificate: {error}"
                        ),
                    )
                })?;

        let serial_number =
            parsed_certificate
                .tbs_certificate
                .serial
                .to_bytes_be();

        let serial_number = serial_number
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        let not_after =
            parsed_certificate
                .validity()
                .not_after
                .to_datetime();

        let certificate_record =
            CertificateRecord::new(
                serial_number,
                request.common_name.clone(),
                request.dns_names.clone(),
                request.ip_addresses.clone(),
                request.client_auth,
                request.server_auth,
                "Daemon PKI Intermediate CA".to_string(),
                certificate_pem.clone(),
                Some(not_after),
            );

        self.certificate_store
            .insert(certificate_record)
            .map_err(|error| IssuanceServiceError::CertificateStore(error.to_string()))?;

        let response = IssueCertificateResponse {
            certificate_pem,
            issuer: "Daemon PKI Intermediate CA".to_string(),
            common_name: request.common_name.clone(),
            dns_names: request.dns_names.clone(),
            ip_addresses: request.ip_addresses.clone(),
            client_auth: request.client_auth,
            server_auth: request.server_auth,
        };

        self.record_event(
            AuditEventType::CertificateIssued,
            AuditOutcome::Success,
            principal,
            &request.common_name,
            None,
        );

        let audit = IssuanceAuditEvent {
            event_id: Uuid::new_v4(),
            principal_id: principal.id,
            principal_name: principal.name.clone(),
            common_name: request.common_name,
            success: true,
            reason: None,
        };

        Ok((response, audit))
    }

    fn validate_request(
        &self,
        request: &IssueCertificateRequest,
    ) -> Result<(), IssuanceServiceError> {
        if request.common_name.trim().is_empty() {
            return Err(
                IssuanceServiceError::InvalidRequest(
                    "common name cannot be empty".to_string(),
                ),
            );
        }

        if request.common_name.len()
            > self.policy.max_common_name_length
        {
            return Err(
                IssuanceServiceError::InvalidRequest(
                    "common name exceeds policy limit"
                        .to_string(),
                ),
            );
        }

        if request.dns_names.len()
            > self.policy.max_dns_names
        {
            return Err(
                IssuanceServiceError::InvalidRequest(
                    "too many DNS names".to_string(),
                ),
            );
        }

        if request.ip_addresses.len()
            > self.policy.max_ip_addresses
        {
            return Err(
                IssuanceServiceError::InvalidRequest(
                    "too many IP addresses".to_string(),
                ),
            );
        }

        if request.dns_names.is_empty()
            && request.ip_addresses.is_empty()
        {
            return Err(
                IssuanceServiceError::InvalidRequest(
                    "certificate must contain at least one SAN identity"
                        .to_string(),
                ),
            );
        }

        if !request.client_auth
            && !request.server_auth
        {
            return Err(
                IssuanceServiceError::InvalidRequest(
                    "at least one extended key usage is required"
                        .to_string(),
                ),
            );
        }

        if self.policy.require_server_auth
            && !request.server_auth
        {
            return Err(
                IssuanceServiceError::InvalidRequest(
                    "server authentication is required by policy"
                        .to_string(),
                ),
            );
        }

        if self.policy.require_client_auth
            && !request.client_auth
        {
            return Err(
                IssuanceServiceError::InvalidRequest(
                    "client authentication is required by policy"
                        .to_string(),
                ),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_principal() -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            id: Uuid::new_v4(),
            name: "test-client".to_string(),
            roles: vec![
                "certificate:issue".to_string(),
            ],
        }
    }

    #[test]
    fn unauthorized_request_is_audited() {
        let service =
            IssuanceService::new(
                IssuancePolicy::default(),
            );

        let principal =
            AuthenticatedPrincipal {
                id: Uuid::new_v4(),
                name: "unauthorized-client".to_string(),
                roles: Vec::new(),
            };

        let root =
            daemon_pki_core::ca::RootCa::generate(
                "Daemon PKI Test Root",
            )
            .expect("root generation should succeed");

        let intermediate =
            IntermediateCa::generate(
                &root,
                "Daemon PKI Test Intermediate",
            )
            .expect("intermediate generation should succeed");

        let request = IssueCertificateRequest {
            common_name: "unauthorized.example.internal"
                .to_string(),
            dns_names: vec![
                "unauthorized.example.internal"
                    .to_string(),
            ],
            ip_addresses: Vec::new(),
            client_auth: false,
            server_auth: true,
        };

        let result =
            service.issue(
                &principal,
                &intermediate,
                request,
            );

        assert!(matches!(
            result,
            Err(IssuanceServiceError::Unauthorized)
        ));

        let events =
            service.audit_store().list();

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            AuditEventType::AuthorizationDenied
        );
        assert_eq!(
            events[0].outcome,
            AuditOutcome::Denied
        );
        assert_eq!(
            events[0].principal_id,
            Some(principal.id)
        );
    }

    #[test]
    fn invalid_request_is_audited() {
        let service =
            IssuanceService::new(
                IssuancePolicy::default(),
            );

        let principal = test_principal();

        let root =
            daemon_pki_core::ca::RootCa::generate(
                "Daemon PKI Test Root",
            )
            .expect("root generation should succeed");

        let intermediate =
            IntermediateCa::generate(
                &root,
                "Daemon PKI Test Intermediate",
            )
            .expect("intermediate generation should succeed");

        let request = IssueCertificateRequest {
            common_name: "invalid.example.internal"
                .to_string(),
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            client_auth: false,
            server_auth: false,
        };

        let result =
            service.issue(
                &principal,
                &intermediate,
                request,
            );

        assert!(matches!(
            result,
            Err(IssuanceServiceError::InvalidRequest(_))
        ));

        let events =
            service.audit_store().list();

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            AuditEventType::PolicyDenied
        );
        assert_eq!(
            events[0].outcome,
            AuditOutcome::Denied
        );
    }
}






