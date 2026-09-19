use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditEventType {
    CertificateIssued,
    CertificateRenewed,
    CertificateRevoked,
    CertificateValidated,
    AuthorizationDenied,
    AuthenticationSucceeded,
    AuthenticationFailed,
    PolicyDenied,
    SecurityConfigurationChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditOutcome {
    Success,
    Denied,
    Failure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub event_type: AuditEventType,
    pub outcome: AuditOutcome,
    pub timestamp: OffsetDateTime,

    pub principal_id: Option<Uuid>,
    pub principal_name: Option<String>,

    pub certificate_id: Option<Uuid>,
    pub certificate_serial: Option<String>,

    pub resource: Option<String>,
    pub action: String,

    pub reason: Option<String>,
    pub metadata: serde_json::Value,
}

impl AuditEvent {
    pub fn new(
        event_type: AuditEventType,
        outcome: AuditOutcome,
        action: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_type,
            outcome,
            timestamp: OffsetDateTime::now_utc(),
            principal_id: None,
            principal_name: None,
            certificate_id: None,
            certificate_serial: None,
            resource: None,
            action: action.into(),
            reason: None,
            metadata: serde_json::json!({}),
        }
    }

    pub fn with_principal(
        mut self,
        principal_id: Uuid,
        principal_name: impl Into<String>,
    ) -> Self {
        self.principal_id = Some(principal_id);
        self.principal_name = Some(principal_name.into());
        self
    }

    pub fn with_certificate(
        mut self,
        certificate_id: Uuid,
        serial: impl Into<String>,
    ) -> Self {
        self.certificate_id = Some(certificate_id);
        self.certificate_serial = Some(serial.into());
        self
    }

    pub fn with_resource(
        mut self,
        resource: impl Into<String>,
    ) -> Self {
        self.resource = Some(resource.into());
        self
    }

    pub fn with_reason(
        mut self,
        reason: impl Into<String>,
    ) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn with_metadata(
        mut self,
        metadata: serde_json::Value,
    ) -> Self {
        self.metadata = metadata;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuditStore {
    events: Arc<RwLock<Vec<AuditEvent>>>,
}

impl AuditStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(
        &self,
        event: AuditEvent,
    ) {
        let mut events = self
            .events
            .write()
            .expect("audit store lock poisoned");

        events.push(event);
    }

    pub fn list(&self) -> Vec<AuditEvent> {
        let events = self
            .events
            .read()
            .expect("audit store lock poisoned");

        events.clone()
    }

    pub fn len(&self) -> usize {
        let events = self
            .events
            .read()
            .expect("audit store lock poisoned");

        events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        let mut events = self
            .events
            .write()
            .expect("audit store lock poisoned");

        events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_is_recorded() {
        let store = AuditStore::new();

        let principal_id =
            Uuid::new_v4();

        let event =
            AuditEvent::new(
                AuditEventType::CertificateIssued,
                AuditOutcome::Success,
                "certificate.issue",
            )
            .with_principal(
                principal_id,
                "test-client",
            )
            .with_resource(
                "certificate",
            );

        store.record(event);

        assert_eq!(store.len(), 1);

        let events = store.list();

        assert_eq!(
            events[0].event_type,
            AuditEventType::CertificateIssued
        );

        assert_eq!(
            events[0].outcome,
            AuditOutcome::Success
        );

        assert_eq!(
            events[0].principal_id,
            Some(principal_id)
        );

        assert_eq!(
            events[0].principal_name.as_deref(),
            Some("test-client")
        );
    }
}
