use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use time::OffsetDateTime;
use uuid::Uuid;

/// The lifecycle state of a certificate managed by Daemon PKI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateState {
    Active,
    Expiring,
    RenewalPending,
    Renewed,
    Revoked,
    Expired,
}

impl CertificateState {
    pub fn is_usable(self) -> bool {
        matches!(self, Self::Active | Self::Expiring)
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked | Self::Expired)
    }
}

/// Cryptographic identity information associated with a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateIdentity {
    pub common_name: Option<String>,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<IpAddr>,
    pub client_auth: bool,
    pub server_auth: bool,
}

/// Complete inventory metadata for an issued certificate.
///
/// Private key material is intentionally NOT represented here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateMetadata {
    pub id: Uuid,
    pub serial_number: String,

    pub issuer: String,
    pub subject: String,

    pub identity: CertificateIdentity,

    pub state: CertificateState,

    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,

    pub fingerprint_sha256: Option<String>,

    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,

    pub renewal_window_seconds: i64,

    pub workload_id: Option<String>,
    pub device_id: Option<String>,
    pub service_id: Option<String>,

    pub tags: Vec<String>,
}

impl CertificateMetadata {
    pub fn new(
        serial_number: impl Into<String>,
        issuer: impl Into<String>,
        subject: impl Into<String>,
        identity: CertificateIdentity,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> Self {
        let now = OffsetDateTime::now_utc();

        Self {
            id: Uuid::new_v4(),
            serial_number: serial_number.into(),
            issuer: issuer.into(),
            subject: subject.into(),
            identity,
            state: CertificateState::Active,
            not_before,
            not_after,
            fingerprint_sha256: None,
            created_at: now,
            updated_at: now,
            renewal_window_seconds: 2_592_000,
            workload_id: None,
            device_id: None,
            service_id: None,
            tags: Vec::new(),
        }
    }

    pub fn expires_at(&self) -> OffsetDateTime {
        self.not_after
    }

    pub fn lifetime_seconds(&self) -> i64 {
        (self.not_after - self.not_before).whole_seconds()
    }

    pub fn remaining_seconds(&self) -> i64 {
        (self.not_after - OffsetDateTime::now_utc()).whole_seconds()
    }

    pub fn renewal_due(&self) -> bool {
        let remaining = self.remaining_seconds();

        remaining <= self.renewal_window_seconds && self.state.is_usable()
    }

    pub fn mark_fingerprint(&mut self, fingerprint: impl Into<String>) {
        self.fingerprint_sha256 = Some(fingerprint.into());
        self.updated_at = OffsetDateTime::now_utc();
    }

    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let tag = tag.into();

        if !self.tags.contains(&tag) {
            self.tags.push(tag);
            self.updated_at = OffsetDateTime::now_utc();
        }
    }

    pub fn assign_workload(&mut self, workload_id: impl Into<String>) {
        self.workload_id = Some(workload_id.into());
        self.updated_at = OffsetDateTime::now_utc();
    }

    pub fn assign_device(&mut self, device_id: impl Into<String>) {
        self.device_id = Some(device_id.into());
        self.updated_at = OffsetDateTime::now_utc();
    }

    pub fn assign_service(&mut self, service_id: impl Into<String>) {
        self.service_id = Some(service_id.into());
        self.updated_at = OffsetDateTime::now_utc();
    }
}
