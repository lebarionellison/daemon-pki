use super::status::{RevocationRecord, RevocationReason};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// A revocation entry suitable for inclusion in a CRL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlEntry {
    pub serial_number: String,
    pub reason: RevocationReason,
    pub revoked_at: OffsetDateTime,
}

/// In-memory CRL model.
///
/// Cryptographic DER/PEM CRL encoding will be implemented
/// after the revocation data model and signing architecture
/// are established.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRevocationList {
    pub id: Uuid,
    pub issuer: String,
    pub generated_at: OffsetDateTime,
    pub next_update: OffsetDateTime,
    pub entries: Vec<CrlEntry>,
}

impl CertificateRevocationList {
    pub fn new(
        issuer: impl Into<String>,
        next_update: OffsetDateTime,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            issuer: issuer.into(),
            generated_at: OffsetDateTime::now_utc(),
            next_update,
            entries: Vec::new(),
        }
    }

    pub fn add_record(
        &mut self,
        record: &RevocationRecord,
    ) {
        self.entries.push(CrlEntry {
            serial_number: record.serial_number.clone(),
            reason: record.reason,
            revoked_at: record.revoked_at,
        });
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains_serial(
        &self,
        serial_number: &str,
    ) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.serial_number == serial_number)
    }
}
