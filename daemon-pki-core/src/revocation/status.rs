use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Standard certificate revocation reasons.
///
/// These map to the X.509/PKIX revocation reason model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

/// Current revocation status for a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationStatus {
    Good,
    Revoked {
        reason: RevocationReason,
        revoked_at: OffsetDateTime,
        revoked_by: Uuid,
    },
    Unknown,
}

impl RevocationStatus {
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked { .. })
    }
}

/// Persistent revocation record.
///
/// This contains metadata only and never private key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub certificate_id: Uuid,
    pub serial_number: String,
    pub reason: RevocationReason,
    pub revoked_at: OffsetDateTime,
    pub revoked_by: Uuid,
    pub invalidity_date: Option<OffsetDateTime>,
    pub comment: Option<String>,
}

impl RevocationRecord {
    pub fn new(
        certificate_id: Uuid,
        serial_number: impl Into<String>,
        reason: RevocationReason,
        revoked_by: Uuid,
    ) -> Self {
        Self {
            certificate_id,
            serial_number: serial_number.into(),
            reason,
            revoked_at: OffsetDateTime::now_utc(),
            revoked_by,
            invalidity_date: None,
            comment: None,
        }
    }

    pub fn with_invalidity_date(
        mut self,
        date: OffsetDateTime,
    ) -> Self {
        self.invalidity_date = Some(date);
        self
    }

    pub fn with_comment(
        mut self,
        comment: impl Into<String>,
    ) -> Self {
        self.comment = Some(comment.into());
        self
    }
}
