use super::status::RevocationStatus;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// OCSP response state.
///
/// This is the service-level model used before DER OCSP
/// response encoding is added.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspStatus {
    pub status: RevocationStatus,
    pub produced_at: OffsetDateTime,
    pub this_update: OffsetDateTime,
    pub next_update: Option<OffsetDateTime>,
}

impl OcspStatus {
    pub fn good() -> Self {
        let now = OffsetDateTime::now_utc();

        Self {
            status: RevocationStatus::Good,
            produced_at: now,
            this_update: now,
            next_update: None,
        }
    }

    pub fn revoked(
        status: RevocationStatus,
    ) -> Self {
        let now = OffsetDateTime::now_utc();

        Self {
            status,
            produced_at: now,
            this_update: now,
            next_update: None,
        }
    }

    pub fn unknown() -> Self {
        let now = OffsetDateTime::now_utc();

        Self {
            status: RevocationStatus::Unknown,
            produced_at: now,
            this_update: now,
            next_update: None,
        }
    }
}
