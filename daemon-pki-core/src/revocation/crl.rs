use rcgen::{
    CertificateRevocationListParams,
    Issuer,
    KeyIdMethod,
    RevocationReason as RcgenRevocationReason,
    RevokedCertParams,
    SerialNumber,
    SigningKey,
};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::status::{RevocationReason, RevocationRecord};

#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    #[error("failed to generate signed certificate revocation list: {0}")]
    Generation(#[from] rcgen::Error),

    #[error("invalid certificate serial number in revocation list")]
    InvalidSerialNumber,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlEntry {
    pub serial_number: String,
    pub reason: RevocationReason,
    pub revoked_at: OffsetDateTime,
}

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

    pub fn signed_der(
        &self,
        issuer: &Issuer<'_, impl SigningKey>,
        crl_number: u64,
    ) -> Result<Vec<u8>, CrlError> {
        let mut revoked_certs = Vec::with_capacity(self.entries.len());

        for entry in &self.entries {
            let serial_bytes =
                hex_to_bytes(&entry.serial_number)
                    .ok_or(CrlError::InvalidSerialNumber)?;

            revoked_certs.push(RevokedCertParams {
                serial_number: SerialNumber::from(serial_bytes),
                revocation_time: entry.revoked_at,
                reason_code: Some(map_reason(entry.reason)),
                invalidity_date: None,
            });
        }

        let params = CertificateRevocationListParams {
            this_update: self.generated_at,
            next_update: self.next_update,
            crl_number: SerialNumber::from(crl_number),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };

        let crl = params.signed_by(issuer)?;

        Ok(crl.der().as_ref().to_vec())
    }
}

fn map_reason(reason: RevocationReason) -> RcgenRevocationReason {
    match reason {
        RevocationReason::Unspecified => {
            RcgenRevocationReason::Unspecified
        }
        RevocationReason::KeyCompromise => {
            RcgenRevocationReason::KeyCompromise
        }
        RevocationReason::CaCompromise => {
            RcgenRevocationReason::CaCompromise
        }
        RevocationReason::AffiliationChanged => {
            RcgenRevocationReason::AffiliationChanged
        }
        RevocationReason::Superseded => {
            RcgenRevocationReason::Superseded
        }
        RevocationReason::CessationOfOperation => {
            RcgenRevocationReason::CessationOfOperation
        }
        RevocationReason::CertificateHold => {
            RcgenRevocationReason::CertificateHold
        }
        RevocationReason::RemoveFromCrl => {
            RcgenRevocationReason::RemoveFromCrl
        }
        RevocationReason::PrivilegeWithdrawn => {
            RcgenRevocationReason::PrivilegeWithdrawn
        }
        RevocationReason::AaCompromise => {
            RcgenRevocationReason::AaCompromise
        }
    }
}

fn hex_to_bytes(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % 2 != 0 {
        return None;
    }

    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(
                &value[index..index + 2],
                16,
            )
            .ok()
        })
        .collect()
}
