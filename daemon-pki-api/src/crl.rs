use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use daemon_pki_core::revocation::{
    CertificateRevocationList,
    RevocationReason,
    RevocationRecord,
};
use daemon_pki_core::ca::IntermediateCa;
use time::Duration;
use uuid::Uuid;

use crate::certificates::CertificateStore;

pub struct CrlManager {
    data_dir: PathBuf,
    certificate_store: Arc<CertificateStore>,
    intermediate_ca: Arc<IntermediateCa>,
}

impl CrlManager {
    pub fn new(
        data_dir: impl Into<PathBuf>,
        certificate_store: Arc<CertificateStore>,
        intermediate_ca: Arc<IntermediateCa>,
    ) -> Self {
        Self {
            data_dir: data_dir.into(),
            certificate_store,
            intermediate_ca,
        }
    }

    pub fn generate_and_persist(&self) -> Result<Vec<u8>> {
        let crl_number = self.next_crl_number()?;

        let now = time::OffsetDateTime::now_utc();
        let next_update = now + Duration::days(7);

        let mut crl = CertificateRevocationList::new(
            "Daemon PKI Intermediate CA",
            next_update,
        );

        for certificate in self.certificate_store.list() {
            if !certificate.revoked {
                continue;
            }

            let reason = parse_reason(
                certificate
                    .revocation_reason
                    .as_deref()
                    .unwrap_or("unspecified"),
            );

            let revoked_by = Uuid::nil();

            let record = RevocationRecord {
                certificate_id: certificate.id,
                serial_number: certificate.serial_number.clone(),
                reason,
                revoked_at: certificate
                    .revoked_at
                    .unwrap_or(now),
                revoked_by,
                invalidity_date: None,
                comment: None,
            };

            crl.add_record(&record);
        }

        let der = crl
            .signed_der(
                &self.intermediate_ca.issuer,
                crl_number,
            )
            .context("failed to sign certificate revocation list")?;

        let crl_path =
            self.data_dir.join("intermediate-ca.crl.der");

        fs::write(&crl_path, &der)
            .with_context(|| {
                format!(
                    "failed to persist CRL to {}",
                    crl_path.display()
                )
            })?;

        Ok(der)
    }

    fn next_crl_number(&self) -> Result<u64> {
        let path =
            self.data_dir.join("crl-number");

        let current = if Path::new(&path).exists() {
            let value =
                fs::read_to_string(&path)
                    .with_context(|| {
                        format!(
                            "failed to read {}",
                            path.display()
                        )
                    })?;

            value
                .trim()
                .parse::<u64>()
                .context("invalid persisted CRL number")?
        } else {
            0
        };

        let next = current
            .checked_add(1)
            .context("CRL number exhausted")?;

        fs::write(&path, next.to_string())
            .with_context(|| {
                format!(
                    "failed to persist CRL number to {}",
                    path.display()
                )
            })?;

        Ok(next)
    }
}

fn parse_reason(value: &str) -> RevocationReason {
    match value.trim().to_ascii_lowercase().as_str() {
        "keycompromise" | "key_compromise" | "key compromise" => {
            RevocationReason::KeyCompromise
        }
        "cacompromise" | "ca_compromise" | "ca compromise" => {
            RevocationReason::CaCompromise
        }
        "affiliationchanged"
        | "affiliation_changed"
        | "affiliation changed" => {
            RevocationReason::AffiliationChanged
        }
        "superseded" => RevocationReason::Superseded,
        "cessationofoperation"
        | "cessation_of_operation"
        | "cessation of operation" => {
            RevocationReason::CessationOfOperation
        }
        "certificatehold"
        | "certificate_hold"
        | "certificate hold" => {
            RevocationReason::CertificateHold
        }
        "removefromcrl"
        | "remove_from_crl"
        | "remove from crl" => {
            RevocationReason::RemoveFromCrl
        }
        "privilegelwithdrawn"
        | "privilegewithdrawn"
        | "privilege_withdrawn"
        | "privilege withdrawn" => {
            RevocationReason::PrivilegeWithdrawn
        }
        "aacompromise" | "aa_compromise" | "aa compromise" => {
            RevocationReason::AaCompromise
        }
        _ => RevocationReason::Unspecified,
    }
}
