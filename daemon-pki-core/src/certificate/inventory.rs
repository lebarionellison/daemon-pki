use super::lifecycle::{LifecycleError, LifecycleManager};
use super::metadata::{CertificateMetadata, CertificateState};

use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("certificate already exists in inventory: {0}")]
    AlreadyExists(Uuid),

    #[error("certificate not found in inventory: {0}")]
    NotFound(Uuid),

    #[error("certificate serial number already exists: {0}")]
    DuplicateSerial(String),

    #[error("certificate fingerprint already exists: {0}")]
    DuplicateFingerprint(String),

    #[error("lifecycle operation failed: {0}")]
    Lifecycle(#[from] LifecycleError),
}

/// Central certificate inventory.
///
/// This stores certificate metadata only.
/// Private key material is intentionally never stored here.
#[derive(Debug, Default)]
pub struct CertificateInventory {
    certificates: HashMap<Uuid, CertificateMetadata>,
    serial_index: HashMap<String, Uuid>,
    fingerprint_index: HashMap<String, Uuid>,
}

impl CertificateInventory {
    pub fn new() -> Self {
        Self {
            certificates: HashMap::new(),
            serial_index: HashMap::new(),
            fingerprint_index: HashMap::new(),
        }
    }

    /// Register a new certificate.
    pub fn register(
        &mut self,
        certificate: CertificateMetadata,
    ) -> Result<Uuid, InventoryError> {
        let id = certificate.id;
        let serial = certificate.serial_number.clone();
        let fingerprint =
            certificate.fingerprint_sha256.clone();

        if self.certificates.contains_key(&id) {
            return Err(InventoryError::AlreadyExists(id));
        }

        if self.serial_index.contains_key(&serial) {
            return Err(InventoryError::DuplicateSerial(serial));
        }

        self.serial_index.insert(serial, id);
        if let Some(fingerprint) = fingerprint {
            self.fingerprint_index.insert(fingerprint, id);
        }
        self.certificates.insert(id, certificate);

        Ok(id)
    }

    /// Replace an existing certificate with its renewed successor.
    pub fn register_renewal(
        &mut self,
        previous_id: Uuid,
        mut replacement: CertificateMetadata,
    ) -> Result<Uuid, InventoryError> {
        let associations = {
            let previous = self.get_mut(previous_id)?;

            LifecycleManager::transition(
                previous,
                CertificateState::Renewed,
            )?;

            (
                previous.workload_id.clone(),
                previous.device_id.clone(),
                previous.service_id.clone(),
                previous.tags.clone(),
            )
        };

        replacement.state = CertificateState::Active;
        replacement.workload_id = associations.0;
        replacement.device_id = associations.1;
        replacement.service_id = associations.2;
        replacement.tags = associations.3;

        self.register(replacement)
    }
    /// Retrieve certificate metadata by ID.
    pub fn get(
        &self,
        id: Uuid,
    ) -> Result<&CertificateMetadata, InventoryError> {
        self.certificates
            .get(&id)
            .ok_or(InventoryError::NotFound(id))
    }

    /// Retrieve mutable certificate metadata by ID.
    pub fn get_mut(
        &mut self,
        id: Uuid,
    ) -> Result<&mut CertificateMetadata, InventoryError> {
        self.certificates
            .get_mut(&id)
            .ok_or(InventoryError::NotFound(id))
    }

    /// Find a certificate by serial number.
    pub fn find_by_serial(
        &self,
        serial: &str,
    ) -> Result<&CertificateMetadata, InventoryError> {
        let id = self
            .serial_index
            .get(serial)
            .copied()
            .ok_or_else(|| {
                InventoryError::NotFound(
                    Uuid::nil(),
                )
            })?;

        self.get(id)
    }

    /// Find a certificate by SHA-256 fingerprint.
    pub fn find_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<&CertificateMetadata, InventoryError> {
        let id = self
            .fingerprint_index
            .get(fingerprint)
            .copied()
            .ok_or(InventoryError::NotFound(Uuid::nil()))?;

        self.get(id)
    }

    /// Resolve the certificate ID associated with a fingerprint.
    pub fn id_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Uuid, InventoryError> {
        self.fingerprint_index
            .get(fingerprint)
            .copied()
            .ok_or(InventoryError::NotFound(Uuid::nil()))
    }

    /// Remove a certificate from the inventory.
    pub fn remove(
        &mut self,
        id: Uuid,
    ) -> Result<CertificateMetadata, InventoryError> {
        let certificate = self
            .certificates
            .remove(&id)
            .ok_or(InventoryError::NotFound(id))?;

        self.serial_index.remove(&certificate.serial_number);
        if let Some(fingerprint) =
            &certificate.fingerprint_sha256
        {
            self.fingerprint_index.remove(fingerprint);
        }

        Ok(certificate)
    }

    /// Number of certificates currently tracked.
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Whether the inventory is empty.
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Return all certificates.
    pub fn all(&self) -> Vec<&CertificateMetadata> {
        self.certificates.values().collect()
    }

    /// Return certificates matching a lifecycle state.
    pub fn by_state(
        &self,
        state: CertificateState,
    ) -> Vec<&CertificateMetadata> {
        self.certificates
            .values()
            .filter(|certificate| certificate.state == state)
            .collect()
    }

    /// Return certificates that are approaching renewal.
    pub fn renewal_candidates(&self) -> Vec<&CertificateMetadata> {
        self.certificates
            .values()
            .filter(|certificate| certificate.renewal_due())
            .collect()
    }

    /// Evaluate lifecycle state for every certificate.
    ///
    /// Returns the number of certificates whose state changed.
    pub fn evaluate_lifecycle(
        &mut self,
    ) -> Result<usize, InventoryError> {
        let ids: Vec<Uuid> = self.certificates.keys().copied().collect();

        let mut changed = 0;

        for id in ids {
            let certificate = self
                .certificates
                .get_mut(&id)
                .ok_or(InventoryError::NotFound(id))?;

            let before = certificate.state;

            LifecycleManager::evaluate(certificate)?;

            if before != certificate.state {
                changed += 1;
            }
        }

        Ok(changed)
    }

    /// Mark a certificate as revoked.
    pub fn revoke(
        &mut self,
        id: Uuid,
    ) -> Result<(), InventoryError> {
        let certificate = self.get_mut(id)?;

        LifecycleManager::transition(
            certificate,
            CertificateState::Revoked,
        )?;

        Ok(())
    }

    /// Mark a certificate as renewed.
    pub fn mark_renewed(
        &mut self,
        id: Uuid,
    ) -> Result<(), InventoryError> {
        let certificate = self.get_mut(id)?;

        LifecycleManager::transition(
            certificate,
            CertificateState::Renewed,
        )?;

        Ok(())
    }

    /// Count certificates in each lifecycle state.
    pub fn state_counts(&self) -> InventoryStateCounts {
        let mut counts = InventoryStateCounts::default();

        for certificate in self.certificates.values() {
            match certificate.state {
                CertificateState::Active => counts.active += 1,
                CertificateState::Expiring => counts.expiring += 1,
                CertificateState::RenewalPending => {
                    counts.renewal_pending += 1
                }
                CertificateState::Renewed => counts.renewed += 1,
                CertificateState::Revoked => counts.revoked += 1,
                CertificateState::Expired => counts.expired += 1,
            }
        }

        counts
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct InventoryStateCounts {
    pub active: usize,
    pub expiring: usize,
    pub renewal_pending: usize,
    pub renewed: usize,
    pub revoked: usize,
    pub expired: usize,
}

impl InventoryStateCounts {
    pub fn total(&self) -> usize {
        self.active
            + self.expiring
            + self.renewal_pending
            + self.renewed
            + self.revoked
            + self.expired
    }
}










