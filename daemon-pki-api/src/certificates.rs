use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRecord {
    pub id: Uuid,
    pub serial_number: String,
    pub common_name: String,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub client_auth: bool,
    pub server_auth: bool,
    pub issuer: String,
    pub certificate_pem: String,
    pub issued_at: OffsetDateTime,
    pub not_after: Option<OffsetDateTime>,
    pub revoked: bool,
    pub revoked_at: Option<OffsetDateTime>,
    pub revocation_reason: Option<String>,
}

impl CertificateRecord {
    pub fn new(
        serial_number: String,
        common_name: String,
        dns_names: Vec<String>,
        ip_addresses: Vec<String>,
        client_auth: bool,
        server_auth: bool,
        issuer: String,
        certificate_pem: String,
        not_after: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            serial_number,
            common_name,
            dns_names,
            ip_addresses,
            client_auth,
            server_auth,
            issuer,
            certificate_pem,
            issued_at: OffsetDateTime::now_utc(),
            not_after,
            revoked: false,
            revoked_at: None,
            revocation_reason: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum CertificateStoreError {
    #[error("certificate store I/O failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("certificate store serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct CertificateStore {
    path: Arc<PathBuf>,
    records: Arc<RwLock<HashMap<Uuid, CertificateRecord>>>,
}

impl CertificateStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, CertificateStoreError> {
        let path = path.as_ref().to_path_buf();

        let records = if path.exists() {
            let contents = fs::read_to_string(&path)?;

            if contents.trim().is_empty() {
                HashMap::new()
            } else {
                serde_json::from_str(&contents)?
            }
        } else {
            HashMap::new()
        };

        Ok(Self {
            path: Arc::new(path),
            records: Arc::new(RwLock::new(records)),
        })
    }

    pub fn path(&self) -> &Path {
        self.path.as_ref()
    }

    pub fn insert(
        &self,
        record: CertificateRecord,
    ) -> Result<Uuid, CertificateStoreError> {
        let id = record.id;

        {
            let mut records = self
                .records
                .write()
                .expect("certificate store lock poisoned");

            records.insert(id, record);
        }

        self.persist()?;

        Ok(id)
    }

    pub fn get(
        &self,
        id: Uuid,
    ) -> Option<CertificateRecord> {
        let records = self
            .records
            .read()
            .expect("certificate store lock poisoned");

        records.get(&id).cloned()
    }

    pub fn list(&self) -> Vec<CertificateRecord> {
        let records = self
            .records
            .read()
            .expect("certificate store lock poisoned");

        let mut result =
            records.values().cloned().collect::<Vec<_>>();

        result.sort_by(|a, b| {
            b.issued_at.cmp(&a.issued_at)
        });

        result
    }

    pub fn revoke(
        &self,
        id: Uuid,
        reason: String,
    ) -> Result<Option<CertificateRecord>, CertificateStoreError> {
        let updated = {
            let mut records = self
                .records
                .write()
                .expect("certificate store lock poisoned");

            let Some(record) = records.get_mut(&id) else {
                return Ok(None);
            };

            if !record.revoked {
                record.revoked = true;
                record.revoked_at =
                    Some(OffsetDateTime::now_utc());
                record.revocation_reason = Some(reason);
            }

            record.clone()
        };

        self.persist()?;

        Ok(Some(updated))
    }

    pub fn is_revoked_serial(
        &self,
        serial_number: &str,
    ) -> bool {
        let records = self
            .records
            .read()
            .expect("certificate store lock poisoned");

        records
            .values()
            .any(|record| {
                record.serial_number == serial_number
                    && record.revoked
            })
    }
    pub fn remove(
        &self,
        id: Uuid,
    ) -> Result<Option<CertificateRecord>, CertificateStoreError> {
        let removed = {
            let mut records = self
                .records
                .write()
                .expect("certificate store lock poisoned");

            records.remove(&id)
        };

        if removed.is_some() {
            self.persist()?;
        }

        Ok(removed)
    }

    pub fn len(&self) -> usize {
        let records = self
            .records
            .read()
            .expect("certificate store lock poisoned");

        records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn persist(&self) -> Result<(), CertificateStoreError> {
        let records = self
            .records
            .read()
            .expect("certificate store lock poisoned");

        let serialized =
            serde_json::to_string_pretty(&*records)?;

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let temporary_path =
            self.path.with_extension("json.tmp");

        fs::write(&temporary_path, serialized)?;

        fs::rename(&temporary_path, self.path.as_ref())?;

        Ok(())
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self {
            path: Arc::new(
                PathBuf::from(
                    "data/pki/certificates.json",
                ),
            ),
            records: Arc::new(
                RwLock::new(HashMap::new()),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_record() -> CertificateRecord {
        CertificateRecord::new(
            "01".to_string(),
            "workload.example.internal".to_string(),
            vec![
                "workload.example.internal".to_string(),
            ],
            Vec::new(),
            true,
            true,
            "Daemon PKI Intermediate CA".to_string(),
            "-----BEGIN CERTIFICATE-----".to_string(),
            None,
        )
    }

    #[test]
    fn certificate_store_tracks_and_revokes_certificate() {
        let temp_dir =
            std::env::temp_dir().join(format!(
                "daemon-pki-cert-store-{}",
                Uuid::new_v4()
            ));

        let path =
            temp_dir.join("certificates.json");

        let store =
            CertificateStore::open(&path)
                .expect("store should open");

        let id =
            store
                .insert(test_record())
                .expect("insert should succeed");

        assert_eq!(store.len(), 1);

        let stored =
            store.get(id)
                .expect("certificate should exist");

        assert!(!stored.revoked);

        let revoked =
            store
                .revoke(
                    id,
                    "operator requested revocation"
                        .to_string(),
                )
                .expect("revoke should succeed")
                .expect("certificate should exist");

        assert!(revoked.revoked);
        assert!(revoked.revoked_at.is_some());

        let reopened =
            CertificateStore::open(&path)
                .expect("store should reopen");

        let persisted =
            reopened
                .get(id)
                .expect("certificate should persist");

        assert!(persisted.revoked);

        let _ =
            fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn removing_certificate_removes_it_from_inventory() {
        let temp_dir =
            std::env::temp_dir().join(format!(
                "daemon-pki-cert-store-{}",
                Uuid::new_v4()
            ));

        let path =
            temp_dir.join("certificates.json");

        let store =
            CertificateStore::open(&path)
                .expect("store should open");

        let id =
            store
                .insert(test_record())
                .expect("insert should succeed");

        assert!(store.get(id).is_some());

        store
            .remove(id)
            .expect("remove should succeed");

        assert!(store.get(id).is_none());

        let reopened =
            CertificateStore::open(&path)
                .expect("store should reopen");

        assert!(reopened.is_empty());

        let _ =
            fs::remove_dir_all(temp_dir);
    }
}
