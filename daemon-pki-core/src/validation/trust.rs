use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// A configured trust anchor.
///
/// The actual certificate DER is supplied by the caller.
/// Private key material is never part of a trust anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchor {
    pub id: Uuid,
    pub name: String,
    pub certificate_der: Vec<u8>,
    pub enabled: bool,
}

impl TrustAnchor {
    pub fn new(
        name: impl Into<String>,
        certificate_der: Vec<u8>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            certificate_der,
            enabled: true,
        }
    }
}

/// Collection of explicitly trusted roots.
#[derive(Debug, Default)]
pub struct TrustStore {
    anchors: Vec<TrustAnchor>,
}

#[derive(Debug, Error)]
pub enum TrustStoreError {
    #[error("trust anchor not found: {0}")]
    NotFound(Uuid),

    #[error("trust anchor is already registered: {0}")]
    AlreadyExists(Uuid),
}

impl TrustStore {
    pub fn new() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    pub fn add(
        &mut self,
        anchor: TrustAnchor,
    ) -> Result<Uuid, TrustStoreError> {
        if self.anchors.iter().any(|item| item.id == anchor.id) {
            return Err(TrustStoreError::AlreadyExists(anchor.id));
        }

        let id = anchor.id;
        self.anchors.push(anchor);

        Ok(id)
    }

    pub fn remove(
        &mut self,
        id: Uuid,
    ) -> Result<TrustAnchor, TrustStoreError> {
        let index = self
            .anchors
            .iter()
            .position(|anchor| anchor.id == id)
            .ok_or(TrustStoreError::NotFound(id))?;

        Ok(self.anchors.remove(index))
    }

    pub fn get(
        &self,
        id: Uuid,
    ) -> Result<&TrustAnchor, TrustStoreError> {
        self.anchors
            .iter()
            .find(|anchor| anchor.id == id)
            .ok_or(TrustStoreError::NotFound(id))
    }

    pub fn enabled(&self) -> impl Iterator<Item = &TrustAnchor> {
        self.anchors.iter().filter(|anchor| anchor.enabled)
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}
