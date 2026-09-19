use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityType {
    Device,
    Workload,
    Service,
    Human,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityStatus {
    Active,
    Disabled,
    Revoked,
}

impl IdentityStatus {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineIdentity {
    pub id: Uuid,
    pub name: String,
    pub identity_type: IdentityType,
    pub certificate_fingerprint_sha256: String,
    pub status: IdentityStatus,
    pub roles: Vec<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl MachineIdentity {
    pub fn new(
        name: impl Into<String>,
        identity_type: IdentityType,
        certificate_fingerprint_sha256: impl Into<String>,
    ) -> Self {
        let now = OffsetDateTime::now_utc();

        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            identity_type,
            certificate_fingerprint_sha256:
                certificate_fingerprint_sha256.into(),
            status: IdentityStatus::Active,
            roles: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_role(
        mut self,
        role: impl Into<String>,
    ) -> Self {
        let role = role.into();

        if !self.roles.iter().any(|item| item == &role) {
            self.roles.push(role);
        }

        self
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|item| item == role)
    }

    pub fn disable(&mut self) {
        if !self.status.is_terminal() {
            self.status = IdentityStatus::Disabled;
            self.updated_at = OffsetDateTime::now_utc();
        }
    }

    pub fn enable(&mut self) {
        if !self.status.is_terminal() {
            self.status = IdentityStatus::Active;
            self.updated_at = OffsetDateTime::now_utc();
        }
    }

    pub fn revoke(&mut self) {
        self.status = IdentityStatus::Revoked;
        self.updated_at = OffsetDateTime::now_utc();
    }
}

#[derive(Debug, Error)]
pub enum IdentityRegistryError {
    #[error("identity already exists: {0}")]
    AlreadyExists(Uuid),

    #[error(
        "certificate fingerprint is already bound to identity: {0}"
    )]
    FingerprintAlreadyBound(Uuid),

    #[error("identity not found: {0}")]
    NotFound(Uuid),

    #[error(
        "certificate fingerprint not found: {0}"
    )]
    FingerprintNotFound(String),

    #[error("identity is not active: {0}")]
    NotActive(Uuid),
}

#[derive(Debug, Default)]
pub struct IdentityRegistry {
    identities: HashMap<Uuid, MachineIdentity>,
    fingerprints: HashMap<String, Uuid>,
}

impl IdentityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        identity: MachineIdentity,
    ) -> Result<Uuid, IdentityRegistryError> {
        if self.identities.contains_key(&identity.id) {
            return Err(
                IdentityRegistryError::AlreadyExists(
                    identity.id,
                ),
            );
        }

        if let Some(existing_id) =
            self.fingerprints
                .get(
                    &identity
                        .certificate_fingerprint_sha256,
                )
        {
            return Err(
                IdentityRegistryError::FingerprintAlreadyBound(
                    *existing_id,
                ),
            );
        }

        let id = identity.id;

        self.fingerprints.insert(
            identity
                .certificate_fingerprint_sha256
                .clone(),
            id,
        );

        self.identities.insert(id, identity);

        Ok(id)
    }

    pub fn get(
        &self,
        id: Uuid,
    ) -> Option<&MachineIdentity> {
        self.identities.get(&id)
    }

    pub fn get_mut(
        &mut self,
        id: Uuid,
    ) -> Option<&mut MachineIdentity> {
        self.identities.get_mut(&id)
    }

    pub fn find_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Option<&MachineIdentity> {
        let id =
            self.fingerprints.get(fingerprint)?;

        self.identities.get(id)
    }

    pub fn authorize(
        &self,
        fingerprint: &str,
        role: &str,
    ) -> Result<&MachineIdentity, IdentityRegistryError> {
        let identity =
            self.find_by_fingerprint(fingerprint)
                .ok_or_else(|| {
                    IdentityRegistryError::FingerprintNotFound(
                        fingerprint.to_string(),
                    )
                })?;

        if !identity.status.is_active() {
            return Err(
                IdentityRegistryError::NotActive(
                    identity.id,
                ),
            );
        }

        if !identity.has_role(role) {
            return Err(
                IdentityRegistryError::NotActive(
                    identity.id,
                ),
            );
        }

        Ok(identity)
    }

    pub fn disable(
        &mut self,
        id: Uuid,
    ) -> Result<(), IdentityRegistryError> {
        let identity =
            self.get_mut(id)
                .ok_or(
                    IdentityRegistryError::NotFound(id)
                )?;

        identity.disable();

        Ok(())
    }

    pub fn enable(
        &mut self,
        id: Uuid,
    ) -> Result<(), IdentityRegistryError> {
        let identity =
            self.get_mut(id)
                .ok_or(
                    IdentityRegistryError::NotFound(id)
                )?;

        identity.enable();

        Ok(())
    }

    pub fn revoke(
        &mut self,
        id: Uuid,
    ) -> Result<(), IdentityRegistryError> {
        let identity =
            self.get_mut(id)
                .ok_or(
                    IdentityRegistryError::NotFound(id)
                )?;

        identity.revoke();

        Ok(())
    }

    pub fn len(&self) -> usize {
        self.identities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    pub fn list(&self) -> Vec<&MachineIdentity> {
        self.identities.values().collect()
    }
}
