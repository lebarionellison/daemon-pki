use super::issuance::CertificateRequest;
use super::metadata::{
    CertificateIdentity,
    CertificateMetadata,
    CertificateState,
};

use time::OffsetDateTime;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum LifecycleError {
    #[error(
        "certificate lifecycle transition is not permitted: {from:?} -> {to:?}"
    )]
    InvalidTransition {
        from: CertificateState,
        to: CertificateState,
    },

    #[error("certificate is already in terminal state: {0:?}")]
    TerminalState(CertificateState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalAction {
    None,
    Renew,
    Revoke,
}

impl RenewalAction {
    pub fn requires_action(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Debug, Clone)]
pub struct RenewalWorkItem {
    pub certificate_id: Uuid,
    pub action: RenewalAction,
    pub attempts: u32,
    pub queued_at: OffsetDateTime,
    pub identity: CertificateIdentity,
}

impl RenewalWorkItem {
    pub fn new(
        certificate: &CertificateMetadata,
    ) -> Option<Self> {
        let action =
            LifecycleManager::renewal_action(certificate);

        if !action.requires_action() {
            return None;
        }

        Some(Self {
            certificate_id: certificate.id,
            action,
            attempts: 0,
            queued_at: OffsetDateTime::now_utc(),
            identity: certificate.identity.clone(),
        })
    }

    pub fn mark_attempt(&mut self) {
        self.attempts =
            self.attempts.saturating_add(1);
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    pub fn queued_at(&self) -> OffsetDateTime {
        self.queued_at
    }

    pub fn identity(&self) -> &CertificateIdentity {
        &self.identity
    }

    pub fn certificate_request(&self) -> CertificateRequest {
        let common_name = self
            .identity
            .common_name
            .clone()
            .unwrap_or_default();

        let mut request =
            CertificateRequest::new(common_name);

        for dns_name in &self.identity.dns_names {
            request =
                request.with_dns_name(
                    dns_name.clone(),
                );
        }

        for ip_address in
            &self.identity.ip_addresses
        {
            request =
                request.with_ip_address(
                    *ip_address,
                );
        }

        request.client_auth =
            self.identity.client_auth;

        request.server_auth =
            self.identity.server_auth;

        request
    }
}

pub struct RenewalExecutor;

impl RenewalExecutor {
    pub fn issue_replacement(
        ca: &crate::ca::IntermediateCa,
        work_item: &mut RenewalWorkItem,
    ) -> Result<
        (
            rcgen::Certificate,
            rcgen::KeyPair,
        ),
        crate::certificate::IssuanceError,
    > {
        if work_item.action != RenewalAction::Renew {
            return Err(
                crate::certificate::IssuanceError::Policy(
                    "renewal work item does not require certificate renewal"
                        .to_string(),
                ),
            );
        }

        work_item.mark_attempt();

        let request =
            work_item.certificate_request();

        crate::certificate::CertificateIssuer::issue(
            ca,
            request,
        )
    }

    pub fn renew_into_inventory(
        inventory: &mut crate::certificate::CertificateInventory,
        replacement: CertificateMetadata,
        work_item: &mut RenewalWorkItem,
    ) -> Result<Uuid, LifecycleError> {
        if work_item.action != RenewalAction::Renew {
            return Err(
                LifecycleError::InvalidTransition {
                    from: CertificateState::Active,
                    to: CertificateState::Active,
                },
            );
        }

        inventory
            .register_renewal(
                work_item.certificate_id,
                replacement,
            )
            .map_err(|error| match error {
                crate::certificate::InventoryError::Lifecycle(
                    lifecycle_error,
                ) => lifecycle_error,

                _ => LifecycleError::InvalidTransition {
                    from: CertificateState::Active,
                    to: CertificateState::Renewed,
                },
            })
    }
}

pub struct LifecycleManager;

impl LifecycleManager {
    pub fn transition(
        certificate: &mut CertificateMetadata,
        next: CertificateState,
    ) -> Result<(), LifecycleError> {
        let current = certificate.state;

        if current == next {
            return Ok(());
        }

        if current.is_terminal() {
            return Err(
                LifecycleError::TerminalState(current)
            );
        }

        let allowed = match (current, next) {
            (
                CertificateState::Active,
                CertificateState::Expiring,
            ) => true,

            (
                CertificateState::Active,
                CertificateState::RenewalPending,
            ) => true,

            (
                CertificateState::Active,
                CertificateState::Revoked,
            ) => true,

            (
                CertificateState::Active,
                CertificateState::Expired,
            ) => true,

            (
                CertificateState::Expiring,
                CertificateState::RenewalPending,
            ) => true,

            (
                CertificateState::Expiring,
                CertificateState::Revoked,
            ) => true,

            (
                CertificateState::Expiring,
                CertificateState::Expired,
            ) => true,

            (
                CertificateState::RenewalPending,
                CertificateState::Renewed,
            ) => true,

            (
                CertificateState::RenewalPending,
                CertificateState::Revoked,
            ) => true,

            (
                CertificateState::RenewalPending,
                CertificateState::Expired,
            ) => true,

            (
                CertificateState::Renewed,
                CertificateState::Active,
            ) => true,

            (
                CertificateState::Renewed,
                CertificateState::Expiring,
            ) => true,

            (
                CertificateState::Renewed,
                CertificateState::RenewalPending,
            ) => true,

            (
                CertificateState::Renewed,
                CertificateState::Revoked,
            ) => true,

            (
                CertificateState::Renewed,
                CertificateState::Expired,
            ) => true,

            _ => false,
        };

        if !allowed {
            return Err(
                LifecycleError::InvalidTransition {
                    from: current,
                    to: next,
                },
            );
        }

        certificate.state = next;
        certificate.updated_at =
            OffsetDateTime::now_utc();

        Ok(())
    }

    pub fn evaluate(
        certificate: &mut CertificateMetadata,
    ) -> Result<CertificateState, LifecycleError> {
        let now =
            OffsetDateTime::now_utc();

        if now >= certificate.not_after {
            if certificate.state
                != CertificateState::Expired
            {
                Self::transition(
                    certificate,
                    CertificateState::Expired,
                )?;
            }

            return Ok(certificate.state);
        }

        if certificate.renewal_due()
            && certificate.state
                == CertificateState::Active
        {
            Self::transition(
                certificate,
                CertificateState::Expiring,
            )?;
        }

        Ok(certificate.state)
    }

    pub fn renewal_action(
        certificate: &CertificateMetadata,
    ) -> RenewalAction {
        match certificate.state {
            CertificateState::Active
                if certificate.renewal_due() =>
            {
                RenewalAction::Renew
            }

            CertificateState::Expiring
            | CertificateState::RenewalPending => {
                RenewalAction::Renew
            }

            CertificateState::Expired
            | CertificateState::Revoked => {
                RenewalAction::Revoke
            }

            _ => RenewalAction::None,
        }
    }

    pub fn evaluate_all(
        inventory: &mut crate::certificate::CertificateInventory,
    ) -> Result<usize, LifecycleError> {
        inventory
            .evaluate_lifecycle()
            .map_err(|error| match error {
                crate::certificate::InventoryError::Lifecycle(
                    lifecycle_error,
                ) => lifecycle_error,

                _ => LifecycleError::InvalidTransition {
                    from: CertificateState::Active,
                    to: CertificateState::Active,
                },
            })
    }

    pub fn renewal_queue(
        inventory: &crate::certificate::CertificateInventory,
    ) -> Vec<RenewalWorkItem> {
        inventory
            .renewal_candidates()
            .into_iter()
            .filter_map(RenewalWorkItem::new)
            .collect()
    }
}
