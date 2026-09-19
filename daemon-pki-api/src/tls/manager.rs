use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::crl::CrlManager;
use crate::tls::server::build_mtls_server_config;

pub struct TlsAcceptorManager {
    acceptor: RwLock<TlsAcceptor>,
    crl_manager: Arc<CrlManager>,
    server_certificate_pem: Vec<u8>,
    server_private_key_pem: Vec<u8>,
    client_ca_pem: Vec<u8>,
}

impl TlsAcceptorManager {
    pub fn new(
        initial_config: Arc<ServerConfig>,
        crl_manager: Arc<CrlManager>,
        server_certificate_pem: Vec<u8>,
        server_private_key_pem: Vec<u8>,
        client_ca_pem: Vec<u8>,
    ) -> Self {
        Self {
            acceptor: RwLock::new(
                TlsAcceptor::from(initial_config),
            ),
            crl_manager,
            server_certificate_pem,
            server_private_key_pem,
            client_ca_pem,
        }
    }

    pub fn current(&self) -> TlsAcceptor {
        self.acceptor
            .read()
            .expect("TLS acceptor lock poisoned")
            .clone()
    }

    pub fn crl_manager(&self) -> Arc<CrlManager> {
        Arc::clone(&self.crl_manager)
    }

    pub fn replace(
        &self,
        config: Arc<ServerConfig>,
    ) {
        let mut acceptor = self
            .acceptor
            .write()
            .expect("TLS acceptor lock poisoned");

        *acceptor = TlsAcceptor::from(config);
    }

    pub fn refresh(&self) -> Result<()> {
        let crl_der =
            self.crl_manager
                .generate_and_persist()
                .context(
                    "failed to regenerate certificate revocation list",
                )?;

        let config =
            build_mtls_server_config(
                &self.server_certificate_pem,
                &self.server_private_key_pem,
                &self.client_ca_pem,
                Some(&crl_der),
            )
            .context(
                "failed to rebuild TLS configuration with CRL",
            )?;

        self.replace(config);

        Ok(())
    }
}