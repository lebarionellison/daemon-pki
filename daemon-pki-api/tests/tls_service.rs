use std::sync::Arc;

use daemon_pki_api::tls::server::build_mtls_server_config;
use daemon_pki_api::tls::service::run_tls_server;

#[test]
fn tls_service_symbols_are_available() {
    let _server_builder = build_mtls_server_config;
    let _server_runner = run_tls_server;

    let _: Option<Arc<rustls::ServerConfig>> = None;
}
