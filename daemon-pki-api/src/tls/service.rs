use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_rustls::TlsAcceptor;

pub fn run_tls_server(
    bind_address: &str,
    config: Arc<ServerConfig>,
) -> Result<()> {
    let runtime =
        Runtime::new().context("failed to create Tokio runtime")?;

    runtime.block_on(async move {
        let listener = TcpListener::bind(bind_address)
            .await
            .context("failed to bind TLS listener")?;

        let acceptor = TlsAcceptor::from(config);

        println!("Daemon PKI TLS service listening on {bind_address}");

        loop {
            let (stream, peer) = listener
                .accept()
                .await
                .context("failed to accept TCP connection")?;

            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(mut tls_stream) => {
                        println!("mTLS connection established: {peer}");

                        if let Err(error) = tokio::io::AsyncWriteExt::write_all(
                            &mut tls_stream,
                            b"Daemon PKI mTLS connection established\n",
                        )
                        .await
                        {
                            eprintln!(
                                "TLS response failed for {peer}: {error}"
                            );
                        }
                    }

                    Err(error) => {
                        eprintln!(
                            "mTLS handshake failed for {peer}: {error}"
                        );
                    }
                }
            });
        }
    })
}
