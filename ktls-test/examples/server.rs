//! Example: TLS server using `ktls`.

use ktls_test::common;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("TRACE"))
        .try_init();

    let Some(compatible_cipher_suites) = common::compatible_cipher_suites() else {
        return Ok(());
    };

    let listener = TcpListener::bind("0.0.0.0:8443").await.expect("Bind error");
    let acceptor = common::server::get_ktls_acceptor(compatible_cipher_suites);

    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received Ctrl + C...");
        }
        result = common::echo_server_loop(listener, acceptor) => {
            result?;
        }
    }

    Ok(())
}
