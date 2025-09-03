//! Test: client connect to real world websites.

use std::io;
use std::num::NonZeroUsize;
use std::time::Duration;

use ktls::KtlsStream;
use ktls_test::common;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[test_case::test_matrix(
    [
        "www.google.com", // Google CDN
        "www.bing.com", // Azure CDN
        // "github.com", // Azure CDN
        "www.baidu.com", // Baidu CDN
        "stackoverflow.com", // Cloudflare CDN
        "fastly.com", // Fastly CDN
    ]
)]
#[tokio::test]
async fn test_connecct_sites(server_name: &'static str) -> io::Result<()> {
    timeout(
        Duration::from_secs(10),
        test_connecct_sites_impl(server_name),
    )
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("Test to {server_name} timed out?");

        Err(io::Error::new(io::ErrorKind::TimedOut, e))
    })
}

async fn test_connecct_sites_impl(server_name: &'static str) -> io::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("TRACE"))
        .pretty()
        .try_init();

    let Some(compatible_cipher_suites) = common::compatible_cipher_suites() else {
        return Ok(());
    };

    let Ok(Ok(socket)) = timeout(
        Duration::from_secs(1),
        TcpStream::connect(format!("{server_name}:443")),
    )
    .await
    else {
        tracing::warn!("Failed to connect to {server_name}, skipped.");

        return Ok(());
    };

    let connector = common::client::get_ktls_connector(compatible_cipher_suites);

    let mut ktls_stream = connector
        .try_connect(socket, ServerName::try_from(server_name).unwrap())
        .await
        .map_err(io::Error::other)?;

    // Test 1
    tracing::info!("First request to {server_name}");
    http_request(&mut ktls_stream, server_name).await?;

    // Test 2
    tracing::info!("Second request to {server_name}");
    http_request(&mut ktls_stream, server_name).await?;

    Ok(())
}

async fn http_request(
    ktls_stream: &mut KtlsStream<TcpStream>,
    server_name: &str,
) -> io::Result<()> {
    // Write HTTP/1.1 request
    {
        ktls_stream
            .write_all(
                format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nconnection: keep-alive\r\naccept-encoding: \
                     identity\r\ntransfer-encoding: identity\r\n\r\n",
                    server_name
                )
                .as_bytes(),
            )
            .await?;

        tracing::debug!("Request sent to {server_name}");

        // Read response
        let mut response = Vec::new();

        let mut buf_stream = tokio::io::BufStream::new(ktls_stream);

        let mut content_length = None;

        loop {
            let total_has_read = response.len();

            let has_read = buf_stream.read_until(b'\n', &mut response).await?;

            if has_read == 0 || response.ends_with(b"\r\n\r\n") {
                break;
            }

            let has_read_bytes = &response[total_has_read..];
            tracing::trace!(
                "Received from {server_name}: {}",
                String::from_utf8_lossy(has_read_bytes)
            );

            const PREFIX: &[u8; 16] = b"content-length: ";

            if has_read_bytes
                .get(..PREFIX.len())
                .map(|v| v.eq_ignore_ascii_case(PREFIX))
                == Some(true)
            {
                let v = std::str::from_utf8(&has_read_bytes[PREFIX.len()..])
                    .expect("content length should be a number string")
                    .trim()
                    .parse::<usize>()
                    .expect("content length should be a number");

                content_length = Some(v);
            }
        }

        // Read body
        {
            let Some(Some(content_length)) = content_length.map(NonZeroUsize::new) else {
                tracing::warn!("No body found in response from {server_name}, skipped.");

                return Ok(());
            };

            tracing::debug!(
                "Headers received from {server_name}, reading body ({content_length} bytes)..."
            );

            response.reserve(content_length.get());

            #[allow(unsafe_code)]
            // Safety: we have reserved enough space above.
            buf_stream
                .read_exact(unsafe {
                    std::slice::from_raw_parts_mut(
                        response.as_mut_ptr().add(response.len()),
                        content_length.get(),
                    )
                })
                .await?;

            #[allow(unsafe_code)]
            // Safety: we just initialized the buffer above.
            unsafe {
                response.set_len(response.len() + content_length.get());
            }
        }

        let response = String::from_utf8_lossy(&response);

        tracing::info!("Got response from {server_name}");

        tracing::trace!(
            "Response from {server_name}: {:#?} (...)",
            &response[..64.min(response.len())]
        );
    }

    Ok(())
}
