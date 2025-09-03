// Shared code for client and server examples.

use std::io;
use std::sync::OnceLock;
use std::time::Duration;

use ktls::utils::CompatibleCipherSuites;
use ktls_util::server::KtlsAcceptor;
use nix::errno::Errno;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::sleep;

pub mod client;
pub mod server;

#[allow(dead_code)]
#[tracing::instrument(err)]
/// Echo test, shared by examples and tests.
pub async fn run_echo_test(close_party: CloseParty, test_option: TestOption) -> io::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("TRACE"))
        .pretty()
        .try_init();

    let Some(compatible_cipher_suites) = compatible_cipher_suites() else {
        return Ok(());
    };

    let server_name = ServerName::try_from("localhost").unwrap();
    let listener = TcpListener::bind("0.0.0.0:0").await.expect("Bind error");
    let server_addr = listener.local_addr().expect("Cannot get local_addr");

    let acceptor = server::get_ktls_acceptor(compatible_cipher_suites);
    let connector = client::get_ktls_connector(compatible_cipher_suites);

    // Start echo server
    let (shutdown_signal_tx, shutdown_signal_rx) = oneshot::channel::<bool>();
    let server_handle = tokio::spawn(echo_server(
        listener,
        acceptor,
        shutdown_signal_rx,
        test_option,
    ));

    let mut ktls_stream = connector
        .try_connect(
            TcpStream::connect(server_addr)
                .await
                .expect("Connect to server error"),
            server_name,
        )
        .await
        .map_err(io::Error::other)?;

    let test_data = test_data();

    {
        // Test: poll_write
        ktls_stream.write_all(&test_data[..16]).await?;
        tracing::info!("Sent 16 bytes");

        let mut buf = [0u8; 16];

        ktls_stream.read_exact(&mut buf).await?;

        assert!(buf == test_data[..16]);
    }

    {
        // Test: poll_flush
        ktls_stream.write_all(&test_data[..16]).await?;
        ktls_stream.flush().await?;
        tracing::info!("Sent 16 bytes and flushed");

        let mut buf = [0u8; 16];

        ktls_stream.read_exact(&mut buf).await?;

        assert!(buf == test_data[..16]);
    }

    {
        const CHUNK_SIZE: usize = 17;
        const VECTORED_WRITE_COUNT: usize = 5;
        const TOTAL: usize = CHUNK_SIZE * VECTORED_WRITE_COUNT;

        let bufs: Vec<_> = test_data.chunks(17).map(io::IoSlice::new).take(5).collect();

        // Test: poll_write_vectored
        let mut has_read = ktls_stream.write_vectored(&bufs).await?;

        if let Some(buf) = test_data.get(has_read..TOTAL) {
            tracing::warn!(
                "Not all data sent, sent {has_read} bytes, remaining {} bytes",
                buf.len()
            );

            ktls_stream.write_all(buf).await?;

            has_read += buf.len();
        }

        assert_eq!(has_read, TOTAL);

        let mut buf = [0u8; TOTAL];

        ktls_stream.read_exact(&mut buf).await?;

        assert!(buf == test_data[..TOTAL]);
    }

    {
        // Test: large data (> u16::MAX)
        ktls_stream.write_all(test_data).await?;
        tracing::info!("Sent {} bytes", test_data.len());

        let mut buf = vec![0u8; test_data.len()];

        ktls_stream.read_exact(&mut buf).await?;

        assert!(buf == test_data);
    }

    match close_party {
        CloseParty::Client => {
            tracing::info!("Client performing active shutdown");
            ktls_stream.shutdown().await?;

            // Try write after shutdown, should write 0 bytes
            let n = ktls_stream.write(b"after shutdown").await?;
            assert_eq!(n, 0);

            // Try write vectored after shutdown, should write 0 bytes
            let bufs = [io::IoSlice::new(b"after shutdown vectored")];
            let n = ktls_stream.write_vectored(&bufs).await?;
            assert_eq!(n, 0);

            // Try flush after shutdown, should be ok
            ktls_stream.flush().await?;

            server_handle.await??;
        }
        CloseParty::Server => {
            tracing::info!("Client performing passive shutdown, waiting for server to close");

            // Notify server to close
            shutdown_signal_tx.send(false).unwrap();

            // Try read after server closed, should read 0 bytes (EOF)
            let mut buf = [0u8; 16];

            let n = ktls_stream.read(&mut buf).await?;

            assert_eq!(n, 0);
        }
    }

    tracing::info!("Echo test completed: {:#?}", compatible_cipher_suites);

    Ok(())
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
/// Which party will close the connection actively.
pub enum CloseParty {
    /// The client
    Client,

    /// The server
    Server,
}

fn test_data() -> &'static [u8] {
    static BUFFER: OnceLock<Vec<u8>> = OnceLock::new();

    BUFFER.get_or_init(|| {
        let mut v = vec![0; u16::MAX as usize + 1];

        v.fill_with(rand::random);

        v
    })
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    /// Options for echo test.
    pub struct TestOption: u8 {
        /// Whether to test vectored write.
        const HANDLE_IO_RESULT = 0b0000_0001;
    }
}

#[allow(dead_code)]
#[tracing::instrument(err)]
/// A simple echo server.
pub async fn echo_server(
    listener: TcpListener,
    acceptor: KtlsAcceptor,
    mut shutdown_signal_rx: oneshot::Receiver<bool>,
    test_option: TestOption,
) -> io::Result<()> {
    match listener.accept().await {
        Ok((stream, remote_addr)) => {
            tracing::info!("Accepted connection from {remote_addr}");

            match acceptor.try_accept(stream).await {
                Ok(mut ktls_stream) => {
                    tracing::info!("Connection established with kTLS");

                    let mut buf = [0u8; 1024];

                    loop {
                        if test_option.contains(TestOption::HANDLE_IO_RESULT) {
                            tracing::info!("Testing improper usage of `handle_io_result`");

                            // Try read application data with improper usage of handle_io_result
                            ktls_stream.handle_io_result(Err::<(), _>(Errno::EIO.into()))?;

                            // Again
                            ktls_stream.handle_io_result(Err::<(), _>(Errno::EIO.into()))?;
                        }

                        let ret = tokio::select! {
                            biased;
                            is_brutal = &mut shutdown_signal_rx => {
                                tracing::info!("Received shutdown signal, is_brutal: {:?}", is_brutal);

                                if is_brutal.unwrap_or(false) {
                                    // Drop the connection brutally
                                    drop(ktls_stream);
                                } else {
                                    ktls_stream.shutdown().await.unwrap();

                                    // Try write after shutdown, should write 0 bytes
                                    let n = ktls_stream.write(b"after shutdown").await.unwrap();

                                    assert_eq!(n, 0);
                                }

                                loop {
                                    sleep(Duration::from_secs(1)).await;
                                }
                            }
                            ret = ktls_stream.read(&mut buf) => ret
                        };

                        match ret {
                            Ok(0) => {
                                tracing::info!("Read EOF, client closed connection");
                                break;
                            }
                            Ok(n) => {
                                tracing::trace!("Received {n} bytes");

                                if let Err(e) = ktls_stream.write_all(&buf[..n]).await {
                                    tracing::error!(
                                        "Failed to write to stream from {remote_addr}: {e:#?}"
                                    );

                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to read from stream from {remote_addr}: {e:#?}"
                                );

                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to accept connection from {remote_addr}: {e:#?}");

                    return Err(io::Error::other(e));
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to accept connection: {e:#?}");

            return Err(e);
        }
    }

    tracing::info!("Server shutting down");

    Ok(())
}

#[allow(dead_code)]
#[tracing::instrument(err)]
/// A simple echo server.
pub async fn echo_server_loop(listener: TcpListener, acceptor: KtlsAcceptor) -> io::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, remote_addr)) => {
                tracing::info!("Accepted connection from {remote_addr}");

                match acceptor.try_accept(stream).await {
                    Ok(mut ktls_stream) => {
                        tokio::spawn(async move {
                            tracing::info!("Connection established with kTLS");

                            let mut buf = [0u8; 1024];

                            loop {
                                match ktls_stream.read(&mut buf).await {
                                    Ok(0) => {
                                        tracing::info!("Read EOF, client closed connection");
                                        break;
                                    }
                                    Ok(n) => {
                                        tracing::trace!("Received {n} bytes");

                                        if let Err(e) = ktls_stream.write_all(&buf[..n]).await {
                                            tracing::error!(
                                                "Failed to write to stream from {remote_addr}: \
                                                 {e:#?}"
                                            );

                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "Failed to read from stream from {remote_addr}: {e:#?}"
                                        );

                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to accept connection from {remote_addr}: {e:#?}");

                        return Err(io::Error::other(e));
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to accept connection: {e:#?}");

                return Err(e);
            }
        }
    }
}

#[allow(dead_code)]
/// Get the compatible cipher suites for the current kernel.
pub fn compatible_cipher_suites() -> Option<&'static CompatibleCipherSuites> {
    static COMPATIBLE_CIPHER_SUITES: OnceLock<Option<CompatibleCipherSuites>> = OnceLock::new();

    COMPATIBLE_CIPHER_SUITES
        .get_or_init(|| {
            let c = CompatibleCipherSuites::probe().expect("probe error");

            if let Some(c) = &c {
                tracing::info!("Compatible cipher suites: {c:#?}");
            } else {
                tracing::info!("The current kernel does not support kTLS");
            }

            c
        })
        .as_ref()
}
