use std::{
    io,
    os::fd::{AsRawFd, RawFd},
    sync::Arc,
    task,
    time::Duration,
};

use ktls::{AsyncReadReady, CorkStream, KtlsCipherSuite, KtlsCipherType, KtlsVersion};
use lazy_static::lazy_static;
use rcgen::generate_simple_self_signed;
use rustls::{
    client::Resumption, crypto::CryptoProvider, ClientConfig, RootCertStore, ServerConfig,
    SupportedCipherSuite,
};

#[cfg(feature = "aws_lc_rs")]
use rustls::crypto::aws_lc_rs::cipher_suite;
#[cfg(feature = "ring")]
use rustls::crypto::ring::cipher_suite;

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsConnector;
use tracing::{debug, Instrument};
use tracing_subscriber::EnvFilter;

const RANDOM_SEED: u128 = 19873239487139847918274_u128;

struct Payloads {
    client: Vec<u8>,
    server: Vec<u8>,
}

impl Default for Payloads {
    fn default() -> Self {
        let mut prng = oorandom::Rand64::new(RANDOM_SEED);
        let payload_len = 262_144;
        let mut gen_payload = || {
            (0..payload_len)
                .map(|_| (prng.rand_u64() % 256) as u8)
                .collect()
        };

        Self {
            client: gen_payload(),
            server: gen_payload(),
        }
    }
}

lazy_static! {
    static ref PAYLOADS: Payloads = Payloads::default();
}

fn all_suites() -> Vec<SupportedCipherSuite> {
    vec![
        cipher_suite::TLS13_AES_128_GCM_SHA256,
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        #[cfg(feature = "tls12")]
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        #[cfg(feature = "tls12")]
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        #[cfg(feature = "tls12")]
        cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ]
}

#[tokio::test]
async fn compatible_ciphers() {
    let cc = ktls::CompatibleCiphers::new().await.unwrap();
    for suite in all_suites() {
        assert!(cc.is_compatible(suite));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn compatible_ciphers_single_thread() {
    let cc = ktls::CompatibleCiphers::new().await.unwrap();
    for suite in all_suites() {
        assert!(cc.is_compatible(suite));
    }
}

#[derive(Clone, Copy)]
enum ServerTestFlavor {
    ClientCloses,
    ServerCloses,
}

#[test_case::test_matrix(
    [
        KtlsVersion::TLS12,
        KtlsVersion::TLS13,
    ],
    [
        KtlsCipherType::AesGcm128,
        KtlsCipherType::AesGcm256,
        KtlsCipherType::Chacha20Poly1305,
    ],
    [
        ServerTestFlavor::ClientCloses,
        ServerTestFlavor::ServerCloses,
    ]
)]
#[tokio::test]
async fn server_tests(version: KtlsVersion, cipher_type: KtlsCipherType, flavor: ServerTestFlavor) {
    if matches!(version, KtlsVersion::TLS12) && !cfg!(feature = "tls12") {
        println!("Skipping...");
        return;
    }

    let cipher_suite = KtlsCipherSuite {
        version,
        typ: cipher_type,
    };

    server_test_inner(cipher_suite, flavor).await
}

async fn server_test_inner(cipher_suite: KtlsCipherSuite, flavor: ServerTestFlavor) {
    tracing_subscriber::fmt()
        // .with_env_filter(EnvFilter::new("rustls=trace,debug"))
        // .with_env_filter(EnvFilter::new("debug"))
        .with_env_filter(EnvFilter::new("trace"))
        .pretty()
        .init();

    let subject_alt_names = vec!["localhost".to_string()];

    let ckey = generate_simple_self_signed(subject_alt_names).unwrap();

    let mut server_config =
        ServerConfig::builder_with_provider(single_suite_provider(cipher_suite))
            .with_protocol_versions(&[cipher_suite.version.as_supported_version()])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![ckey.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(ckey.key_pair.serialize_der()).into(),
            )
            .unwrap();

    server_config.enable_secret_extraction = true;
    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let ln = TcpListener::bind("[::]:0").await.unwrap();
    let addr = ln.local_addr().unwrap();

    let jh = tokio::spawn(
        async move {
            let (stream, addr) = ln.accept().await.unwrap();
            debug!("Accepted TCP conn from {}", addr);
            let stream = SpyStream(stream, "server");
            let stream = CorkStream::new(stream);

            let stream = acceptor.accept(stream).await.unwrap();
            debug!("Completed TLS handshake");

            // sleep for a bit to let client write more data and stress test
            // the draining logic
            tokio::time::sleep(Duration::from_millis(100)).await;

            let mut stream = ktls::config_ktls_server(stream).await.unwrap();
            debug!("Configured kTLS");

            debug!("Server reading data (1/5)");
            let mut buf = vec![0u8; PAYLOADS.client.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, PAYLOADS.client);

            debug!("Server writing data (2/5)");
            stream.write_all(&PAYLOADS.server).await.unwrap();
            stream.flush().await.unwrap();

            debug!("Server reading data (3/5)");
            let mut buf = vec![0u8; PAYLOADS.client.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, PAYLOADS.client);

            debug!("Server writing data (4/5)");
            stream.write_all(&PAYLOADS.server).await.unwrap();
            stream.flush().await.unwrap();

            match flavor {
                ServerTestFlavor::ClientCloses => {
                    debug!("Server reading from closed session (5/5)");
                    assert!(
                        stream.read_exact(&mut buf[..1]).await.is_err(),
                        "Session still open?"
                    );
                }
                ServerTestFlavor::ServerCloses => {
                    debug!("Server sending close notify (5/5)");
                    stream.shutdown().await.unwrap();

                    debug!("Server trying to write after closing");
                    stream.write_all(&PAYLOADS.server).await.unwrap_err();
                }
            }

            assert_eq!(stream.get_ref().1, "server");
            assert_eq!(stream.get_mut().1, "server");
            assert_eq!(stream.into_raw().1 .1, "server");
        }
        .instrument(tracing::info_span!("server")),
    );

    let mut root_store = RootCertStore::empty();
    root_store.add(ckey.cert.der().clone()).unwrap();

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let tls_connector = TlsConnector::from(Arc::new(client_config));

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut stream = tls_connector
        .connect("localhost".try_into().unwrap(), stream)
        .await
        .unwrap();

    debug!("Client writing data (1/5)");
    stream.write_all(&PAYLOADS.client).await.unwrap();
    debug!("Flushing");
    stream.flush().await.unwrap();

    debug!("Client reading data (2/5)");
    let mut buf = vec![0u8; PAYLOADS.server.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, PAYLOADS.server);

    debug!("Client writing data (3/5)");
    stream.write_all(&PAYLOADS.client).await.unwrap();
    debug!("Flushing");
    stream.flush().await.unwrap();

    debug!("Client reading data (4/5)");
    let mut buf = vec![0u8; PAYLOADS.server.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, PAYLOADS.server);

    match flavor {
        ServerTestFlavor::ClientCloses => {
            debug!("Client sending close notify (5/5)");
            stream.shutdown().await.unwrap();

            debug!("Client trying to write after closing");
            stream.write_all(&PAYLOADS.client).await.unwrap_err();
        }
        ServerTestFlavor::ServerCloses => {
            debug!("Client reading from closed session (5/5)");
            assert!(
                stream.read_exact(&mut buf[..1]).await.is_err(),
                "Session still open?"
            );
        }
    }

    jh.await.unwrap();
}

#[test_case::test_matrix(
    [
        KtlsVersion::TLS12,
        KtlsVersion::TLS13,
    ],
    [
        KtlsCipherType::AesGcm128,
        KtlsCipherType::AesGcm256,
        KtlsCipherType::Chacha20Poly1305,
    ],
    [
        ClientTestFlavor::ShortLastBuffer,
        ClientTestFlavor::LongLastBuffer,
    ]
)]
#[tokio::test]
async fn client_tests(version: KtlsVersion, cipher_type: KtlsCipherType, flavor: ClientTestFlavor) {
    if matches!(version, KtlsVersion::TLS12) && !cfg!(feature = "tls12") {
        println!("Skipping...");
        return;
    }

    let cipher_suite = KtlsCipherSuite {
        version,
        typ: cipher_type,
    };

    client_test_inner(cipher_suite, flavor).await
}

enum ClientTestFlavor {
    ShortLastBuffer,
    LongLastBuffer,
}

async fn client_test_inner(cipher_suite: KtlsCipherSuite, flavor: ClientTestFlavor) {
    tracing_subscriber::fmt()
        // .with_env_filter(EnvFilter::new("rustls=trace,debug"))
        // .with_env_filter(EnvFilter::new("debug"))
        .with_env_filter(EnvFilter::new("trace"))
        .pretty()
        .init();

    let subject_alt_names = vec!["localhost".to_string()];

    let ckey = generate_simple_self_signed(subject_alt_names).unwrap();

    let mut server_config =
        ServerConfig::builder_with_provider(single_suite_provider(cipher_suite))
            .with_protocol_versions(&[cipher_suite.version.as_supported_version()])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![ckey.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(ckey.key_pair.serialize_der()).into(),
            )
            .unwrap();

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());
    // server_config.send_tls13_tickets = 0;

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let ln = TcpListener::bind("[::]:0").await.unwrap();
    let addr = ln.local_addr().unwrap();

    let jh = tokio::spawn(
        async move {
            let (stream, addr) = ln.accept().await.unwrap();

            debug!("Accepted TCP conn from {}", addr);
            let mut stream = acceptor.accept(stream).await.unwrap();
            debug!("Completed TLS handshake");

            debug!("Server reading data (1/5)");
            let mut buf = vec![0u8; PAYLOADS.client.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, PAYLOADS.client);

            debug!("Server writing data (2/5)");
            stream.write_all(&PAYLOADS.server).await.unwrap();

            debug!("Server reading data (3/5)");
            let mut buf = vec![0u8; PAYLOADS.client.len()];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, PAYLOADS.client);

            for _i in 0..3 {
                debug!("Making the client wait (to make busywaits REALLY obvious)");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }

            debug!("Server writing data (4/5)");
            stream.write_all(&PAYLOADS.server).await.unwrap();

            debug!("Server sending close notify (5/5)");
            stream.shutdown().await.unwrap();

            debug!("Server trying to write after close notify");
            stream.write_all(&PAYLOADS.server).await.unwrap_err();

            debug!("Server is happy with the exchange");
        }
        .instrument(tracing::info_span!("server")),
    );

    let mut root_store = RootCertStore::empty();
    root_store.add(ckey.cert.der().clone()).unwrap();

    let mut client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    client_config.enable_secret_extraction = true;
    client_config.resumption = Resumption::disabled();

    let tls_connector = TlsConnector::from(Arc::new(client_config));

    let stream = TcpStream::connect(addr).await.unwrap();
    let stream = CorkStream::new(stream);

    let stream = tls_connector
        .connect("localhost".try_into().unwrap(), stream)
        .await
        .unwrap();

    let stream = ktls::config_ktls_client(stream).await.unwrap();
    let mut stream = SpyStream(stream, "client");

    debug!("Client writing data (1/5)");
    stream.write_all(&PAYLOADS.client).await.unwrap();
    debug!("Flushing");
    stream.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(250)).await;

    debug!("Client reading data (2/5)");
    let mut buf = vec![0u8; PAYLOADS.server.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, PAYLOADS.server);

    debug!("Client writing data (3/5)");
    stream.write_all(&PAYLOADS.client).await.unwrap();
    debug!("Flushing");
    stream.flush().await.unwrap();

    debug!("Client reading data (4/5)");
    let mut buf = vec![0u8; PAYLOADS.server.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, PAYLOADS.server);

    let buf = match flavor {
        ClientTestFlavor::ShortLastBuffer => &mut buf[..1],
        ClientTestFlavor::LongLastBuffer => &mut buf[..2],
    };
    debug!(
        "Client reading from closed session (with buffer of size {})",
        buf.len()
    );
    assert!(stream.read_exact(buf).await.is_err(), "Session still open?");

    jh.await.unwrap();
}

struct SpyStream<IO>(IO, &'static str);

impl<IO> AsyncRead for SpyStream<IO>
where
    IO: AsyncRead,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> task::Poll<std::io::Result<()>> {
        let old_filled = buf.filled().len();
        let name = self.1;
        let res = unsafe {
            let io = self.map_unchecked_mut(|s| &mut s.0);
            io.poll_read(cx, buf)
        };

        match &res {
            task::Poll::Ready(res) => match res {
                Ok(_) => {
                    let num_read = buf.filled().len() - old_filled;
                    tracing::debug!(%name, "SpyStream read {num_read} bytes",);
                }
                Err(e) => {
                    tracing::debug!(%name, "SpyStream read errored: {e}");
                }
            },
            task::Poll::Pending => {
                tracing::debug!(%name, "SpyStream read would've blocked")
            }
        }
        res
    }
}

impl<IO> AsyncReadReady for SpyStream<IO>
where
    IO: AsyncReadReady,
{
    fn poll_read_ready(&self, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.0.poll_read_ready(cx)
    }
}

impl<IO> AsyncWrite for SpyStream<IO>
where
    IO: AsyncWrite,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<Result<usize, std::io::Error>> {
        let res = unsafe {
            let io = self.map_unchecked_mut(|s| &mut s.0);
            io.poll_write(cx, buf)
        };

        match &res {
            task::Poll::Ready(res) => match res {
                Ok(n) => {
                    tracing::debug!("SpyStream wrote {n} bytes");
                }
                Err(e) => {
                    tracing::debug!("SpyStream writing errored: {e}");
                }
            },
            task::Poll::Pending => {
                tracing::debug!("SpyStream writing would've blocked")
            }
        }
        res
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), std::io::Error>> {
        unsafe {
            let io = self.map_unchecked_mut(|s| &mut s.0);
            io.poll_flush(cx)
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), std::io::Error>> {
        unsafe {
            let io = self.map_unchecked_mut(|s| &mut s.0);
            io.poll_shutdown(cx)
        }
    }
}

impl<IO> AsRawFd for SpyStream<IO>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

fn single_suite_provider(cipher_suite: KtlsCipherSuite) -> Arc<CryptoProvider> {
    let mut provider = {
        #[cfg(feature = "aws_lc_rs")]
        {
            rustls::crypto::aws_lc_rs::default_provider()
        }

        #[cfg(feature = "ring")]
        {
            rustls::crypto::ring::default_provider()
        }
    };
    provider.cipher_suites.clear();
    provider
        .cipher_suites
        .push(cipher_suite.as_supported_cipher_suite());

    Arc::new(provider)
}
