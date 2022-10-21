use ffi::{setup_tls_info, setup_ulp, KtlsCompatibilityError};
use futures::future::join_all;
use rustls::{Connection, ConnectionTrafficSecrets, SupportedCipherSuite};
use scopeguard::guard;
use std::{
    io,
    net::SocketAddr,
    os::unix::prelude::{AsRawFd, RawFd},
    pin::Pin,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};

mod ffi;
use crate::ffi::CryptoInfo;

mod ktls_stream;
pub use ktls_stream::KtlsStream;

#[derive(Debug, Default)]
pub struct CompatibleCiphers {
    pub tls12: CompatibleCiphersForVersion,
    pub tls13: CompatibleCiphersForVersion,
}

#[derive(Debug, Default)]
pub struct CompatibleCiphersForVersion {
    pub aes_gcm_128: bool,
    pub aes_gcm_256: bool,
    pub chacha20_poly1305: bool,
}

impl CompatibleCiphers {
    /// List compatible ciphers. This listens on a TCP socket and blocks for a
    /// little while. Do once at the very start of a program. Should probably be
    /// behind a lazy_static / once_cell
    pub async fn new() -> io::Result<Self> {
        let mut ciphers = CompatibleCiphers::default();

        let ln = TcpListener::bind("0.0.0.0:0").await?;
        let local_addr = ln.local_addr()?;

        async fn accept_conns(ln: TcpListener) {
            let mut conns = Vec::with_capacity(8);

            loop {
                if let Ok((sock, _addr)) = ln.accept().await {
                    conns.push(sock);
                }
            }
        }

        // Must spawn it, using futures::join! or futures::future::join here
        // will block the process forever.
        let _task_guard = guard(tokio::spawn(accept_conns(ln)), |task| task.abort());

        ciphers.test_ciphers(local_addr).await;

        Ok(ciphers)
    }

    async fn test_ciphers(&mut self, local_addr: SocketAddr) {
        async fn test_cipher(
            cipher_suite: SupportedCipherSuite,
            field: &mut bool,
            local_addr: SocketAddr,
        ) {
            *field = sample_cipher_setup(local_addr, cipher_suite).await.is_ok()
        }

        join_all([
            test_cipher(
                rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
                &mut self.tls13.aes_gcm_128,
                local_addr,
            ),
            test_cipher(
                rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
                &mut self.tls13.aes_gcm_256,
                local_addr,
            ),
            test_cipher(
                rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                &mut self.tls13.chacha20_poly1305,
                local_addr,
            ),
            test_cipher(
                rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                &mut self.tls12.aes_gcm_128,
                local_addr,
            ),
            test_cipher(
                rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                &mut self.tls12.aes_gcm_256,
                local_addr,
            ),
            test_cipher(
                rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                &mut self.tls12.chacha20_poly1305,
                local_addr,
            ),
        ])
        .await;
    }

    /// Returns true if we're reasonably confident that functions like
    /// [config_ktls_client] and [config_ktls_server] will succeed.
    pub fn is_compatible(&self, suite: &SupportedCipherSuite) -> bool {
        let (fields, bulk) = match suite {
            SupportedCipherSuite::Tls12(suite) => (&self.tls12, &suite.common.bulk),
            SupportedCipherSuite::Tls13(suite) => (&self.tls13, &suite.common.bulk),
        };
        match bulk {
            rustls::BulkAlgorithm::Aes128Gcm => fields.aes_gcm_128,
            rustls::BulkAlgorithm::Aes256Gcm => fields.aes_gcm_256,
            rustls::BulkAlgorithm::Chacha20Poly1305 => fields.chacha20_poly1305,
        }
    }
}

async fn sample_cipher_setup(
    addr: SocketAddr,
    cipher_suite: SupportedCipherSuite,
) -> Result<(), Error> {
    let bulk_algo = match cipher_suite {
        SupportedCipherSuite::Tls12(suite) => &suite.common.bulk,
        SupportedCipherSuite::Tls13(suite) => &suite.common.bulk,
    };
    let zero_secrets = match bulk_algo {
        rustls::BulkAlgorithm::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm {
            key: Default::default(),
            salt: Default::default(),
            iv: Default::default(),
        },
        rustls::BulkAlgorithm::Aes256Gcm => ConnectionTrafficSecrets::Aes256Gcm {
            key: Default::default(),
            salt: Default::default(),
            iv: Default::default(),
        },
        rustls::BulkAlgorithm::Chacha20Poly1305 => ConnectionTrafficSecrets::Chacha20Poly1305 {
            key: Default::default(),
            iv: Default::default(),
        },
    };

    let seq_secrets = (0, zero_secrets);
    let info = CryptoInfo::from_rustls(cipher_suite, seq_secrets).unwrap();

    let sock = TcpStream::connect(addr)
        .await
        .map_err(Error::ConnectionError)?;
    let fd = sock.as_raw_fd();

    setup_ulp(fd).map_err(Error::UlpError)?;

    setup_tls_info(fd, ffi::Direction::Tx, info)?;

    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to connect to the tcp socket: {0}")]
    ConnectionError(#[source] std::io::Error),

    #[error("failed to enable TLS ULP (upper level protocol): {0}")]
    UlpError(#[source] std::io::Error),

    #[error("kTLS compatibility error: {0}")]
    KtlsCompatibility(#[from] KtlsCompatibilityError),

    #[error("failed to export secrets")]
    ExportSecrets(#[source] rustls::Error),

    #[error("failed to configure tx/rx (unsupported cipher?): {0}")]
    TlsCryptoInfoError(#[source] std::io::Error),

    #[error("no negotiated cipher suite: call config_ktls_* only /after/ the handshake")]
    NoNegotiatedCipherSuite,
}

/// Configure kTLS for this socket. If this call succeeds, data can be
/// written and read from this socket, and the kernel takes care of encryption
/// (and key updates, etc.) transparently.
///
/// Most errors return the `TlsStream<IO>`, allowing the caller to fall back
/// to software encryption with rustls.
pub fn config_ktls_server<IO>(
    mut stream: tokio_rustls::server::TlsStream<IO>,
) -> Result<KtlsStream<IO>, Error>
where
    IO: AsRawFd + AsyncRead + AsyncWrite + Unpin,
{
    let drained = drain(&mut stream);
    let (io, conn) = stream.into_inner();
    setup_inner(io.as_raw_fd(), Connection::Server(conn))?;
    Ok(KtlsStream::new(io, drained))
}

/// Configure kTLS for this socket. If this call succeeds, data can be
/// written and read from this socket, and the kernel takes care of encryption
/// (and key updates, etc.) transparently.
///
/// Most errors return the `TlsStream<IO>`, allowing the caller to fall back
/// to software encryption with rustls.
pub fn config_ktls_client<IO>(
    mut stream: tokio_rustls::client::TlsStream<IO>,
) -> Result<KtlsStream<IO>, Error>
where
    IO: AsRawFd + AsyncRead + AsyncWrite + Unpin,
{
    let drained = drain(&mut stream);
    let (io, conn) = stream.into_inner();
    setup_inner(io.as_raw_fd(), Connection::Client(conn))?;
    Ok(KtlsStream::new(io, drained))
}

/// Read all the bytes we can read without blocking. This is used to drained the
/// already-decrypted buffer from a tokio-rustls I/O type
fn drain(stream: &mut (dyn AsyncRead + Unpin)) -> Option<Vec<u8>> {
    let mut drained = vec![0u8; 16384];
    let mut rb = ReadBuf::new(&mut drained[..]);

    let noop_waker = futures::task::noop_waker();
    let mut cx = std::task::Context::from_waker(&noop_waker);

    match Pin::new(stream).poll_read(&mut cx, &mut rb) {
        std::task::Poll::Ready(_) => {
            let filled_len = rb.filled().len();
            drained.resize(filled_len, 0);
            Some(drained)
        }
        _ => None,
    }
}

fn setup_inner(fd: RawFd, conn: Connection) -> Result<(), Error> {
    let cipher_suite = match conn.negotiated_cipher_suite() {
        Some(cipher_suite) => cipher_suite,
        None => {
            return Err(Error::NoNegotiatedCipherSuite);
        }
    };

    let secrets = match conn.extract_secrets() {
        Ok(secrets) => secrets,
        Err(err) => return Err(Error::ExportSecrets(err)),
    };

    ffi::setup_ulp(fd).map_err(Error::UlpError)?;

    let tx = CryptoInfo::from_rustls(cipher_suite, secrets.tx)?;
    setup_tls_info(fd, ffi::Direction::Tx, tx)?;

    let rx = CryptoInfo::from_rustls(cipher_suite, secrets.rx)?;
    setup_tls_info(fd, ffi::Direction::Rx, rx)?;

    Ok(())
}
