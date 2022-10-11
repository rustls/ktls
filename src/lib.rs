use ffi::{setup_tls_info, KtlsCompatibilityError};
use rustls::Connection;
use std::{
    os::unix::{io::AsRawFd, prelude::RawFd},
    pin::Pin,
};

mod ffi;
use crate::ffi::CryptoInfo;

mod ktls_stream;
pub use ktls_stream::KtlsStream;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(thiserror::Error, Debug)]
pub enum Error<IO> {
    #[error("recoverable: {1}")]
    Recoverable(IO, RecoverableError),

    #[error("unrecoverable: {0}")]
    Unrecoverable(#[from] UnrecoverableError),
}

#[derive(thiserror::Error, Debug)]
pub enum RecoverableError {
    // TODO: some errors are recoverable, make them so
}

#[derive(thiserror::Error, Debug)]
pub enum UnrecoverableError {
    #[error("failed to enable TLS ULP (upper level protocol): {0}")]
    UlpError(std::io::Error),

    #[error("kTLS compatibility error: {0}")]
    KtlsCompatibility(#[from] KtlsCompatibilityError),

    #[error("failed to export secrets")]
    ExportSecrets(rustls::Error),

    #[error("failed to configure tx/rx (unsupported cipher?): {0}")]
    TlsCryptoInfoError(std::io::Error),

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
) -> Result<KtlsStream<IO>, Error<tokio_rustls::server::TlsStream<IO>>>
where
    IO: AsRawFd + AsyncRead + AsyncWrite + Unpin,
{
    let drained = drain(&mut stream);

    let (io, conn) = stream.into_inner();
    let fd = io.as_raw_fd();

    let (tx, rx) = match setup_inner(fd, Connection::Server(conn)) {
        Ok(pair) => pair,
        Err(e) => return Err(e.into()),
    };

    setup_tls_info(fd, ffi::Direction::Tx, tx)?;
    setup_tls_info(fd, ffi::Direction::Rx, rx)?;

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
) -> Result<KtlsStream<IO>, Error<tokio_rustls::client::TlsStream<IO>>>
where
    IO: AsRawFd + AsyncRead + AsyncWrite + Unpin,
{
    // TODO: before draining the stream:
    // 1) check cipher compability
    // 2) try setting up ULP
    // 2) try setting up TX with zero credentials (undo correctly if that fails)
    let drained = drain(&mut stream);

    let (io, conn) = stream.into_inner();
    let fd = io.as_raw_fd();

    let (tx, rx) = match setup_inner(fd, Connection::Client(conn)) {
        Ok(pair) => pair,
        Err(e) => return Err(e.into()),
    };

    setup_tls_info(fd, ffi::Direction::Tx, tx)?;
    setup_tls_info(fd, ffi::Direction::Rx, rx)?;

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

fn setup_inner(
    fd: RawFd,
    conn: Connection,
) -> Result<(CryptoInfo, CryptoInfo), UnrecoverableError> {
    let cipher_suite = match conn.negotiated_cipher_suite() {
        Some(cipher_suite) => cipher_suite,
        None => {
            return Err(UnrecoverableError::NoNegotiatedCipherSuite);
        }
    };

    let secrets = match conn.extract_secrets() {
        Ok(secrets) => secrets,
        Err(err) => return Err(UnrecoverableError::ExportSecrets(err)),
    };

    let tx = CryptoInfo::from_rustls(cipher_suite, secrets.tx)?;
    let rx = CryptoInfo::from_rustls(cipher_suite, secrets.rx)?;

    if let Err(err) = ffi::setup_ulp(fd) {
        return Err(UnrecoverableError::UlpError(err));
    };

    Ok((tx, rx))
}
