use ffi::KtlsCompatibilityError;
use futures::FutureExt;
use std::{os::unix::io::AsRawFd, pin::Pin};

mod ffi;
use crate::ffi::CryptoInfo;

mod ktls_stream;
pub use ktls_stream::KtlsStream;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(thiserror::Error, Debug)]
pub enum Error<IO> {
    #[error("failed to export secrets")]
    ExportSecrets(IO, rustls::Error),

    #[error("no negotiated cipher suite: call config_ktls_* only /after/ the handshake")]
    NoNegotiatedCipherSuite,

    #[error("kTLS compatibility error: {0}")]
    KtlsCompatibility(#[from] KtlsCompatibilityError),

    #[error("failed to enable TLS ULP (upper level protocol): {0}")]
    UlpError(IO, std::io::Error),

    #[error("failed to pass crypto info to kernel: {0}")]
    TlsCryptoInfoError(std::io::Error),
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
    let (io, conn) = stream.get_ref();

    let secrets = match stream.get_ref().1.export_all_secrets() {
        Ok(secrets) => secrets,
        Err(err) => return Err(Error::ExportSecrets(stream, err)),
    };

    let cipher_suite = match conn.negotiated_cipher_suite() {
        Some(cipher_suite) => cipher_suite,
        None => {
            return Err(Error::NoNegotiatedCipherSuite);
        }
    };

    let server_info =
        CryptoInfo::from_rustls(cipher_suite, &secrets.server, &secrets.extra_random)?;
    let client_info =
        CryptoInfo::from_rustls(cipher_suite, &secrets.client, &secrets.extra_random)?;

    let fd = io.as_raw_fd();

    if let Err(err) = ffi::setup_ulp(fd) {
        return Err(Error::UlpError(stream, err));
    };

    // we've set up TLS as the ULP, now we should drain whatever data rustls
    // has already read+decrypted from the socket before we set up tx/rx
    let drained = {
        let mut drained = vec![0u8; 16384];
        let mut rb = ReadBuf::new(&mut drained[..]);
        let read_fut = std::future::poll_fn(|cx| Pin::new(&mut stream).poll_read(cx, &mut rb));

        match read_fut.now_or_never() {
            Some(res) => {
                println!("read was ok? {}", res.is_ok());
                println!("drained {} bytes", rb.filled().len());
                println!(
                    "drained bytes: {:x?} ({:?})",
                    rb.filled(),
                    std::str::from_utf8(rb.filled())
                );
                let filled_len = rb.filled().len();
                drained.resize(filled_len, 0);
                Some(drained)
            }
            None => {
                println!("read_fut not ready");
                None
            }
        }
    };

    ffi::setup_tls_info(fd, ffi::Direction::Tx, server_info).map_err(Error::TlsCryptoInfoError)?;
    ffi::setup_tls_info(fd, ffi::Direction::Rx, client_info).map_err(Error::TlsCryptoInfoError)?;

    let (io, _conn) = stream.into_inner();

    Ok(KtlsStream::new(io, drained))
}

/// Configure kTLS for this socket. If this call succeeds, data can be
/// written and read from this socket, and the kernel takes care of encryption
/// (and key updates, etc.) transparently.
///
/// Most errors return the `TlsStream<IO>`, allowing the caller to fall back
/// to software encryption with rustls.
pub fn config_ktls_client<IO>(
    stream: tokio_rustls::client::TlsStream<IO>,
) -> Result<KtlsStream<IO>, Error<tokio_rustls::client::TlsStream<IO>>>
where
    IO: AsRawFd,
{
    let (io, conn) = stream.get_ref();

    let secrets = match stream.get_ref().1.export_all_secrets() {
        Ok(secrets) => secrets,
        Err(err) => return Err(Error::ExportSecrets(stream, err)),
    };

    let cipher_suite = match conn.negotiated_cipher_suite() {
        Some(cipher_suite) => cipher_suite,
        None => {
            return Err(Error::NoNegotiatedCipherSuite);
        }
    };

    let server_info =
        CryptoInfo::from_rustls(cipher_suite, &secrets.server, &secrets.extra_random)?;
    let client_info =
        CryptoInfo::from_rustls(cipher_suite, &secrets.client, &secrets.extra_random)?;

    let fd = io.as_raw_fd();

    if let Err(err) = ffi::setup_ulp(fd) {
        return Err(Error::UlpError(stream, err));
    };

    ffi::setup_tls_info(fd, ffi::Direction::Tx, client_info).map_err(Error::TlsCryptoInfoError)?;
    ffi::setup_tls_info(fd, ffi::Direction::Rx, server_info).map_err(Error::TlsCryptoInfoError)?;

    let (io, _conn) = stream.into_inner();

    Ok(KtlsStream::new(io, None /* TODO: drain */))
}
