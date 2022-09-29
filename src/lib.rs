use std::os::unix::io::AsRawFd;

use ffi::KtlsCompatibilityError;

use crate::ffi::CryptoInfo;

pub(crate) mod ffi;

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
    stream: tokio_rustls::server::TlsStream<IO>,
) -> Result<IO, Error<tokio_rustls::server::TlsStream<IO>>>
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

    ffi::setup_tls_info(fd, ffi::Direction::Tx, server_info).map_err(Error::TlsCryptoInfoError)?;
    ffi::setup_tls_info(fd, ffi::Direction::Rx, client_info).map_err(Error::TlsCryptoInfoError)?;

    let (io, _conn) = stream.into_inner();
    Ok(io)
}
