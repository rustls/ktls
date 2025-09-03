//! See the [module-level documentation](crate::setup) for more details.

#![allow(rustdoc::private_intra_doc_links)]
#![allow(unreachable_pub)]

use std::os::fd::{AsFd, AsRawFd};
use std::{io, mem};

use libc::c_int;
use nix::errno::Errno;
use nix::sys::socket::{setsockopt, SetSockOpt};
use rustls::crypto::cipher::NONCE_LEN;
use rustls::{ConnectionTrafficSecrets, ExtractedSecrets, SupportedCipherSuite};

use crate::error::{Error, InvalidCryptoInfo};

/// Sets the kTLS parameters on the socket after the TLS handshake is completed.
///
/// ## Errors
///
/// * Invalid crypto materials.
/// * Syscall error.
pub fn setup_tls_params<S: AsFd>(
    socket: &S,
    cipher_suite: SupportedCipherSuite,
    secrets: ExtractedSecrets,
) -> Result<(), Error> {
    let (tx, rx) = TlsCryptoInfo::extract_from(cipher_suite, secrets)?;

    setsockopt(socket, TcpTlsTx {}, &tx)
        .and_then(|()| setsockopt(socket, TcpTlsRx {}, &rx))
        .map_err(io::Error::from)
        .map_err(Error::IO)
}

/// Like [`setup_tls_params`], but only sets up the transmit direction.
///
/// This is useful when performing key update.
///
/// ## Errors
///
/// See [`setup_tls_params`].
pub fn setup_tls_params_tx<S: AsFd>(
    socket: &S,
    cipher_suite: SupportedCipherSuite,
    (seq, secrets): (u64, ConnectionTrafficSecrets),
) -> Result<(), Error> {
    let tx = TlsCryptoInfoTx::extract_tx_from(cipher_suite, (seq, secrets))?;

    setsockopt(socket, TcpTlsTx {}, &tx)
        .map_err(io::Error::from)
        .map_err(Error::IO)
}

/// Like [`setup_tls_params`], but only sets up the receive direction.
///
/// This is useful when performing key update.
///
/// ## Errors
///
/// See [`setup_tls_params`].
pub fn setup_tls_params_rx<S: AsFd>(
    socket: &S,
    cipher_suite: SupportedCipherSuite,
    (seq, secrets): (u64, ConnectionTrafficSecrets),
) -> Result<(), Error> {
    let rx = TlsCryptoInfoRx::extract_rx_from(cipher_suite, (seq, secrets))?;

    setsockopt(socket, TcpTlsRx {}, &rx)
        .map_err(io::Error::from)
        .map_err(Error::IO)
}

#[derive(Debug, Clone, Copy)]
/// Sets the Kernel TLS read/write parameters on the TCP socket.
struct TcpTls<const DIRECTION: c_int> {}

/// See [`TcpTls`].
type TcpTlsTx = TcpTls<{ libc::TLS_TX }>;

/// See [`TcpTls`].
type TcpTlsRx = TcpTls<{ libc::TLS_RX }>;

impl<const DIRECTION: c_int> SetSockOpt for TcpTls<DIRECTION> {
    type Val = TlsCryptoInfo<DIRECTION>;

    fn set<F: AsFd>(&self, fd: &F, val: &Self::Val) -> nix::Result<()> {
        let (ffi_ptr, ffi_len) = val.0.as_ffi_value();

        #[allow(unsafe_code)]
        // SAFETY: syscall
        unsafe {
            let res = libc::setsockopt(
                fd.as_fd().as_raw_fd(),
                libc::SOL_TLS,
                DIRECTION,
                ffi_ptr,
                ffi_len,
            );
            Errno::result(res)?;
        }

        Ok(())
    }
}

#[repr(transparent)]
/// Sets the Kernel TLS read/write parameters on the TCP socket.
pub struct TlsCryptoInfo<const DIRECTION: c_int = 0>(TlsCryptoInfoImpl);

/// See [`TlsCryptoInfo`].
pub type TlsCryptoInfoTx = TlsCryptoInfo<{ libc::TLS_TX }>;

/// See [`TlsCryptoInfo`].
pub type TlsCryptoInfoRx = TlsCryptoInfo<{ libc::TLS_RX }>;

#[cfg(any(feature = "raw-api", feature = "probe-ktls-compatibility"))]
impl<const DIRECTION: c_int> TlsCryptoInfo<DIRECTION> {
    /// Create a custom [`TlsCryptoInfo`] from the given
    /// [`libc::tls12_crypto_info_aes_gcm_128`].
    ///
    /// This is for advanced usage only.
    pub const fn custom_aes_128_gcm(inner: libc::tls12_crypto_info_aes_gcm_128) -> Self {
        Self(TlsCryptoInfoImpl::AesGcm128(inner))
    }

    /// Create a custom [`TlsCryptoInfo`] from the given
    /// [`libc::tls12_crypto_info_aes_gcm_256`].
    pub const fn custom_aes_256_gcm(inner: libc::tls12_crypto_info_aes_gcm_256) -> Self {
        Self(TlsCryptoInfoImpl::AesGcm256(inner))
    }

    /// Create a custom [`TlsCryptoInfo`] from the given
    /// [`libc::tls12_crypto_info_chacha20_poly1305`].
    pub const fn custom_chacha20_poly1305(
        inner: libc::tls12_crypto_info_chacha20_poly1305,
    ) -> Self {
        Self(TlsCryptoInfoImpl::Chacha20Poly1305(inner))
    }

    /// Sets the kTLS parameters on the given file descriptor.
    pub fn set<Fd: AsFd>(&self, fd: &Fd) -> Result<(), Error> {
        setsockopt(fd, TcpTls {}, self)
            .map_err(io::Error::from)
            .map_err(Error::IO)
    }
}

impl TlsCryptoInfo {
    /// Extract the bidirectional `TlsCryptoInfo` from the given
    /// `SupportedCipherSuite` and `ExtractedSecrets`.
    ///
    /// ## Errors
    ///
    /// * Invalid crypto materials
    fn extract_from(
        cipher_suite: SupportedCipherSuite,
        secrets: ExtractedSecrets,
    ) -> Result<(TlsCryptoInfoTx, TlsCryptoInfoRx), InvalidCryptoInfo> {
        Ok((
            TlsCryptoInfo(TlsCryptoInfoImpl::extract_from(cipher_suite, secrets.tx)?),
            TlsCryptoInfo(TlsCryptoInfoImpl::extract_from(cipher_suite, secrets.rx)?),
        ))
    }
}

impl TlsCryptoInfoTx {
    fn extract_tx_from(
        cipher_suite: SupportedCipherSuite,
        (seq, secrets): (u64, ConnectionTrafficSecrets),
    ) -> Result<Self, InvalidCryptoInfo> {
        TlsCryptoInfoImpl::extract_from(cipher_suite, (seq, secrets)).map(TlsCryptoInfo)
    }
}

impl TlsCryptoInfoRx {
    fn extract_rx_from(
        cipher_suite: SupportedCipherSuite,
        (seq, secrets): (u64, ConnectionTrafficSecrets),
    ) -> Result<Self, InvalidCryptoInfo> {
        TlsCryptoInfoImpl::extract_from(cipher_suite, (seq, secrets)).map(TlsCryptoInfo)
    }
}

#[repr(C)]
#[allow(unused)]
/// A wrapper around the system `tls12_crypto_info_*` structs, use with setting
/// up the kTLS r/w parameters on the TCP socket.
///
/// This is originated from the `nix` crate, which currently does not support
/// `AES-128-CCM` and `SM4`, so we implement our own version here.
enum TlsCryptoInfoImpl {
    AesGcm128(libc::tls12_crypto_info_aes_gcm_128),
    AesGcm256(libc::tls12_crypto_info_aes_gcm_256),
    Chacha20Poly1305(libc::tls12_crypto_info_chacha20_poly1305),
    AesCcm128(libc::tls12_crypto_info_aes_ccm_128),
    Sm4Gcm(libc::tls12_crypto_info_sm4_gcm),
    Sm4Ccm(libc::tls12_crypto_info_sm4_ccm),
}

impl TlsCryptoInfoImpl {
    #[allow(unused_qualifications)]
    #[allow(clippy::cast_possible_truncation)] // Since Rust 2021 doesn't have `size_of_val` included in prelude.
    #[inline]
    fn as_ffi_value(&self) -> (*const libc::c_void, libc::socklen_t) {
        match self {
            Self::AesGcm128(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
            Self::AesGcm256(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
            Self::AesCcm128(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
            Self::Chacha20Poly1305(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
            Self::Sm4Gcm(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
            Self::Sm4Ccm(crypto_info) => (
                <*const _>::cast(crypto_info),
                mem::size_of_val(crypto_info) as libc::socklen_t,
            ),
        }
    }

    /// Extract the `TlsCryptoInfoImpl` from the given
    /// `SupportedCipherSuite` and `ConnectionTrafficSecrets`.
    fn extract_from(
        cipher_suite: SupportedCipherSuite,
        (seq, secrets): (u64, ConnectionTrafficSecrets),
    ) -> Result<Self, InvalidCryptoInfo> {
        let version = match cipher_suite {
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(..) => libc::TLS_1_2_VERSION,
            SupportedCipherSuite::Tls13(..) => libc::TLS_1_3_VERSION,
        };

        Ok(match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                // see https://github.com/rustls/rustls/issues/1833, between
                // rustls 0.21 and 0.22, the extract_keys codepath was changed,
                // so, for TLS 1.2, both GCM-128 and GCM-256 return the
                // Aes128Gcm variant.
                //
                // This issue is fixed since rustls 0.23.

                let iv_and_salt: &[u8; NONCE_LEN] = iv.as_ref().try_into().unwrap();

                Self::AesGcm128(libc::tls12_crypto_info_aes_gcm_128 {
                    info: libc::tls_crypto_info {
                        version,
                        cipher_type: libc::TLS_CIPHER_AES_GCM_128,
                    },
                    iv: iv_and_salt[4..].try_into().unwrap(),
                    key: key
                        .as_ref()
                        .try_into()
                        .map_err(|_| InvalidCryptoInfo::WrongSizeKey)?,
                    salt: iv_and_salt[..4].try_into().unwrap(),
                    rec_seq: seq.to_be_bytes(),
                })
            }
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                let iv_and_salt: &[u8; NONCE_LEN] = iv.as_ref().try_into().unwrap();

                Self::AesGcm256(libc::tls12_crypto_info_aes_gcm_256 {
                    info: libc::tls_crypto_info {
                        version,
                        cipher_type: libc::TLS_CIPHER_AES_GCM_256,
                    },
                    iv: iv_and_salt[4..].try_into().unwrap(),
                    key: key
                        .as_ref()
                        .try_into()
                        .map_err(|_| InvalidCryptoInfo::WrongSizeKey)?,
                    salt: iv_and_salt[..4].try_into().unwrap(),
                    rec_seq: seq.to_be_bytes(),
                })
            }
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                Self::Chacha20Poly1305(libc::tls12_crypto_info_chacha20_poly1305 {
                    info: libc::tls_crypto_info {
                        version,
                        cipher_type: libc::TLS_CIPHER_CHACHA20_POLY1305,
                    },
                    iv: iv.as_ref().try_into().unwrap(),
                    key: key
                        .as_ref()
                        .try_into()
                        .map_err(|_| InvalidCryptoInfo::WrongSizeKey)?,
                    salt: [],
                    rec_seq: seq.to_be_bytes(),
                })
            }
            _ => {
                return Err(InvalidCryptoInfo::UnsupportedCipherSuite(cipher_suite));
            }
        })
    }
}
