use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::prelude::RawFd;
use std::{io, mem};

use ktls_sys::bindings as ktls;
use nix::sys::socket::{setsockopt, sockopt};
use rustls::crypto::cipher::NONCE_LEN;
use rustls::internal::msgs::enums::AlertLevel;
use rustls::internal::msgs::message::Message;
use rustls::{AlertDescription, ConnectionTrafficSecrets, ExtractedSecrets, SupportedCipherSuite};

pub(crate) const TLS_1_2_VERSION_NUMBER: u16 = (((ktls::TLS_1_2_VERSION_MAJOR & 0xFF) as u16) << 8)
    | ((ktls::TLS_1_2_VERSION_MINOR & 0xFF) as u16);

pub(crate) const TLS_1_3_VERSION_NUMBER: u16 = (((ktls::TLS_1_3_VERSION_MAJOR & 0xFF) as u16) << 8)
    | ((ktls::TLS_1_3_VERSION_MINOR & 0xFF) as u16);

/// `setsockopt` level constant: TLS
const SOL_TLS: libc::c_int = 282;

/// Sets the TLS Upper Layer Protocol (ULP).
///
/// This should be called before performing any I/O operations on the
/// socket.
///
/// # Errors
///
/// [`SetupUlpError`]. The caller may check if the error is due to the system
/// not supporting kTLS (e.g., kernel module `tls` not being enabled or the
/// kernel version being too old) with [`SetupUlpError::is_ktls_unsupported`].
pub fn setup_ulp<S: AsFd>(socket: &S) -> Result<(), SetupUlpError> {
    setsockopt(socket, sockopt::TcpUlp::default(), b"tls")
        .map_err(io::Error::from)
        .map_err(SetupUlpError)
}

#[derive(Debug, thiserror::Error)]
#[error("Failed to set TLS ULP, error: {0}")]
/// An error that occurred while configuring the ULP.
///
/// This error wraps the underlying `io::Error` that caused the failure.
/// The caller may check if the error is due to the system not supporting kTLS
/// (e.g., kernel module `tls` not being enabled or the kernel version being too
/// old).
pub struct SetupUlpError(#[source] io::Error);

impl SetupUlpError {
    /// Returns `true` if the error is due to the system not supporting kTLS.
    pub fn is_ktls_unsupported(&self) -> bool {
        matches!(self.0.raw_os_error(), Some(libc::ENOENT))
    }
}

impl From<SetupUlpError> for io::Error {
    fn from(err: SetupUlpError) -> Self {
        io::Error::other(err)
    }
}

/// Sets the kTLS parameters on the socket after the TLS handshake is completed.
///
/// ## Errors
///
/// * Invalid crypto materials.
/// * Syscall error.
pub(crate) fn setup_tls_params<S: AsFd>(
    socket: &S,
    cipher_suite: SupportedCipherSuite,
    secrets: ExtractedSecrets,
) -> io::Result<()> {
    TlsCryptoInfo::extract(cipher_suite, secrets.tx)?.set_tx(socket)?;
    TlsCryptoInfo::extract(cipher_suite, secrets.rx)?.set_rx(socket)?;

    Ok(())
}

#[repr(C)]
#[allow(unused)]
/// A wrapper around the `libc::tls12_crypto_info_*` structs, use with setting
/// up the kTLS r/w parameters on the TCP socket.
///
/// This is originated from the `nix` crate, which currently does not support
/// `AES-128-CCM` or `SM4-*`, so we implement our own version here.
pub(crate) enum TlsCryptoInfo {
    AesGcm128(libc::tls12_crypto_info_aes_gcm_128),
    AesGcm256(libc::tls12_crypto_info_aes_gcm_256),
    AesCcm128(libc::tls12_crypto_info_aes_ccm_128),
    Chacha20Poly1305(libc::tls12_crypto_info_chacha20_poly1305),
    Sm4Gcm(libc::tls12_crypto_info_sm4_gcm),
    Sm4Ccm(libc::tls12_crypto_info_sm4_ccm),
}

impl TlsCryptoInfo {
    /// Sets the kTLS parameters on the given file descriptor, assuming that the
    /// [`TlsCryptoInfo`] is *extract* from the sequence number and
    /// secrets for the "tx" (transmit) direction.
    pub(crate) fn set_tx<S: AsFd>(self, socket: &S) -> io::Result<()> {
        self.set(socket, libc::TLS_TX)
    }

    /// Sets the kTLS parameters on the given file descriptor, assuming that the
    /// [`TlsCryptoInfo`] is *extract* from the sequence number and
    /// secrets for the "rx" (receive) direction.
    pub(crate) fn set_rx<S: AsFd>(self, socket: &S) -> io::Result<()> {
        self.set(socket, libc::TLS_RX)
    }

    /// Sets the kTLS parameters on the given file descriptor.
    fn set<S: AsFd>(&self, socket: &S, direction: libc::c_int) -> io::Result<()> {
        let (ffi_ptr, ffi_len) = match self {
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
        };

        // SAFETY: syscall
        let ret = unsafe {
            libc::setsockopt(
                socket.as_fd().as_raw_fd(),
                libc::SOL_TLS,
                direction,
                ffi_ptr,
                ffi_len,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
/// Crypto material is invalid, e.g., wrong size key or IV.
enum InvalidCryptoInfo {
    #[error("Wrong size key")]
    /// The provided key has an incorrect size (unlikely).
    WrongSizeKey,

    #[error("The negotiated cipher suite [{0:?}] is not supported by the current kernel")]
    /// The negotiated cipher suite is not supported by the current kernel.
    UnsupportedCipherSuite(SupportedCipherSuite),
}

impl From<InvalidCryptoInfo> for io::Error {
    fn from(err: InvalidCryptoInfo) -> Self {
        io::Error::other(err)
    }
}

impl TlsCryptoInfo {
    /// Extract the [`TlsCryptoInfo`] from the given
    /// [`SupportedCipherSuite`] and [`ConnectionTrafficSecrets`].
    fn extract(
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

const TLS_SET_RECORD_TYPE: libc::c_int = 1;
const ALERT: u8 = 0x15;

// Yes, really. cmsg components are aligned to [libc::c_long]
#[cfg_attr(target_pointer_width = "32", repr(C, align(4)))]
#[cfg_attr(target_pointer_width = "64", repr(C, align(8)))]
struct Cmsg<const N: usize> {
    hdr: libc::cmsghdr,
    data: [u8; N],
}

impl<const N: usize> Cmsg<N> {
    fn new(level: i32, typ: i32, data: [u8; N]) -> Self {
        Self {
            hdr: libc::cmsghdr {
                // on Linux this is a usize, on macOS this is a u32
                #[allow(clippy::unnecessary_cast)]
                cmsg_len: (memoffset::offset_of!(Self, data) + N) as _,
                cmsg_level: level,
                cmsg_type: typ,
            },
            data,
        }
    }
}

pub fn send_close_notify(fd: RawFd) -> std::io::Result<()> {
    let mut data = vec![];
    Message::build_alert(AlertLevel::Warning, AlertDescription::CloseNotify)
        .payload
        .encode(&mut data);

    let mut cmsg = Cmsg::new(SOL_TLS, TLS_SET_RECORD_TYPE, [ALERT]);

    let msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut libc::iovec {
            iov_base: data.as_mut_ptr() as _,
            iov_len: data.len(),
        },
        msg_iovlen: 1,
        msg_control: &mut cmsg as *mut _ as *mut _,
        msg_controllen: cmsg.hdr.cmsg_len,
        msg_flags: 0,
    };

    let ret = unsafe { libc::sendmsg(fd, &msg, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
