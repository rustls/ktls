use std::os::unix::prelude::RawFd;

use ktls_sys::bindings as ktls;
use rustls::{
    internal::msgs::{enums::AlertLevel, message::Message},
    AlertDescription, ConnectionTrafficSecrets, SupportedCipherSuite,
};

pub(crate) const TLS_1_2_VERSION_NUMBER: u16 = (((ktls::TLS_1_2_VERSION_MAJOR & 0xFF) as u16) << 8)
    | ((ktls::TLS_1_2_VERSION_MINOR & 0xFF) as u16);

pub(crate) const TLS_1_3_VERSION_NUMBER: u16 = (((ktls::TLS_1_3_VERSION_MAJOR & 0xFF) as u16) << 8)
    | ((ktls::TLS_1_3_VERSION_MINOR & 0xFF) as u16);

/// `setsockopt` level constant: TCP
const SOL_TCP: libc::c_int = 6;

/// `setsockopt` SOL_TCP name constant: "upper level protocol"
const TCP_ULP: libc::c_int = 31;

/// `setsockopt` level constant: TLS
const SOL_TLS: libc::c_int = 282;

/// `setsockopt` SOL_TLS level constant: transmit (write)
const TLS_TX: libc::c_int = 1;

/// `setsockopt` SOL_TLS level constant: receive (read)
const TLX_RX: libc::c_int = 2;

pub fn setup_ulp(fd: RawFd) -> std::io::Result<()> {
    unsafe {
        if libc::setsockopt(
            fd,
            SOL_TCP,
            TCP_ULP,
            "tls".as_ptr() as *const libc::c_void,
            3,
        ) < 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub enum Direction {
    // Transmit
    Tx,
    // Receive
    Rx,
}

impl From<Direction> for libc::c_int {
    fn from(val: Direction) -> Self {
        match val {
            Direction::Tx => TLS_TX,
            Direction::Rx => TLX_RX,
        }
    }
}

trait CryptoInfoRaw: Sized {}

macro_rules! impl_crypto_info_raw {
    ($($type:ty)*) => {
		$(impl CryptoInfoRaw for $type {})*
    };
}

impl_crypto_info_raw!(
    ktls::tls12_crypto_info_aes_gcm_128
    ktls::tls12_crypto_info_aes_gcm_256
    ktls::tls12_crypto_info_aes_ccm_128
    ktls::tls12_crypto_info_chacha20_poly1305
    ktls::tls12_crypto_info_sm4_gcm
    ktls::tls12_crypto_info_sm4_ccm
);

#[allow(dead_code)]
pub enum CryptoInfo {
    AesGcm128(ktls::tls12_crypto_info_aes_gcm_128),
    AesGcm256(ktls::tls12_crypto_info_aes_gcm_256),
    AesCcm128(ktls::tls12_crypto_info_aes_ccm_128),
    Chacha20Poly1305(ktls::tls12_crypto_info_chacha20_poly1305),
    Sm4Gcm(ktls::tls12_crypto_info_sm4_gcm),
    Sm4Ccm(ktls::tls12_crypto_info_sm4_ccm),
}

impl CryptoInfo {
    fn as_ptr(&self) -> *const libc::c_void {
        match self {
            CryptoInfo::AesGcm128(info) => info as *const _ as *const libc::c_void,
            CryptoInfo::AesGcm256(info) => info as *const _ as *const libc::c_void,
            CryptoInfo::AesCcm128(info) => info as *const _ as *const libc::c_void,
            CryptoInfo::Chacha20Poly1305(info) => info as *const _ as *const libc::c_void,
            CryptoInfo::Sm4Gcm(info) => info as *const _ as *const libc::c_void,
            CryptoInfo::Sm4Ccm(info) => info as *const _ as *const libc::c_void,
        }
    }

    fn size(&self) -> usize {
        match self {
            CryptoInfo::AesGcm128(_) => std::mem::size_of::<ktls::tls12_crypto_info_aes_gcm_128>(),
            CryptoInfo::AesGcm256(_) => std::mem::size_of::<ktls::tls12_crypto_info_aes_gcm_256>(),
            CryptoInfo::AesCcm128(_) => std::mem::size_of::<ktls::tls12_crypto_info_aes_ccm_128>(),
            CryptoInfo::Chacha20Poly1305(_) => {
                std::mem::size_of::<ktls::tls12_crypto_info_chacha20_poly1305>()
            }
            CryptoInfo::Sm4Gcm(_) => std::mem::size_of::<ktls::tls12_crypto_info_sm4_gcm>(),
            CryptoInfo::Sm4Ccm(_) => std::mem::size_of::<ktls::tls12_crypto_info_sm4_ccm>(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum KtlsCompatibilityError {
    #[error("cipher suite not supported with kTLS: {0:?}")]
    UnsupportedCipherSuite(SupportedCipherSuite),

    #[error("wrong size key")]
    WrongSizeKey,

    #[error("wrong size iv")]
    WrongSizeIv,
}

impl CryptoInfo {
    /// Try to convert rustls cipher suite and secrets into a `CryptoInfo`.
    pub fn from_rustls(
        cipher_suite: SupportedCipherSuite,
        (seq, secrets): (u64, ConnectionTrafficSecrets),
    ) -> Result<CryptoInfo, KtlsCompatibilityError> {
        let version = match cipher_suite {
            SupportedCipherSuite::Tls12(..) => TLS_1_2_VERSION_NUMBER,
            SupportedCipherSuite::Tls13(..) => TLS_1_3_VERSION_NUMBER,
        };

        Ok(match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                // see https://github.com/rustls/rustls/issues/1833,
                // between rustls 0.21 and 0.22, the extract_keys codepath
                // was changed, so it always returns AesGcm128, even if
                // the cipher suite is Aes256Gcm.

                match key.as_ref().len() {
                    16 => CryptoInfo::AesGcm128(ktls::tls12_crypto_info_aes_gcm_128 {
                        info: ktls::tls_crypto_info {
                            version,
                            cipher_type: ktls::TLS_CIPHER_AES_GCM_128 as _,
                        },
                        iv: iv
                            .as_ref()
                            .get(4..)
                            .expect("AES-GCM-128 iv is 8 bytes")
                            .try_into()
                            .expect("AES-GCM-128 iv is 8 bytes"),
                        key: key
                            .as_ref()
                            .try_into()
                            .expect("AES-GCM-128 key is 16 bytes"),
                        salt: iv
                            .as_ref()
                            .get(..4)
                            .expect("AES-GCM-128 salt is 4 bytes")
                            .try_into()
                            .expect("AES-GCM-128 salt is 4 bytes"),
                        rec_seq: seq.to_be_bytes(),
                    }),
                    32 => CryptoInfo::AesGcm256(ktls::tls12_crypto_info_aes_gcm_256 {
                        info: ktls::tls_crypto_info {
                            version,
                            cipher_type: ktls::TLS_CIPHER_AES_GCM_256 as _,
                        },
                        iv: iv
                            .as_ref()
                            .get(4..)
                            .expect("AES-GCM-256 iv is 8 bytes")
                            .try_into()
                            .expect("AES-GCM-256 iv is 8 bytes"),
                        key: key
                            .as_ref()
                            .try_into()
                            .expect("AES-GCM-256 key is 32 bytes"),
                        salt: iv
                            .as_ref()
                            .get(..4)
                            .expect("AES-GCM-256 salt is 4 bytes")
                            .try_into()
                            .expect("AES-GCM-256 salt is 4 bytes"),
                        rec_seq: seq.to_be_bytes(),
                    }),
                    _ => unreachable!("GCM key length is not 16 or 32"),
                }
            }
            ConnectionTrafficSecrets::Aes256Gcm { .. } => {
                unreachable!("a bug in rustls 0.22 means this codepath is dead. when we can upgrade to 0.23, we should fix this. see https://github.com/rustls/rustls/issues/1833")
            }
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                CryptoInfo::Chacha20Poly1305(ktls::tls12_crypto_info_chacha20_poly1305 {
                    info: ktls::tls_crypto_info {
                        version,
                        cipher_type: ktls::TLS_CIPHER_CHACHA20_POLY1305 as _,
                    },
                    iv: iv
                        .as_ref()
                        .try_into()
                        .expect("Chacha20-Poly1305 iv is 12 bytes"),
                    key: key
                        .as_ref()
                        .try_into()
                        .expect("Chacha20-Poly1305 key is 32 bytes"),
                    salt: ktls::__IncompleteArrayField::new(),
                    rec_seq: seq.to_be_bytes(),
                })
            }
            _ => {
                return Err(KtlsCompatibilityError::UnsupportedCipherSuite(cipher_suite));
            }
        })
    }
}

pub fn setup_tls_info(fd: RawFd, dir: Direction, info: CryptoInfo) -> Result<(), crate::Error> {
    let ret = unsafe { libc::setsockopt(fd, SOL_TLS, dir.into(), info.as_ptr(), info.size() as _) };
    if ret < 0 {
        return Err(crate::Error::TlsCryptoInfoError(
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
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
