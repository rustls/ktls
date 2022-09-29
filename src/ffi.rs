use std::os::unix::prelude::RawFd;

use ktls_sys::bindings as ktls;
use rustls::{
    internal::msgs::{
        enums::AlertLevel,
        message::{Message, OpaqueMessage},
    },
    AlertDescription, BulkAlgorithm, DirectionalSecrets, SupportedCipherSuite,
};
use tokio_rustls::rustls::ContentType;

const TLS_1_2_VERSION_NUMBER: u16 = (((ktls::TLS_1_2_VERSION_MAJOR & 0xFF) as u16) << 8)
    | ((ktls::TLS_1_2_VERSION_MINOR & 0xFF) as u16);

const TLS_1_3_VERSION_NUMBER: u16 = (((ktls::TLS_1_3_VERSION_MAJOR & 0xFF) as u16) << 8)
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
        secrets: &DirectionalSecrets,
        extra_random: &[u8],
    ) -> Result<CryptoInfo, KtlsCompatibilityError> {
        // TODO: don't panic if key sizes are wrong, just return an error

        match cipher_suite {
            // XXX: ktls_test uses completely random IVs here, not sure why:
            // https://github.com/fasterthanlime/ktls_test/blob/e69d07d2613b3aa91ac7501549bd33738c65ec21/tls_client.c#L138-L140
            SupportedCipherSuite::Tls12(suite) => match suite.common.bulk {
                BulkAlgorithm::Aes128Gcm => {
                    Ok(CryptoInfo::AesGcm128(ktls::tls12_crypto_info_aes_gcm_128 {
                        info: ktls::tls_crypto_info {
                            version: TLS_1_2_VERSION_NUMBER,
                            cipher_type: ktls::TLS_CIPHER_AES_GCM_128 as _,
                        },
                        key: secrets.key[..].try_into().unwrap(),
                        rec_seq: secrets.seq_number.to_be_bytes(),
                        salt: secrets.iv[..].try_into().unwrap(),
                        iv: extra_random[..8].try_into().unwrap(),
                    }))
                }
                BulkAlgorithm::Aes256Gcm => {
                    Ok(CryptoInfo::AesGcm256(ktls::tls12_crypto_info_aes_gcm_256 {
                        info: ktls::tls_crypto_info {
                            version: TLS_1_2_VERSION_NUMBER,
                            cipher_type: ktls::TLS_CIPHER_AES_GCM_256 as _,
                        },
                        key: secrets.key[..].try_into().unwrap(),
                        rec_seq: secrets.seq_number.to_be_bytes(),
                        salt: secrets.iv[..].try_into().unwrap(),
                        iv: extra_random[..8].try_into().unwrap(),
                    }))
                }
                BulkAlgorithm::Chacha20Poly1305 => Ok(CryptoInfo::Chacha20Poly1305(
                    ktls::tls12_crypto_info_chacha20_poly1305 {
                        info: ktls::tls_crypto_info {
                            version: TLS_1_2_VERSION_NUMBER,
                            cipher_type: ktls::TLS_CIPHER_CHACHA20_POLY1305 as _,
                        },
                        key: secrets.key[..].try_into().unwrap(),
                        rec_seq: secrets.seq_number.to_be_bytes(),
                        salt: ktls::__IncompleteArrayField::new(),
                        iv: secrets.iv[..].try_into().unwrap(),
                    },
                )),
            },
            SupportedCipherSuite::Tls13(suite) => match suite.common.bulk {
                BulkAlgorithm::Aes128Gcm => {
                    Ok(CryptoInfo::AesGcm128(ktls::tls12_crypto_info_aes_gcm_128 {
                        info: ktls::tls_crypto_info {
                            version: TLS_1_3_VERSION_NUMBER,
                            cipher_type: ktls::TLS_CIPHER_AES_GCM_128 as _,
                        },
                        key: secrets.key[..].try_into().unwrap(),
                        rec_seq: secrets.seq_number.to_be_bytes(),
                        salt: secrets.iv[..4].try_into().unwrap(),
                        iv: secrets.iv[4..].try_into().unwrap(),
                    }))
                }
                BulkAlgorithm::Aes256Gcm => {
                    Ok(CryptoInfo::AesGcm256(ktls::tls12_crypto_info_aes_gcm_256 {
                        info: ktls::tls_crypto_info {
                            version: TLS_1_3_VERSION_NUMBER,
                            cipher_type: ktls::TLS_CIPHER_AES_GCM_256 as _,
                        },
                        key: secrets.key[..].try_into().unwrap(),
                        rec_seq: secrets.seq_number.to_be_bytes(),
                        salt: secrets.iv[..4].try_into().unwrap(),
                        iv: secrets.iv[4..].try_into().unwrap(),
                    }))
                }
                BulkAlgorithm::Chacha20Poly1305 => Ok(CryptoInfo::Chacha20Poly1305(
                    ktls::tls12_crypto_info_chacha20_poly1305 {
                        info: ktls::tls_crypto_info {
                            version: TLS_1_3_VERSION_NUMBER,
                            cipher_type: ktls::TLS_CIPHER_CHACHA20_POLY1305 as _,
                        },
                        key: secrets.key[..].try_into().unwrap(),
                        rec_seq: secrets.seq_number.to_be_bytes(),
                        salt: ktls::__IncompleteArrayField::new(),
                        iv: secrets.iv[..].try_into().unwrap(),
                    },
                )),
            },
        }
    }
}

pub fn setup_tls_info(fd: RawFd, dir: Direction, info: CryptoInfo) -> std::io::Result<()> {
    let ret = unsafe { libc::setsockopt(fd, SOL_TLS, dir.into(), info.as_ptr(), info.size() as _) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
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
                cmsg_len: memoffset::offset_of!(Self, data) + N,
                cmsg_level: level,
                cmsg_type: typ,
            },
            data,
        }
    }
}

pub fn send_close_notify(fd: RawFd) -> std::io::Result<()> {
    // let mut data = vec![];
    // Message::build_alert(AlertLevel::Warning, AlertDescription::CloseNotify)
    //     .payload
    //     .encode(&mut data);
    let mut data: Vec<u8> = vec![2, 50];
    println!("data = {data:x?}");

    let mut cmsg = Cmsg::new(SOL_TLS, TLS_SET_RECORD_TYPE, [ALERT]);
    unsafe {
        println!(
            "cmsg = {:x?}",
            std::slice::from_raw_parts(
                &cmsg as *const _ as *const u8,
                std::mem::size_of_val(&cmsg)
            )
        );
    }
    println!("size_of cmsg: {}", std::mem::size_of::<Cmsg<1>>());
    println!("offset of data = {}", memoffset::offset_of!(Cmsg<1>, data));
    println!("cmsg_len = {}", cmsg.hdr.cmsg_len);

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

    unsafe {
        dbg!(msg.msg_name);
        dbg!(msg.msg_namelen);
        dbg!((*msg.msg_iov).iov_base);
        dbg!((*msg.msg_iov).iov_len);
        dbg!(msg.msg_iov);
        dbg!(msg.msg_iovlen);
        dbg!(msg.msg_control);
        dbg!(msg.msg_controllen);
        dbg!(msg.msg_flags);
        dbg!(std::slice::from_raw_parts(
            msg.msg_control as *const u8,
            msg.msg_controllen as usize
        ));
    }

    dbg!(fd);

    let ret = unsafe { libc::sendmsg(fd, &msg, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
