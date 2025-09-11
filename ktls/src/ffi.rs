use std::os::unix::prelude::RawFd;

use ktls_sys::bindings as ktls;
use rustls::internal::msgs::enums::AlertLevel;
use rustls::internal::msgs::message::Message;
use rustls::AlertDescription;

pub(crate) const TLS_1_2_VERSION_NUMBER: u16 = (((ktls::TLS_1_2_VERSION_MAJOR & 0xFF) as u16) << 8)
    | ((ktls::TLS_1_2_VERSION_MINOR & 0xFF) as u16);

pub(crate) const TLS_1_3_VERSION_NUMBER: u16 = (((ktls::TLS_1_3_VERSION_MAJOR & 0xFF) as u16) << 8)
    | ((ktls::TLS_1_3_VERSION_MINOR & 0xFF) as u16);

/// `setsockopt` level constant: TLS
const SOL_TLS: libc::c_int = 282;

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
