//! Raw FFI wrappers.

// Since Rust 2021 doesn't have `size_of_val` included in prelude.
#![allow(unused_qualifications)]

use std::os::fd::RawFd;
use std::{io, mem, ptr};

#[repr(C)]
pub(crate) struct Cmsg<const N: usize> {
    _hdr: libc::cmsghdr,
    data: [u8; N],
}

impl<const N: usize> Cmsg<N> {
    #[allow(trivial_numeric_casts)]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_possible_wrap)]
    pub(crate) fn new(level: i32, typ: i32, data: [u8; N]) -> Self {
        #[allow(unsafe_code)]
        // SAFETY: zeroed is fine for cmsghdr as we will set all the fields we use.
        let mut hdr = unsafe { mem::zeroed::<libc::cmsghdr>() };

        hdr.cmsg_level = level;
        hdr.cmsg_type = typ;
        // For MUSL target, this is u32.
        hdr.cmsg_len = (mem::offset_of!(Self, data) + N) as _;

        Self { _hdr: hdr, data }
    }
}

#[allow(trivial_numeric_casts)]
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_possible_wrap)]
/// A wrapper around [`libc::sendmsg`].
pub(crate) fn sendmsg<const N: usize>(
    fd: RawFd,
    data: &mut [io::IoSlice<'_>],
    cmsg: &mut Cmsg<N>,
    flags: i32,
) -> io::Result<usize> {
    #[allow(unsafe_code)]
    // SAFETY: zeroed is fine for msghdr as we will set all the fields we use.
    let mut msghdr: libc::msghdr = unsafe { mem::zeroed() };

    msghdr.msg_control = ptr::from_mut(cmsg).cast();
    msghdr.msg_controllen = mem::size_of_val(cmsg) as _;
    msghdr.msg_iov = ptr::from_mut(data).cast();
    msghdr.msg_iovlen = data.len() as _;

    #[allow(unsafe_code)]
    // SAFETY: syscall
    let ret = unsafe { libc::sendmsg(fd, &msghdr, flags) };

    if ret >= 0 {
        #[allow(clippy::cast_sign_loss)]
        Ok(ret as usize)
    } else {
        Err(io::Error::last_os_error())
    }
}
