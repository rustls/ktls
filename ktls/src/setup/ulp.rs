//! See the [module-level documentation](crate::setup) for more details.

use std::os::fd::AsFd;
use std::{fmt, io};

use nix::errno::Errno;
use nix::sys::socket::{setsockopt, sockopt};

/// Sets the TLS Upper Layer Protocol (ULP).
///
/// This should be called before performing any I/O operations on the
/// socket.
///
/// # Errors
///
/// [`SetupError`].
///
/// If the error is caused by the system not supporting kTLS, such as kernel
/// module `tls` not being enabled or the kernel version being too old, will
/// have the original socket returned, see [`SetupError::socket`].
pub fn setup_ulp<S: AsFd>(socket: S) -> Result<S, SetupError<S>> {
    match setsockopt(&socket, sockopt::TcpUlp::default(), b"tls") {
        Ok(()) => Ok(socket),
        Err(err) if err == Errno::ENOENT => Err(SetupError {
            error: io::Error::from(err),
            socket: Some(socket),
        }),
        Err(err) => Err(SetupError {
            error: io::Error::from(err),
            socket: None,
        }),
    }
}

#[allow(clippy::exhaustive_structs)]
/// An error that occurred while configuring the ULP.
pub struct SetupError<S> {
    /// The I/O error that occurred while configuring the ULP.
    pub error: io::Error,

    /// The original I/O socket.
    pub socket: Option<S>,
}

impl<S> fmt::Debug for SetupError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl<S> fmt::Display for SetupError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl<S> std::error::Error for SetupError<S> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
