//! Transport Layer Security (TLS) is a Upper Layer Protocol (ULP) that runs
//! over TCP. TLS provides end-to-end data integrity and confidentiality.
//!
//! Once the TCP connection is established, sets the TLS ULP, which allows us to
//! set/get TLS socket options.
//!
//! This module provides the [`setup_ulp`] function, which sets the ULP (Upper
//! Layer Protocol) to TLS for a TCP socket. The user can also determine whether
//! the kernel supports kTLS with [`setup_ulp`].
//!
//! After the TLS handshake is completed, we have all the parameters required to
//! move the data-path to the kernel. There is a separate socket option for
//! moving the transmit and the receive into the kernel.
//!
//! This module provides the low-level [`setup_tls_params`] function (when
//! feature `raw-api` is enabled), which sets the Kernel TLS parameters on the
//! TCP socket, allowing the kernel to handle encryption and decryption of the
//! TLS data.

#![allow(clippy::module_name_repetitions)]

pub(crate) mod tls;
pub(crate) mod ulp;

#[cfg(feature = "raw-api")]
pub use tls::{
    setup_tls_params, setup_tls_params_rx, setup_tls_params_tx, TlsCryptoInfoRx, TlsCryptoInfoTx,
};
pub use ulp::{setup_ulp, SetupError};
