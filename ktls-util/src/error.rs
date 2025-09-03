//! Errors

use std::io;

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
/// Unified error type for this crate
pub(crate) enum Error {
    #[error(transparent)]
    /// General IO error.
    IO(#[from] io::Error),

    #[error("The peer closed the connection before the TLS handshake could be completed")]
    /// (Reserved) The peer closed the connection before the TLS handshake could
    /// be completed.
    ConnectionClosedBeforeHandshakeCompleted,

    #[error("Failed to create rustls unbuffered connection: {0}")]
    /// (Reserved)
    Config(#[source] rustls::Error),

    #[error("An error occurred during handshake: {0}")]
    /// (Reserved)
    Handshake(#[source] rustls::Error),

    #[error(transparent)]
    /// Errors from ktls crate.
    Ktls(#[from] ktls::Error),
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::IO(error) => error,
            _ => Self::other(error),
        }
    }
}
