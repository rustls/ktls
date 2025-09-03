//! Error types for the `ktls` crate

use std::{fmt, io};

use rustls::SupportedCipherSuite;

#[non_exhaustive]
#[derive(Debug)]
/// Unified error type for this crate
pub enum Error {
    /// Invalid crypto material, e.g., wrong size key or IV.
    InvalidCryptoInfo(InvalidCryptoInfo),

    /// Failed to extract connection secrets from rustls connection, e.g., not
    /// have `config.enable_secret_extraction` set to true
    ExtractSecrets(rustls::Error),

    /// General IO error.
    IO(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCryptoInfo(e) => e.fmt(f),
            Self::ExtractSecrets(e) => {
                write!(f, "failed to extract secrets from rustls connection: {e}")
            }
            Self::IO(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCryptoInfo(_) => None,
            Self::ExtractSecrets(e) => Some(e),
            Self::IO(e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::IO(error)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::IO(error) => error,
            _ => Self::other(error),
        }
    }
}

impl From<InvalidCryptoInfo> for Error {
    fn from(error: InvalidCryptoInfo) -> Self {
        Self::InvalidCryptoInfo(error)
    }
}

#[non_exhaustive]
#[derive(Debug)]
/// Crypto material is invalid, e.g., wrong size key or IV.
pub enum InvalidCryptoInfo {
    /// The provided key has an incorrect size (unlikely).
    WrongSizeKey,

    /// The provided IV has an incorrect size (unlikely).
    WrongSizeIv,

    /// The negotiated cipher suite is not supported for ktls by the running
    /// kernel.
    UnsupportedCipherSuite(SupportedCipherSuite),
}

impl fmt::Display for InvalidCryptoInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSizeKey => write!(f, "wrong size key"),
            Self::WrongSizeIv => write!(f, "wrong size iv"),
            Self::UnsupportedCipherSuite(suite) => {
                write!(
                    f,
                    "the negotiated cipher suite [{suite:?}] is not supported for ktls by the \
                     running kernel"
                )
            }
        }
    }
}
