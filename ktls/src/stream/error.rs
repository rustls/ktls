//! Error type of `KtlsStream` and related operations.

use std::{fmt, io};

use rustls::{AlertDescription, InvalidMessage, PeerMisbehaved};

#[non_exhaustive]
#[derive(Debug)]
/// The error type for `KtlsStream` and related operations.
pub enum KtlsStreamError {
    /// A corrupt message was received from the peer.
    InvalidMessage(InvalidMessage),

    /// The peer misbehaved in some way.
    PeerMisbehaved(PeerMisbehaved),

    /// Failed to handle a key update request.
    KeyUpdateFailed(rustls::Error),

    /// Failed to handle a provided session ticket.
    SessionTicketFailed(rustls::Error),

    /// The connection has been closed by the peer.
    Closed,

    /// Cannot handle control messages while there is buffered data to read.
    ControlMessageWithBufferedData,

    /// The connection peer closed the connection with an alert.
    Alert(AlertDescription),
}

impl fmt::Display for KtlsStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessage(e) => {
                write!(f, "Received corrupt message of type {e:?}")
            }
            Self::PeerMisbehaved(e) => write!(f, "Peer misbehaved: {e:?}"),
            Self::KeyUpdateFailed(e) => {
                write!(f, "Failed to handle a key update request: {e}")
            }
            Self::SessionTicketFailed(e) => {
                write!(f, "Failed to handle a provided session ticket: {e}")
            }
            Self::Closed => write!(f, "The connection has been closed by the peer"),
            Self::ControlMessageWithBufferedData => {
                write!(
                    f,
                    "Cannot handle control messages while there is buffered data to read"
                )
            }
            Self::Alert(desc) => {
                write!(
                    f,
                    "Connection peer closed the connection with an alert: {desc:?}",
                )
            }
        }
    }
}

impl std::error::Error for KtlsStreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KeyUpdateFailed(e) | Self::SessionTicketFailed(e) => Some(e),
            _ => None,
        }
    }
}

impl From<InvalidMessage> for KtlsStreamError {
    fn from(error: InvalidMessage) -> Self {
        Self::InvalidMessage(error)
    }
}

impl From<PeerMisbehaved> for KtlsStreamError {
    fn from(error: PeerMisbehaved) -> Self {
        Self::PeerMisbehaved(error)
    }
}

impl From<KtlsStreamError> for io::Error {
    fn from(value: KtlsStreamError) -> Self {
        Self::other(value)
    }
}
