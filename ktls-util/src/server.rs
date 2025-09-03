//! A TLS acceptor with kTLS offload support.

// TODO: Well, this should be included in `tokio-rustls`? Or we should provide
// both sync/async versions?

use std::io;
use std::os::fd::AsFd;
use std::sync::Arc;

use ktls::setup::{setup_ulp, SetupError};
use ktls::stream::KtlsStream;
use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::error::Error;
use crate::read_record;

#[derive(Debug, Clone)]
/// A TLS acceptor with kTLS offload support.
pub struct KtlsAcceptor {
    config: Arc<ServerConfig>,
}

impl KtlsAcceptor {
    #[must_use]
    /// Create a new [`KtlsAcceptor`] with the given [`ServerConfig`].
    pub const fn new(config: Arc<ServerConfig>) -> Self {
        Self { config }
    }

    /// Accepts a TLS connection on the given socket.
    ///
    /// ## Errors
    ///
    /// [`SetupError`]. This may contain the original socket if the setup failed
    /// and the caller can fallback to normal TLS acceptor implementation.
    pub async fn try_accept<S>(&self, socket: S) -> Result<KtlsStream<S>, SetupError<S>>
    where
        S: AsyncRead + AsyncWrite + AsFd + Unpin,
    {
        let socket = setup_ulp(socket)?;

        self.internal_try_accept(socket)
            .await
            .map_err(|error| SetupError {
                error: io::Error::other(error),
                socket: None,
            })
    }

    async fn internal_try_accept<S>(&self, mut socket: S) -> Result<KtlsStream<S>, Error>
    where
        S: AsyncWrite + AsyncRead + AsFd + Unpin,
    {
        let mut conn =
            UnbufferedServerConnection::new(self.config.clone()).map_err(Error::Config)?;

        let mut incoming = Vec::with_capacity(u16::MAX as usize + 5);
        let mut outgoing = Vec::with_capacity(u16::MAX as usize + 5);
        let mut outgoing_used = 0usize;
        let mut early_data_received = Vec::new();

        loop {
            let UnbufferedStatus { mut discard, state } = conn.process_tls_records(&mut incoming);

            let state = state.map_err(Error::Handshake)?;

            match state {
                ConnectionState::BlockedHandshake => {
                    read_record(&mut socket, &mut incoming).await?;
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    return Err(Error::ConnectionClosedBeforeHandshakeCompleted);
                }
                ConnectionState::ReadEarlyData(mut data) => {
                    while let Some(record) = data.next_record() {
                        let record = record.map_err(Error::Handshake)?;

                        discard += record.discard;

                        early_data_received.extend_from_slice(record.payload);
                    }
                }
                ConnectionState::EncodeTlsData(mut state) => {
                    match state.encode(&mut outgoing[outgoing_used..]) {
                        Ok(count) => outgoing_used += count,
                        Err(EncodeError::AlreadyEncoded) => unreachable!(),
                        Err(EncodeError::InsufficientSize(e)) => {
                            outgoing.resize(outgoing_used + e.required_size, 0u8);

                            match state.encode(&mut outgoing[outgoing_used..]) {
                                Ok(count) => outgoing_used += count,
                                Err(e) => unreachable!("encode failed after resizing buffer: {e}"),
                            }
                        }
                    }
                }
                ConnectionState::TransmitTlsData(data) => {
                    socket
                        .write_all(&outgoing[..outgoing_used])
                        .await
                        .map_err(Error::IO)?;
                    outgoing_used = 0;
                    data.done();
                }
                ConnectionState::WriteTraffic(_) => {
                    incoming.drain(..discard);
                    break;
                }
                ConnectionState::ReadTraffic(_) => unreachable!(
                    "ReadTraffic should not be encountered during the handshake process"
                ),
                _ => unreachable!("unexpected connection state"),
            }

            incoming.drain(..discard);
        }

        KtlsStream::from_unbuffered_server_connnection(socket, conn, Some(early_data_received))
            .map_err(Error::Ktls)
    }
}
