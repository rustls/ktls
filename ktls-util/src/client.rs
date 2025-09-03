//! A TLS connector with kTLS offload support.

// TODO: Well, this should be included in `tokio-rustls`? Or we should provide
// both sync/async versions?

use std::io;
use std::os::fd::AsFd;
use std::sync::Arc;

use ktls::setup::{setup_ulp, SetupError};
use ktls::stream::KtlsStream;
use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::ServerName;
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::error::Error;
use crate::read_record;

#[derive(Debug, Clone)]
/// A TLS connector with kTLS offload support.
pub struct KtlsConnector {
    config: Arc<ClientConfig>,
}

impl KtlsConnector {
    #[must_use]
    /// Create a new [`KtlsConnector`] with the given [`ClientConfig`].
    pub const fn new(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }

    /// Connects to a TLS server using the given socket and server name.
    ///
    /// ## Errors
    ///
    /// [`SetupError`]. This may contain the original socket if the setup failed
    /// and the caller can fallback to normal TLS connector implementation.
    pub async fn try_connect<S>(
        &self,
        socket: S,
        server_name: ServerName<'static>,
    ) -> Result<KtlsStream<S>, SetupError<S>>
    where
        S: AsyncRead + AsyncWrite + AsFd + Unpin,
    {
        let socket = setup_ulp(socket)?;

        self.internal_try_connect(socket, server_name)
            .await
            .map_err(|error| SetupError {
                error: io::Error::other(error),
                socket: None,
            })
    }

    // `rustls` has poor support for async/await...
    async fn internal_try_connect<S>(
        &self,
        mut socket: S,
        server_name: ServerName<'static>,
    ) -> Result<KtlsStream<S>, Error>
    where
        S: AsyncRead + AsyncWrite + AsFd + Unpin,
    {
        let mut conn = UnbufferedClientConnection::new(self.config.clone(), server_name)
            .map_err(Error::Config)?;

        let mut incoming = Vec::with_capacity(u16::MAX as usize + 5);
        let mut outgoing = Vec::with_capacity(u16::MAX as usize + 5);
        let mut outgoing_used = 0usize;

        loop {
            let UnbufferedStatus { discard, state } = conn.process_tls_records(&mut incoming);

            let state = state.map_err(Error::Handshake)?;

            match state {
                ConnectionState::BlockedHandshake => {
                    read_record(&mut socket, &mut incoming).await?;
                }
                ConnectionState::PeerClosed | ConnectionState::Closed => {
                    return Err(Error::ConnectionClosedBeforeHandshakeCompleted);
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
                    // FIXME: may_encrypt_app_data to check if we can send early data?

                    socket
                        .write_all(&outgoing[..outgoing_used])
                        .await
                        .map_err(Error::IO)?;
                    outgoing_used = 0;
                    data.done();
                }
                ConnectionState::WriteTraffic(_) => {
                    // Handshake is done
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

        KtlsStream::from_unbuffered_client_connnection(socket, conn).map_err(Error::Ktls)
    }
}
