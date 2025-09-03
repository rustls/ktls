//! See [`KtlsStream`].

#![allow(clippy::module_name_repetitions)]

pub mod context;
pub mod error;
pub mod impl_std;
#[cfg(feature = "async-io-tokio")]
pub mod impl_tokio;

#[cfg(feature = "raw-api")]
use std::io;
use std::os::fd::AsFd;

use rustls::client::UnbufferedClientConnection;
use rustls::server::UnbufferedServerConnection;

use crate::error::Error;
use crate::setup::tls::setup_tls_params;
#[cfg(feature = "raw-api")]
use crate::stream::context::Buffer;
use crate::stream::context::{Context, StreamState, TlsConnData};

const DEFAULT_SCRATCH_CAPACITY: usize = 64;

pin_project_lite::pin_project! {
    #[derive(Debug)]
    #[project = KTlsStreamProject]
    /// A thin wrapper around an inner socket with kernel TLS (kTLS) offload
    /// configured.
    ///
    /// This implements traits [`Read`](std::io::Read) and
    /// [`Write`](std::io::Write), [`AsyncRead`](tokio::io::AsyncRead) and
    /// [`AsyncWrite`](tokio::io::AsyncWrite) (when feature `async-io-tokio` is
    /// enabled).
    ///
    /// For those who may need low-level access to the inner socket, feature
    /// `raw-api` provides an unsafe method [`as_raw`](Self::as_raw) to get a
    /// mutable reference to the inner socket.
    ///
    /// ## Behaviours
    ///
    /// Once a TLS `close_notify` alert from the peer is received, all subsequent
    /// read operations will return EOF.
    ///
    /// Once the caller explicitly calls `(poll_)shutdown` on the stream, all
    /// subsequent write operations will return 0 bytes, indicating that the
    /// stream is closed for writing.
    ///
    /// Once the stream is being dropped, a `close_notify` alert would be sent to
    /// the peer automatically before shutting down the inner socket, according to
    /// [RFC 8446, section 6.1].
    ///
    /// The caller may call `(poll_)shutdown` on the stream to shutdown explicitly
    /// both sides of the stream. Currently, there's no way provided by this crate
    /// to shutdown the TLS stream write side only. For TLS 1.2, this is ideal since
    /// once one party sends a `close_notify` alert, *the other party MUST respond
    /// with a `close_notify` alert of its own and close down the connection
    /// immediately*, according to [RFC 5246, section 7.2.1]; for TLS 1.3, *both
    /// parties need not wait to receive a "`close_notify`" alert before
    /// closing their read side of the connection*, according to [RFC 8446, section
    /// 6.1].
    ///
    /// [RFC 5246, section 7.2.1]: https://tools.ietf.org/html/rfc5246#section-7.2.1
    /// [RFC 8446, section 6.1]: https://tools.ietf.org/html/rfc8446#section-6.1
    pub struct KtlsStream<S: AsFd> {
        #[pin]
        inner: S,
        ctx: Context,
    }

    impl<S: AsFd> PinnedDrop for KtlsStream<S> {
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();

            // TODO: No need to flush? It's a no-op anyway for TcpStream / UnixStream.
            this.ctx.shutdown(&*this.inner);
        }
    }
}

impl<S> KtlsStream<S>
where
    S: AsFd,
{
    /// Attempts to construct a new [`KtlsStream`] from the provided socket and
    /// [`UnbufferedClientConnection`].
    ///
    /// ## Prerequisites
    ///
    /// - The provided [`UnbufferedClientConnection`] must meet the following
    ///   requirements:
    ///
    ///   - TLS handshake must be completed
    ///   - [`enable_extract_secrets`](rustls::ClientConfig::enable_secret_extraction) must be set to `true`
    ///
    ///   For detailed information about these prerequisites, see the
    ///   [`rustls::kernel`] module documentation.
    ///
    /// - The socket provided must have ULP configured with
    ///   [`setup_ktls_ulp`](crate::setup::setup_ulp) in advance.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection does not meet the prerequisites or if
    /// the underlying kernel TLS setup fails.
    pub fn from_unbuffered_client_connnection(
        socket: S,
        conn: UnbufferedClientConnection,
    ) -> Result<Self, Error> {
        let (secrets, conn) = conn
            .dangerous_into_kernel_connection()
            .map_err(Error::ExtractSecrets)?;

        let supported_cipher_suite = conn.negotiated_cipher_suite();

        let this = Self {
            inner: socket,
            ctx: Context::new(StreamState::empty(), Vec::new(), TlsConnData::Client(conn)),
        };

        setup_tls_params(&this.inner, supported_cipher_suite, secrets)?;

        Ok(this)
    }

    /// Attempts to construct a new [`KtlsStream`] from the provided socket and
    /// [`UnbufferedServerConnection`].
    ///
    /// ## Prerequisites
    ///
    /// - The provided [`UnbufferedServerConnection`] must meet the following
    ///   requirements:
    ///
    ///   - TLS handshake must be completed
    ///   - [`enable_extract_secrets`](rustls::ServerConfig::enable_secret_extraction) must be set to `true`
    ///
    ///   For detailed information about these prerequisites, see the
    ///   [`rustls::kernel`] module documentation.
    ///
    /// - The socket provided must have ULP configured with
    ///   [`setup_ktls_ulp`](crate::setup::setup_ulp) in advance.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection does not meet the prerequisites or if
    /// the underlying kernel TLS setup fails.
    pub fn from_unbuffered_server_connnection(
        socket: S,
        conn: UnbufferedServerConnection,
        early_data_received: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        let (secrets, conn) = conn
            .dangerous_into_kernel_connection()
            .map_err(Error::ExtractSecrets)?;

        // From here, the connection is considered established and handshake is
        // completed

        let supported_cipher_suite = conn.negotiated_cipher_suite();
        let (state, buffer) = match early_data_received {
            Some(early_data_received) if !early_data_received.is_empty() => {
                (StreamState::HAS_BUFFERED_DATA, early_data_received)
            }
            _ => (
                StreamState::empty(),
                Vec::with_capacity(DEFAULT_SCRATCH_CAPACITY),
            ),
        };

        let this = Self {
            inner: socket,
            ctx: Context::new(state, buffer, TlsConnData::Server(conn)),
        };

        setup_tls_params(&this.inner, supported_cipher_suite, secrets)?;

        Ok(this)
    }

    #[allow(unsafe_code)]
    #[cfg(feature = "raw-api")]
    #[inline]
    /// Returns a mutable reference to the inner socket if the TLS stream is not
    /// closed (unidirectionally or bidirectionally).
    ///
    /// This requires a mutable reference to the [`KtlsStream`] to ensure a
    /// exclusive access to the inner socket.
    ///
    /// ## Safety
    ///
    /// The caller must ensure that:
    ///
    /// * All buffered data **MUST** be retrieved using
    ///   [`Self::take_buffered_data`] and properly consumed before accessing
    ///   the inner socket. Buffered data typically consists of:
    ///
    ///   - Early data received during handshake.
    ///   - Application data received due to improper usage of
    ///     [`Self::handle_io_result`].
    ///
    /// * The caller **MAY** handle any [`io::Result`]s returned by I/O
    ///   operations on the inner socket with [`Self::handle_io_result`].
    ///
    /// * The caller **MUST NOT** shutdown the inner socket directly, which will
    ///   lead to undefined behaviours. Instead, the caller **MAY** call
    ///   `(poll_)shutdown` explictly on the [`KtlsStream`] to gracefully
    ///   shutdown the TLS stream (with `close_notify` be sent) manually, or
    ///   just drop the stream to do automatic graceful shutdown.
    ///
    /// [RFC 8446, section 6.1]: https://tools.ietf.org/html/rfc8446#section-6.1
    pub unsafe fn as_raw(&mut self) -> Option<&mut S> {
        debug_assert!(
            !self.ctx.state().has_buffered_data(),
            "Buffered data must be consumed before accessing the inner stream."
        );

        if self.ctx.state().is_partially_closed() {
            return None;
        }

        Some(&mut self.inner)
    }

    #[cfg(feature = "raw-api")]
    /// Inspects and handles the [`io::Result`] returned by a I/O operation on
    /// the inner socket directly.
    ///
    /// - If the result is `Ok`, it returns `Some(T)`.
    /// - If the errno is [`EIO`](libc::EIO), it tries to handle any TLS control
    ///   messages received, and returns `None` if succeeded.
    /// - Otherwise, it aborts the connection with `internal_error` alert and
    ///   returns the error.
    ///
    /// ## Errors
    ///
    /// The unrecoverable original [`io::Error`].
    pub fn handle_io_result<T>(&mut self, ret: io::Result<T>) -> io::Result<Option<T>> {
        self.ctx.handle_io_result(&self.inner, ret)
    }

    #[cfg(feature = "raw-api")]
    #[must_use = "The buffered data must be handled."]
    /// Takes the buffered data, if any, and resets the buffer state.
    ///
    /// This method is useful and should be called before performing low-level
    /// I/O operations on the inner socket.
    pub fn take_buffered_data(&mut self) -> Option<Buffer> {
        self.ctx.take_buffer()
    }
}
