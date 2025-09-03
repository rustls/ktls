//! kTLS stream context

use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd};
use std::{fmt, io, mem, ops, slice};

use nix::errno::Errno;
use nix::sys::socket::{cmsg_space, recvmsg, ControlMessageOwned, MsgFlags, TlsGetRecordType};
use rustls::client::ClientConnectionData;
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::enums::AlertLevel;
use rustls::kernel::KernelConnection;
use rustls::server::ServerConnectionData;
use rustls::{
    AlertDescription, ConnectionTrafficSecrets, ContentType, HandshakeType, InvalidMessage,
    PeerMisbehaved, ProtocolVersion, SupportedCipherSuite,
};

use crate::protocol::{KeyUpdateRequest, KEY_UPDATE_NOT_REQUESTED, KEY_UPDATE_REQUESTED};
use crate::setup::tls::{setup_tls_params_rx, setup_tls_params_tx};
use crate::stream::error::KtlsStreamError;

/// Helper macro to handle the return value of an I/O operation on the
/// kTLS stream.
macro_rules! handle_ret {
    ($this:expr, $($tt:tt)+) => {
        loop {
            let ret = $($tt)+;

            if let Some(ret) = $this.ctx.handle_io_result(&$this.inner, ret).transpose() {
                return ret.into();
            };
        }
    };
}

#[allow(unused)]
/// `poll` version of `handle_ret` macro, for async I/O operations.
macro_rules! handle_ret_async {
    ($this:expr, $($tt:tt)+) => {
        loop {
            let ret = std::task::ready!($($tt)+);

            if let Some(ret) = $this.ctx.handle_io_result(&*$this.inner, ret).transpose() {
                return std::task::Poll::Ready(ret);
            };
        }
    };
}

#[allow(unused)]
pub(crate) use {handle_ret, handle_ret_async};

macro_rules! abort_and_return_error {
    ($ctx:expr, $stream:expr, $desc:expr, $error:expr) => {
        let _ = $ctx.abort($stream, Some($desc));

        return Err($error);
    };
    ($ctx:expr, $stream:expr, $error:expr) => {
        let _ = $ctx.abort($stream, None);

        return Err($error);
    };
}

#[derive(Debug)]
/// kTLS stream context.
pub(crate) struct Context {
    /// The I/O state
    state: StreamState,

    /// Shared buffer
    buffer: Buffer,

    /// The TLS connection data, managing connection secrets and session
    /// tickets.
    data: TlsConnData,
}

impl Context {
    /// Creates a new context.
    pub(crate) fn new(state: StreamState, buffer: Vec<u8>, data: TlsConnData) -> Self {
        Self {
            state,
            buffer: Buffer {
                inner: buffer,
                offset: 0,
            },
            data,
        }
    }

    /// Returns the current state.
    pub(crate) fn state(&self) -> &StreamState {
        &self.state
    }

    /// Reads buffered data from the inner buffer into the provided one, and
    /// returns the number of bytes read.
    pub(crate) fn read_buffer(&mut self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        crate::trace!(
            "Reading from internal buffer, remaining_len={}",
            self.buffer.len()
        );

        // Read from the inner buffer into the provided buffer
        let has_read = self.buffer.read(buf);

        if self.buffer.is_read_done() {
            // Clear the buffer.
            self.buffer.reset();
            self.state.set_has_buffered_data(false);
        }

        has_read
    }

    #[must_use = "The buffered data must be handled."]
    #[cfg_attr(not(feature = "raw-api"), allow(unused))]
    /// Takes the buffered data, if any.
    pub(crate) fn take_buffer(&mut self) -> Option<Buffer> {
        if self.state.has_buffered_data() {
            self.state.set_has_buffered_data(false);

            Some(mem::take(&mut self.buffer))
        } else {
            None
        }
    }

    // /// Returns the TLS connection data.
    // pub(crate) fn data(&self) -> &TlsConnData {
    //     &self.data
    // }

    /// Shuts down the TLS stream and sends a `close_notify` alert to the peer.
    pub(crate) fn shutdown<S: AsFd>(&mut self, socket: &S) {
        crate::trace!("Shutting down the TLS stream with `close_notify` alert");

        #[allow(unused)]
        if let Err(e) = self.set_closed_state_and_try_send_alert(
            socket,
            AlertLevel::Warning,
            AlertDescription::CloseNotify,
        ) {
            crate::error!("Failed to send `close_notify` alert: {}", e);
        } else {
            crate::trace!("`close_notify` alert sent");
        };
    }

    /// Aborts the TLS stream and sends an `internal_error` alert to the peer.
    pub(crate) fn abort<S: AsFd>(&mut self, socket: &S, desc: Option<AlertDescription>) {
        crate::trace!("Aborting the TLS stream with `internal_error` alert");

        #[allow(unused)]
        if let Err(e) = self.set_closed_state_and_try_send_alert(
            socket,
            AlertLevel::Fatal,
            desc.unwrap_or(AlertDescription::InternalError),
        ) {
            crate::error!("Failed to send `internal_error` alert: {}", e);
        } else {
            crate::trace!("`internal_error` alert sent");
        };
    }

    fn set_closed_state_and_try_send_alert<S: AsFd>(
        &mut self,
        socket: &S,
        level: AlertLevel,
        desc: AlertDescription,
    ) -> io::Result<()> {
        let ret = if self.state.is_write_closed() {
            Ok(())
        } else {
            Self::try_send_tls_control_message(
                socket,
                ContentType::Alert,
                &[level.into(), desc.into()],
            )
            .map(|_| ())
        };

        self.state.set_closed();

        ret
    }

    #[inline]
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(
            level = "INFO",
            name = "Context::handle_io_result",
            skip(socket, ret),
            err
        )
    )]
    /// Inspects and handles the [`io::Result`] returned by a I/O operation on
    /// the inner socket directly.
    ///
    /// - If the result is `Ok`, it returns `Some(T)`.
    /// - If the errno is `EIO`, it tries to handle any TLS control messages
    ///   received, and returns `None` if succeeded.
    /// - If the error kind is `BrokenPipe`, it marks the stream as closed and
    ///   returns `None`.
    /// - Otherwise, it aborts the connection with `internal_error` alert and
    ///   returns the error.
    ///
    /// ## Errors
    ///
    /// The unrecoverable original [`io::Error`].
    pub(crate) fn handle_io_result<S: AsFd, T>(
        &mut self,
        socket: &S,
        ret: io::Result<T>,
    ) -> io::Result<Option<T>> {
        match ret {
            Ok(ret) => Ok(Some(ret)),
            Err(e) if e.raw_os_error() == Some(libc::EIO) => {
                crate::debug!("Received EIO, trying to receive TLS control message");

                self.try_recv_tls_control_message(socket)?;

                Ok(None)
            }
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                // The peer may send a `close_notify` alert and close the connection
                // immediately?
                crate::debug!("The peer closed the connection: {}", e);

                self.state.set_closed();

                Ok(None)
            }
            Err(e) => {
                self.abort(socket, None);

                Err(e)
            }
        }
    }

    // === Internal methods ===

    /// Other than application data, TLS has control messages such as alert
    /// messages (record type 21) and handshake messages (record type 22), etc.
    /// These messages can be sent over the socket with this method.
    ///
    /// Control message data should be provided unencrypted, and will be
    /// encrypted by the kernel.
    fn try_send_tls_control_message<S: AsFd>(
        socket: &S,
        typ: ContentType,
        encoded_payload: &[u8],
    ) -> io::Result<usize> {
        // Nix does not support sending control messages with `sendmsg` yet.

        // TODO: Should an error here abort the whole connection?

        crate::ffi::sendmsg(
            socket.as_fd().as_raw_fd(),
            &mut [io::IoSlice::new(encoded_payload)],
            &mut crate::ffi::Cmsg::new(libc::SOL_TLS, libc::TLS_SET_RECORD_TYPE, [typ.into()]),
            0,
        )
    }

    #[allow(clippy::too_many_lines)]
    /// Handles TLS control messages received by kernel.
    ///
    /// The caller **SHOULD** first check if the raw os error returned were
    /// `EIO`, which indicates that there is a TLS control message available.
    /// But in fact, this method can be called even if there's no TLS control
    /// message (not recommended to do so).
    ///
    /// Will abort the connection if the control message is invalid or
    /// unexpected, and return an error.
    fn try_recv_tls_control_message<S: AsFd>(&mut self, socket: &S) -> io::Result<()> {
        // Reuse the existing buffer to avoid extra allocations.
        self.buffer.inner.reserve(u16::MAX as usize + 5);

        #[allow(unsafe_code)]
        // Safety: We have reserved enough space in the buffer above.
        let mut buffer: &mut [u8] = unsafe {
            slice::from_raw_parts_mut(
                self.buffer
                    .inner
                    .as_mut_ptr()
                    .add(self.buffer.inner.len())
                    .cast(),
                self.buffer.inner.capacity() - self.buffer.inner.len(),
            )
        };
        let buffer_capacity = buffer.len();

        // Read the control message and the associated data into the buffer.
        let content_type = {
            let (content_type, recv_bytes) = {
                // For Linux kernel <= 5.10, will read more cmsgs than one.
                let cmsg_buffer =
                    &mut [mem::MaybeUninit::<u8>::zeroed(); cmsg_space::<TlsGetRecordType>() * 24];

                let iov = &mut [io::IoSliceMut::new(buffer)];

                let recv_msg = match recvmsg::<()>(
                    socket.as_fd().as_raw_fd(),
                    iov,
                    {
                        #[allow(unsafe_code)]
                        // Safety: will access only the initialized part of the buffer below.
                        Some(unsafe {
                            slice::from_raw_parts_mut(
                                cmsg_buffer.as_mut_ptr().cast(),
                                cmsg_buffer.len(),
                            )
                        })
                    },
                    MsgFlags::MSG_DONTWAIT,
                ) {
                    Ok(recv_msg) => recv_msg,
                    Err(Errno::EAGAIN) => {
                        return Ok(());
                    }
                    Err(e) => {
                        abort_and_return_error!(
                            self,
                            socket,
                            io::Error::other(format!("recvmsg failed: {e}"))
                        );
                    }
                };

                if recv_msg.bytes > buffer_capacity {
                    abort_and_return_error!(
                        self,
                        socket,
                        io::Error::other(format!(
                            "recvmsg read more bytes ({}) than maximum ({})?",
                            recv_msg.bytes, buffer_capacity
                        ))
                    );
                }

                let mut cmsgs = recv_msg
                    .cmsgs()
                    .expect("should have 1..24 control message received");

                match cmsgs.next().expect("should have at least one CMSG?") {
                    ControlMessageOwned::TlsGetRecordType(content_type) => {
                        // `recv` will never return data from mixed types of TLS records.
                        debug_assert!(cmsgs.all(|cmsg| {
                            matches!(cmsg, ControlMessageOwned::TlsGetRecordType(_))
                        }));

                        (content_type, recv_msg.bytes)
                    }
                    value => {
                        abort_and_return_error!(
                            self,
                            socket,
                            io::Error::other(format!(
                                "unknown control message received: {value:?}"
                            ))
                        );
                    }
                }
            };

            // Safety: We have just written `recv_msg.bytes` bytes to the spare capacity of
            // the buffer.
            buffer = &mut buffer[..recv_bytes];

            content_type
        };

        match content_type {
            TlsGetRecordType::Handshake => {
                self.try_handle_tls_control_message_handshake(socket, buffer)?;
            }
            TlsGetRecordType::Alert => {
                if let [level, desc] = buffer {
                    self.try_handle_tls_control_message_alert(
                        socket,
                        (*level).into(),
                        (*desc).into(),
                    )?;
                } else {
                    // The peer sent an invalid alert. We send back an error
                    // and close the connection.

                    crate::error!("Invalid alert message received: {:?}", &buffer);

                    abort_and_return_error!(
                        self,
                        socket,
                        AlertDescription::DecodeError,
                        KtlsStreamError::InvalidMessage(InvalidMessage::MessageTooLarge).into()
                    );
                }
            }
            TlsGetRecordType::ChangeCipherSpec => {
                // ChangeCipherSpec should only be sent under the following conditions:
                //
                // * TLS 1.2: during a handshake or a rehandshake
                // * TLS 1.3: during a handshake
                //
                // We don't have to worry about handling messages during a handshake
                // and rustls does not support TLS 1.2 rehandshakes so we just emit
                // an error here and abort the connection.

                abort_and_return_error!(
                    self,
                    socket,
                    AlertDescription::UnexpectedMessage,
                    KtlsStreamError::PeerMisbehaved(
                        PeerMisbehaved::IllegalMiddleboxChangeCipherSpec,
                    )
                    .into()
                );
            }
            TlsGetRecordType::ApplicationData => {
                // This shouldn't happen in normal operation.

                crate::warn!(
                    "Received {} bytes of application data when handling TLS control message",
                    buffer.len()
                );

                if !buffer.is_empty() {
                    #[allow(unsafe_code)]
                    // SAFETY: We have checked the buffer length above.
                    unsafe {
                        self.buffer
                            .inner
                            .set_len(self.buffer.inner.len() + buffer.len());
                    }

                    self.state.set_has_buffered_data(true);
                }
            }
            _ => {
                crate::error!(
                    "Received unexpected TLS control message: {content_type:?}, with data {:?}",
                    buffer
                );

                abort_and_return_error!(
                    self,
                    socket,
                    AlertDescription::UnexpectedMessage,
                    KtlsStreamError::InvalidMessage(InvalidMessage::InvalidContentType).into()
                );
            }
        }

        Ok(())
    }

    /// Handles a TLS alert received from the peer.
    fn try_handle_tls_control_message_alert<S: AsFd>(
        &mut self,
        socket: &S,
        level: AlertLevel,
        desc: AlertDescription,
    ) -> io::Result<()> {
        match desc {
            AlertDescription::CloseNotify
                if self.data.protocol_version() == ProtocolVersion::TLSv1_2 =>
            {
                // RFC 5246, section 7.2.1: Unless some other fatal alert has been transmitted,
                // each party is required to send a close_notify alert before closing the write
                // side of the connection.  The other party MUST respond with a close_notify
                // alert of its own and close down the connection immediately, discarding any
                // pending writes.
                crate::trace!("Received `close_notify` alert, should shutdown the TLS stream");

                self.shutdown(socket);
            }
            AlertDescription::CloseNotify => {
                // RFC 8446, section 6.1: Each party MUST send a "close_notify" alert before
                // closing its write side of the connection, unless it has already sent some
                // error alert. This does not have any effect on its read side of the
                // connection. Note that this is a change from versions of TLS prior to TLS 1.3
                // in which implementations were required to react to a "close_notify" by
                // discarding pending writes and sending an immediate "close_notify" alert of
                // their own. That previous requirement could cause truncation in the read
                // side. Both parties need not wait to receive a "close_notify" alert before
                // closing their read side of the connection, though doing so would introduce
                // the possibility of truncation.

                crate::trace!(
                    "Received `close_notify` alert, should shutdown the read side of TLS stream"
                );

                self.state.set_read_closed();
            }
            _ if self.data.protocol_version() == ProtocolVersion::TLSv1_2
                && level == AlertLevel::Warning =>
            {
                // RFC 5246, section 7.2.2: If an alert with a level of warning
                // is sent and received, generally the connection can continue
                // normally.

                crate::warn!("Received alert, level={level:?}, desc: {desc:?}");
            }
            _ => {
                // All other alerts are treated as fatal and result in us immediately shutting
                // down the connection and emitting an error.

                crate::error!("Received fatal alert, level={level:?}, desc: {desc:?}");

                self.state.set_closed();

                return Err(KtlsStreamError::Alert(desc).into());
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    /// Handles a TLS alert received from the peer.
    fn try_handle_tls_control_message_handshake<S: AsFd>(
        &mut self,
        socket: &S,
        payload: &[u8],
    ) -> io::Result<()> {
        fn read_message<'a>(reader: &mut Reader<'a>) -> Option<(HandshakeType, &'a [u8])> {
            let &[typ, a, b, c] = reader.take(4)? else {
                unreachable!()
            };

            let handshake_type = HandshakeType::from(typ);
            let length = u32::from_be_bytes([0, a, b, c]) as usize;

            let payload = reader.take(length)?;

            Some((handshake_type, payload))
        }

        let mut reader = Reader::init(payload);
        let mut sub_message_count = 0;

        loop {
            let Some((handshake_type, payload)) = read_message(&mut reader) else {
                crate::error!(
                    "Received truncated handshake message, payload: {:?}",
                    payload
                );

                abort_and_return_error!(
                    self,
                    socket,
                    AlertDescription::DecodeError,
                    KtlsStreamError::InvalidMessage(InvalidMessage::MessageTooShort).into()
                );
            };

            sub_message_count += 1;

            match handshake_type {
                HandshakeType::KeyUpdate
                    if self.data.protocol_version() == ProtocolVersion::TLSv1_3 =>
                {
                    self.try_handle_tls_control_message_handshake_key_update(
                        socket,
                        payload,
                        &reader,
                        sub_message_count,
                    )?;
                }
                HandshakeType::NewSessionTicket
                    if self.data.protocol_version() == ProtocolVersion::TLSv1_3 =>
                {
                    let TlsConnData::Client(conn) = &mut self.data else {
                        abort_and_return_error!(
                            self,
                            socket,
                            AlertDescription::UnexpectedMessage,
                            KtlsStreamError::InvalidMessage(InvalidMessage::UnexpectedMessage(
                                "TLS 1.2 peer sent a TLS 1.3 NewSessionTicket message",
                            ))
                            .into()
                        );
                    };

                    match conn.handle_new_session_ticket(payload) {
                        Ok(()) => (),
                        // Convert some messages into their higher-level equivalents
                        Err(rustls::Error::InvalidMessage(err)) => {
                            abort_and_return_error!(
                                self,
                                socket,
                                AlertDescription::DecodeError,
                                KtlsStreamError::InvalidMessage(err).into()
                            );
                        }
                        Err(rustls::Error::PeerMisbehaved(err)) => {
                            abort_and_return_error!(
                                self,
                                socket,
                                AlertDescription::UnexpectedMessage,
                                KtlsStreamError::PeerMisbehaved(err).into()
                            );
                        }

                        // Other errors are not necessarily fatal
                        Err(_) => {}
                    }
                }
                _ if self.data.protocol_version() == ProtocolVersion::TLSv1_3 => {
                    abort_and_return_error!(
                        self,
                        socket,
                        AlertDescription::UnexpectedMessage,
                        KtlsStreamError::InvalidMessage(InvalidMessage::UnexpectedMessage(
                            "expected KeyUpdate or NewSessionTicket handshake messages only",
                        ))
                        .into()
                    );
                }
                _ => {
                    crate::error!(
                        "Unexpected handshake message: ver={:?}, typ={handshake_type:?}",
                        self.data.protocol_version()
                    );

                    abort_and_return_error!(
                        self,
                        socket,
                        AlertDescription::UnexpectedMessage,
                        KtlsStreamError::InvalidMessage(InvalidMessage::UnexpectedMessage(
                            "handshake messages are not expected on TLS 1.2 connections",
                        ))
                        .into()
                    );
                }
            }

            if reader.any_left() {
                crate::trace!("Processing next sub messages.");
            } else {
                crate::trace!("All sub messages are processed.");
                return Ok(());
            }
        }
    }

    fn try_handle_tls_control_message_handshake_key_update<S: AsFd>(
        &mut self,
        socket: &S,
        payload: &[u8],
        reader: &Reader<'_>,
        sub_message_count: usize,
    ) -> io::Result<()> {
        if sub_message_count != 1 || reader.any_left() {
            // RFC 8446, section 5.1: Handshake messages MUST NOT span key changes.
            abort_and_return_error!(
                self,
                socket,
                AlertDescription::UnexpectedMessage,
                KtlsStreamError::PeerMisbehaved(PeerMisbehaved::KeyEpochWithPendingFragment).into()
            );
        }

        let key_update_request = match payload {
            [KEY_UPDATE_REQUESTED] => KeyUpdateRequest::UpdateRequested,
            [KEY_UPDATE_NOT_REQUESTED] => KeyUpdateRequest::UpdateNotRequested,
            _ => {
                crate::error!("Received invalid KeyUpdateRequest: {:?}", payload);

                abort_and_return_error!(
                    self,
                    socket,
                    AlertDescription::DecodeError,
                    KtlsStreamError::InvalidMessage(InvalidMessage::InvalidKeyUpdate).into()
                );
            }
        };

        {
            let (seq, secrets) = match self.data.update_rx_secret() {
                Ok(secrets) => secrets,
                Err(e) => {
                    abort_and_return_error!(
                        self,
                        socket,
                        AlertDescription::InternalError,
                        KtlsStreamError::KeyUpdateFailed(e).into()
                    );
                }
            };

            if let Err(e) =
                setup_tls_params_rx(socket, self.data.negotiated_cipher_suite(), (seq, secrets))
            {
                abort_and_return_error!(self, socket, AlertDescription::InternalError, e.into());
            }
        }

        match key_update_request {
            KeyUpdateRequest::UpdateNotRequested => return Ok(()),
            KeyUpdateRequest::UpdateRequested => {
                let message = [
                    HandshakeType::KeyUpdate.into(), // typ
                    0,
                    0,
                    1, // length
                    KeyUpdateRequest::UpdateNotRequested.into(),
                ];

                if let Err(e) =
                    Self::try_send_tls_control_message(socket, ContentType::Handshake, &message)
                {
                    abort_and_return_error!(
                        self,
                        socket,
                        AlertDescription::InternalError,
                        io::Error::other(format!("Failed to send KeyUpdate message: {e}"))
                    );
                }

                let (seq, secrets) = match self.data.update_tx_secret() {
                    Ok(secrets) => secrets,
                    Err(e) => {
                        abort_and_return_error!(
                            self,
                            socket,
                            AlertDescription::InternalError,
                            KtlsStreamError::KeyUpdateFailed(e).into()
                        );
                    }
                };

                if let Err(e) =
                    setup_tls_params_tx(socket, self.data.negotiated_cipher_suite(), (seq, secrets))
                {
                    abort_and_return_error!(
                        self,
                        socket,
                        AlertDescription::InternalError,
                        e.into()
                    );
                }
            }
            _ => {
                unreachable!(
                    "KeyUpdateRequest should only be UpdateNotRequested or UpdateRequested here"
                );
            }
        }

        Ok(())
    }
}

/// [`KernelConnection`], client side or server side.
pub(crate) enum TlsConnData {
    Client(KernelConnection<ClientConnectionData>),
    Server(KernelConnection<ServerConnectionData>),
}

impl fmt::Debug for TlsConnData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(_) => f.debug_struct("TlsConnData::Client").finish(),
            Self::Server(_) => f.debug_struct("TlsConnData::Server").finish(),
        }
    }
}

impl TlsConnData {
    #[inline]
    fn protocol_version(&self) -> ProtocolVersion {
        match self {
            Self::Client(data) => data.protocol_version(),
            Self::Server(data) => data.protocol_version(),
        }
    }

    #[inline]
    fn negotiated_cipher_suite(&self) -> SupportedCipherSuite {
        match self {
            Self::Client(conn) => conn.negotiated_cipher_suite(),
            Self::Server(conn) => conn.negotiated_cipher_suite(),
        }
    }

    #[inline]
    fn update_tx_secret(&mut self) -> Result<(u64, ConnectionTrafficSecrets), rustls::Error> {
        match self {
            Self::Client(conn) => conn.update_tx_secret(),
            Self::Server(conn) => conn.update_tx_secret(),
        }
    }

    #[inline]
    fn update_rx_secret(&mut self) -> Result<(u64, ConnectionTrafficSecrets), rustls::Error> {
        match self {
            Self::Client(conn) => conn.update_rx_secret(),
            Self::Server(conn) => conn.update_rx_secret(),
        }
    }
}

bitflags::bitflags! {
    #[derive(Debug)]
    pub(crate) struct StreamState : u8 {
        /// The read side of the TLS stream is closed.
        const READ_CLOSED = 0b0000_0001;

        /// The write side of the TLS stream is closed.
        const WRITE_CLOSED = 0b0000_0010;

        /// The stream is closed, both read and write sides.
        const CLOSED = StreamState::READ_CLOSED.bits() | StreamState::WRITE_CLOSED.bits();

        /// Has buffered data that needs to be handled before reading from the inner stream.
        const HAS_BUFFERED_DATA = 0b0001_0000;
    }
}

impl StreamState {
    #[inline]
    /// If the read side of the TLS stream were closed.
    pub(crate) fn is_read_closed(&self) -> bool {
        self.contains(Self::READ_CLOSED)
    }

    #[inline]
    /// Sets the read side of the TLS stream as closed.
    pub(crate) fn set_read_closed(&mut self) {
        self.insert(Self::READ_CLOSED);
    }

    #[inline]
    /// If the write side of the TLS stream were closed.
    pub(crate) fn is_write_closed(&self) -> bool {
        self.contains(Self::WRITE_CLOSED)
    }

    // #[inline]
    // /// Sets the write side of the TLS stream as closed.
    // pub(crate) fn set_write_closed(&mut self) {
    //     self.insert(Self::WRITE_CLOSED);
    // }

    #[cfg_attr(not(feature = "raw-api"), allow(unused))]
    #[inline]
    /// If the stream is partially closed, either read or write side.
    pub(crate) fn is_partially_closed(&self) -> bool {
        self.is_read_closed() || self.is_write_closed()
    }

    // #[inline]
    // /// If the stream is closed, both read and write sides.
    // pub(crate) fn is_closed(self) -> bool {
    //     self.contains(Self::CLOSED)
    // }

    #[inline]
    /// Sets the stream as closed, both read and write sides.
    pub(crate) fn set_closed(&mut self) {
        self.insert(Self::CLOSED);
    }

    #[inline]
    /// If the stream has buffered data that needs to be handled before reading
    /// from the inner stream.
    pub(crate) fn has_buffered_data(&self) -> bool {
        self.contains(Self::HAS_BUFFERED_DATA)
    }

    #[inline]
    /// Sets the stream as having buffered data that needs to be handled before
    /// reading from the inner stream.
    pub(crate) fn set_has_buffered_data(&mut self, val: bool) {
        self.set(Self::HAS_BUFFERED_DATA, val);
    }
}

#[derive(Clone, Default)]
/// A simple buffer with a read offset.
pub struct Buffer {
    /// The inner buffer data.
    inner: Vec<u8>,

    /// Read offset of the buffer.
    offset: usize,
}

impl fmt::Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("inner", &self.inner.len())
            .field("offset", &self.offset)
            .finish()
    }
}

impl ops::Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // TODO: Here can actually avoid panic check, since `self.offset` is always
        // guaranteed to be less than or equal to `self.inner.len()`, but the MSRV
        // limits so.
        &self.inner[self.offset..]
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Buffer {
    #[inline]
    /// Reads from the inner buffer into the provided buffer, and advances the
    /// read offset.
    ///
    /// Returns the number of bytes read.
    pub fn read(&mut self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        // Read zero: buffer is empty or offset is at the end
        let to_read = NonZeroUsize::new(buf.len().min(self.len()))?;

        buf[..to_read.get()].copy_from_slice(&self[..to_read.get()]);

        self.offset += to_read.get();

        Some(to_read)
    }

    #[allow(clippy::must_use_candidate)]
    #[inline]
    /// Check if the read offset has reached the end of the inner buffer.
    pub fn is_read_done(&self) -> bool {
        self.offset >= self.inner.len()
    }

    #[inline]
    /// Resets the buffer, clearing the inner data and resetting the read
    /// offset.
    pub(crate) fn reset(&mut self) {
        #[allow(unsafe_code)]
        // SAFETY: We are setting length to 0, which is always valid.
        unsafe {
            self.inner.set_len(0);
        }
        self.offset = 0;
    }
}
