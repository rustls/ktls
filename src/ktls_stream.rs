use std::{
    io::{self, IoSliceMut},
    os::unix::prelude::AsRawFd,
    pin::Pin,
    task,
};

use nix::{
    cmsg_space,
    sys::socket::{ControlMessageOwned, MsgFlags, SockaddrIn},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::AsyncReadReady;

// A wrapper around `IO` that sends a `close_notify` when shut down or dropped.
pin_project_lite::pin_project! {
    pub struct KtlsStream<IO>
    where
        IO: AsRawFd
    {
        #[pin]
        inner: IO,
        close_notified: bool,
        drained: Option<(usize, Vec<u8>)>,
    }
}

impl<IO> KtlsStream<IO>
where
    IO: AsRawFd,
{
    pub fn new(inner: IO, drained: Option<Vec<u8>>) -> Self {
        Self {
            inner,
            close_notified: false,
            drained: drained.map(|drained| (0, drained)),
        }
    }

    /// Return the drained data + the original I/O
    pub fn into_raw(self) -> (Option<Vec<u8>>, IO) {
        (self.drained.map(|(_, drained)| drained), self.inner)
    }

    /// Returns a reference to the original I/O
    pub fn get_ref(&self) -> &IO {
        &self.inner
    }

    /// Returns a mut reference to the original I/O
    pub fn get_mut(&mut self) -> &mut IO {
        &mut self.inner
    }

    /// Returns the number of bytes that have been drained from rustls but not yet read.
    /// Only really used in integration tests.
    pub fn drained_remaining(&self) -> usize {
        match self.drained.as_ref() {
            Some((offset, v)) => v.len() - offset,
            None => 0,
        }
    }
}

impl<IO> AsyncRead for KtlsStream<IO>
where
    IO: AsRawFd + AsyncRead + AsyncReadReady,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        tracing::trace!(buf.remaining = %buf.remaining(), "KtlsStream::poll_read");

        let mut this = self.project();

        if let Some((drain_index, drained)) = this.drained.as_mut() {
            let drained = &drained[*drain_index..];
            let len = std::cmp::min(buf.remaining(), drained.len());

            tracing::trace!(%len, "KtlsStream::poll_read, can take from drain");
            buf.put_slice(&drained[..len]);

            *drain_index += len;
            if *drain_index >= drained.len() {
                tracing::trace!("KtlsStream::poll_read, done draining");
                *this.drained = None;
            }
            cx.waker().wake_by_ref();

            tracing::trace!("KtlsStream::poll_read, returning after drain");
            return task::Poll::Ready(Ok(()));
        }

        let read_res = this.inner.as_mut().poll_read(cx, buf);
        if let task::Poll::Ready(Err(e)) = &read_res {
            // 5 is a generic "input/output error", it happens when
            // using poll_read on a kTLS socket that just received
            // a control message
            if let Some(5) = e.raw_os_error() {
                // could be a control message, let's check
                let fd = this.inner.as_raw_fd();

                let mut cmsgspace = cmsg_space!(nix::sys::time::TimeVal);
                let mut iov = [IoSliceMut::new(buf.initialize_unfilled())];
                let flags = MsgFlags::empty();

                let r = nix::sys::socket::recvmsg::<SockaddrIn>(
                    fd,
                    &mut iov,
                    Some(&mut cmsgspace),
                    flags,
                );
                let r = match r {
                    Ok(r) => r,
                    Err(nix::errno::Errno::EAGAIN) => {
                        unreachable!("expected a control message, got EAGAIN")
                    }
                    Err(e) => {
                        // ok I guess it really failed then
                        tracing::trace!(?e, "recvmsg failed");
                        return Err(e.into()).into();
                    }
                };
                let cmsg = r
                    .cmsgs()
                    .next()
                    .expect("we should've received exactly one control message");
                match cmsg {
                    // cf. RFC 5246, Section 6.2.1
                    // https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.1
                    ControlMessageOwned::TlsGetRecordType(t) => {
                        match t {
                            // change_cipher_spec
                            20 => {
                                panic!(
                                    "received TLS change_cipher_spec, this isn't supported by ktls"
                                )
                            }
                            // alert
                            21 => {
                                panic!("received TLS alert, this isn't supported by ktls")
                            }
                            // handshake
                            22 => {
                                // TODO: this is where we receive TLS 1.3 resumption tickets,
                                // should those be stored anywhere? I'm not even sure what
                                // format they have at this point
                                tracing::trace!(
                                    "ignoring handshake message (probably a resumption ticket)"
                                );
                            }
                            // application data
                            23 => {
                                unreachable!("received TLS application in recvmsg, this is supposed to happen in the poll_read codepath")
                            }
                            _ => {
                                // just ignore the message type then
                                tracing::trace!("received message_type {t:#?}");
                            }
                        }
                    }
                    _ => panic!("unexpected cmsg type: {cmsg:#?}"),
                };

                // FIXME: this is hacky, but can we do better?
                // after we handled (..ignored) the control message, we don't
                // know whether the scoket is still ready to be read or not.
                //
                // we could try looping (tricky code structure), but we can't,
                // for example, just call `poll_read`, which might fail not
                // not with EAGAIN/EWOULDBLOCK, but because _another_ control
                // message is available.
                cx.waker().wake_by_ref();
                return task::Poll::Pending;
            }
        }

        read_res
    }
}

impl<IO> AsyncWrite for KtlsStream<IO>
where
    IO: AsRawFd + AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        let this = self.project();

        if !*this.close_notified {
            // setting this optimistically, I don't think calling it more than
            // once is going to help if it failed the first time.
            *this.close_notified = true;
            if let Err(e) = crate::ffi::send_close_notify(this.inner.as_raw_fd()) {
                return Err(e).into();
            }
        }

        this.inner.poll_shutdown(cx)
    }
}

impl<IO> AsRawFd for KtlsStream<IO>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.inner.as_raw_fd()
    }
}
