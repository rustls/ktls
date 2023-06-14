use std::{
    io::{self, IoSliceMut},
    os::unix::prelude::AsRawFd,
    pin::Pin,
    task,
};

use nix::{
    cmsg_space,
    sys::socket::{MsgFlags, SockaddrIn},
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
        tracing::trace!(remaining = %buf.remaining(), "KtlsStream::poll_read");

        let this = self.project();

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

            return task::Poll::Ready(Ok(()));
        }

        tracing::trace!("KtlsStream::poll_read, forwarding to inner IO");
        let fd = this.inner.as_raw_fd();

        let res = futures::ready!(this.inner.poll_read_ready(cx));
        if let Err(e) = res {
            tracing::trace!(?e, "KtlsStream::poll_read, poll_read_ready");
            return Err(e).into();
        }
        tracing::trace!("KtlsStream::poll_read, ready to read");

        let mut cmsgspace = cmsg_space!(nix::sys::time::TimeVal);
        let mut iov = [IoSliceMut::new(buf.initialize_unfilled())];
        let flags = MsgFlags::empty();

        let r = nix::sys::socket::recvmsg::<SockaddrIn>(fd, &mut iov, Some(&mut cmsgspace), flags);
        let r = match r {
            Ok(r) => r,
            Err(e) => {
                tracing::trace!(?e, "recvmsg failed");
                return Err(e.into()).into();
            }
        };
        tracing::trace!("recvmsg result = {:#?}", r);
        let read_bytes = r.bytes;

        // FIXME: is that correct?
        buf.advance(read_bytes);
        task::Poll::Ready(Ok(()))
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
