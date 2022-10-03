use std::{io, os::unix::prelude::AsRawFd, pin::Pin, task};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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

    impl<IO> PinnedDrop for KtlsStream<IO>
    where
        IO: AsRawFd
    {
        fn drop(this: Pin<&mut Self>) {
            if !this.close_notified {
                // can't do much on error here. also no point in setting
                // close_notified, because we're about to drop the stream anyway.
                _ = crate::ffi::send_close_notify(this.inner.as_raw_fd());
            }
        }
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
}

impl<IO> AsyncRead for KtlsStream<IO>
where
    IO: AsRawFd + AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        let this = self.project();

        if let Some((drain_index, drained)) = this.drained.as_mut() {
            let drained = &drained[*drain_index..];
            let len = std::cmp::min(buf.remaining(), drained.len());
            buf.put_slice(&drained[..len]);
            *drain_index += len;
            if *drain_index >= drained.len() {
                *this.drained = None;
            }
            cx.waker().wake_by_ref();

            return task::Poll::Ready(Ok(()));
        }

        this.inner.poll_read(cx, buf)
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
