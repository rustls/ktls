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
    pub fn new(inner: IO) -> Self {
        Self {
            inner,
            close_notified: false,
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
        self.project().inner.poll_read(cx, buf)
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
        let mut this = self.project();
        let res = match this.inner.as_mut().poll_shutdown(cx) {
            task::Poll::Pending => return task::Poll::Pending,
            task::Poll::Ready(res) => res,
        };

        if let Err(e) = res {
            return Err(e).into();
        }

        if !*this.close_notified {
            // setting this optimistically, I don't think calling it more than
            // once is going to help if it failed the first time.
            *this.close_notified = true;
            if let Err(e) = crate::ffi::send_close_notify(this.inner.as_raw_fd()) {
                return Err(e).into();
            }
        }
        Ok(()).into()
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
