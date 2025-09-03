//! Optional: Tokio's `AsyncRead` / `AsyncWrite` support for `KtlsStream`.

use std::os::fd::AsFd;
use std::pin::Pin;
use std::{io, ptr, task};

use tokio::io::{self as async_io, AsyncRead, AsyncWrite};

use crate::stream::context::handle_ret_async;
use crate::stream::KtlsStream;

impl<S: AsyncRead + AsFd> AsyncRead for KtlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut async_io::ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        let mut this = self.project();

        handle_ret_async!(this, {
            let state = this.ctx.state();

            if state.is_read_closed() {
                // received a `close_notify` alert from the peer, return EOF.

                crate::trace!("Read closed, returning EOF");

                return task::Poll::Ready(Ok(()));
            }

            if state.has_buffered_data() {
                // Unlikely path, actually.

                #[allow(unsafe_code)]
                #[allow(trivial_casts)]
                // Safety: will set the initialized part after reading.
                if let Some(has_read) = this
                    .ctx
                    .read_buffer(unsafe { &mut *(ptr::from_mut(buf.unfilled_mut()) as *mut [u8]) })
                {
                    #[allow(unsafe_code)]
                    // Safety: has filled and written `has_read` bytes.
                    unsafe {
                        buf.assume_init(has_read.get());
                    };
                    buf.advance(has_read.get());

                    return task::Poll::Ready(Ok(()));
                }
            }

            this.inner.as_mut().poll_read(cx, buf)
        })
    }
}

impl<S: AsyncWrite + AsFd> AsyncWrite for KtlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        let mut this = self.project();

        handle_ret_async!(this, {
            if this.ctx.state().is_write_closed() {
                crate::trace!("Write closed, returning EOF");

                return task::Poll::Ready(Ok(0));
            }

            this.inner.as_mut().poll_write(cx, buf)
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        let mut this = self.project();

        handle_ret_async!(this, {
            if this.ctx.state().is_write_closed() {
                return task::Poll::Ready(Ok(()));
            }

            this.inner.as_mut().poll_flush(cx)
        })
    }

    /// Shuts down both read and write sides of the TLS stream.
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        let this = self.project();

        this.ctx.shutdown(&*this.inner);

        this.inner.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> task::Poll<Result<usize, io::Error>> {
        let mut this = self.project();

        handle_ret_async!(this, {
            if this.ctx.state().is_write_closed() {
                crate::trace!("Write closed, returning EOF");

                return task::Poll::Ready(Ok(0));
            }

            this.inner.as_mut().poll_write_vectored(cx, bufs)
        })
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
