use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct CorkStream<IO> {
    pub io: IO,
    // if true, causes empty reads
    pub corked: bool,
}

impl<IO> CorkStream<IO> {
    pub fn new(io: IO) -> Self {
        Self { io, corked: false }
    }
}

impl<IO> AsyncRead for CorkStream<IO>
where
    IO: AsyncRead,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.corked {
            return Poll::Ready(Ok(()));
        }

        {
            let io = unsafe { self.map_unchecked_mut(|s| &mut s.io) };
            io.poll_read(cx, buf)
        }
    }
}

impl<IO> AsyncWrite for CorkStream<IO>
where
    IO: AsyncWrite,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let io = unsafe { self.map_unchecked_mut(|s| &mut s.io) };
        io.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let io = unsafe { self.map_unchecked_mut(|s| &mut s.io) };
        io.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let io = unsafe { self.map_unchecked_mut(|s| &mut s.io) };
        io.poll_shutdown(cx)
    }
}
