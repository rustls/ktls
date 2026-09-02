use std::io;
use std::task::{Context, Poll};

use tokio::io::Interest;

pub trait AsyncReadReady {
    /// cf. https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html#method.poll_read_ready
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
}

impl AsyncReadReady for tokio::net::TcpStream {
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::net::TcpStream::poll_read_ready(self, cx)
    }
}

pub trait AsyncWriteReady {
    /// cf. https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html#method.poll_write_ready
    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    /// Perform a write to the socket using a user-provided I/O operation
    ///
    /// If the operation returns `WouldBlock`, the socket's write-readiness is cleared.
    /// cf. https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html#method.try_io
    fn try_write_io<R>(&self, f: impl FnOnce() -> io::Result<R>) -> io::Result<R>;
}

impl AsyncWriteReady for tokio::net::TcpStream {
    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::net::TcpStream::poll_write_ready(self, cx)
    }

    fn try_write_io<R>(&self, f: impl FnOnce() -> io::Result<R>) -> io::Result<R> {
        self.try_io(Interest::WRITABLE, f)
    }
}
