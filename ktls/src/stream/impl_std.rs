//! `Read` / `Write` support for `KtlsStream`.

use std::io::{self, Read, Write};
use std::os::fd::AsFd;

use crate::stream::context::handle_ret;
use crate::stream::KtlsStream;

impl<S: Read + AsFd> KtlsStream<S> {
    /// Shuts down both read and write sides of the TLS stream.
    pub fn shutdown(&mut self) {
        self.ctx.shutdown(&self.inner);
    }
}

impl<S: Read + AsFd> Read for KtlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        handle_ret!(self, {
            let state = self.ctx.state();

            if state.is_read_closed() {
                crate::trace!("Read closed, returning EOF");

                // received a `close_notify` alert from the peer, return EOF.
                return Ok(0);
            }

            if state.has_buffered_data() {
                // Unlikely path, actually.

                if let Some(has_read) = self.ctx.read_buffer(buf) {
                    return Ok(has_read.get());
                }
            }

            self.inner.read(buf)
        })
    }
}

impl<S: Write + AsFd> Write for KtlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        handle_ret!(self, {
            if self.ctx.state().is_write_closed() {
                crate::trace!("Write closed, returning EOF");

                return Ok(0);
            }

            self.inner.write(buf)
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }

    fn by_ref(&mut self) -> &mut Self
    where
        Self: Sized,
    {
        self
    }
}
