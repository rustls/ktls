use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use rustls::internal::msgs::codec::Codec;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

enum State {
    ReadHeader { header_buf: [u8; 5], offset: usize },
    ReadPayload { msg_size: usize, offset: usize },
}

pub struct CorkStream<IO> {
    pub io: IO,
    // if true, causes empty reads
    pub corked: bool,
    state: State,
}

impl<IO> CorkStream<IO> {
    pub fn new(io: IO) -> Self {
        Self {
            io,
            corked: false,
            state: State::ReadHeader {
                header_buf: Default::default(),
                offset: 0,
            },
        }
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
        // if self.corked {
        //     return Poll::Ready(Ok(()));
        // }

        let this = unsafe { self.get_unchecked_mut() };
        let mut io = unsafe { Pin::new_unchecked(&mut this.io) };

        let state = &mut this.state;

        loop {
            match state {
                State::ReadHeader { header_buf, offset } => {
                    if *offset == 0 && this.corked {
                        tracing::trace!("corked, returning empty read");
                        return Poll::Ready(Ok(()));
                    }

                    let left = header_buf.len() - *offset;
                    tracing::trace!("reading header, {left}/{} bytes left", header_buf.len());

                    {
                        let mut rest = ReadBuf::new(&mut header_buf[*offset..]);
                        futures::ready!(io.as_mut().poll_read(cx, &mut rest)?);
                        if rest.filled().is_empty() {
                            tracing::trace!("eof!");
                            // FIXME: this should still put what we've read so far

                            return Poll::Ready(Ok(()));
                        }
                        tracing::trace!("read {} bytes off of header", rest.filled().len());
                        *offset += rest.filled().len();
                    }

                    if *offset == 5 {
                        // TODO: error handling
                        let typ =
                            rustls::ContentType::read_bytes(&header_buf[0..1]).expect("valid typ");
                        let version = rustls::ProtocolVersion::read_bytes(&header_buf[1..3])
                            .expect("valid version");
                        let len: u16 = u16::from_be_bytes(header_buf[3..5].try_into().unwrap());
                        tracing::trace!("read header: typ={typ:?}, version={version:?}, len={len}");

                        // TODO: handle cases where buffer is smalelr than 5,
                        // as-is, this'll panic
                        buf.put_slice(&header_buf[..]);
                        *state = State::ReadPayload {
                            msg_size: len as usize,
                            offset: 0,
                        };
                        return Poll::Ready(Ok(()));
                    } else {
                        // keep trying
                    }
                }
                State::ReadPayload { msg_size, offset } => {
                    let rest = *msg_size - *offset;

                    let just_read = {
                        let mut rest = buf.take(rest);
                        futures::ready!(io.as_mut().poll_read(cx, &mut rest)?);

                        tracing::trace!("read {} bytes off of payload", rest.filled().len());
                        *offset += rest.filled().len();

                        if *offset == *msg_size {
                            tracing::trace!("read full payload (all {} bytes)", *offset);
                            *state = State::ReadHeader {
                                header_buf: Default::default(),
                                offset: 0,
                            };
                        }

                        rest.filled().len()
                    };

                    let new_filled = buf.filled().len() + just_read;
                    buf.set_filled(new_filled);

                    return Poll::Ready(Ok(()));
                }
            }
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
