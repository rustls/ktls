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
    // we encountered EOF while reading, or saw an invalid header and we're just
    // passing reads through without doing any sort of processing now.
    Passthrough,
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
                        // TODO: handle cases where buffer has less than 5 bytes
                        // remaining. I (fasterthanlime) bet this never happens in
                        // practice since the rustls deframer uses `copy_within` to
                        // get rid of the part of the buffer it's already decoded.
                        assert!(buf.remaining() >= 5, "you found an edge case in ktls!");
                        buf.put_slice(&header_buf[..]);

                        match decode_header(*header_buf) {
                            Some((typ, version, len)) => {
                                tracing::trace!(
                                    "read header: typ={typ:?}, version={version:?}, len={len}"
                                );
                                *state = State::ReadPayload {
                                    msg_size: len as usize,
                                    offset: 0,
                                };
                            }
                            None => {
                                // we encountered an invalid header, let's bail out
                                *state = State::Passthrough;
                            }
                        }

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
                State::Passthrough => {
                    // we encountered EOF while reading, or saw an invalid header and we're just
                    // passing reads through without doing any sort of processing now.
                    return io.poll_read(cx, buf);
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

fn decode_header(b: [u8; 5]) -> Option<(rustls::ContentType, rustls::ProtocolVersion, u16)> {
    let typ = rustls::ContentType::read_bytes(&b[0..1])?;
    let version = rustls::ProtocolVersion::read_bytes(&b[1..3])?;
    // this is dumb but it looks less scary than `.try_into().unwrap()`:
    let len: u16 = u16::from_be_bytes([b[3], b[4]]);
    Some((typ, version, len))
}
