//! Utilities for ktls crate.

#![warn(
    unsafe_code,
    unused_must_use,
    clippy::alloc_instead_of_core,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::manual_let_else,
    clippy::use_self,
    clippy::upper_case_acronyms,
    elided_lifetimes_in_paths,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]

use std::{io, slice};

use tokio::io::{AsyncRead, AsyncReadExt};

pub mod client;
pub(crate) mod error;
pub mod server;

pub(crate) async fn read_record<S>(socket: &mut S, incoming: &mut Vec<u8>) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    const RECORD_HDR_SIZE: usize = 5;

    incoming.reserve(RECORD_HDR_SIZE);

    #[allow(unsafe_code)]
    // Safety: We just reserved enough space for the header.
    let record_hdr = unsafe {
        slice::from_raw_parts_mut(
            incoming.spare_capacity_mut().as_mut_ptr().cast(),
            RECORD_HDR_SIZE,
        )
    };

    socket
        .read_exact(record_hdr)
        .await
        .map_err(ktls::Error::IO)?;

    let payload_length = u16::from_be_bytes([record_hdr[3], record_hdr[4]]) as usize;

    incoming.reserve(payload_length);

    #[allow(unsafe_code)]
    // Safety: We just reserved enough space for the payload.
    let payload = unsafe {
        slice::from_raw_parts_mut(
            incoming
                .spare_capacity_mut()
                .as_mut_ptr()
                .add(RECORD_HDR_SIZE)
                .cast(),
            payload_length,
        )
    };

    socket.read_exact(payload).await.map_err(ktls::Error::IO)?;

    #[allow(unsafe_code)]
    // Safety: We have just read data into the space we reserved.
    unsafe {
        incoming.set_len(incoming.len() + RECORD_HDR_SIZE + payload_length);
    }

    Ok(())
}
