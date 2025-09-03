#![doc = include_str!("../README.md")]
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

#[cfg(not(target_os = "linux"))]
compile_error!("This crate only supports Linux");

pub mod error;
mod ffi;
pub mod log;
mod protocol;
pub mod setup;
pub mod stream;
pub mod utils;

pub use error::Error;
pub use stream::KtlsStream;
