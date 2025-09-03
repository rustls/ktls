[![Crates.io](https://img.shields.io/crates/v/ktls)](https://crates.io/crates/ktls)
[![Docs.rs](https://docs.rs/ktls/badge.svg)](https://docs.rs/ktls)
[![Test pipeline](https://github.com/rustls/ktls/actions/workflows/ci.yml/badge.svg)](https://github.com/rustls/ktls/actions/workflows/ci.yml?query=branch%3Amain)
[![Coverage Status (codecov.io)](https://codecov.io/gh/rustls/ktls/branch/main/graph/badge.svg)](https://codecov.io/gh/rustls/ktls/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

# `ktls` - Kernel TLS offload (kTLS) support built on top of [rustls].

This crate provides high-level APIs for configuring [kernel TLS offload] (kTLS),
extending the bare minimum functionality provided by [rustls].

## MSRV

1.77.0

## LICENSE

This project is primarily distributed under the terms of both the MIT license
and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

[kernel TLS offload]: https://www.kernel.org/doc/html/latest/networking/tls-offload.html
[rustls]: https://docs.rs/rustls/latest/rustls/kernel/index.html
