[![Crates.io](https://img.shields.io/crates/v/ktls-sys)](https://crates.io/crates/ktls-sys)
[![Docs.rs](https://docs.rs/ktls-sys/badge.svg)](https://docs.rs/ktls-sys)
[![Test pipeline](https://github.com/rustls/ktls/actions/workflows/ci.yml/badge.svg)](https://github.com/rustls/ktls/actions/workflows/ci.yml?query=branch%3Amain)
[![Coverage Status (codecov.io)](https://codecov.io/gh/rustls/ktls/branch/main/graph/badge.svg)](https://codecov.io/gh/rustls/ktls/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

# ktls-sys

> [!WARNING]
> This crate is deprecated.

`linux/tls.h` bindings, for TLS kernel offload.

Generated with `bindgen tls.h -o src/bindings.rs`

See <https://github.com/rustls/ktls> for a higher-level / safer interface.

## License

This project is primarily distributed under the terms of both the MIT license
and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
