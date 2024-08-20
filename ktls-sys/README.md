[![test pipeline](https://github.com/hapsoc/ktls/actions/workflows/test.yml/badge.svg)](https://github.com/hapsoc/ktls/actions/workflows/test.yml?query=branch%3Amain)
[![Coverage Status (codecov.io)](https://codecov.io/gh/hapsoc/ktls/branch/main/graph/badge.svg)](https://codecov.io/gh/hapsoc/ktls/)
[![Crates.io](https://img.shields.io/crates/v/ktls-sys)](https://crates.io/crates/ktls-sys)
[![license: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

# ktls-sys

`linux/tls.h` bindings, for TLS kernel offload.

Generated with `bindgen tls.h -o src/bindings.rs`

See <https://github.com/bearcove/ktls> for a higher-level / safer interface.

## License

This project is primarily distributed under the terms of both the MIT license
and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
