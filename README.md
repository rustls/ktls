# ktls

Configures kTLS (kernel TLS) for any type that implements `AsRawFd`, given a
rustls `ServerConnection`.

The `export` branch of this rustls fork must be used:
https://github.com/hapsoc/rustls to export all the relevant secrets.


## Status

[![test pipeline](https://github.com/hapsoc/ktls/actions/workflows/test.yml/badge.svg)](https://github.com/hapsoc/ktls/actions/workflows/test.yml?query=branch%3Amain)
[![Coverage Status (codecov.io)](https://codecov.io/gh/hapsoc/ktls/branch/main/graph/badge.svg)](https://codecov.io/gh/hapsoc/ktls/)

