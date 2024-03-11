# Changelog

## [4.0.1](https://github.com/hapsoc/ktls/compare/v4.0.0...v4.0.1) - 2024-03-11

### Other
- TLS 1.3 codepath still does the right thing in rustls 0.22.2
- backtraces in CI
- Fix integration test compile errors
- rustls 0.22 support
- Get rid of constrandom
- Add flake to have the toolchain anywhere
- Re-add Cargo.lock as per updated best practices
- Disable incremental compilation
- Remove token
- Install missing tools
- Use the sccache action
- Just straight up try running it on GitHub-hosted runners

## [4.0.0](https://github.com/hapsoc/ktls/compare/v3.0.2...v4.0.0) - 2023-10-08

### Fixed
- [**breaking**] Remove drained_remaining public method

### Other
- Add more test coverage
- Remove more explicit libc::close calls
- Clarifies what this.inner.poll_shutdown does
- Improve integration tests: try reading/writing after close, catch errors from both sides
- Don't forget to close fd on writer side
- Simplify/clarify code around alerts
- Use enums to 'parse' TLS alerts
- Depend on ktls-recvmsg v0.1.3
- Remove panic, ktls may send unfinished alert msg
- assert instead of asser_eq
- Adding edge case in integration test for session shutdown
- Properly handle critical alerts
- Add crates.io badge
- Use Rust stable for tests

## [3.0.2](https://github.com/hapsoc/ktls/compare/v3.0.1...v3.0.2) - 2023-10-02

### Other
- Create FUNDING.yml
- Upgrade rcgen to 0.11.3
- Upgrade dependencies

## 3.0.1 (unreleased)

Fix test suite (follow rustls' `ClientConfig::enable_tickets` transition to
`ClientConfig::resumption`).

## 3.0.0 (2023-06-14) (yanked)

Upgrade to tokio-rustls 0.24.1

## 2.0.0 (2023-03-29)

Comes with a bunch of breaking changes, necessary to address some issues.

Essentially, the rustls stream wasn't being drained properly in
`config_ktls_{client,server}`. Doing this properly required introducing
`CorkStream`, which is TLS-framing-aware.

As a result, `config_ktls_*` functions now take a `TlsStream<CorkStream<IO>>`
(where `IO` is typically `TcpStream`), and are async, since to properly drain we
might need to read till the end of the last TLS messages rustls has partially
buffered.

## 1.0.1 (2022-10-21)

Initial release.