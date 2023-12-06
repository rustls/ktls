# just manual: https://github.com/casey/just#readme

_default:
	just --list

# Run all tests with nextest and cargo-llvm-cov
ci-test:
	#!/bin/bash -eux
	cargo llvm-cov nextest --lcov --output-path coverage.lcov

# Run all tests with cargo nextest
test *args:
	RUST_BACKTRACE=1 cargo nextest run {{args}}

check:
	cargo clippy --all-targets
