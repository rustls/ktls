# just manual: https://github.com/casey/just#readme

_default:
	just --list

# Run all tests with nextest and cargo-llvm-cov
ci-test:
	#!/bin/bash -eux
	cargo llvm-cov nextest --lcov --output-path coverage.lcov

# Show coverage locally
cov:
	#!/bin/bash -eux
	cargo llvm-cov nextest --hide-instantiations --html --output-dir coverage

# Run all tests
test *args:
	#!/bin/bash -eux
	export RUST_BACKTRACE=1
	for feature in ring aws_lc_rs; do
		cargo nextest run --no-default-features --features tls12,$feature {{args}}
	done

check:
	cargo clippy --no-default-features --features tls12,ring --all-targets
	cargo clippy --no-default-features --features tls12,aws_lc_rs --all-targets

check-powerset:
	cargo hack --feature-powerset --mutually-exclusive-features ring,aws_lc_rs check