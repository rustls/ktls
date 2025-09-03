# just manual: https://github.com/casey/just#readme

_default:
	just --list

# Run all tests with nextest and cargo-llvm-cov
ci-test *args:
	#!/bin/bash -eux
	cargo llvm-cov nextest {{args}} --locked --all-features --lcov --output-path coverage.lcov

# =========== LOCAL COMMANDS ===========

build *args:
	cargo build {{args}} --locked

b *args:
	just build {{args}}

# Show coverage locally
cov *args:
	#!/bin/bash -eux
	cargo llvm-cov nextest {{args}} --locked --all-features --hide-instantiations --html --output-dir coverage

check *args:
    cargo check {{args}} --locked --all-features

c *args:
	just check {{args}}

clippy *args:
	cargo clippy {{args}} --locked --all-features -- -Dclippy::all -Dclippy::pedantic

example *args:
	cargo run --example {{args}}

e *args:
	just example {{args}}

msrv *args:
	cargo +1.77.0 clippy {{args}} --locked --all-features -- -Dclippy::all -Dclippy::pedantic

t *args:
	just test {{args}}

test *args:
	#!/bin/bash -eux
	export RUST_BACKTRACE=1
	cargo nextest run {{args}} --locked --all-features
