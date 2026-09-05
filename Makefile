.PHONY: dev test build lint check

CONFIG ?= config/eri.toml

dev:
	cargo run --locked -- --config "$(CONFIG)"

test:
	cargo test --locked

build:
	cargo build --locked --release

lint:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings

check: lint test build
