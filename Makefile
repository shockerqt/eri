.PHONY: dev test test-oauth-smoke build lint check

CONFIG ?= config/eri.toml

dev:
	cargo run --locked -- --config "$(CONFIG)"

test: test-oauth-smoke
	cargo test --locked

test-oauth-smoke:
	node --test scripts/staging-oauth-smoke.test.mjs

build:
	cargo build --locked --release

lint:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings

check: lint test build
