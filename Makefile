.PHONY: dev test test-oauth-smoke test-rss build lint check

CONFIG ?= config/eri.toml

dev:
	cargo run --locked -- --config "$(CONFIG)"

test: test-oauth-smoke test-rss
	cargo test --locked

test-oauth-smoke:
	node --test scripts/staging-oauth-smoke.test.mjs

test-rss:
	node --test scripts/staging-rss.test.mjs

build:
	cargo build --locked --release
	cargo build --locked --release --example staging-benchmark

lint:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings

check: lint test build
