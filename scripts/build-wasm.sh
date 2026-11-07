#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release --target wasm32-unknown-unknown -p tidemark-wasm
wasm-bindgen --target web --out-dir npm/dist --out-name tidemark \
  target/wasm32-unknown-unknown/release/tidemark_wasm.wasm
