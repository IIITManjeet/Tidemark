#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${TIDEMARK_BUILD_DIR:-$HOME/.cache/tidemark-contracts}"
mkdir -p "$WORK"
rsync -a --delete --exclude target --exclude .anchor --exclude build.log "$ROOT/contracts/" "$WORK/"
cd "$WORK"
cargo build-sbf --manifest-path programs/tidemark-ledger/Cargo.toml
cp target/deploy/tidemark_ledger.so "$ROOT/fixtures/tidemark_ledger.so"
ls -l "$ROOT/fixtures/tidemark_ledger.so"
