#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${TIDEMARK_BUILD_DIR:-$HOME/.cache/tidemark-contracts}"

mkdir -p "$WORK" "$ROOT/fixtures"
rsync -a --delete --exclude target --exclude .anchor "$ROOT/contracts/" "$WORK/"
if [ -d "$ROOT/contracts/target/deploy" ]; then
  mkdir -p "$WORK/target/deploy"
  cp -n "$ROOT"/contracts/target/deploy/*-keypair.json "$WORK/target/deploy/" 2>/dev/null || true
fi

cd "$WORK"
anchor build
anchor keys sync
anchor build
cargo build-sbf --manifest-path programs/demo-vault/Cargo.toml --features v2 --sbf-out-dir target/v2

cp target/deploy/demo_vault.so "$ROOT/fixtures/demo_vault_v1.so"
cp target/v2/demo_vault.so "$ROOT/fixtures/demo_vault_v2.so"
cp target/deploy/tidemark_ledger.so "$ROOT/fixtures/"

cp Anchor.toml "$ROOT/contracts/Anchor.toml"
for p in programs/*/src/lib.rs; do cp "$p" "$ROOT/contracts/$p"; done
mkdir -p "$ROOT/contracts/target/deploy"
cp target/deploy/*-keypair.json "$ROOT/contracts/target/deploy/"

ls -l "$ROOT/fixtures"
