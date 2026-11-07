#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/build-wasm.sh
rm -rf site
mkdir -p site/npm site/fixtures
cp web/* site/
cp -r npm/dist npm/ledger.js site/npm/
cp fixtures/demo_vault_v1.so fixtures/demo_vault_v2.so site/fixtures/
