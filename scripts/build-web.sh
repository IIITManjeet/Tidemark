#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/build-wasm.sh
rm -rf web/public/wasm web/public/fixtures
mkdir -p web/public/wasm web/public/fixtures
cp npm/dist/tidemark.js npm/dist/tidemark_bg.wasm web/public/wasm/
cp fixtures/demo_vault_v1.so fixtures/demo_vault_v2.so web/public/fixtures/
cd web
npm ci
npm run typecheck
npm run build
