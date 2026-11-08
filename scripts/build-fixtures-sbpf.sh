#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${TIDEMARK_BUILD_DIR:-$HOME/.cache/tidemark-sbpf}"
AGAVE_BIN="${AGAVE_BIN:-$HOME/.local/share/agave-v4.3.2/solana-release/bin}"
export PATH="$AGAVE_BIN:$PATH"

mkdir -p "$WORK" "$ROOT/fixtures/sbpf"
rsync -a --delete --exclude target --exclude .anchor "$ROOT/contracts/" "$WORK/src/"
cd "$WORK/src"
build() {
  local arch=$1 variant=$2
  local feat=()
  [ "$variant" = v2 ] && feat=(--features v2)
  cargo-build-sbf --arch "$arch" --manifest-path programs/demo-vault/Cargo.toml "${feat[@]}" \
    --sbf-out-dir "$WORK/out-$arch-$variant"
  cp "$WORK/out-$arch-$variant/demo_vault.so" "$ROOT/fixtures/sbpf/demo_vault_${variant}_sbpf${arch}.so"
}
build v1 v1
for arch in v2 v3; do
  build "$arch" v1
  build "$arch" v2
done
ls -l "$ROOT/fixtures/sbpf"
