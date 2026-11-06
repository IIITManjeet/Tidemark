#!/usr/bin/env bash
set -euo pipefail

RPC="${RPC:-https://api.devnet.solana.com}"
LEDGER="${LEDGER:-BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc}"
PROGRAM="${1:?usage: demo-devnet.sh <PROGRAM_ID> [before.so]}"
BEFORE="${2:-}"
KEYPAIR="${KEYPAIR:-$HOME/.config/solana/id.json}"
OUT="${OUT:-live}"
TM="cargo run -q -p tidemark-cli --"

mkdir -p "$OUT"
if [ -z "$BEFORE" ]; then
  $TM fetch "$PROGRAM" --rpc "$RPC" -o "$OUT/before.so"
  echo "snapshot saved; upgrade the program, then run: $0 $PROGRAM $OUT/before.so"
  exit 0
fi

$TM fetch "$PROGRAM" --rpc "$RPC" -o "$OUT/after.so"
$TM diff "$BEFORE" "$OUT/after.so" --json "$OUT/report.json" --hunks 0 || true
$TM init-registry --ledger "$LEDGER" --keypair "$KEYPAIR" --rpc "$RPC" 2>/dev/null || true
$TM attest "$OUT/report.json" --program "$PROGRAM" --ledger "$LEDGER" --keypair "$KEYPAIR" --rpc "$RPC"
