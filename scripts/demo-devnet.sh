#!/usr/bin/env bash
set -euo pipefail

RPC="${RPC:-https://api.devnet.solana.com}"
LEDGER="${LEDGER:-BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc}"
KEYPAIR="${KEYPAIR:-$HOME/.config/solana/id.json}"
OUT="${OUT:-live}"
TM="cargo run -q -p tidemark-cli --"

usage() {
  echo "usage:"
  echo "  $0 snapshot <PROGRAM_ID>                 save the program before you upgrade it"
  echo "  $0 attest   <PROGRAM_ID> <REGISTRY>      review the deployed upgrade and publish it"
  echo "  $0 approve  <REGISTRY> <INDEX>           re-run a review and co-sign it"
  exit 1
}

mkdir -p "$OUT"
case "${1:-}" in
  snapshot)
    $TM fetch "${2:?program id}" --rpc "$RPC" -o "$OUT/before.so"
    ;;
  attest)
    $TM attest --ledger "$LEDGER" --rpc "$RPC" --keypair "$KEYPAIR" \
      --program "${2:?program id}" --registry "${3:?registry}" --old "$OUT/before.so" --json "$OUT/report.json"
    ;;
  approve)
    $TM approve --ledger "$LEDGER" --rpc "$RPC" --keypair "$KEYPAIR" \
      --registry "${2:?registry}" --index "${3:?index}" --old "$OUT/before.so"
    ;;
  *) usage ;;
esac
