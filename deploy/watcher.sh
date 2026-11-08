#!/usr/bin/env bash
set -euo pipefail

: "${WATCH_PROGRAMS:?set WATCH_PROGRAMS to one or more program ids, separated by spaces or commas}"
RPC="${TIDEMARK_RPC:-https://api.devnet.solana.com}"
INTERVAL="${WATCH_INTERVAL:-30}"
DATA="${TIDEMARK_DATA:-/data}"

attest=()
if [ -n "${TIDEMARK_LEDGER:-}" ]; then
  : "${TIDEMARK_KEYPAIR:?TIDEMARK_LEDGER is set, so TIDEMARK_KEYPAIR must hold the attesting key (JSON byte array)}"
  key="$(mktemp)"
  chmod 600 "$key"
  printf '%s' "$TIDEMARK_KEYPAIR" > "$key"
  attest=(--attest "$TIDEMARK_LEDGER" --keypair "$key")
  [ -n "${TIDEMARK_REGISTRY:-}" ] && attest+=(--registry "$TIDEMARK_REGISTRY")
fi

for program in ${WATCH_PROGRAMS//,/ }; do
  mkdir -p "$DATA/$program"
  echo "watching $program on $RPC every ${INTERVAL}s"
  tidemark watch "$program" --rpc "$RPC" --dir "$DATA/$program" --interval "$INTERVAL" "${attest[@]}" &
done

wait -n
echo "a watcher exited; stopping so the platform restarts the service" >&2
exit 1
