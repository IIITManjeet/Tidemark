# tidemark-wasm

Tidemark's upgrade review engine compiled to WebAssembly. It diffs two Solana
program binaries (sBPF ELF), runs the `tm-rules` risk rules and checks a
Tidemark attestation ledger, all locally in the browser or Node. Nothing is
uploaded anywhere.

```js
import init, { review, inspect } from "tidemark-wasm";
import { fetchLedger } from "tidemark-wasm/ledger.js";

await init();
const { report, verdict_hash } = JSON.parse(review(oldBytes, newBytes));
console.log(report.risk, report.findings);

const ledger = await fetchLedger(
  "https://api.devnet.solana.com",
  "BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc",
  "72HSqJR6Y2uiedNWVQxDDRXYr9LjB4cDUn3Me2AtenxU",
);
console.log(ledger.ok, ledger.entries);
```

| Function | Returns (JSON string) |
|---|---|
| `review(old, new)` | `{report, report_hash, verdict_hash, verdict_risk}`, same report as `tidemark diff --json` |
| `inspect(bytes)` | sha256, size, SBPF version, syscalls, instruction handlers |
| `verifyLedger(input)` | parses and verifies raw ledger accounts; `fetchLedger` gathers them over JSON-RPC |
| `rulesVersion()` | the rules version, e.g. `tm-rules-0.4` |

In Node, load the module with `initSync({ module: readFileSync(".../tidemark_bg.wasm") })`.

Build with `bash scripts/build-wasm.sh` from the repository root (needs the
`wasm32-unknown-unknown` target and `wasm-bindgen-cli 0.2.130`).
