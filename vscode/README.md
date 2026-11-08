# Tidemark for VS Code

Review a Solana program upgrade from its bytecode before you deploy it.

Tidemark disassembles the deployed program and your new build (sBPF v0 to v3), aligns them, and flags risky
changes: new hardcoded keys, removed or neutralized account checks, new instructions, retargeted branches and
new CPIs. Everything runs locally; no file leaves your machine.

## Commands

- **Tidemark: Review a build against the deployed program**: pick your new `.so`, enter the program id, and
  Tidemark fetches the deployed ELF over RPC and diffs it against your build.
- **Tidemark: Review two program binaries**: diff any two `.so` files.

The report appears in the Tidemark output panel: overall risk, each finding and the changed code. A warning
pops up when the risk reaches `tidemark.warnAt`.

## Settings

| Setting | Default | |
|---|---|---|
| `tidemark.rpc` | `https://api.devnet.solana.com` | RPC used to fetch the deployed program |
| `tidemark.warnAt` | `high` | Risk at which a warning is shown |

## Learn more

The rules are heuristics tuned on Anchor programs: a clean report means nothing obvious changed, not that the
upgrade is safe. See the [docs](https://github.com/IIITManjeet/Tidemark#readme) for the CLI, CI gate, npm
package and the on-chain review ledger.
