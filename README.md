# Tidemark

**See what a Solana program upgrade actually changed, before and after it lands.**

Any upgradeable Solana program can be replaced at any moment by whoever holds
its upgrade authority. Users, integrators and even the multisig signers who
approve the upgrade usually can't see what the new bytecode does. Today's open
tooling monitors instructions, watches the authority header, or checks that a
build hash matches source. None of it shows the **behavioural difference
between two deployed versions**.

Tidemark reads the bytecode itself, tells you what changed and how risky it
is, and writes every review to a public, hash-linked ledger on Solana.

```
$ tidemark diff fixtures/demo_vault_v1.so fixtures/demo_vault_v2.so
Tidemark upgrade review  (tm-rules-0.3)
  old  99e7c4fe98f886be  20066 insns
  new  519015fa4879499f  20608 insns
  changed instructions: 996 (2.45%)
  overall risk: HIGH

[HIGH    ] TM-KEY-ADD  1 new hardcoded key(s)
             9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin
[HIGH    ] TM-CHECK-GONE  Account checks were removed
             withdraw: ConstraintHasOne (2001): 1 → 0 check sites
             withdraw: AccountNotSigner (3010): 1 → 0 check sites
[MEDIUM  ] TM-IX-CHANGE  Instruction handlers added or removed
             + sweep
```

That is a real run against the demo vault and its backdoored upgrade, built
from `contracts/programs/demo-vault`. Tidemark recovers the attacker's address
byte for byte, spots that `withdraw` lost its `has_one` and signer checks and names the new `sweep`
handler, all from bytecode alone.

---

## Features

Status key: **Shipped** is in this repository and tested. **Roadmap** is designed
(see [HLD](docs/architecture/HLD.md)) but not built yet.

### 1. Bytecode-level upgrade diff · Shipped
Works on deployed SBPFv1 programs (what `cargo build-sbf` and Anchor 0.31
produce today), with no source code or IDL required. The SBPF version is read
from the ELF header; v2 and v3 binaries, which change instruction meanings, are
refused with a clear message instead of being mis-read.
- A purpose-built **sBPF decoder** handles every instruction class, including
  two-word `lddw`.
- **Normalized comparison**: jump targets, internal call targets and load
  addresses are masked, so code that only *moved* compares equal. The same
  masking currently also hides a branch or call that was *retargeted* and a
  changed 64-bit constant; fixing that is the next detection milestone.
- **Bounded work**: inputs over 16 MiB are rejected, the line diff runs a
  patience algorithm with a 10 s deadline, and every rule runs in near-linear
  time, so a hostile binary can't stall a CI job.
- **Syscall resolution** through `R_BPF_64_32` relocations (SBPFv1) and murmur3
  syscall ids (static syscalls). `call 0x…` shows as `call sol_invoke_signed_rust`.
- Extracts `.rodata` strings, candidate 32-byte keys and `security.txt` from both versions.

### 2. Upgrade risk rules · Shipped
Deterministic, versioned rules (`tm-rules-0.3`) turn a diff into ranked findings:

| Rule | What it catches |
|---|---|
| `TM-KEY-ADD` | New 32-byte keys, found anywhere in `.rodata` or rebuilt from four `lddw` immediates that are stored to, or compared against, consecutive 8-byte slots |
| `TM-CHECK-GONE` | An instruction handler lost Anchor account-check sites (`has_one`, signer, owner, seeds, address), counted by error-code immediates in the code each handler can reach |
| `TM-ERR-GONE` | An instruction handler lost custom error checks (`require!`, error codes 6000+) |
| `TM-IX-CHANGE` | Instruction handlers added or removed, read from the Anchor dispatch table; names confirmed by matching `sha256("global:<name>")[..8]` |
| `TM-SYSCALL-ADD` | New `invoke_signed` and other sensitive syscall call sites |
| `TM-CALLX-ADD` | New indirect calls with runtime-computed targets |
| `TM-BRANCH-RETARGET` | A branch that looks unchanged now jumps to different code |
| `TM-CALL-RETARGET` | A call that looks unchanged now calls a different function |
| `TM-CONST-CHANGE` | 64-bit constants (not addresses, not handler discriminators) that are no longer used |
| `TM-SECTXT` | `security.txt` removed or changed (possible change of responsible party) |
| `TM-CHURN` | Large rewrites that can hide small malicious changes |

Well-known program ids (System, Token, Token-2022, ATA, …) are recognised and
named, so a new reference to Token isn't mistaken for a planted key.

These rules are heuristics over compiled code, tuned on Anchor programs. They
catch the demo backdoor exactly, but a determined attacker can shape code to
avoid them (for example splitting a key across functions, or reusing an
existing CPI call site). Treat a clean report as "nothing obvious
changed", not as proof of safety. Known gaps are tracked as GitHub issues.

### 3. Quorum-signed attestation ledger · Shipped (live on devnet)
An Anchor program (`tidemark-ledger` v2) records reviews on Solana. Who may
speak for a registry is enforced by the contract itself, not by trusting
whoever holds a key file.
- **Reviewer allowlist**: only keys the registry authority adds on-chain
  (a `Reviewer` PDA per key) can attest or approve. Anyone else is rejected by
  the program.
- **k-of-n quorum**: each entry records the threshold in force when it was
  created. Other reviewers co-sign with `approve`, one `Approval` PDA each, so
  nobody can vote twice. An entry is *final* once it reaches k approvals. The
  threshold can never exceed the number of active reviewers.
- **Independent re-review**: `attest` fetches the deployed program from chain
  and runs the diff itself; `approve` re-runs the whole review on the
  approver's machine and refuses to co-sign unless it reaches the same verdict.
  A quorum therefore means k reviewers got the same answer on their own.
- **Deterministic verdict hash**: what is attested covers the rules version,
  both code hashes, the findings and the risk, and leaves out timing-dependent
  parts of the report, so honest reviewers on different hardware agree.
- **Two-step authority rotation**: the authority proposes a successor, who
  must sign to accept. A typo can't hand a registry away, and a lost key can be
  replaced before it matters.
- **Sponsored fees**: a separate payer covers rent and fees, so reviewer keys
  never need to hold SOL.
- **Hash-linked entries**: `entry_hash = sha256(index ‖ registry ‖ program ‖
  code hashes ‖ verdict ‖ risk ‖ rules ‖ model ‖ reviewer ‖ slot ‖ prev_hash)`.
- **Checked verification**: `tidemark verify-ledger` checks account owners,
  re-derives the registry, entry and approval PDAs, confirms every signer is a
  listed reviewer, counts approvals, requires slots to increase, and
  cross-checks the chain head across every `--rpc` you pass.
- **Confirmed writes**: every transaction is polled until confirmed, and a
  failed one is reported as a failure.

Remaining trust assumption: the ledger program on devnet is still upgradeable
by a single key (tracked in #15, to move behind a multisig with a timelock or
be frozen).

### 4. CI gate for safe code shipping · Shipped
`tidemark diff` exits with code `2` when the risk reaches the `--fail-on` level
(`high` by default), so a pipeline can block risky upgrades automatically. Use
`--fail-on medium` to also stop on a new instruction handler or indirect call.
An unknown level is a usage error (exit `1`), never a silent pass. This repo's own
CI runs clippy with warnings as errors, the test suite, a live review of the
demo upgrade, and the Kani proofs.

### 5. Typed, proof-checked Rust · Shipped
- **Kani model-checking harnesses**, run in CI on every pull request and push
  to `main`: each sBPF decoding step on any input up to 24 bytes, the ELF
  length computation on any input up to 160 bytes, the loader's store, compare
  and dispatch scans over any 6 instructions, all four ledger account parsers
  on any prefix of their account size (and they accept exactly the full-size
  accounts with the right discriminator), and the transaction length encoding
  for every `u16`. Rendering, the
  SBPF version check and the `.rodata` scan are checked by exhaustive or
  randomized tests instead, because string formatting and sets are too costly
  for the model checker. Full ELF parsing (goblin) and the rules are covered by
  tests, not proofs.
- **Fuzz-style regression tests** for the inputs reviewers used to stall or crash
  the tool: oversized log names, tens of thousands of stack constants, very
  large unrelated programs, and malformed hashes in a report.
- **Typed on-chain accounts**: Anchor `Account<T>` with PDA seeds and bumps
  validated by the framework, `InitSpace`-derived sizes, checked arithmetic on
  the attestation counter, and a bounded risk value.
- **No SDK lock-in**: the client builds and signs Solana transactions itself
  (legacy message format, PDA derivation with an off-curve check, Anchor
  sighashes), so the library stays small and auditable.

### 6. Chain fetch and authority inspection · Shipped
`tidemark fetch` reads a program through the BPF Upgradeable Loader, strips the
45-byte ProgramData header, and reports the upgrade authority and last deploy
slot. Immutable programs are identified as such.

### 7. AI review agents · Roadmap
A small set of agents layered on top of the deterministic engine:
- **Explainer** turns findings into two plain-English sentences for signers and users.
- **Triage** ranks ambiguous diffs and requests more context only when the rules can't decide.
- **Verifier** writes a local LiteSVM test that reproduces a finding. Findings it can't reproduce are dropped.

Guardrails: agents hold no keys and can't sign. They return schema-checked JSON
only. Program bytes and on-chain strings are treated as untrusted data, never
as instructions, which defends against prompt and memory injection. The model
id and prompt hash will be recorded in each attestation's `model_id` (zero
today, since no model runs yet).

### 8. Cost-efficient inference cascade · Roadmap
Expensive work runs only when it has to:
1. **Content cache** keyed by `sha256(old) ‖ sha256(new)`. Repeat reviews are free.
2. **Rule pre-check** settles most diffs locally, with no model call and minimal RPC lookups.
3. **Model calls** use a fixed prompt prefix (system prompt plus rule pack), so
   the inference server reuses its **KV cache** across requests. Self-hosted
   deployments can add KV-cache quantization (TurboQuant-style, about 3–4 bits
   per value) to cut memory further.

### 9. Upgrade watcher with snapshots · Roadmap
A watcher subscribes to loader `Upgrade` instructions and snapshots ProgramData
*before* it is overwritten, so the "old" side of every diff is always available.
Each review is attested automatically.

### 10. Multisig pre-approval review · Roadmap
When an upgrade proposal is created, Tidemark diffs the proposal's buffer
against the live program and posts the report to signers during the timelock
window, so nobody approves bytecode they haven't seen.

### 11. Upgrade-authority census · Shipped (CLI)
`tidemark census <program ids…>` (or `--file`) classifies who can upgrade each
program and whether it embeds a `security.txt`:
- **immutable**: no upgrade authority, or not owned by the upgradeable loader
- **single key**: the authority is an ordinary ed25519 key
- **multisig / governance**: the authority account is owned by Squads v3/v4
  or SPL Governance
- **program-controlled (PDA)**: the authority is off the ed25519 curve, so no
  private key exists and only a program can sign. Squads v4 vaults show up
  this way, since a vault PDA is a plain system account.

```
$ tidemark census --rpc https://api.mainnet-beta.solana.com JUP6Lkb… whirLbM… MarBmsS…
JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4   program-controlled (PDA)   no
whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc   program-controlled (PDA)   no
MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD   program-controlled (PDA)   yes
```

Reading multisig thresholds and timelocks, verified-build status and a public
dashboard are still on the roadmap.

### 12. MEV transparency layer · Roadmap
A slot scanner detects sandwich patterns (buy → victim → sell on one pool in
one slot). It publishes a daily Merkle root of detections to the same ledger,
so validator behaviour becomes publicly verifiable.

### 13. Hardened analysis runner · Roadmap
The binaries Tidemark analyzes are untrusted, so parsing and verifier tests run
in a locked-down process: no network, read-only filesystem, a minimal syscall
allowlist (seccomp-bpf, Landlock) and a distroless container image. Signing
keys never share a process with untrusted input.

### 14. Distribution: npm (Shipped) and VS Code (Roadmap)
- **npm package** (`npm/`, Shipped): `tidemark-core` compiled to WebAssembly.
  `review(old, new)` returns the same report and verdict hash as
  `tidemark diff --json`, `inspect(bytes)` lists syscalls and handlers, and
  `fetchLedger(rpc, ledger, registry)` pulls the ledger accounts over JSON-RPC
  and verifies the whole chain in the browser. CI builds the package and checks
  it against the CLI's demo report. Not published to the npm registry yet.
- **VS Code extension** (Roadmap): diff a local build against the deployed program before
  you run `anchor deploy`, with findings shown inline.

### 15. Web app · Shipped (diff viewer and ledger feed)
`web/` is a static site on top of the npm package; nothing runs on a server.
- **Review**: drop the current and the new `.so` (or load the demo vault).
  The WASM engine produces the same findings, hunks and verdict hash as the CLI.
  Files never leave the browser.
- **Ledger**: enter an RPC endpoint, ledger program and registry. The page
  pulls the raw accounts and verifies the hash chain, PDAs, reviewer allowlist
  and quorum itself, then lists each attestation with its risk and approvals.
- Restrained dark interface: near-black panels with fine rules, a serif for
  headings, blue for actions and orange reserved for high-risk findings.
  Severity is always written out as text as well as colour.

Build it with `bash scripts/build-web.sh` (writes `site/`) and serve that
folder with any static server, e.g. `python -m http.server -d site`.
The authority census view is still on the roadmap.

The visual language is **liquid glass**: panels are translucent layers with
backdrop blur, soft refraction at the edges and light that follows depth, so
the ledger feed and diff hunks read as stacked sheets over the chain. It
respects `prefers-reduced-transparency` and `prefers-reduced-motion`, falling
back to solid surfaces that keep WCAG AA contrast, so the effect never costs
legibility.

---

## Live on devnet

The ledger v2 program runs on devnet, and a real upgrade has gone through the
full quorum flow: deploy a vault, snapshot it, upgrade it on-chain to the
backdoored build, have reviewer 1 attest, and have reviewer 2 independently
re-review and co-sign.

| What | Address |
|---|---|
| Ledger program (v2) | [`BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc`](https://explorer.solana.com/address/BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc?cluster=devnet) |
| Demo vault (upgraded to v2) | [`5pHTptDKd3fS6vnx82rHxSH1xURrYacDr17uJhnc7aX3`](https://explorer.solana.com/address/5pHTptDKd3fS6vnx82rHxSH1xURrYacDr17uJhnc7aX3?cluster=devnet) |
| Registry (2-of-2) | [`72HSqJR6Y2uiedNWVQxDDRXYr9LjB4cDUn3Me2AtenxU`](https://explorer.solana.com/address/72HSqJR6Y2uiedNWVQxDDRXYr9LjB4cDUn3Me2AtenxU?cluster=devnet) |
| Reviewer 1 | [`9fxLpiKzK1zeF42911g5ruKDdTuJFduJSEXcZHh4mCB1`](https://explorer.solana.com/address/9fxLpiKzK1zeF42911g5ruKDdTuJFduJSEXcZHh4mCB1?cluster=devnet) |
| Reviewer 2 | [`BWueozAMDiJxxvc96NC8tnfHRKxeyKhB39kS13nzq9Np`](https://explorer.solana.com/address/BWueozAMDiJxxvc96NC8tnfHRKxeyKhB39kS13nzq9Np?cluster=devnet) |
| Entry #0 | [`ak6XANj3vkFQz1EGsVHzc2CLC9vF8CbB9rbTB2SFaKd`](https://explorer.solana.com/address/ak6XANj3vkFQz1EGsVHzc2CLC9vF8CbB9rbTB2SFaKd?cluster=devnet) |

| Step | Transaction |
|---|---|
| Vault upgraded to backdoored v2 | [`4YxnJMQY…`](https://explorer.solana.com/tx/4YxnJMQYyRrNEPtQgrvLSfy4CGpK7zC7yUiHa6PzJJkcDvbBAkLmUgTCad1ipJ4Q2oThmeCHkZQTipXJALVCcRyA?cluster=devnet) |
| Ledger upgraded to v2 | [`2ERLV1b7…`](https://explorer.solana.com/tx/2ERLV1b7gxv7LooeZBWwVYEAt5zruehKugXzWTrTXEPJGEfNFR1UqBheXcW67qboXBqrKpRGkZkTHJx6uM6reYjt?cluster=devnet) |
| Registry created | [`5bwesoG5…`](https://explorer.solana.com/tx/5bwesoG5rLpfdV2PLN7RhaYebP5R52q1AEJ8pQjitcXCVUfYQp5S35hUGhniJbkY1HCNXaqWsjnChXQXCYiVwxAx?cluster=devnet) |
| Reviewers added | [`542j9ayK…`](https://explorer.solana.com/tx/542j9ayKKxDUriUzwgqEqhqXifRYFg89g6spcC3YPnyNG83YBe3M558vgzGwebYwNgsE59q9J5hkBwwRhtERE2Lq?cluster=devnet) [`5DWDvHh8…`](https://explorer.solana.com/tx/5DWDvHh8NRb9WjRYuXwvHRdpVVujUpHPRWAVfA9RLqX9bEQtUdpHNgUcqzUzT8KLX67BPgGZMtvb1WUvgicanNiB?cluster=devnet) |
| Threshold set to 2 | [`4Lir1M6v…`](https://explorer.solana.com/tx/4Lir1M6vkHrJzTAAjgwWcUtpwLhXaK7yhTJ3DgMBcz5k8tEfqcjJvSJjLtCuTNa5W1LUrZNz3D5Zw37FmMDdkLz1?cluster=devnet) |
| Reviewer 1 attests (1/2, pending) | [`3LEvQwNJ…`](https://explorer.solana.com/tx/3LEvQwNJ4CJDjX8AwpXeri3LtyRCm3GHTsfeQwXPdAPhSAcawx5Dkv58XSSg5QRCG9arHxmwZ4Nh1Chdz3SL8TZx?cluster=devnet) |
| Reviewer 2 re-reviews and approves (2/2, final) | [`6sJWSnwV…`](https://explorer.solana.com/tx/6sJWSnwV7vbjwPKYV36K2GsKyzKcyR3fsGd9j2Du32h3XwJnekd6qme3bLkRGH1ppezXkJYuNH22mB4DTFt6QM8?cluster=devnet) |

Both reviewers independently computed verdict `30204461…0d31` (risk High).
On the same registry, a key that isn't on the allowlist was refused by the
program, and a second approval from reviewer 2 was refused too.

```sh
cargo run -p tidemark-cli -- verify-ledger \
  --program BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc \
  --registry 72HSqJR6Y2uiedNWVQxDDRXYr9LjB4cDUn3Me2AtenxU
```

```
threshold  2 of 2 active reviewers
  #0   slot 519460795  risk 3  program 5pHT…7aX3  by 9fxL…mCB1  2/2 final
https://api.devnet.solana.com: chain OK, 1 entries, head a47556f807496f9a
```

The first ledger version's registry (`BEeLrro…`) and entry (`84BquZa…`) remain
on devnet as legacy records; v2 uses new account types and seeds and does not
read them.

## Repository layout

```
crates/tidemark-core     diff engine, rules, ledger client and verifier (Rust)
crates/tidemark-cli      `tidemark` command-line tool
contracts/               Anchor workspace
  programs/tidemark-ledger   attestation ledger program
  programs/demo-vault        demo vault and its backdoored v2 upgrade (devnet only)
fixtures/                built program binaries used by tests and CI
scripts/                 build helpers
docs/architecture/       HLD.md, LLD.md
```

## Quick start

```sh
# review the demo upgrade (v1 → backdoored v2)
cargo run -p tidemark-cli -- diff fixtures/demo_vault_v1.so fixtures/demo_vault_v2.so --json report.json

# publish a review of a deployed upgrade (snapshot taken before the upgrade)
cargo run -p tidemark-cli -- init-registry --ledger <LEDGER> --threshold 1
cargo run -p tidemark-cli -- add-reviewer --ledger <LEDGER> <YOUR_KEY>
cargo run -p tidemark-cli -- attest --ledger <LEDGER> --program <PROGRAM> --old before.so

# anyone can verify the chain
cargo run -p tidemark-cli -- verify-ledger --program <LEDGER_PROGRAM_ID> --registry <REGISTRY>

# inspect any deployed program
cargo run -p tidemark-cli -- fetch <PROGRAM_ID> -o program.so
cargo run -p tidemark-cli -- census <PROGRAM_ID>...      # who can upgrade these programs?
```

### Commands

| Command | Purpose |
|---|---|
| `diff OLD NEW` | Review an upgrade locally; `--json` writes the full report |
| `inspect FILE` | Summarize one binary |
| `fetch PROGRAM_ID` | Download deployed bytecode and show its upgrade authority |
| `init-registry --threshold K` | Create a registry you control |
| `add-reviewer KEY` / `set-reviewer KEY --active BOOL` | Manage who may attest |
| `set-threshold K` | Change how many approvals make an entry final |
| `propose-authority KEY` / `accept-authority` | Hand a registry to a new key in two steps |
| `attest --program ID --old SNAPSHOT` | Review the deployed upgrade and publish the verdict |
| `approve --registry R --index N --old SNAPSHOT` | Re-run a published review and co-sign if it matches |
| `verify-ledger --registry R [--rpc URL]...` | Check chain, reviewers, approvals and PDAs |

Chain commands take `--keypair` (the signer) and an optional `--payer`.

### Building and verifying

```sh
cargo test --workspace              # unit and integration tests
cargo kani -p tidemark-core         # model-check the proof harnesses (Linux/macOS)
bash scripts/build-fixtures.sh      # on-chain programs + demo fixtures (Solana CLI 2.1+, Anchor 0.31)
```

## Documentation

- [High-level design](docs/architecture/HLD.md)
- [Low-level design](docs/architecture/LLD.md)

## License

MIT
