# Tidemark

**See what a Solana program upgrade actually changed, before and after it lands.**

Any upgradeable Solana program can be replaced at any moment by whoever holds
its upgrade authority. Users, integrators and even the multisig signers who
approve the upgrade usually can't see what the new bytecode does. Today's open
tooling monitors instructions, watches the authority header, or checks that a
build hash matches source. None of it shows the **behavioural difference
between two deployed versions**.

Tidemark reads the bytecode itself, tells you what changed and how risky it
is, and writes every review to a public, tamper-evident ledger on Solana.

```
$ tidemark diff fixtures/demo_vault_v1.so fixtures/demo_vault_v2.so
Tidemark upgrade review  (tm-rules-0.2)
  old  99e7c4fe98f886be  20066 insns
  new  519015fa4879499f  20608 insns
  changed instructions: 912 (2.24%)
  overall risk: HIGH

[HIGH    ] TM-KEY-ADD  1 new hardcoded key(s)
             9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin
[HIGH    ] TM-CHECK-GONE  Account checks were removed
             ConstraintHasOne (2001): 5 → 4 check sites
[MEDIUM  ] TM-IX-CHANGE  Instruction handlers added or removed
             + sweep
```

That is a real run against the demo vault and its backdoored upgrade, built
from `contracts/programs/demo-vault`. Tidemark recovers the attacker's address
byte for byte, spots the dropped `has_one` check and names the new `sweep`
handler, all from bytecode alone.

---

## Features

Status key: **Shipped** is in this repository and tested. **Roadmap** is designed
(see [HLD](docs/architecture/HLD.md)) but not built yet.

### 1. Bytecode-level upgrade diff · Shipped
Works on any deployed program, with no source code or IDL required.
- A purpose-built **sBPF decoder** handles every instruction class, including
  two-word `lddw`.
- **Normalized comparison**: jump targets, internal call targets and load
  addresses are masked, so code that only *moved* compares equal and the diff
  shows real behaviour changes.
- **Syscall resolution** through `R_BPF_64_32` relocations (SBPFv1) and murmur3
  syscall ids (static syscalls). `call 0x…` shows as `call sol_invoke_signed_rust`.
- Extracts `.rodata` strings, candidate 32-byte keys and `security.txt` from both versions.

### 2. Upgrade risk rules · Shipped
Deterministic, versioned rules (`tm-rules-0.2`) turn a diff into ranked findings:

| Rule | What it catches |
|---|---|
| `TM-KEY-ADD` | New 32-byte keys, recovered from `.rodata` or rebuilt from four `lddw` immediates stored to consecutive stack slots |
| `TM-CHECK-GONE` | Fewer Anchor account-check sites (`has_one`, signer, owner, seeds, address), counted by their error-code immediates |
| `TM-IX-CHANGE` | Instruction handlers added or removed, each name confirmed by matching `sha256("global:<name>")[..8]` in the code |
| `TM-SYSCALL-ADD` | New `invoke_signed` and other sensitive syscall call sites |
| `TM-CALLX-ADD` | New indirect calls with runtime-computed targets |
| `TM-SECTXT` | `security.txt` removed or changed (possible change of responsible party) |
| `TM-CHURN` | Large rewrites that can hide small malicious changes |

Well-known program ids (System, Token, Token-2022, ATA, …) are recognised and
named, so a new reference to Token isn't mistaken for a planted key.

### 3. Public, tamper-evident attestation ledger · Shipped (live on devnet)
An Anchor program (`tidemark-ledger`) records each review on Solana.
- **Hash-linked PDAs**: each attestation stores program, old and new code hash,
  report hash, risk, rule version, model id, reviewer and slot, plus the previous
  entry's hash. `entry_hash = sha256(fields ‖ prev_hash)`.
- **Independent verification**: `tidemark verify-ledger` rebuilds the chain
  from raw account data and detects edited, deleted or truncated entries without
  trusting Tidemark's servers.
- **Permissionless reviewers**: anyone can run a registry, and every entry is
  signed by its reviewer, so reputation is earned on-chain.
- **Canonical report hashing**: reports are hashed as sorted-key JSON, so the
  hash `diff` prints is exactly the one `attest` publishes.

### 4. CI gate for safe code shipping · Shipped
`tidemark diff` exits with code `2` on High or Critical findings. Drop it into a
pipeline and a risky upgrade can't merge or deploy unnoticed. This repo's own
CI runs clippy with warnings as errors, the test suite, and a live review of the
demo upgrade.

### 5. Typed, proof-checked Rust · Shipped
- **Kani model-checking harnesses** cover the code that touches untrusted input.
  They prove that the decoder never panics or reads out of bounds on arbitrary
  bytes, that account parsers reject hostile data instead of crashing, and that
  the transaction length encoding round-trips for every `u16`.
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
id and prompt hash are recorded in each attestation's `model_id`.

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

### 11. Upgrade-authority census · Roadmap
A public dashboard that classifies every upgradeable program by who controls
it: single key, multisig (threshold and timelock read on-chain), governance, or
immutable. It joins this with verified-build and `security.txt` status.

### 12. MEV transparency layer · Roadmap
A slot scanner detects sandwich patterns (buy → victim → sell on one pool in
one slot). It publishes a daily Merkle root of detections to the same ledger,
so validator behaviour becomes publicly verifiable.

### 13. Hardened analysis runner · Roadmap
The binaries Tidemark analyzes are untrusted, so parsing and verifier tests run
in a locked-down process: no network, read-only filesystem, a minimal syscall
allowlist (seccomp-bpf, Landlock) and a distroless container image. Signing
keys never share a process with untrusted input.

### 14. Distribution: npm and VS Code · Roadmap
- **npm package**: a WASM build of `tidemark-core` exposing
  `diff(old: Uint8Array, new: Uint8Array) → Report`, usable in Node, browsers and CLIs (`npx tidemark`).
- **VS Code extension**: diff a local build against the deployed program before
  you run `anchor deploy`, with findings shown inline.

### 15. Web app · Roadmap
A diff viewer, attestation feed and census in a dark-first interface: midnight
black surfaces, electric blue for primary actions, and orange reserved for
high-risk findings. Severity is always shown as a text label as well as colour.

The visual language is **liquid glass**: panels are translucent layers with
backdrop blur, soft refraction at the edges and light that follows depth, so
the ledger feed and diff hunks read as stacked sheets over the chain. It
respects `prefers-reduced-transparency` and `prefers-reduced-motion`, falling
back to solid surfaces that keep WCAG AA contrast, so the effect never costs
legibility.

---

## Live on devnet

The full flow has run on Solana devnet: deploy a vault, snapshot it, upgrade it
on-chain to the backdoored build, fetch the new bytecode from chain, review it,
and publish the review to the ledger.

| What | Address |
|---|---|
| Ledger program | [`BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc`](https://explorer.solana.com/address/BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc?cluster=devnet) |
| Demo vault (upgraded to v2) | [`5pHTptDKd3fS6vnx82rHxSH1xURrYacDr17uJhnc7aX3`](https://explorer.solana.com/address/5pHTptDKd3fS6vnx82rHxSH1xURrYacDr17uJhnc7aX3?cluster=devnet) |
| Reviewer registry | [`BEeLrroZNSULfZuSUQuneuzetKXtKMvkmPtuH7x7k6qK`](https://explorer.solana.com/address/BEeLrroZNSULfZuSUQuneuzetKXtKMvkmPtuH7x7k6qK?cluster=devnet) |
| Attestation #0 | [`84BquZaNLSjHpNY5Ccz2AkyK9wHv2jnj2tZGDNoZWv3R`](https://explorer.solana.com/address/84BquZaNLSjHpNY5Ccz2AkyK9wHv2jnj2tZGDNoZWv3R?cluster=devnet) |

| Step | Transaction |
|---|---|
| Vault v1 deploy | [`4VmsbXQv…`](https://explorer.solana.com/tx/4VmsbXQv5LVP45XnfwUkmDKXocu9SsMuvraSn1baexCwJuJspTPEQUxAxtsmPHhPR6tEt8HZcqdKMgnxGRW9z1Tc?cluster=devnet) |
| Upgrade to backdoored v2 | [`4YxnJMQY…`](https://explorer.solana.com/tx/4YxnJMQYyRrNEPtQgrvLSfy4CGpK7zC7yUiHa6PzJJkcDvbBAkLmUgTCad1ipJ4Q2oThmeCHkZQTipXJALVCcRyA?cluster=devnet) |
| Registry created | [`pNqQHuwt…`](https://explorer.solana.com/tx/pNqQHuwtVFPpriTyR75mXSoWQdCbVfWu6ncoRCMVxPEZgmWpC65tDBseranVdhATchz8n4T7z79AfnC9kzqPhxd?cluster=devnet) |
| Review attested (risk High) | [`28MK4nNB…`](https://explorer.solana.com/tx/28MK4nNBorrSTJ7m5BpjDBs1DBGjFRe3Y5R1M157kknx7DDCzPdJAmpjW7ePyT7jfneteLUp5cDrrSrkmhA4mAvL?cluster=devnet) |

The attestation stores old code hash `99e7c4fe…`, new code hash `519015fa…`
and report hash `acddec1b…`, the same values `tidemark diff` prints locally.
Check it yourself:

```sh
cargo run -p tidemark-cli -- verify-ledger   --program BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc   --registry BEeLrroZNSULfZuSUQuneuzetKXtKMvkmPtuH7x7k6qK
```

Rerun the flow on any program you control with `scripts/demo-devnet.sh`.

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

# publish the review on devnet
cargo run -p tidemark-cli -- init-registry --ledger <LEDGER_PROGRAM_ID>
cargo run -p tidemark-cli -- attest report.json --program <REVIEWED_PROGRAM_ID> --ledger <LEDGER_PROGRAM_ID>

# anyone can verify the chain
cargo run -p tidemark-cli -- verify-ledger --program <LEDGER_PROGRAM_ID> --registry <REGISTRY>

# inspect any deployed program
cargo run -p tidemark-cli -- fetch <PROGRAM_ID> -o program.so
```

### Commands

| Command | Purpose |
|---|---|
| `diff OLD NEW` | Review an upgrade; `--json` writes the full report |
| `inspect FILE` | Summarize one binary |
| `fetch PROGRAM_ID` | Download deployed bytecode and show its upgrade authority |
| `init-registry` | Create your reviewer registry on the ledger |
| `attest REPORT` | Publish a report's hash as the next ledger entry |
| `verify-ledger` | Rebuild and check a registry's hash chain |

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
