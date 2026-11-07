# Tidemark: High-Level Design

## 1. Problem

A Solana program marked upgradeable can be replaced at any moment by the
holder of its upgrade authority. Users, integrators and the multisig signers
who approve upgrades rarely see what the new bytecode does. Existing open
tooling covers neighbouring problems:

| Existing tooling | What it covers | What it misses |
|---|---|---|
| Instruction/event monitors | Decoded instructions and alerts | The bytecode itself |
| Authority watchdogs | ProgramData header (authority, slot) | What changed in the code |
| Verified builds | Hash equality with a source repo | Behaviour, and unverified programs |
| Single-binary analyzers | One version at a time | The difference between versions |

Tidemark answers one question: **what did this upgrade change, and should
anyone be worried?**

## 2. Goals and non-goals

**Goals**
- Diff two deployed versions of any program, with or without source or IDL.
- Turn the diff into ranked, explainable findings.
- Record every review on-chain as a tamper-evident, public attestation.
- Fit existing workflows: CLI, CI gate, multisig proposal review, dashboard.

**Non-goals (v0)**
- Full decompilation to source-level Rust.
- Proving a program is safe. Tidemark reports changes, not guarantees.
- Live transaction interception.

## 3. System context

```
             ┌──────────────┐   upgrade / proposal events   ┌────────────────┐
 Solana ────►│  Watcher     │──────────────────────────────►│  Review queue  │
 (RPC/gRPC)  └──────────────┘                               └───────┬────────┘
 CI upload ─────────────────────────────────────────────────────────┤
 CLI user  ─────────────────────────────────────────────────────────┤
                                                                    ▼
                         ┌─────────────────────────────────────────────────┐
                         │                Analysis pipeline                │
                         │  fetch ─► cache ─► decode ─► diff ─► rules      │
                         │                       │                 │       │
                         │                       ▼                 ▼       │
                         │              isolated runner       explainer    │
                         │              (untrusted ELF)       (LLM, opt.)  │
                         └───────────────────────┬─────────────────────────┘
                                                 │ report + report hash
                          ┌──────────────────────┼───────────────────────┐
                          ▼                      ▼                       ▼
                 tidemark-ledger (Anchor)   Dashboard / API        Multisig review bot
                 hash-linked attestations   census, diff viewer    comment on proposal
```

## 4. Components

| Component | Responsibility | Tech |
|---|---|---|
| tidemark-core | ELF parsing, sBPF decoding, normalized diff, risk rules, report hashing, RPC fetch | Rust library |
| tidemark-cli | `diff`, `inspect`, `fetch`; exit code 2 on High/Critical | Rust binary |
| tidemark-ledger | Registry and attestation PDAs, hash chain, `Attested` events | Anchor program |
| Watcher (planned) | Subscribes to loader `Upgrade` and multisig proposals; snapshots ProgramData before it is overwritten | Rust, Geyser/gRPC |
| Explainer (planned) | Turns structured findings into a short plain-English summary | LLM with strict JSON schema |
| Isolated runner (planned) | Parses untrusted binaries with no network, read-only FS, minimal syscalls | Linux namespaces, distroless image |
| Web app | Diff viewer and attestation feed, verified in the browser | Next.js, TypeScript, Tailwind, WASM core |
| Distribution | npm package and VS Code extension | WASM build of core |

## 5. Key flows

**Upgrade review (CLI / CI)**
1. Load old and new ELF from files, or `fetch` them over RPC.
2. Decode both, normalize code addresses, diff.
3. Apply rules to produce findings and an overall risk.
4. Emit text and JSON; compute `report_hash = sha256(json)`.
5. Optionally submit `attest` to the ledger.

**Multisig pre-approval (planned)**
1. A proposal references a buffer account.
2. Diff the buffer against live ProgramData.
3. Post the report to the proposal and attest it.

**Public verification**
Anyone reads the registry, walks attestations in index order, recomputes each
`entry_hash` from its fields and `prev_hash`, and checks the final hash equals
`registry.last_hash`.

## 6. Trust model

- Program bytes, `.rodata` strings and security.txt are untrusted. They are
  parsed, never executed, and never given to an LLM as instructions.
- LLM output is advisory. A finding exists only if a deterministic rule
  produced it.
- Write access to a registry is enforced on-chain: only allowlisted reviewers
  can attest or approve, and only the authority manages that list. Authority
  changes need the new key's signature.
- An entry is final only when k distinct reviewers have each re-run the review
  and reached the same verdict hash.
- Entries are hash-linked and bound to their registry and slot, so edits,
  deletions and reordering are detectable by anyone with an RPC endpoint.
  Cross-checking several RPCs reduces trust in any single provider.
- Open item: the ledger program's own upgrade authority is a single key on
  devnet. Production deployments should put it behind a multisig with a
  timelock or make the program immutable.

## 7. Cost model

1. Content cache keyed by `sha256(old) ‖ sha256(new)`; repeat reviews cost nothing.
2. Deterministic rules settle most diffs.
3. The explainer runs only on non-trivial diffs, with a fixed prompt prefix so
   the inference server reuses its KV cache. Self-hosted deployments can add
   KV-cache quantization to cut memory further.

## 8. Roadmap

| Stage | Scope |
|---|---|
| v0 | core and CLI, ledger program, demo upgrade fixture, CI gate |
| v0.1 | watcher with ProgramData snapshots, web diff viewer |
| v0.2 | explainer, multisig proposal review |
| v0.3 | authority census, npm (WASM) package, VS Code extension |

## 9. Frontend direction

Dark-first: midnight black surfaces, electric blue for primary actions and
links, a small amount of orange reserved for warnings and high-risk findings.
Severity is always shown with a text label as well as colour.

Surface style is liquid glass: translucent, blurred panels with edge
refraction layered over the dark base. Under `prefers-reduced-transparency` or
`prefers-reduced-motion` the UI switches to solid surfaces and static
transitions, keeping WCAG AA contrast in every mode.
