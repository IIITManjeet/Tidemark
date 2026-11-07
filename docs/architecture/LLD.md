# Tidemark: Low-Level Design

## 1. Repository layout

```
tidemark/
├── Cargo.toml                 off-chain Rust workspace (crates/*)
├── crates/
│   ├── tidemark-core/         library
│   │   └── src/
│   │       ├── lib.rs         module wiring, report_hash()
│   │       ├── elf.rs         ELF → Program (sections, relocations, strings, consts)
│   │       ├── disasm.rs      sBPF decoder, readable and normalized rendering
│   │       ├── syscalls.rs    murmur3_32, syscall table and weights
│   │       ├── diff.rs        Program × Program → Report (rules, hunks)
│   │       └── rpc.rs         ProgramData fetch, upgrade authority
│   ├── tidemark-cli/          `tidemark` binary
│   └── tidemark-wasm/         wasm-bindgen exports for the npm package
├── npm/                       package.json, ledger.js, test.mjs (dist/ is generated)
├── web/                       static web app (index.html, app.js, style.css)
├── vscode/                    VS Code extension (extension.js, review.js; wasm/ is generated)
├── contracts/                 Anchor workspace (separate toolchain)
│   └── programs/
│       ├── tidemark-ledger/   attestation registry
│       └── demo-vault/        demo fixture (v1 and backdoored v2)
├── fixtures/                  built .so files used by tests and CI
├── scripts/build-fixtures.sh
└── docs/architecture/         HLD.md, LLD.md
```

`contracts/` is excluded from the root workspace because Solana's
platform-tools compiler lags stable Rust; each workspace has its own lockfile.

## 2. tidemark-core

### 2.1 ELF loading (`elf.rs`)

The SBPF version comes from the header: `e_machine` 247 with `e_flags` 0 is v0,
247 with `0x20` is v2, and 263 carries the version in `e_flags` (0–3). Only v0
and v1 are decoded; anything else is refused before analysis.


| Field | Source |
|---|---|
| `sha256`, `size` | whole file |
| `lines`, `norm`, `insn_count` | `.text`, decoded |
| `syscalls` | `call` sites resolved by `R_BPF_64_32` relocations against undefined dynamic symbols (SBPFv1), or by `imm == murmur3_32(name)` |
| `callx` | count of opcode `0x8d` |
| `strings` | printable runs of 8+ bytes in `.rodata` and `.data.rel.ro` |
| `consts32` | 8-aligned 32-byte windows with 24+ distinct bytes and fewer than 28 printable bytes (candidate pubkeys) |
| `imm_counts` | count of each immediate used by `mov`/`st` instructions |
| `wide` | every `lddw` value with its pc and destination stack slot |
| `rodata` | raw `.rodata` and `.data.rel.ro` bytes |
| `security_txt` | `.security.txt` section |

### 2.2 Decoder (`disasm.rs`)

Instruction word: `op:u8 | dst:u4 src:u4 | off:i16 | imm:i32`. `lddw`
(`0x18`) spans two words and forms a 64-bit immediate.

| Class (`op & 7`) | Handling |
|---|---|
| 0 LD | `lddw` |
| 1 LDX, 2 ST, 3 STX | size from `(op >> 3) & 3` |
| 4 ALU32, 7 ALU64 | operation from `op >> 4`; bit `0x08` selects register source |
| 5 JMP | `call 0x85`, `callx 0x8d`, `exit 0x95`, conditional jumps |

`render()` returns a readable and a normalized string. The normalized form
masks jump targets, internal call targets and `lddw` addresses so code that
only moved compares equal. Syscall names and ALU immediates are kept.

The loader then puts real 64-bit constants back into the normalized line. An
`lddw` counts as an address if a `R_BPF_64_RELATIVE` or `R_BPF_64_64`
relocation points at it, if it falls below the end of the loaded image, or if
its upper half is a VM region (1 to 4). Everything else is a constant and is
compared as-is. Alongside each line the loader keeps a `Flow` record: the
absolute branch or internal-call target and the constant, if any.

### 2.3 Rules (`diff.rs`, `tm-rules-0.4`)

| Rule | Trigger | Severity |
|---|---|---|
| TM-KEY-ADD | new unknown 32-byte keys (see below) | High |
| TM-PROG-REF | new keys matching well-known program ids | Low |
| TM-CHECK-GONE | a handler reaches fewer immediates for Anchor check error codes (2001 has_one, 2002 signer, 2003 raw, 2004 owner, 2006 seeds, 2012 address, 3007 wrong owner program, 3010 not signer); program-wide counts if either side has no dispatch table | High |
| TM-ERR-GONE | a handler reaches fewer custom error immediates (6000–6999) | Medium |
| TM-IX-CHANGE | handler set (by discriminator) changed; unnamed handlers show as their discriminator | Medium if added, else Low |
| TM-SYSCALL-ADD | call-site count of a syscall rose | High for `invoke_signed*`, Low for other sensitive syscalls, else Info |
| TM-SYSCALL-DEL | call-site count fell | Info |
| TM-CALLX-ADD | more `callx` sites | Medium |
| TM-BRANCH-RETARGET | an aligned branch whose target no longer maps to the old target (see below) | High |
| TM-CALL-RETARGET | same, for internal calls | High |
| TM-CONST-CHANGE | constants present in old and missing in new, excluding handler discriminators | Medium |
| TM-CONST-ADD | constants only added, excluding discriminators and new key limbs | Low |
| TM-SECTXT | security.txt added, removed or changed | Medium if removed, else Low |
| TM-CHURN | 25%+ of instructions changed, programs of 200+ instructions | Medium |

**Key recovery.** Compiled Rust rarely keeps a `Pubkey` constant as 32
contiguous bytes. It loads it as four 64-bit `lddw` immediates and either
stores each with `stxdw` to `[base + o]` … `[base + o+24]`, or compares each
with `jeq`/`jne` against a value loaded by `ldxdw` from such a slot. For every
`lddw` the loader looks up to 32 instructions ahead, stopping if the register
is overwritten (any LD, LDX or ALU write, or a call for r0–r5), and records
the store slot, or failing that the slot of the compared value. Store and
compare slots are kept apart.

Keys are assembled per program: four non-zero immediates (not handler
discriminators) in consecutive slots of one base register, each limb within
64 instructions of the previous one, accepted if the 32 bytes hold 20+ distinct values. The rule
then reports keys assembled in the new program that were neither assembled in
the old one nor present in its `.rodata`. Comparing whole keys rather than
limbs means limbs planted ahead of time in an older version don't hide a key,
and a single low-entropy limb doesn't either.

`.rodata` is scanned with a sliding 32-byte window at every offset (24+
distinct bytes, under 28 printable). Overlapping new windows are joined, so a
longer random blob shows up once as `<first window> (start of an N-byte
blob)`; at most 4096 new windows are examined. The loader keeps at most
65,536 windows per program, so a multi-megabyte random `.rodata` stays cheap
(the finding still fires; only the detail list is truncated).

**Handlers (`handlers.rs`).** Anchor dispatches with
`ldxdw rA, [rB+0]; lddw rC, disc; jeq rA, rC, stub`. The loader records every
such compare (the `ldxdw` must be within 8 instructions and read offset 0).
The dispatch table is the largest run of these whose `lddw`s are at most 8
instructions apart, capped at 256 entries. Names come from `Instruction: X`
log strings: each prefix of the CamelCase words is tried as snake_case, both
as-is and with digits split off (`Sweep1` → `sweep1`, `sweep_1`), and kept if
`sha256("global:name")[..8]` is a known discriminator. A build without logs
still lists every handler, just by discriminator.

**Per-handler checks.** Functions start at every internal call target and
after every `exit`. From a handler's stub (up to 32 instructions, stopping at
`ja`/`exit`) the walk follows internal calls and sums the error-code
immediates (2000–3999, 6000–6999) of every function reached. Old and new
handlers with the same discriminator are compared code by code, so a decoy
check added to another handler no longer cancels a removed one. The stub's
own check window ends where its call scan ends (the first `ja`/`exit`). The
program-wide count still runs as a backstop: a code whose total fell without
any handler accounting for it is reported as `outside any handler`, which
covers handlers inlined into the entrypoint. A decoy added
inside code the same handler reaches still can. The walk has a total budget
of 4M steps; past it the rule falls back to program-wide counts.

**Retargets.** Normalization hides targets, so a branch moved by one
instruction diffs as unchanged. The rule maps old lines to new lines through
the `Equal` runs of the line diff, then checks every aligned branch and call:
the old target, mapped forward, must be the new target. The line diff can pair
look-alike blocks wrongly (Anchor handler stubs differ only in stack offsets),
so the map is refined first. Aligned branches vote on where each old target
went; when every vote agrees and the two blocks have the same opcode sequence
up to the next `ja`/`exit` (at least two instructions), that block is remapped.
Lines that set `r0` (`mov64/mov32/lddw r0, …`, the return code) must match
exactly, so an error return and a success return never count as the same
block, and a branch moved from one to the other is reported.
Calls then vote the same way. A mismatch is reported only if both the
instruction and the old target sit inside runs aligned for 4 lines either
side, which drops pairings inside rewritten code. Moving a branch onto a block
with an identical opcode sequence is not caught.

Overall risk is the highest finding severity. Code hunks come from a line diff
of normalized disassembly with three lines of context, shown in readable form.

### 2.4 Report hash

`report_hash = sha256(serde_json::to_vec(serde_json::to_value(report)))`.
Converting through `Value` sorts object keys (serde_json's default map), so the
hash does not depend on struct field order or on how a report file was
formatted. This relies on serde_json's `preserve_order` feature staying off.

### 2.5 RPC fetch (`rpc.rs`)

1. `getAccountInfo(program_id)`; owner must be the BPF Upgradeable Loader.
2. Bytes `4..36` give the ProgramData address.
3. `getAccountInfo(programdata)`; owner must be the loader. Header is 45 bytes:
   tag `u32` (must be 3), slot `u64`, `Option<Pubkey>` (tag must be 0 or 1).
   The program account's tag must be 2.
4. The ELF length is computed from its own headers (section and program header
   tables plus every non-NOBITS section), so trailing zero bytes that belong to
   the file are kept and allocation padding is dropped.

All RPC calls share one client with a 10 s connect timeout, a 60 s overall
timeout and a 64 MiB response cap.

### 2.6 Resource limits

| Limit | Value | Why |
|---|---|---|
| Program size | 16 MiB | Solana programs are far smaller; bounds memory |
| Line diff | patience, 10 s deadline | Myers is quadratic on unrelated inputs |
| Handler name scan | 64 chars, 8 words per log string | stops quadratic name guessing |
| Key grouping | slot-indexed, 64-pc window | linear in the number of `lddw` |

When the diff deadline is hit the report sets `diff_exact: false` and the CLI
says the hunks are approximate.

An `lddw` value counts as an address only if it falls inside a real VM region
layout: below the image end, program region (upper half 1) with an offset
below the image end, stack or heap (upper half 2 or 3) below 16 MiB, or input
(upper half 4) below 256 MiB. So lamport limits such as 5 or 10 SOL are
tracked as constants. Constants that only appear in the new version raise
TM-CONST-ADD (Low); limbs of a key TM-KEY-ADD already reports are left out.
Discriminator compares outside the largest dispatch cluster that are new in
this version, and not limbs of a new key, are listed under TM-IX-CHANGE as
`(outside the dispatch table)`.

Known limit: an honest compiler change that merges identical error returns
lowers check counts and can raise a false TM-CHECK-GONE.

## 3. tidemark-cli

| Command | Behaviour | Exit code |
|---|---|---|
| `diff OLD NEW [--json PATH] [--hunks N] [--fail-on LEVEL]` | summary, findings, hunks, verdict and report hashes | 2 if risk ≥ LEVEL (default high); 1 on bad input |
| `inspect FILE` | hash, size, syscalls, callx, constants, security.txt | 0 |
| `fetch PROGRAM_ID --rpc URL -o FILE` | writes ELF, prints authority and last deploy slot | 0 |

## 4. tidemark-ledger (v2)

### 4.1 Accounts

| Account | Seeds | Fields |
|---|---|---|
| RegistryV2 | `["registry2", authority]` | authority, pending_authority, name, count, last_hash, threshold, active_reviewers, bump |
| Reviewer | `["reviewer", registry, key]` | registry, key, active, added_slot, bump |
| AttestationV2 | `["attest2", registry, count_le]` | registry, index, program, old_code_hash, new_code_hash, report_hash (verdict), risk, rules_version, model_id, reviewer, slot, prev_hash, entry_hash, threshold, approvals, bump |
| Approval | `["approval", attestation, reviewer]` | attestation, reviewer, slot, bump |

### 4.2 Instructions

| Instruction | Signers | Checks |
|---|---|---|
| `init_registry(name, threshold)` | authority, payer | threshold ≥ 1 |
| `add_reviewer(key)` | authority, payer | `has_one = authority`; Reviewer PDA must not exist |
| `set_reviewer_active(active)` | authority | deactivating may not drop active reviewers below the threshold |
| `set_threshold(k)` | authority | 1 ≤ k ≤ active reviewers |
| `propose_authority(key)` | authority | |
| `accept_authority()` | pending authority | signer equals `pending_authority`, which is non-default |
| `attest(args)` | reviewer, payer | Reviewer PDA for the signer exists and is active; risk ≤ 4; creates the entry and the submitter's Approval |
| `approve(report_hash)` | reviewer, payer | active Reviewer; entry belongs to the registry; hash equals the entry's; Approval PDA must not exist |

The payer is a separate signer everywhere rent is paid, so reviewers need no SOL.

### 4.3 Hash chain

```
entry_hash = sha256( index_le ‖ registry ‖ program ‖ old_code_hash ‖
                     new_code_hash ‖ report_hash ‖ risk ‖ rules_version ‖
                     model_id ‖ reviewer ‖ slot_le ‖ prev_hash )
```

`approvals` is excluded because it changes after creation; it is checked
against the Approval accounts instead. The first entry uses 32 zero bytes as
`prev_hash`.

### 4.4 Verdict hash

`report_hash` on-chain is `sha256(canonical_json(verdict))`, where `verdict`
is `{rules_version, old, new, risk, findings}` with TM-CHURN removed and risk
recomputed from the remaining findings. Hunks, churn and `diff_exact` depend on
the diff deadline and machine speed, so they are left out to keep independent
reviewers in agreement.

### 4.5 Off-chain verification (`ledger.rs`)

1. Registry account owner is the ledger program and its address equals
   `PDA("registry2", authority)`.
2. Entries are fetched with `getProgramAccounts` (dataSize + registry memcmp),
   sorted by index, and must be contiguous from 0.
3. Each entry's address equals `PDA("attest2", registry, index)`, its
   `registry` field matches, `prev_hash` links, `entry_hash` recomputes, and
   slots never decrease.
4. The submitter and every approver must be Reviewer accounts of this registry;
   each Approval address equals `PDA("approval", entry, reviewer)`; approvers
   are unique; their count equals `approvals` and includes the submitter.
5. The last entry equals `registry.last_hash` and the count matches.
6. With several `--rpc` values the chain head must agree across all of them.

### 4.6 Transactions (`submit.rs`)

Messages are compiled by hand: payer first, then writable signers, read-only
signers, writable non-signers and read-only non-signers, with header counts
derived from those groups. Every listed signer must provide a key or signing
fails. After `sendTransaction` the client polls `getSignatureStatuses` for up
to 60 s and fails on any `err`.

## 5. Demo fixture

- v1: `withdraw` requires `has_one = authority` and a signer.
- v2 (`--features v2`): `withdraw` accepts an unchecked authority, and a new
  `sweep` instruction moves the treasury to a hardcoded key via `invoke_signed`.
- Actual findings (`fixtures/demo_report.json`): TM-KEY-ADD with the exact
  sweep address, TM-CHECK-GONE for `withdraw` (`ConstraintHasOne` 1 → 0,
  `AccountNotSigner` 1 → 0), TM-IX-CHANGE `+ sweep`.

## 6. Toolchain notes

The Anchor workspace pins `rust-version = 1.79` and a lockfile resolved for it
(`blake3 1.5.5`, `zerocopy 0.8.25`) so `cargo build-sbf` from Solana CLI 2.1
compiles it.

## 7. Proofs

The CI job `proofs` (Kani 0.68.0) runs every harness below; each verifies in
under a minute on a 4 GB machine:

| Harness | Property |
|---|---|
| `disasm::decode_step_stays_in_bounds` | one decoding step on any ≤24-byte input at any offset never panics, advances 8 or 16 bytes and stays inside the input; `decode` loops only while a step succeeds, so the whole buffer follows |
| `elf::slot_scans_stay_in_bounds` | store, compare and dispatch scans never index out of bounds |
| `rpc::elf_len_stays_in_bounds` | on any input up to 160 bytes, `elf_end` never panics and a returned length is within the data |
| `submit::compact_u16_roundtrips` | length encoding round-trips for every `u16` |
| `ledger::parse_*_never_panics` | the registry, attestation, reviewer and approval parsers never panic on any prefix of their account size; registry and attestation parse exactly when the data is full length and starts with the right discriminator |

`elf_len` rejects section header entries that are not 64 bytes, which also
keeps its loop bounded. The proved cores (`elf_end`, `registry_from`, …)
return `Option` or static errors; the public functions wrap them in `anyhow`,
because formatted errors and hashing are far too costly for CBMC. Account
discriminators are pinned as constants and a unit test checks each against
`sha256("account:<Name>")[..8]`.

Some properties are tested rather than proved, because string formatting and
`BTreeSet` make CBMC run out of memory or time: `render` on every opcode with extreme
operands, `sbpf_version` on the version table, and the `.rodata` sliding
window against a naive count on 2,000 random inputs.

## 8. WebAssembly build

`tidemark-core` has a default `net` feature. Without it the crate drops `ureq`
and every function that performs RPC (`rpc::call`/`fetch`, `submit::Ctx`,
`ledger::fetch*`), so it compiles for `wasm32-unknown-unknown`. The diff
deadline uses `web-time` there, and `similar` is built with
`wasm32_web_time`, because `std::time::Instant` panics on that target.

`tidemark-wasm` exports four functions that take bytes or JSON and return
JSON strings: `review`, `inspect`, `verifyLedger` and `rulesVersion`.
`verifyLedger` takes the raw registry, attestation, reviewer and approval
accounts (base64) and runs `ledger::snapshot_from` plus `ledger::verify`, the
same code the CLI's `verify-ledger` uses. `npm/ledger.js` fetches those
accounts with `fetch`, so the browser never trusts an indexer.

`programDataAddress`, `deployedInfo` and `deployedElf` let JS turn raw
`getAccountInfo` data into the deployed ELF with the same parsing and
`elf_len` trimming as `tidemark fetch`; the VS Code extension uses them, built
with `wasm-bindgen --target nodejs` (`scripts/build-vscode.sh`).

`scripts/build-wasm.sh` builds the release `.wasm` and runs
`wasm-bindgen --target web` into `npm/dist/`.

## 9. Census (`census.rs`)

`classify(authority, authority_owner)`:

| Condition | Result |
|---|---|
| no upgrade authority | `Immutable` |
| authority account owned by Squads v4/v3 | `Multisig` |
| owned by SPL Governance | `Governance` |
| authority on the ed25519 curve | `SingleKey` |
| otherwise (a PDA) | `ProgramControlled` with the owner if it isn't the System Program |

`survey(rpc, program)` reads the program owner (a program not owned by the
upgradeable loader is immutable), fetches ProgramData through `rpc::fetch`,
checks the ELF for `security.txt`, and looks up the authority account's
owner with a zero-length `dataSlice`. Errors are recorded per program so one
bad id doesn't stop the run.

## 10. Watcher (`snapshots.rs`, `tidemark watch`)

Snapshots live at `<dir>/<program>/<last_deploy_slot>.so`. `store` writes to a
`.part` file and renames it, so a crash never leaves a truncated snapshot that
looks complete, and it returns `false` when that slot is already stored.
`previous(dir, program, slot)` is the largest stored slot below `slot`;
files that don't parse as `<u64>.so` are ignored.

Each poll: `rpc::fetch`, `store`; on a new slot with a previous snapshot, run
`diff::compare(previous, deployed)`, print it, write `<prev>-<slot>.json`, and
with `--attest` call the same `attest_report` the `attest` command uses. RPC
errors are logged and the loop continues; `--once` turns them into a failing
exit code. The interval is at least 5 s.

## 11. Review cache (`cache.rs`)

`tidemark diff --cache <dir>` stores `{report, verdict_hash, report_hash}` at
`<dir>/<rules version>/<sha256 old>-<sha256 new>.json`. Both hashes are taken
from the input bytes before loading, so a hit skips parsing and diffing. An
entry is used only if its report names the same rules version and both
hashes, its overall risk equals the highest finding severity, and its stored
verdict and report hashes match ones recomputed from the cached report.
Anything else, including a corrupt file, is a miss: the review is recomputed
and the entry rewritten. This stops edits that change the risk, findings or
hashes on their own, but entries are not signed: someone who can write the
cache folder can rewrite an entry consistently. Treat the folder as trusted
local state and don't restore it from an untrusted source (for example a CI
cache shared with pull requests from forks).
A new rules version uses a new folder, so a rules change never serves a stale
verdict. The CLI prints from the report's JSON form, so cached and fresh
reviews print identically.

## 12. Planned interfaces

- `POST /v1/review {old, new}` returns the report and its hash, backed by the cache.
