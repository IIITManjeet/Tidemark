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
├── web/                       Next.js + TypeScript + Tailwind app, static export
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
247 with `0x20` is v2, 247 with 1–3 and 263 with 0–3 carry the version in
`e_flags`. v4 and unknown flags are refused.

Each version decodes into the v0 instruction form (`disasm::decode_for`):
- v2: memory opcodes moved into the ALU classes are mapped back to `ldx`/`st`/
  `stx`; `lddw` does not exist, so a `mov32`/`mov64` immediate followed by
  `hor64` on the same register becomes one wide constant load; class 6 is the
  PQR multiply/divide group; `callx` takes its register from `src`.
- v3: class 6 is 32-bit conditional jumps (`jeq32` …), which count as branches
  for retargets, guards and dispatch; `callx` takes its register from `dst`;
  syscalls are `call` with the murmur hash in `imm`, internal calls are
  relative.

`.text` and `.rodata` come from section headers when present, otherwise from
the executable and read-only `PT_LOAD` segments, as SIMD-0189 allows. The
address check uses the low 32 bits of every section and segment end, so v3's
bytecode at `1 << 32` and rodata at 0 fall inside the same regions as before.
Before `.rodata` is scanned for 32-byte keys, aligned 8-byte words that are
addresses are zeroed, so pointer tables that move between builds are not
reported as new keys.

Dispatch entries are `lddw disc` followed by `jeq` (handler at the target) or
`jne` (handler at the fall-through) against a register loaded with
`ldxdw [rB+0]`. Newer compilers emit a binary search: range compares (`jsle`,
`jgt` …) are split points, not handlers, and an entry whose block has no
visible load is tied to the closest earlier load of the same register within
64 instructions. The backward search for that load stops at `ja` and `exit`.


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

### 2.3 Rules (`diff.rs`, `tm-rules-0.7`)

| Rule | Trigger | Severity |
|---|---|---|
| TM-KEY-ADD | new unknown 32-byte keys (see below) | High |
| TM-PROG-REF | new keys matching well-known program ids | Low |
| TM-CHECK-GONE | a handler reaches fewer immediates for Anchor check error codes (2001 has_one, 2002 signer, 2003 raw, 2004 owner, 2006 seeds, 2012 address, 3007 wrong owner program, 3010 not signer); program-wide counts if either side has no dispatch table | High |
| TM-GUARD-GONE | an old conditional branch near an error path (see below) is now `ja`, a branch to its own fall-through, or a non-jump in an equal-length edit, or a guard was deleted in an edit of at most 4 lines | High; Medium when over a quarter of all guards change |
| TM-ERR-GONE | a handler reaches fewer custom error immediates (6000–6999) | Medium |
| TM-IX-CHANGE | handler set (by discriminator) changed; unnamed handlers show as their discriminator | Medium if added, else Low |
| TM-SYSCALL-ADD | call-site count of a syscall rose | High for `invoke_signed*`, Low for other sensitive syscalls, else Info |
| TM-SYSCALL-DEL | call-site count fell | Info |
| TM-CALLX-ADD | more `callx` sites | Medium |
| TM-BRANCH-RETARGET | an aligned branch whose target no longer maps to the old target (see below) | High |
| TM-CALL-RETARGET | same, for internal calls | High |
| TM-TARGET-SWAP | retargets that only trade places with each other (a permutation), typical of compiler reordering; a retarget whose new target runs the same code as the old one is not reported | Medium |
| TM-KEY-SPLIT | 4+ new constants with 6+ distinct bytes each within 256 instructions | High |
| TM-CONST-CHANGE | constants present in old and missing in new, excluding handler discriminators | Medium |
| TM-CONST-ADD | constants only added, excluding discriminators and new key limbs | Low |
| TM-SECTXT | security.txt added, removed or changed | Medium if removed, else Low |
| TM-CHURN | 25%+ of instructions changed, programs of 200+ instructions | Medium |
| TM-PARTIAL | diff deadline hit, `.rodata` window cap reached, or handler walk out of budget | Medium |
| TM-VERSION-CHANGE | old and new SBPF versions differ; nothing is downgraded, because flipping the header flag alone (v0 to v1 decode identically) must not lower a finding | Medium |

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

**Guards.** Counting error-code immediates misses a check that is kept but
can no longer fail: Anchor's `has_one` compiles to compares that set a flag,
then one branch on the flag, and patching the compares into jumps leaves every
error immediate in place. A *guard* is a conditional branch where exactly one
successor reaches an error-code immediate within 24 instructions (following
fall-through and `ja`, stopping at `exit`). A branch *feeds* a check if it is a
guard or either successor reaches a guard or an error site in that window.
Old branches are paired with new lines through the same map as retargets, plus
position inside replace blocks of at most 4 lines. A feeding branch that now
is `ja`, branches to its own fall-through, or (in an equal-length edit) is no
longer a jump raises TM-GUARD-GONE; so does a guard deleted in a block of at
most 4 lines, capped at the drop in the total guard count.

Known limits: rebuilding the same source from v2 to v3 lowers one seeds check
count and raises a false TM-CHECK-GONE; v2 is enabled on mainnet but not
used by current toolchains. An honest compiler change that merges identical error returns
lowers check counts and can raise a false TM-CHECK-GONE. A guard moved
somewhere else in a large rewrite is not tracked; TM-CHURN covers that case.
Keys computed at runtime, or read from an account, are not constants and are
not found.

## 3. tidemark-cli

| Command | Behaviour | Exit code |
|---|---|---|
| `diff OLD NEW [--json PATH] [--hunks N] [--fail-on LEVEL]` | summary, findings, hunks, verdict and report hashes | 2 if risk ≥ LEVEL (default high); 1 on bad input |
| `inspect FILE` | hash, size, syscalls, callx, constants, security.txt | 0 |
| `fetch PROGRAM_ID --rpc URL -o FILE` | writes ELF, prints authority and last deploy slot | 0 |

## 4. tidemark-ledger (v3; v2 still read)

v3 is a new program (`8f43wqFP4wZ8NLrJgBrGXDrXp92FgxSvM9Ng21GrgPq6`, built for
SBPF v3 so it can be frozen after SIMD-0500). The v2 program on devnet keeps
working; clients pick the layout from the registry account (148 bytes is v2,
188 is v3) and `ledger::layout_for` picks it for new registries by program id.

### 4.1 Accounts

| Account | Seeds | Fields |
|---|---|---|
| RegistryV3 | `["registry3", seed_key]` | seed_key (the first authority, never changes), authority, pending_authority, name, count, last_hash, threshold, active_reviewers, config_version, bump |
| Reviewer | `["reviewer", registry, key]` | registry, key, active, added_slot, bump |
| AttestationV3 | `["attest3", registry, count_le]` | the v2 fields (registry, index, program, old/new code hash, report_hash, risk, rules_version, model_id, reviewer, slot, prev_hash, entry_hash, threshold, approvals) plus program_data, deployed_slot, config_version, elf_len, bump |
| ApprovalV3 | `["approval", attestation, reviewer]` | registry, attestation, reviewer, slot, digest, bump |

v2 used `["registry2", authority]`, so rotating the authority moved the
registry's address and every client rejected it. v3 seeds from the stored
`seed_key`, so rotation only changes a field (the pattern Squads uses with its
create key). `config_version` goes up on every reviewer, threshold or authority
change, and each entry records the version it was written under.

### 4.2 Instructions

| Instruction | Signers | Checks |
|---|---|---|
| `init_registry(name, threshold)` | authority, payer | threshold ≥ 1; seed_key = authority |
| `add_reviewer(key)` | authority, payer | `has_one = authority`; Reviewer PDA must not exist |
| `set_reviewer_active(active)` | authority | deactivating may not drop active reviewers below the threshold |
| `set_threshold(k)` | authority | 1 ≤ k ≤ active reviewers |
| `propose_authority(key)` | authority | |
| `accept_authority()` | pending authority | signer equals `pending_authority`, which is non-default |
| `attest(args)` | reviewer, payer | active Reviewer; risk ≤ 4; `target_program` and `program_data` are owned by the upgradeable loader and the Program account names that ProgramData; `elf_len > 0` and SHA-256 of `program_data[45 .. 45 + elf_len]` equals `new_code_hash`; `elf_len` is stored and hashed into the entry; records the ProgramData slot as `deployed_slot`; creates the entry and the submitter's Approval |
| `approve(digest)` | reviewer, payer | active Reviewer; entry belongs to the registry; `digest == SHA-256("tidemark/approval/v1" ‖ entry_hash)`; Approval PDA must not exist |

**Deploy binding.** The attestation can only be written while the reviewed
bytes are the deployed bytes: the program hashes the ELF in ProgramData itself
(about 0.5 CU per byte, so the CLI asks for 1.4 M compute units). A later
upgrade changes the ProgramData slot, so clients can tell "deployed now" from
"what was reviewed", and `tidemark approve` refuses an entry whose
`deployed_slot` is not the current deploy.

**Full-content approvals.** The entry hash commits to every field, including
risk, rules version, program, both code hashes and the deploy slot. Approving
the domain-separated digest of it means a co-signer approves all of them, not
just the verdict hash; `tidemark approve` also re-runs the review and compares
risk and rules version before signing.

**Approvals are filterable.** ApprovalV3 starts with the registry, so clients
fetch only their registry's approvals (`memcmp` at offset 8) instead of every
approval on the program.

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
   `PDA("registry2", authority)` for v2 or `PDA("registry3", seed_key)` for v3.
2. Entries are fetched with `getProgramAccounts` (dataSize + registry memcmp),
   sorted by index, and must be contiguous from 0.
3. Each entry's address equals `PDA("attest2" | "attest3", registry, index)`, its
   `registry` field matches, `prev_hash` links, `entry_hash` recomputes, and
   slots never decrease.
4. The submitter and every approver must be Reviewer accounts of this registry;
   each Approval address equals `PDA("approval", entry, reviewer)`; approvers
   are unique; their count equals `approvals` and includes the submitter.
   For v3 every Approval names this registry and carries the entry's approval
   digest, and every entry has deploy fields.
5. The last entry equals `registry.last_hash` and the count matches.
6. With several `--rpc` values the chain head must agree across all of them.
7. Approvals by reviewers whose `added_slot` is after the entry's slot are
   counted and shown, so a quorum completed by reviewers added later is visible.
8. `verify-ledger` also reads the ledger program's own ProgramData and prints
   its upgrade authority and last deploy slot, warning if the ledger was
   redeployed after its first entry.

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

## 12. AI judge (`judge.rs`, `diff --judge`)

`Backend::ask(system, prompt, schema)` returns the model's text. `Gemini`
(behind `net`) calls `models/{model}:generateContent` with the key in the
`x-goog-api-key` header, temperature 1.0 so the three votes are independent
samples, and a JSON response schema for jury questions. The key is read from
`GEMINI_KEY` at runtime only.

| Step | Calls | Output |
|---|---|---|
| Explain | 1 | at most 120 words, findings named by id |
| Jury | 3 questions × 3 votes | `{answer: yes/no, cites: [...], reason}` each |

A vote is `failed` if it is not JSON or not yes/no, `dropped` if it is yes but
none of its cites is a finding id in the report or `hunk:N` for a hunk that was
sent, and counted otherwise. A question passes with a majority of counted yes
votes (2 of 3). `risk_after = max(risk, High)` if any question passes, else
`risk`; the CLI exits on `max(report risk, risk_after)`.

**Prompt injection.** The system instruction says the report block is
untrusted program data and must not be followed. The data (risk, findings,
first 12 hunks of 40 lines) is serialized to JSON and then encoded again as a
single JSON string, so quotes, newlines and fake `END REPORT` markers inside
handler names, log strings or security.txt stay escaped inside one literal.
Answers are only accepted in the schema, cites are checked against the report,
and the jury can only raise the risk, so a successful injection can at worst
cause a false alarm. The judgement never enters the verdict hash, report hash,
cache entry or attestation.

## 13. Planned interfaces

- `POST /v1/review {old, new}` returns the report and its hash, backed by the cache.
