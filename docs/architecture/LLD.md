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
│   └── tidemark-cli/          `tidemark` binary
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

### 2.3 Rules (`diff.rs`, `tm-rules-0.3`)

| Rule | Trigger | Severity |
|---|---|---|
| TM-KEY-ADD | new unknown 32-byte keys (see below) | High |
| TM-PROG-REF | new keys matching well-known program ids | Low |
| TM-CHECK-GONE | fewer immediates for Anchor check error codes (2001 has_one, 2002 signer, 2003 raw, 2004 owner, 2006 seeds, 2012 address, 3007 wrong owner program, 3010 not signer) | High |
| TM-IX-CHANGE | handler set changed; names taken from `Instruction: X` log text and kept only if `sha256("global:x")[..8]` appears as an `lddw` immediate | Medium if added, else Low |
| TM-SYSCALL-ADD | call-site count of a syscall rose | High for `invoke_signed*`, Low for other sensitive syscalls, else Info |
| TM-SYSCALL-DEL | call-site count fell | Info |
| TM-CALLX-ADD | more `callx` sites | Medium |
| TM-BRANCH-RETARGET | an aligned branch whose target no longer maps to the old target (see below) | High |
| TM-CALL-RETARGET | same, for internal calls | High |
| TM-CONST-CHANGE | constants present in old and missing in new, excluding handler discriminators | Medium |
| TM-SECTXT | security.txt added, removed or changed | Medium if removed, else Low |
| TM-CHURN | 25%+ of instructions changed, programs of 200+ instructions | Medium |

**Key recovery.** Compiled Rust rarely keeps a `Pubkey` constant as 32
contiguous bytes. It loads it as four 64-bit `lddw` immediates and stores
each with `stxdw` to `[base + o]`, `[base + o+8]`, `[base + o+16]`,
`[base + o+24]`. The loader records, for every `lddw`, the first `stxdw` of
that register within the next 8 instructions. A key is reported when four new,
high-entropy immediates (6+ distinct bytes, upper half above 0x10, not a
handler discriminator) land in consecutive slots of one base register within
64 instructions. 32-byte windows in `.rodata` are still checked as well.

**Retargets.** Normalization hides targets, so a branch moved by one
instruction diffs as unchanged. The rule maps old lines to new lines through
the `Equal` runs of the line diff, then checks every aligned branch and call:
the old target, mapped forward, must be the new target. The line diff can pair
look-alike blocks wrongly (Anchor handler stubs differ only in stack offsets),
so the map is refined first. Aligned branches vote on where each old target
went; when every vote agrees and the two blocks have the same opcode sequence
up to the next `ja`/`exit` (at least two instructions), that block is remapped.
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
  sweep address, TM-CHECK-GONE for `ConstraintHasOne` 5 → 4, TM-IX-CHANGE `+ sweep`.

## 6. Toolchain notes

The Anchor workspace pins `rust-version = 1.79` and a lockfile resolved for it
(`blake3 1.5.5`, `zerocopy 0.8.25`) so `cargo build-sbf` from Solana CLI 2.1
compiles it.

## 7. Planned interfaces

- `tidemark-wasm`: `diff(old: Uint8Array, new: Uint8Array) -> ReportJson`, used
  by the npm package and VS Code extension. RPC fetch stays on the host side.
- `POST /v1/review {old, new}` returns the report and its hash, backed by the cache.
