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

| Field | Source |
|---|---|
| `sha256`, `size` | whole file |
| `lines`, `norm`, `insn_count` | `.text`, decoded |
| `syscalls` | `call` sites resolved by `R_BPF_64_32` relocations against undefined dynamic symbols (SBPFv1), or by `imm == murmur3_32(name)` |
| `callx` | count of opcode `0x8d` |
| `strings` | printable runs of 8+ bytes in `.rodata` and `.data.rel.ro` |
| `consts32` | 8-aligned 32-byte windows with 24+ distinct bytes and fewer than 28 printable bytes (candidate pubkeys) |
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

### 2.3 Rules (`diff.rs`)

| Rule | Trigger | Severity |
|---|---|---|
| TM-SYSCALL-ADD | call-site count of a syscall rose | High for `invoke_signed*`, Low for other sensitive syscalls, else Info |
| TM-SYSCALL-DEL | call-site count fell | Info |
| TM-CALLX-ADD | more `callx` sites | Medium |
| TM-KEY-ADD | new unknown 32-byte constants | High |
| TM-PROG-REF | new constants matching well-known program ids | Low |
| TM-IX-CHANGE | Anchor `Instruction: X` log strings added or removed | Medium if added, else Low |
| TM-CHECK-GONE | removed strings mentioning signer, owner, has_one, constraint, authority | High |
| TM-SECTXT | security.txt added, removed or changed | Medium if removed, else Low |
| TM-CHURN | 25%+ of instructions changed | Medium |

Overall risk is the highest finding severity. Code hunks come from a line diff
of normalized disassembly with three lines of context, shown in readable form.

### 2.4 Report hash

`report_hash = sha256(serde_json::to_vec(report))`. Field order is fixed by
the struct definitions, so the hash is reproducible for a given version.

### 2.5 RPC fetch (`rpc.rs`)

1. `getAccountInfo(program_id)`; owner must be the BPF Upgradeable Loader.
2. Bytes `4..36` give the ProgramData address.
3. `getAccountInfo(programdata)`. Header is 45 bytes: tag `u32`, slot `u64`,
   `Option<Pubkey>`. The ELF follows; trailing zero padding is trimmed.

## 3. tidemark-cli

| Command | Behaviour | Exit code |
|---|---|---|
| `diff OLD NEW [--json PATH] [--hunks N]` | summary, findings, hunks, report hash | 2 if risk is High or Critical |
| `inspect FILE` | hash, size, syscalls, callx, constants, security.txt | 0 |
| `fetch PROGRAM_ID --rpc URL -o FILE` | writes ELF, prints authority and last deploy slot | 0 |

## 4. tidemark-ledger

### 4.1 Accounts

| Account | Seeds | Fields |
|---|---|---|
| Registry | `["registry", authority]` | authority, name, count, last_hash, bump |
| Attestation | `["attest", registry, count_le]` | registry, index, program, old_code_hash, new_code_hash, report_hash, risk, rules_version, model_id, reviewer, slot, prev_hash, entry_hash, bump |

### 4.2 Instructions

- `init_registry(name)`: creates the signer's registry.
- `attest(args)`: permissionless; the reviewer signs and pays. Checks
  `risk <= 4`, fills the attestation, links `prev_hash`, computes
  `entry_hash`, advances the registry and emits `Attested`.

### 4.3 Hash chain

```
entry_hash = sha256( index_le ‖ program ‖ old_code_hash ‖ new_code_hash ‖
                     report_hash ‖ risk ‖ rules_version ‖ model_id ‖
                     reviewer ‖ prev_hash )
```

The first entry uses 32 zero bytes as `prev_hash`.

## 5. Demo fixture

- v1: `withdraw` requires `has_one = authority` and a signer.
- v2 (`--features v2`): `withdraw` accepts an unchecked authority, and a new
  `sweep` instruction moves the treasury to a hardcoded key via `invoke_signed`.
- Expected findings: TM-SYSCALL-ADD, TM-KEY-ADD, TM-IX-CHANGE.

## 6. Toolchain notes

The Anchor workspace pins `rust-version = 1.79` and a lockfile resolved for it
(`blake3 1.5.5`, `zerocopy 0.8.25`) so `cargo build-sbf` from Solana CLI 2.1
compiles it.

## 7. Planned interfaces

- `tidemark-wasm`: `diff(old: Uint8Array, new: Uint8Array) -> ReportJson`, used
  by the npm package and VS Code extension. RPC fetch stays on the host side.
- `POST /v1/review {old, new}` returns the report and its hash, backed by the cache.
