# Testing on real programs

Besides the unit, fixture and Kani tests in CI, the engine was run on 67 well-known mainnet programs
(Jupiter, Orca, Raydium, Meteora, Drift, Kamino, marginfi, Mango, Marinade, Jito, Metaplex, Tensor, Magic
Eden, Pyth, Switchboard, Wormhole, Squads, Phoenix, OpenBook, SPL programs and others) on 8 Nov 2026.

| Check | Result |
|---|---|
| Fetch the deployed ELF from mainnet | 65 / 67 (ATA and Memo are owned by the legacy BPFLoader2, cannot be upgraded, and are refused by design) |
| Parse, decode and inspect | 65 / 65, each under 0.6 s |
| Diff each program against itself (must be INFO with no findings) | 65 / 65 |
| Same program id on devnet with different bytes: devnet → mainnet as a real-world upgrade pair | 28 pairs, 15 identical |
| Same verdict hash on repeated runs | 28 / 28 |
| CLI and WebAssembly engine (web app, npm, VS Code) give the same verdict hash | 108 / 108 |

## What the run found and fixed (`tm-rules-0.7`)

- **Non-deterministic verdicts.** One alignment pass walked a hash map in random order, and the instruction
  diff stopped on a wall-clock deadline, so the same pair could get different hashes on different runs and
  machines. The pass is now ordered, and the exact-or-approximate decision is made from the inputs alone
  (an estimate of diff work and the share of lines that can anchor the diff), so every machine agrees.
- **False guard removals.** 15 programs reported HIGH against themselves: branches whose target is the next
  instruction were read as neutralized checks. A branch that already fell through is no longer a guard.
- **Retarget noise.** Compiler reordering made identical or swapped blocks look like retargeted calls
  (Orca: 1,195). Retargets whose new target runs the same code are dropped, and targets that only trade places
  are reported as `TM-TARGET-SWAP` (Medium).

Devnet and mainnet builds of the same protocol are often far apart in version and embed different fee or
admin keys, so most of those pairs are correctly High. They show that real programs flow through the
pipeline end to end; they are not a false-positive rate.
