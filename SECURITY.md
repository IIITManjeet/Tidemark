# Security policy

## Reporting a vulnerability

Please report privately through the repository's **Security** tab →
**Report a vulnerability**. Don't open a public issue for anything that could be
exploited.

Include the version or commit, what you ran, and a sample `.so` or transaction
if you have one.

## In scope

- `tidemark-core`: parsing and diffing untrusted program binaries (crashes,
  hangs, unbounded memory, a different verdict for the same inputs)
- The `tidemark-ledger` Anchor program: anything that lets a non-reviewer
  attest or approve, a double approval, or an entry that verifies but doesn't
  match what was deployed
- `verify-ledger` and the web ledger view accepting a chain they should reject
- The web app sending a reviewed file or an API key anywhere other than the
  user's chosen RPC or Google

## Not a vulnerability

- An upgrade that the rules don't flag. The rules are heuristics over compiled
  code; open a normal issue with the two binaries so a rule can be added.
- The devnet deployments: they are demonstrations, all reviewer and multisig
  keys are held by one maintainer, and the code has not been audited.
