# Releasing

Each channel is published by CI from this repository. Accounts and tokens belong to the maintainer and live
only in GitHub Actions secrets or the hosting dashboards, never in the repo.

| Channel | What ships | Trigger | Secrets |
|---|---|---|---|
| GitHub Releases | `tidemark` CLI for Linux, macOS (arm64), Windows; the `.vsix` | tag `v*` | none |
| npm | `tidemark-wasm` (engine + ledger reader) | tag `v*` | `NPM_TOKEN` |
| VS Code Marketplace | `tidemark.tidemark-vscode` | tag `v*` | `VSCE_PAT` |
| Open VSX (Cursor, VSCodium) | same `.vsix` | tag `v*` | `OVSX_PAT` |
| Vercel | the static site in `web/out` | push to `main` | `VERCEL_TOKEN`, `VERCEL_ORG_ID`, `VERCEL_PROJECT_ID` |
| Railway | the upgrade watcher (`Dockerfile`) | push to `main` | set in Railway |

A publish step is skipped when its secret is missing, so forks and first runs stay green.

## One-time setup

**npm.** Create an npm account with 2FA, then an automation token: `npm token create --type automation`
(or a granular token scoped to `tidemark-wasm`). Add it as `NPM_TOKEN`. Releases carry npm provenance,
linking each tarball to the workflow run that built it.

**VS Code Marketplace.** Create the publisher `tidemark` at
<https://marketplace.visualstudio.com/manage> (or change `publisher` in `vscode/package.json` to one you
own). Create an Azure DevOps personal access token with the *Marketplace: Manage* scope, organization *All
accessible organizations*, and add it as `VSCE_PAT`.

**Open VSX.** Sign in at <https://open-vsx.org> with GitHub, sign the publisher agreement, create the same
namespace (`npx ovsx create-namespace tidemark -p <token>`), and add the token as `OVSX_PAT`.

**Vercel.** Create a project (framework *Other*; Vercel does not build it, CI does). Run `npx vercel link` once
locally to get the org and project ids from `.vercel/project.json`, create a token under Account Settings →
Tokens, and add all three as secrets. CI builds the WebAssembly engine and the site, then uploads the
prebuilt output.

**Railway.** New project → Deploy from GitHub repo. Railway reads `railway.json` and builds the `Dockerfile`.
Add a volume mounted at `/data` so snapshots survive restarts, and set:

| Variable | Required | Meaning |
|---|---|---|
| `WATCH_PROGRAMS` | yes | program ids, separated by spaces or commas |
| `TIDEMARK_RPC` | no | RPC endpoint (default devnet) |
| `WATCH_INTERVAL` | no | seconds between checks (default 30) |
| `TIDEMARK_LEDGER` | no | attest every review to this ledger program |
| `TIDEMARK_KEYPAIR` | with ledger | the attesting key as a JSON byte array; use a dedicated, low-balance key |
| `TIDEMARK_REGISTRY` | no | registry to attest into |

The service has no public port. Its log shows every upgrade it reviews.

## Cutting a release

1. Bump the version in `Cargo.toml` (`[workspace.package]`), `npm/package.json` and `vscode/package.json`;
   the release workflow refuses a tag that does not match all three.
2. Merge to `main`, then tag: `git tag v0.2.0 && git push origin v0.2.0`.
3. Check the run: binaries and the `.vsix` land on the GitHub release, then npm and both extension stores
   update.
