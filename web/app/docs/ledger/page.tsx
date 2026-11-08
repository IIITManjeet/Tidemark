import { C, Callout, Code, DocPage, DocTable, H2, P, Ul } from "@/components/docs";
import { LEDGER_V2, LEDGER_V3, REGISTRY_V2 } from "@/lib/site";

export const metadata = { title: "Attestation ledger · Tidemark docs" };

export default function Page() {
  return (
    <DocPage
      title="Attestation ledger"
      lead="An Anchor program where reviewers publish verdicts, bound to the deployed bytes, and co-sign each other's reviews."
    >
      <H2 id="flow">The flow</H2>
      <Ul>
        <li>A registry authority creates a registry, adds reviewers and sets a k-of-n threshold.</li>
        <li>
          A reviewer runs <C>tidemark attest</C>: the CLI fetches the deployed program, reviews it against the pre-upgrade
          snapshot and publishes the verdict hash.
        </li>
        <li>
          Other reviewers run <C>tidemark approve</C>, which re-runs the whole review and co-signs only if they reach the
          same verdict.
        </li>
        <li>An entry is final at k approvals. Anyone can check the chain with <C>verify-ledger</C> or the web app.</li>
      </Ul>

      <H2 id="v3">What v3 guarantees</H2>
      <DocTable
        head={["Property", "How"]}
        rows={[
          [
            "Reviewed bytes are the deployed bytes",
            "attest reads the program's ProgramData on chain, hashes the ELF itself and refuses unless it equals the reviewed hash; it records the deploy slot",
          ],
          [
            "Approvals cover every field",
            "each approval signs SHA-256(\"tidemark/approval/v1\" ‖ entry_hash); the entry hash covers program, hashes, risk, rules, deploy slot and config version",
          ],
          ["The registry survives key rotation", "its address comes from the first authority, stored as seed_key; rotation only changes a field"],
          ["Reviewer changes are visible", "config_version bumps on every reviewer, threshold or authority change and is recorded per entry"],
          ["Entries can't be edited or dropped", "each entry hashes the previous one; clients recompute every link and PDA"],
          ["No double votes", "one Approval account per reviewer per entry"],
        ]}
      />

      <H2 id="verify">Verify a registry</H2>
      <Code>{`tidemark verify-ledger --program ${LEDGER_V2} \\\n  --registry ${REGISTRY_V2} \\\n  --rpc https://api.devnet.solana.com --rpc <SECOND_RPC>`}</Code>
      <P>
        It also prints the ledger program's own upgrade authority and warns if the ledger was redeployed after entries were
        written, and it counts approvals by reviewers added after an entry.
      </P>

      <H2 id="deployments">Deployments</H2>
      <DocTable
        head={["Version", "Program id", "Status"]}
        rows={[
          ["v2", <C key="2">{LEDGER_V2}</C>, "Live on devnet with a co-signed review of the demo upgrade"],
          ["v3", <C key="3">{LEDGER_V3}</C>, "Tested end to end on a local validator; devnet deploy pending"],
        ]}
      />
      <Callout tone="warn" title="Who controls the ledger itself">
        The ledger program is upgradeable by a single key today. The plan is a Squads multisig with a long timelock while it
        beds in, then freezing it; v3 is built for SBPF v3 so it can be frozen after SIMD-0500.
      </Callout>
    </DocPage>
  );
}
