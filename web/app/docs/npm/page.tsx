import { C, Callout, Code, DocPage, DocTable, H2, P } from "@/components/docs";

export const metadata = { title: "npm package · Tidemark docs" };

export default function Page() {
  return (
    <DocPage
      title="npm package"
      lead="tidemark-wasm is the review engine compiled to WebAssembly, for wallets, explorers and dashboards. Nothing is uploaded anywhere."
    >
      <H2 id="install">Install</H2>
      <Callout title="Not on the npm registry yet">Build it from the repository and install the folder.</Callout>
      <Code>{`bash scripts/build-wasm.sh\nnpm install ./path/to/Tidemark/npm`}</Code>

      <H2 id="review">Review an upgrade</H2>
      <Code title="js">{`import init, { review } from "tidemark-wasm";

await init();
const { report, verdict_hash } = JSON.parse(review(oldBytes, newBytes));
console.log(report.risk, report.findings.map((f) => f.id));`}</Code>
      <P>
        The report and verdict hash are byte-for-byte what <C>tidemark diff --json</C> produces, so a browser review can be
        checked against an on-chain attestation.
      </P>

      <H2 id="ledger">Verify the ledger</H2>
      <Code title="js">{`import { fetchLedger } from "tidemark-wasm/ledger.js";

const v = await fetchLedger(rpcUrl, ledgerProgramId, registryAddress);
if (!v.ok) throw new Error(v.error);
for (const e of v.entries) console.log(e.index, e.risk, e.final, e.deployed_slot);`}</Code>
      <P>
        <C>fetchLedger</C> reads the raw accounts at finalized commitment and checks the hash chain, every PDA, the
        reviewer allowlist, approvals and quorum itself. It reads both ledger layouts.
      </P>

      <H2 id="api">API</H2>
      <DocTable
        head={["Function", "Returns (JSON string)"]}
        rows={[
          [<C key="1">review(old, new)</C>, "{ report, report_hash, verdict_hash, verdict_risk }"],
          [<C key="2">inspect(bytes)</C>, "sha256, size, SBPF version, syscalls, instruction handlers"],
          [<C key="3">verifyLedger(input)</C>, "chain status for raw ledger accounts"],
          [<C key="4">rulesVersion()</C>, "the rules version, e.g. tm-rules-0.6"],
        ]}
      />
      <P>
        In Node, load the module with <C>initSync(&#123; module: readFileSync(&quot;.../tidemark_bg.wasm&quot;) &#125;)</C>.
      </P>
    </DocPage>
  );
}
