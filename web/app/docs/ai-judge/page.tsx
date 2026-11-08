import { C, Callout, Code, DocPage, DocTable, H2, P, Ul } from "@/components/docs";

export const metadata = { title: "AI judge · Tidemark docs" };

export default function Page() {
  return (
    <DocPage
      title="AI judge"
      lead="An optional, advisory layer: a plain-English explanation and a cited yes/no jury on top of the deterministic report."
    >
      <Code>{`export GEMINI_KEY=...            # read from the environment only\ntidemark diff old.so new.so --judge`}</Code>

      <H2 id="what">What it adds</H2>
      <Ul>
        <li>
          <strong className="text-text">Explainer</strong>: up to 120 words a multisig signer can act on, naming findings
          by id.
        </li>
        <li>
          <strong className="text-text">Jury</strong>: three fixed questions, each answered three times in one call per
          vote, with the vote count shown.
        </li>
      </Ul>
      <DocTable
        head={["Question", "Raises risk when"]}
        rows={[
          ["Can a single key move funds out of the program's accounts?", "2 of 3 cited yes"],
          ["Was an authority, signer or ownership check removed or weakened?", "2 of 3 cited yes"],
          ["Is there a new path that withdraws funds or closes accounts?", "2 of 3 cited yes"],
        ]}
      />

      <H2 id="guardrails">Guardrails</H2>
      <Ul>
        <li>The jury can raise the risk to High but never lower it.</li>
        <li>Every yes must cite a finding id or hunk that is really in the report; others are dropped and counted.</li>
        <li>Nothing it says enters the verdict hash, report hash, cache or ledger. It is written to a separate file.</li>
        <li>
          Program strings reach the model only inside one quoted JSON string marked as untrusted data, and answers must
          match a schema.
        </li>
      </Ul>
      <Callout title="Off by default">
        Without <C>GEMINI_KEY</C> the CLI says the judge was skipped and carries on. <C>GEMINI_MODEL</C> picks the model;
        rate-limited calls are retried with backoff.
      </Callout>
      <H2 id="web">In the web app</H2>
      <P>
        After a review in <C>/app</C>, the AI judge panel takes a Gemini key and model. The browser sends the same
        prompts straight to Google and hands the answers back to the WebAssembly engine, which counts the votes with the
        same code as the CLI. The key is held in the page only and never stored or sent anywhere else.
      </P>
      <P>The judge sits behind a small backend interface, so another yes/no model can be added as one file.</P>
    </DocPage>
  );
}
