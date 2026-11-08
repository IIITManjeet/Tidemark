import Link from "next/link";
import { C, Code, DocPage, H2, P, Steps } from "@/components/docs";
import { RELEASE, REPO } from "@/lib/site";

export const metadata = { title: "Quickstart · Tidemark docs" };

export default function Page() {
  return (
    <DocPage title="Quickstart" lead="Build the CLI, review the demo backdoor, then review a program that is live on devnet.">
      <H2 id="no-install">No install</H2>
      <P>
        Open <Link href="/app" className="text-link">the web app</Link> and press <em>Load demo: backdoored vault</em>. The
        review runs in your browser.
      </P>

      <H2 id="cli">With the command line</H2>
      <Steps
        items={[
          {
            title: "Get the CLI",
            body: (
              <>
                Download it from the{" "}
                <a href={RELEASE} className="text-link">
                  v0.1.0 release
                </a>{" "}
                and put <C>tidemark</C> on your PATH, or build it with Rust:
                <Code>{`cargo install --git ${REPO} tidemark-cli`}</Code>
              </>
            ),
          },
          { title: "Get the demo files", body: <Code>{`git clone ${REPO}.git\ncd Tidemark`}</Code> },
          {
            title: "Review the demo upgrade",
            body: (
              <>
                <Code>{`tidemark diff fixtures/demo_vault_v1.so fixtures/demo_vault_v2.so`}</Code>
                You should see <C>overall risk: HIGH</C>, the attacker key <C>9xQeWv…</C>, the removed <C>has_one</C> and
                signer checks on <C>withdraw</C>, and the new <C>sweep</C> handler.
              </>
            ),
          },
          {
            title: "Review a live program",
            body: (
              <Code>{`tidemark fetch 5pHTptDKd3fS6vnx82rHxSH1xURrYacDr17uJhnc7aX3 -o deployed.so\ntidemark diff fixtures/demo_vault_v1.so deployed.so`}</Code>
            ),
          },
          {
            title: "Gate a pipeline",
            body: (
              <>
                <C>tidemark diff</C> exits with code 2 when risk reaches <C>--fail-on</C> (high by default). See{" "}
                <Link href="/docs/ci" className="text-link">CI gate</Link>.
              </>
            ),
          },
        ]}
      />

      <H2 id="next">Next</H2>
      <P>
        Developers should add the <Link href="/docs/vscode" className="text-link">VS Code extension</Link>; teams that sign
        upgrades should read about the <Link href="/docs/ledger" className="text-link">attestation ledger</Link>.
      </P>
    </DocPage>
  );
}
