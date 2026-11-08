import Link from "next/link";
import { C, Callout, DocPage, H2, P, Ul } from "@/components/docs";

export const metadata = { title: "Docs · Tidemark" };

const CARDS = [
  ["Quickstart", "/docs/quickstart", "Review the demo backdoor in two minutes."],
  ["Command line", "/docs/cli", "diff, fetch, watch, census and the ledger commands."],
  ["VS Code extension", "/docs/vscode", "Compare your build with what is deployed before you ship."],
  ["npm package", "/docs/npm", "The engine as WebAssembly for wallets and dashboards."],
  ["Risk rules", "/docs/rules", "Every finding, what it means and how severe it is."],
  ["Attestation ledger", "/docs/ledger", "How reviews are bound to deployed bytes and co-signed."],
];

export default function Page() {
  return (
    <DocPage
      title="Tidemark documentation"
      lead="Tidemark reviews Solana program upgrades from bytecode: what changed, how risky it is, and a public record of who checked it."
    >
      <div className="grid gap-3 sm:grid-cols-2">
        {CARDS.map(([t, href, body]) => (
          <Link key={href} href={href} className="card p-5 hover:border-line-2">
            <div className="font-medium">{t}</div>
            <div className="mt-1 text-sm text-muted">{body}</div>
          </Link>
        ))}
      </div>

      <H2 id="why">Why it exists</H2>
      <P>
        Most Solana programs are upgradeable. Whoever holds the upgrade authority can replace the code users trust, and
        the people approving that upgrade usually see only a hash. Verified builds prove which source built a binary;
        they do not say what changed between two versions.
      </P>
      <P>Tidemark compares the deployed program with the new build and answers the questions that matter before you sign:</P>
      <Ul>
        <li>Did a new hardcoded key appear that could receive funds?</li>
        <li>Was an account check removed, or patched so it can never fail?</li>
        <li>Is there a new instruction handler, cross-program call or indirect call?</li>
        <li>Is the reviewed build exactly what is deployed now?</li>
      </Ul>

      <H2 id="pieces">The pieces</H2>
      <Ul>
        <li>
          <strong className="text-text">Engine</strong> (<C>tidemark-core</C>): decodes SBPF v0 to v3, diffs, runs the{" "}
          <C>tm-rules</C> and hashes the verdict.
        </li>
        <li>
          <strong className="text-text">Clients</strong>: the <C>tidemark</C> CLI, a VS Code extension, an npm package and
          this web app. All produce the same report and verdict hash.
        </li>
        <li>
          <strong className="text-text">Ledger</strong>: an Anchor program where reviewers publish verdicts, bound to the
          deployed bytes, and co-sign each other's reviews.
        </li>
      </Ul>

      <Callout title="Heuristic review, not proof of safety">
        The rules catch real backdoor patterns, but a determined attacker can shape code to avoid them. Treat a clean
        report as "nothing obvious changed". The <Link href="/docs/security" className="text-link">security model</Link>{" "}
        lists the known limits.
      </Callout>
    </DocPage>
  );
}
