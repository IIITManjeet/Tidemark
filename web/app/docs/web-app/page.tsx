import Link from "next/link";
import { C, Code, DocPage, H2, P, Ul } from "@/components/docs";

export const metadata = { title: "Web app · Tidemark docs" };

export default function Page() {
  return (
    <DocPage title="Web app" lead="Review two builds or verify a ledger in the browser. It is a static site with no server.">
      <H2 id="review">Review</H2>
      <P>
        On <Link href="/app" className="text-link">Try it</Link>, drop the current and the new <C>.so</C>, or load the demo
        vault. You get the overall risk, each finding with its evidence, the code hunks and the verdict hash.
      </P>

      <H2 id="ledger">Ledger</H2>
      <P>Enter an RPC, the ledger program and a registry. The page then:</P>
      <Ul>
        <li>reads every account at finalized commitment,</li>
        <li>checks links, addresses, reviewers and quorum with the same code as the CLI,</li>
        <li>with a second RPC, shows VERIFIED only if both agree on the head and every entry.</li>
      </Ul>

      <H2 id="host">Host your own</H2>
      <Code>{`bash scripts/build-web.sh          # writes web/out/\npython -m http.server -d web/out\nBASE_PATH=/Tidemark bash scripts/build-web.sh   # for a sub-path such as GitHub Pages`}</Code>
      <P>
        Built with Next.js, TypeScript and Tailwind. Colours, radii and breakpoints are theme tokens in{" "}
        <C>web/app/globals.css</C>.
      </P>
    </DocPage>
  );
}
