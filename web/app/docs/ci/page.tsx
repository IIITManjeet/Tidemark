import { C, Code, DocPage, H2, P } from "@/components/docs";

export const metadata = { title: "CI gate · Tidemark docs" };

export default function Page() {
  return (
    <DocPage title="CI gate" lead="Block a risky upgrade in the pipeline that builds it.">
      <H2 id="how">How it works</H2>
      <P>
        <C>tidemark diff</C> exits with code 2 when the risk reaches <C>--fail-on</C> (default <C>high</C>). Use{" "}
        <C>--fail-on medium</C> to also stop on a new instruction handler or indirect call. An unknown level is a usage
        error (exit 1), never a silent pass.
      </P>

      <H2 id="github">GitHub Actions</H2>
      <Code title="yaml">{`- name: Review the upgrade against what is deployed
  run: |
    cargo install --git https://github.com/IIITManjeet/Tidemark tidemark-cli
    tidemark fetch $PROGRAM_ID --rpc $RPC -o deployed.so
    tidemark diff deployed.so target/deploy/my_program.so --json tidemark.json --fail-on high`}</Code>
      <P>
        Keep <C>tidemark.json</C> as a build artifact; its verdict hash is the one reviewers attest on chain. Add{" "}
        <C>--cache .tidemark-cache</C> to skip re-reviewing identical pairs, but never restore that folder from untrusted
        pull requests.
      </P>
    </DocPage>
  );
}
