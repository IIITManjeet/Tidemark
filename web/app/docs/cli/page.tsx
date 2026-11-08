import { C, Callout, Code, DocPage, DocTable, H2, P } from "@/components/docs";
import { RELEASE } from "@/lib/site";

export const metadata = { title: "Command line · Tidemark docs" };

export default function Page() {
  return (
    <DocPage title="Command line" lead="The tidemark binary reviews upgrades, watches programs and reads and writes the attestation ledger.">
      <P>
        Download a prebuilt binary for Linux, macOS or Windows from the{" "}
        <a href={RELEASE} className="text-link">
          v0.1.0 release
        </a>
        , or build it with Cargo:
      </P>
      <Code>{`cargo install --git https://github.com/IIITManjeet/Tidemark tidemark-cli\ntidemark --help`}</Code>

      <H2 id="review">Review two builds</H2>
      <Code>{`tidemark diff old.so new.so --json report.json --hunks 4 --fail-on high`}</Code>
      <DocTable
        head={["Flag", "Meaning"]}
        rows={[
          [<C key="1">--json PATH</C>, "Write the full report; its hash is printed as the report hash"],
          [<C key="2">--hunks N</C>, "How many code hunks to print"],
          [<C key="3">--fail-on LEVEL</C>, "Exit 2 at or above info, low, medium, high or critical"],
          [<C key="4">--cache DIR</C>, "Reuse earlier reviews keyed by both hashes and the rules version"],
          [<C key="5">--judge</C>, "Add the advisory AI judge (needs GEMINI_KEY)"],
        ]}
      />

      <H2 id="inspect">Inspect and fetch</H2>
      <Code>{`tidemark inspect program.so\ntidemark fetch <PROGRAM_ID> --rpc https://api.devnet.solana.com -o program.so`}</Code>
      <P>
        <C>fetch</C> reads ProgramData, strips the 45-byte header and trailing padding, and prints the upgrade authority and
        last deploy slot.
      </P>

      <H2 id="watch">Watch a program</H2>
      <Code>{`tidemark watch <PROGRAM_ID> --dir snapshots`}</Code>
      <P>
        Keeps every deployed version as <C>snapshots/&lt;program&gt;/&lt;slot&gt;.so</C> and reviews each upgrade against
        the previous snapshot. Add <C>--attest &lt;LEDGER&gt;</C> to publish each review.
      </P>

      <H2 id="census">Who can upgrade it?</H2>
      <Code>{`tidemark census --rpc https://api.mainnet-beta.solana.com <PROGRAM_ID>...`}</Code>
      <P>Classifies each program as immutable, single key, multisig or governance, or program-controlled.</P>
      <P>
        A Squads v4 vault is a plain system account, so name its multisig with <C>--squads MULTISIG</C> (repeatable).
        Census derives that multisig&apos;s vaults and reports <C>multisig (Squads v4)</C> when one of them holds the
        upgrade authority.
      </P>
      <Code>{`tidemark census 8f43wqFP4wZ8NLrJgBrGXDrXp92FgxSvM9Ng21GrgPq6 \\\n  --squads 8jGmTqcvXfp8taPTq6u5Tmorbu7pByKGDmy4eYU2xki9`}</Code>

      <H2 id="ledger">Ledger commands</H2>
      <DocTable
        head={["Command", "Purpose"]}
        rows={[
          [<C key="1">init-registry --threshold K</C>, "Create a registry you control"],
          [<C key="2">add-reviewer KEY</C>, "Allow a key to attest and approve"],
          [<C key="3">set-reviewer KEY --active BOOL</C>, "Enable or disable a reviewer"],
          [<C key="4">set-threshold K</C>, "Approvals needed before an entry is final"],
          [<C key="5">propose-authority / accept-authority</C>, "Hand a registry to a new key in two steps"],
          [<C key="6">attest --program ID --old SNAPSHOT</C>, "Review the deployed upgrade and publish the verdict"],
          [<C key="7">approve --registry R --index N --old SNAPSHOT</C>, "Re-run the review and co-sign only if it matches"],
          [<C key="8">verify-ledger --registry R --rpc URL...</C>, "Check the whole chain, reviewers and approvals"],
        ]}
      />
      <P>
        Every chain command takes <C>--ledger</C>, <C>--rpc</C>, <C>--keypair</C> and an optional <C>--payer</C> that
        covers fees, so reviewer keys never need SOL.
      </P>

      <H2 id="exit">Exit codes</H2>
      <DocTable
        head={["Code", "Meaning"]}
        rows={[
          ["0", "Review finished below the --fail-on level"],
          ["1", "Bad input or usage, for example an unknown level or a non-SBPF file"],
          ["2", "Risk at or above --fail-on"],
          ["3", "verify-ledger found a broken chain or RPCs that disagree"],
        ]}
      />
      <Callout title="Untrusted input">
        Program binaries are attacker-controlled. Inputs over 16 MiB are rejected and every analysis step is bounded, so a
        hostile file can slow a review down but not hang it.
      </Callout>
    </DocPage>
  );
}
