import { C, DocPage, DocTable, H2, P, Ul } from "@/components/docs";
import { ISSUES } from "@/lib/site";

export const metadata = { title: "Security model and limits · Tidemark docs" };

export default function Page() {
  return (
    <DocPage
      title="Security model and limits"
      lead="What Tidemark protects against, what it assumes, and where it can be fooled."
    >
      <H2 id="trust">What you trust</H2>
      <DocTable
        head={["Component", "Assumption", "Mitigation"]}
        rows={[
          ["RPC", "Serves the real chain", "finalized reads, a second --rpc cross-check, and the ledger itself hashing deployed bytes"],
          ["Rules", "Catch the change you care about", "versioned, deterministic, tested against patched backdoors; heuristics, not proofs"],
          ["Reviewers", "Act independently", "each co-signer re-runs the review; quorum is only as independent as the people"],
          ["Registry authority", "Adds honest reviewers", "reviewer changes bump config_version and late approvals are shown"],
          ["Ledger program", "Its code is what was reviewed", "clients print its upgrade authority and warn on redeploys; multisig then freeze"],
          ["AI judge", "Nothing", "advisory only, can only raise risk, never part of a hash"],
        ]}
      />

      <H2 id="hostile">Hostile binaries</H2>
      <P>
        Programs under review are attacker-controlled. Inputs over 16 MiB are refused, the diff has a deadline, scans have
        caps, and when a limit is hit the report says so with <C>TM-PARTIAL</C> instead of passing quietly. The ELF and
        ledger parsers are model-checked with Kani.
      </P>

      <H2 id="limits">Known limits</H2>
      <Ul>
        <li>Keys computed at run time or read from an account are not constants and are not found.</li>
        <li>Malicious logic added inside an existing handler, or a reused CPI call site, may only show in the hunks.</li>
        <li>Merged error returns after a compiler change can raise a false TM-CHECK-GONE.</li>
        <li>A same-source rebuild from SBPF v2 to v3 can raise a false TM-CHECK-GONE.</li>
        <li>Non-Anchor programs get the bytecode rules but no per-handler check counts.</li>
        <li>On-chain ELF hashing costs about 0.5 compute units per byte, so programs over about 2.7 MB cannot be attested.</li>
      </Ul>
      <P>
        Found something else?{" "}
        <a href={ISSUES} className="text-link">
          Open an issue
        </a>
        .
      </P>
    </DocPage>
  );
}
