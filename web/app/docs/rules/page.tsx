import { C, Callout, DocPage, DocTable, H2, P } from "@/components/docs";

export const metadata = { title: "Risk rules · Tidemark docs" };

const SEV: Record<string, string> = {
  High: "text-orange",
  Medium: "text-amber",
  Low: "text-link",
  Info: "text-faint",
};

const RULES: [string, string, string][] = [
  ["TM-KEY-ADD", "High", "A new 32-byte key: found in read-only data, or rebuilt from four 64-bit loads stored or compared side by side"],
  ["TM-KEY-SPLIT", "High", "Four or more new high-entropy constants close together: a key loaded in pieces"],
  ["TM-CHECK-GONE", "High", "A handler reaches fewer Anchor account-check sites (has_one, signer, owner, seeds, address)"],
  ["TM-GUARD-GONE", "High", "A branch into an error path became a plain jump, falls straight through, or was deleted, so the check can't fail"],
  ["TM-BRANCH-RETARGET", "High", "A branch that looks unchanged now jumps somewhere else"],
  ["TM-CALL-RETARGET", "High", "A call that looks unchanged now calls a different function"],
  ["TM-SYSCALL-ADD", "High / Low / Info", "New invoke_signed call sites are High; other sensitive syscalls Low"],
  ["TM-IX-CHANGE", "Medium / Low", "Instruction handlers added (Medium) or removed (Low), named from the Anchor dispatch table"],
  ["TM-ERR-GONE", "Medium", "A handler lost custom error checks (require!, codes 6000+)"],
  ["TM-CALLX-ADD", "Medium", "New indirect calls whose target is computed at run time"],
  ["TM-CONST-CHANGE", "Medium", "64-bit constants that are no longer used"],
  ["TM-SECTXT", "Medium / Low", "security.txt removed (Medium) or changed (Low)"],
  ["TM-CHURN", "Medium", "Over a quarter of the program changed; small changes can hide in big diffs"],
  ["TM-PARTIAL", "Medium", "A time or size limit cut the analysis short, so findings may be missing"],
  ["TM-VERSION-CHANGE", "Medium", "The SBPF version changed; layout-sensitive rules are capped at Medium"],
  ["TM-PROG-REF", "Low", "New references to well-known programs such as Token or System"],
  ["TM-CONST-ADD", "Low", "New 64-bit constants"],
];

export default function Page() {
  return (
    <DocPage
      title="Risk rules"
      lead="Deterministic, versioned rules turn a bytecode diff into ranked findings. The current set is tm-rules-0.6."
    >
      <H2 id="table">Every rule</H2>
      <DocTable
        head={["Rule", "Severity", "Fires when"]}
        rows={RULES.map(([id, sev, body]) => [
          <C key="id">{id}</C>,
          <span key="sev" className={`whitespace-nowrap ${SEV[sev.split(" ")[0]] ?? ""}`}>
            {sev}
          </span>,
          body,
        ])}
      />
      <P>
        The overall risk is the highest finding. TM-CHURN is left out of the verdict hash because it depends on diff
        timing; everything else is in it.
      </P>

      <H2 id="versions">Every SBPF version</H2>
      <P>
        v0 to v3 are decoded into one form: v2's moved memory opcodes and <C>mov</C> + <C>hor64</C> constants, v3's 32-bit
        jumps, static syscalls and strict program headers. The demo backdoor is High in all 16 old→new version pairs.
        Once SIMD-0500 activates, every deploy and upgrade must be v3.
      </P>

      <H2 id="verdict">The verdict hash</H2>
      <P>
        SHA-256 of the canonical JSON of the rules version, both code hashes, the risk and the findings. Honest reviewers
        on different machines get the same hash, which is what the ledger records and what co-signers compare.
      </P>
      <Callout tone="warn" title="Rules are heuristics">
        They are tuned on Anchor programs. Keys computed at run time, logic moved into an existing handler, or a reused
        CPI site can evade them. A clean report means nothing obvious changed.
      </Callout>
    </DocPage>
  );
}
