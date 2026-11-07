import { verifyLedger } from "./dist/tidemark.js";

const SIZES = { attestation: 332, reviewer: 82, approval: 81 };

async function rpc(url, method, params) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`${method}: HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

async function accounts(url, ledger, size, registry) {
  const filters = [{ dataSize: size }];
  if (registry) filters.push({ memcmp: { offset: 8, bytes: registry } });
  const list = await rpc(url, "getProgramAccounts", [
    ledger,
    { encoding: "base64", commitment: "confirmed", filters },
  ]);
  return list.map((a) => ({ address: a.pubkey, data: a.account.data[0] }));
}

export async function fetchLedger(url, ledger, registry) {
  const info = await rpc(url, "getAccountInfo", [
    registry,
    { encoding: "base64", commitment: "confirmed" },
  ]);
  if (!info.value) throw new Error(`registry ${registry} not found`);
  if (info.value.owner !== ledger) {
    throw new Error(`registry ${registry} is not owned by ${ledger}`);
  }
  const [attestations, reviewers, approvals] = await Promise.all([
    accounts(url, ledger, SIZES.attestation, registry),
    accounts(url, ledger, SIZES.reviewer, registry),
    accounts(url, ledger, SIZES.approval),
  ]);
  return JSON.parse(
    verifyLedger(
      JSON.stringify({
        ledger,
        registry: { address: registry, data: info.value.data[0] },
        attestations,
        reviewers,
        approvals,
      }),
    ),
  );
}
