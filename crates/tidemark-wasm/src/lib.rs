use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use tidemark_core::{bs58_encode, diff, elf, handlers, ledger, submit};
use wasm_bindgen::prelude::*;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

#[wasm_bindgen(js_name = rulesVersion)]
pub fn rules_version() -> String {
    diff::RULES_VERSION.to_string()
}

pub fn review_json(old: &[u8], new: &[u8]) -> anyhow::Result<Value> {
    let (a, b) = (elf::load(old)?, elf::load(new)?);
    let report = diff::compare(&a, &b);
    Ok(json!({
        "report_hash": tidemark_core::report_hash(&report),
        "verdict_hash": tidemark_core::verdict_hash(&report),
        "verdict_risk": tidemark_core::verdict_risk(&report),
        "report": report,
    }))
}

#[wasm_bindgen]
pub fn review(old: &[u8], new: &[u8]) -> Result<String, JsError> {
    review_json(old, new).map(|v| v.to_string()).map_err(err)
}

pub fn inspect_json(bytes: &[u8]) -> anyhow::Result<Value> {
    let p = elf::load(bytes)?;
    let hs: Vec<Value> = handlers::handlers(&p)
        .iter()
        .filter(|(_, h)| h.dispatched || h.name.is_some())
        .map(|(d, h)| json!({"name": h.label(*d), "discriminator": format!("{d:#018x}")}))
        .collect();
    Ok(json!({
        "sha256": p.sha256,
        "size": p.size,
        "instructions": p.insn_count,
        "sbpf_version": p.sbpf_version,
        "syscalls": p.syscalls,
        "callx": p.callx,
        "handlers": hs,
        "security_txt": p.security_txt,
    }))
}

#[wasm_bindgen]
pub fn inspect(bytes: &[u8]) -> Result<String, JsError> {
    inspect_json(bytes).map(|v| v.to_string()).map_err(err)
}

#[derive(Deserialize)]
struct Account {
    address: String,
    data: String,
}

#[derive(Deserialize)]
struct LedgerInput {
    ledger: String,
    registry: Account,
    attestations: Vec<Account>,
    reviewers: Vec<Account>,
    approvals: Vec<Account>,
}

fn raw(a: &Account) -> anyhow::Result<ledger::RawAccount> {
    Ok((
        submit::decode_pubkey(&a.address)?,
        base64::engine::general_purpose::STANDARD.decode(&a.data)?,
    ))
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .trim_end_matches('\0')
        .to_string()
}

pub fn verify_json(input: &str) -> anyhow::Result<Value> {
    let i: LedgerInput = serde_json::from_str(input)?;
    let program = submit::decode_pubkey(&i.ledger)?;
    let (reg_key, reg_data) = raw(&i.registry)?;
    let registry = ledger::parse_registry(reg_key, &reg_data)?;
    let all = |v: &[Account]| v.iter().map(raw).collect::<anyhow::Result<Vec<_>>>();
    let snap = ledger::snapshot_from(
        registry,
        &all(&i.attestations)?,
        &all(&i.reviewers)?,
        &all(&i.approvals)?,
    )?;
    let verdict = ledger::verify(&program, &snap);
    let mut entries = snap.attestations.clone();
    entries.sort_by_key(|a| a.index);
    let entries: Vec<Value> = entries
        .iter()
        .map(|a| {
            json!({
                "index": a.index,
                "address": bs58_encode(&a.address),
                "program": bs58_encode(&a.program),
                "old_code_hash": hex(&a.old_code_hash),
                "new_code_hash": hex(&a.new_code_hash),
                "verdict_hash": hex(&a.report_hash),
                "risk": a.risk,
                "rules_version": text(&a.rules_version),
                "reviewer": bs58_encode(&a.reviewer),
                "slot": a.slot,
                "approvals": a.approvals,
                "threshold": a.threshold,
                "final": a.approvals >= a.threshold,
                "entry_hash": hex(&a.entry_hash),
            })
        })
        .collect();
    let r = &snap.registry;
    Ok(json!({
        "ok": verdict.is_ok(),
        "error": verdict.err().map(|e| format!("{e:?}")),
        "registry": {
            "address": bs58_encode(&r.address),
            "authority": bs58_encode(&r.authority),
            "count": r.count,
            "threshold": r.threshold,
            "active_reviewers": r.active_reviewers,
            "head": hex(&r.last_hash),
        },
        "reviewers": snap.reviewers.keys().map(|k| bs58_encode(k)).collect::<Vec<_>>(),
        "entries": entries,
    }))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[wasm_bindgen(js_name = verifyLedger)]
pub fn verify_ledger(input: &str) -> Result<String, JsError> {
    verify_json(input).map(|v| v.to_string()).map_err(err)
}

pub fn deployed_parts(programdata: &[u8]) -> anyhow::Result<(u64, Option<String>, Vec<u8>)> {
    let pd = tidemark_core::rpc::parse_programdata(programdata)?;
    if pd.elf.iter().all(|b| *b == 0) {
        anyhow::bail!("the program has been closed");
    }
    let elf = pd.elf[..tidemark_core::rpc::elf_len(pd.elf)?].to_vec();
    Ok((pd.slot, pd.authority.map(|a| bs58_encode(&a)), elf))
}

#[wasm_bindgen(js_name = programDataAddress)]
pub fn program_data_address(program_account: &[u8]) -> Result<String, JsError> {
    tidemark_core::rpc::parse_program_account(program_account)
        .map(|k| bs58_encode(&k))
        .map_err(err)
}

#[wasm_bindgen(js_name = deployedInfo)]
pub fn deployed_info(programdata: &[u8]) -> Result<String, JsError> {
    let (slot, authority, elf) = deployed_parts(programdata).map_err(err)?;
    Ok(json!({"slot": slot, "authority": authority, "size": elf.len()}).to_string())
}

#[wasm_bindgen(js_name = deployedElf)]
pub fn deployed_elf(programdata: &[u8]) -> Result<Vec<u8>, JsError> {
    deployed_parts(programdata).map(|(_, _, e)| e).map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name);
        std::fs::read(p).unwrap()
    }

    #[test]
    fn review_matches_the_cli_report() {
        let v = review_json(&fixture("demo_vault_v1.so"), &fixture("demo_vault_v2.so")).unwrap();
        assert_eq!(v["report"]["risk"], "high");
        let saved: Value = serde_json::from_slice(&fixture("demo_report.json")).unwrap();
        assert_eq!(v["report"]["findings"], saved["findings"]);
    }

    #[test]
    fn inspect_lists_named_handlers() {
        let v = inspect_json(&fixture("demo_vault_v2.so")).unwrap();
        let names: Vec<&str> = v["handlers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|h| h["name"].as_str())
            .collect();
        assert!(names.contains(&"sweep"), "{names:?}");
    }

    #[test]
    fn deployed_elf_round_trips_through_a_programdata_account() {
        let elf = fixture("demo_vault_v2.so");
        let mut pd = vec![3, 0, 0, 0];
        pd.extend(42u64.to_le_bytes());
        pd.push(1);
        pd.extend([7u8; 32]);
        pd.extend(&elf);
        pd.extend([0u8; 512]);
        let (slot, auth, got) = deployed_parts(&pd).unwrap();
        assert_eq!((slot, got), (42, elf));
        assert_eq!(auth.as_deref(), Some(bs58_encode(&[7u8; 32]).as_str()));
        assert!(deployed_parts(&[3, 0, 0, 0]).is_err());
    }

    #[test]
    fn bad_ledger_input_is_an_error() {
        assert!(verify_json("{}").is_err());
    }
}
