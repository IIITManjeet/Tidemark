pub mod cache;
pub mod census;
pub mod diff;
pub mod disasm;
pub mod elf;
pub mod handlers;
pub mod judge;
pub mod ledger;
pub mod proposal;
pub mod rpc;
pub mod snapshots;
pub mod submit;
pub mod syscalls;

pub fn report_hash(report: &diff::Report) -> String {
    let v = serde_json::to_value(report).expect("report serializes");
    canonical_hash(&v)
}

pub fn canonical_hash(v: &serde_json::Value) -> String {
    elf::sha256_hex(&serde_json::to_vec(v).expect("value serializes"))
}

pub fn verdict(report: &diff::Report) -> serde_json::Value {
    let findings: Vec<&diff::Finding> = report
        .findings
        .iter()
        .filter(|f| f.id != "TM-CHURN")
        .collect();
    let risk = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(diff::Severity::Info);
    serde_json::json!({
        "rules_version": report.rules_version,
        "old": report.old.sha256,
        "new": report.new.sha256,
        "risk": risk,
        "findings": findings,
    })
}

pub fn verdict_risk(report: &diff::Report) -> u8 {
    match verdict(report)["risk"].as_str() {
        Some("critical") => 4,
        Some("high") => 3,
        Some("medium") => 2,
        Some("low") => 1,
        _ => 0,
    }
}

pub fn verdict_hash(report: &diff::Report) -> String {
    canonical_hash(&verdict(report))
}

fn rank(s: &serde_json::Value) -> Option<u8> {
    Some(match s.as_str()? {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => return None,
    })
}

pub fn checked_hashes(report: &serde_json::Value) -> Option<(String, String)> {
    let all = report["findings"].as_array()?;
    let ranks = all
        .iter()
        .map(|f| rank(&f["severity"]))
        .collect::<Option<Vec<u8>>>()?;
    if rank(&report["risk"])? != ranks.iter().copied().max().unwrap_or(0) {
        return None;
    }
    let kept: Vec<&serde_json::Value> = all.iter().filter(|f| f["id"] != "TM-CHURN").collect();
    let risk = kept
        .iter()
        .filter_map(|f| rank(&f["severity"]))
        .max()
        .unwrap_or(0);
    let names = ["info", "low", "medium", "high", "critical"];
    let verdict = serde_json::json!({
        "rules_version": report["rules_version"],
        "old": report["old"]["sha256"],
        "new": report["new"]["sha256"],
        "risk": names[risk as usize],
        "findings": kept,
    });
    Some((canonical_hash(&verdict), canonical_hash(report)))
}

pub fn bs58_encode(b: &[u8]) -> String {
    bs58::encode(b).into_string()
}

pub fn parse_hash32(s: &str) -> anyhow::Result<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("expected 64 hex characters, got {:?}", s);
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

pub fn parse_risk(s: &str) -> anyhow::Result<u8> {
    Ok(match s {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        other => anyhow::bail!("unknown risk level {other:?}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_hashes_match_the_report_functions() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        let a = elf::load(&std::fs::read(dir.join("demo_vault_v1.so")).unwrap()).unwrap();
        let b = elf::load(&std::fs::read(dir.join("demo_vault_v2.so")).unwrap()).unwrap();
        let r = diff::compare(&a, &b);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            checked_hashes(&v),
            Some((verdict_hash(&r), report_hash(&r)))
        );
        let mut lied = v.clone();
        lied["risk"] = "info".into();
        assert_eq!(checked_hashes(&lied), None);
    }

    #[test]
    fn hash_parsing_rejects_bad_input_without_panicking() {
        assert!(parse_hash32("abc").is_err());
        assert!(parse_hash32(&"g".repeat(64)).is_err());
        assert!(parse_hash32(&"+1".repeat(32)).is_err());
        assert!(parse_hash32(&"é".repeat(32)).is_err());
        assert_eq!(parse_hash32(&"ab".repeat(32)).unwrap(), [0xab; 32]);
    }

    #[test]
    fn risk_levels_are_strict() {
        assert_eq!(parse_risk("high").unwrap(), 3);
        assert!(parse_risk("High").is_err());
        assert!(parse_risk("").is_err());
    }
}
