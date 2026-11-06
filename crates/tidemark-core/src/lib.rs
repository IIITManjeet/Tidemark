pub mod diff;
pub mod disasm;
pub mod elf;
pub mod ledger;
pub mod rpc;
pub mod submit;
pub mod syscalls;

pub fn report_hash(report: &diff::Report) -> String {
    let v = serde_json::to_value(report).expect("report serializes");
    canonical_hash(&v)
}

pub fn canonical_hash(v: &serde_json::Value) -> String {
    elf::sha256_hex(&serde_json::to_vec(v).expect("value serializes"))
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
