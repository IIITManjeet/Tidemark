use crate::diff::{Report, RULES_VERSION};
use anyhow::Result;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub fn path(dir: &Path, old_sha: &str, new_sha: &str) -> PathBuf {
    dir.join(RULES_VERSION)
        .join(format!("{old_sha}-{new_sha}.json"))
}

pub fn entry(report: &Report) -> Value {
    json!({
        "report": report,
        "verdict_hash": crate::verdict_hash(report),
        "report_hash": crate::report_hash(report),
    })
}

pub fn get(dir: &Path, old_sha: &str, new_sha: &str) -> Option<Value> {
    let v: Value =
        serde_json::from_slice(&std::fs::read(path(dir, old_sha, new_sha)).ok()?).ok()?;
    let r = &v["report"];
    let (verdict, report) = crate::checked_hashes(r)?;
    let fits = r["rules_version"] == RULES_VERSION
        && r["old"]["sha256"] == old_sha
        && r["new"]["sha256"] == new_sha
        && v["verdict_hash"] == verdict.as_str()
        && v["report_hash"] == report.as_str();
    fits.then_some(v)
}

pub fn put(dir: &Path, old_sha: &str, new_sha: &str, entry: &Value) -> Result<()> {
    let p = path(dir, old_sha, new_sha);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = p.with_extension("json.part");
    std::fs::write(&tmp, serde_json::to_vec(entry)?)?;
    std::fs::rename(tmp, p)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf;

    fn fixture(name: &str) -> Vec<u8> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures")
            .join(name);
        std::fs::read(p).unwrap()
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tidemark-cache-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn round_trips_and_keeps_hashes() {
        let d = tmp("rt");
        let (a, b) = (fixture("demo_vault_v1.so"), fixture("demo_vault_v2.so"));
        let (oa, ob) = (elf::sha256_hex(&a), elf::sha256_hex(&b));
        assert!(get(&d, &oa, &ob).is_none());
        let r = crate::diff::compare(&elf::load(&a).unwrap(), &elf::load(&b).unwrap());
        put(&d, &oa, &ob, &entry(&r)).unwrap();
        let hit = get(&d, &oa, &ob).unwrap();
        assert_eq!(hit["verdict_hash"], crate::verdict_hash(&r));
        assert_eq!(hit["report"]["risk"], "high");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn mismatched_or_corrupt_entries_are_misses() {
        let d = tmp("bad");
        let (oa, ob) = ("a".repeat(64), "b".repeat(64));
        put(
            &d,
            &oa,
            &ob,
            &json!({"report": {"rules_version": "tm-rules-0.1"}}),
        )
        .unwrap();
        assert!(get(&d, &oa, &ob).is_none());
        std::fs::write(path(&d, &oa, &ob), b"{not json").unwrap();
        assert!(get(&d, &oa, &ob).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn edited_entries_are_misses() {
        let d = tmp("edit");
        let (a, b) = (fixture("demo_vault_v1.so"), fixture("demo_vault_v2.so"));
        let (oa, ob) = (elf::sha256_hex(&a), elf::sha256_hex(&b));
        let r = crate::diff::compare(&elf::load(&a).unwrap(), &elf::load(&b).unwrap());
        let mut e = entry(&r);
        e["report"]["risk"] = "info".into();
        put(&d, &oa, &ob, &e).unwrap();
        assert!(get(&d, &oa, &ob).is_none());
        let mut e = entry(&r);
        e["report"]["findings"] = json!([]);
        put(&d, &oa, &ob, &e).unwrap();
        assert!(get(&d, &oa, &ob).is_none());
        let mut e = entry(&r);
        e["verdict_hash"] = "0".repeat(64).into();
        put(&d, &oa, &ob, &e).unwrap();
        assert!(get(&d, &oa, &ob).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
