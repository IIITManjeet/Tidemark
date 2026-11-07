use std::path::PathBuf;
use tidemark_core::{cache, checked_hashes, diff, elf, judge};

fn read(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name);
    std::fs::read(p).unwrap()
}

struct AlwaysYes;

impl judge::Backend for AlwaysYes {
    fn name(&self) -> &str {
        "always-yes"
    }
    fn ask(&self, _: &str, _: &str, schema: Option<&serde_json::Value>) -> anyhow::Result<String> {
        Ok(match schema {
            Some(_) => {
                let yes =
                    serde_json::json!({"answer": "yes", "cites": ["TM-KEY-ADD"], "reason": "r"});
                let ballot: serde_json::Map<String, serde_json::Value> = judge::QUESTIONS
                    .iter()
                    .map(|q| (q.id.to_string(), yes.clone()))
                    .collect();
                serde_json::Value::Object(ballot).to_string()
            }
            None => "explained".into(),
        })
    }
}

#[test]
fn judging_leaves_the_report_and_its_hashes_untouched() {
    let r = diff::compare(
        &elf::load(&read("demo_vault_v1.so")).unwrap(),
        &elf::load(&read("demo_vault_v2.so")).unwrap(),
    );
    let e = cache::entry(&r);
    let report = e["report"].clone();
    let j = judge::judge(&AlwaysYes, &report).unwrap();
    assert!(j.questions.iter().all(|t| t.yes == judge::VOTES));
    assert_eq!(report, e["report"]);
    let (verdict, whole) = checked_hashes(&report).unwrap();
    assert_eq!(verdict, e["verdict_hash"].as_str().unwrap());
    assert_eq!(whole, e["report_hash"].as_str().unwrap());
}
