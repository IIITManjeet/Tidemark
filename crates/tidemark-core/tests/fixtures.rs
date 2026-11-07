use std::path::PathBuf;
use tidemark_core::diff::{compare, Severity};
use tidemark_core::elf::load;

fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|_| panic!("missing fixture {}", p.display()))
}

#[test]
fn backdoored_upgrade_is_caught() {
    let old = load(&fixture("demo_vault_v1.so")).unwrap();
    let new = load(&fixture("demo_vault_v2.so")).unwrap();
    let r = compare(&old, &new);
    assert_eq!(r.risk, Severity::High);

    let find = |id: &str| {
        r.findings
            .iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("no {id}"))
    };
    assert_eq!(
        find("TM-KEY-ADD").detail,
        vec!["9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"]
    );
    assert_eq!(
        find("TM-CHECK-GONE").detail,
        vec![
            "withdraw: ConstraintHasOne (2001): 1 → 0 check sites",
            "withdraw: AccountNotSigner (3010): 1 → 0 check sites",
        ]
    );
    assert_eq!(find("TM-IX-CHANGE").detail, vec!["+ sweep"]);
}

#[test]
fn same_binary_is_clean() {
    let p = load(&fixture("demo_vault_v1.so")).unwrap();
    let r = compare(&p, &p);
    assert_eq!(r.risk, Severity::Info);
    assert!(r.findings.is_empty());
    assert_eq!(r.changed_instructions, 0);
}

#[test]
fn unrelated_programs_have_no_false_key_hits_from_discriminators() {
    let a = load(&fixture("demo_vault_v1.so")).unwrap();
    let b = load(&fixture("tidemark_ledger.so")).unwrap();
    let r = compare(&a, &b);
    let keys = r.findings.iter().find(|f| f.id == "TM-KEY-ADD");
    if let Some(k) = keys {
        assert!(!k.detail.iter().any(|d| d.len() < 32));
    }
}

#[test]
fn dispatch_handlers_are_named() {
    let p = load(&fixture("demo_vault_v1.so")).unwrap();
    let names: Vec<String> = tidemark_core::handlers::handlers(&p)
        .values()
        .filter(|h| h.dispatched)
        .filter_map(|h| h.name.clone())
        .collect();
    for n in ["deposit", "init_vault", "withdraw"] {
        assert!(names.iter().any(|x| x == n), "{names:?}");
    }
}
