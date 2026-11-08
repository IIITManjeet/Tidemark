use std::path::PathBuf;
use tidemark_core::diff::{compare, Report, Severity};
use tidemark_core::elf::{load, Program};

fn read(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name);
    std::fs::read(p).unwrap()
}

fn vault(variant: &str, ver: u8) -> Program {
    let name = match ver {
        0 => format!("demo_vault_{variant}.so"),
        _ => format!("sbpf/demo_vault_{variant}_sbpfv{ver}.so"),
    };
    load(&read(&name)).unwrap()
}

fn high(r: &Report) -> Vec<&str> {
    r.findings
        .iter()
        .filter(|f| f.severity >= Severity::High)
        .map(|f| f.id)
        .collect()
}

const BUILT: [u8; 2] = [2, 3];

#[test]
fn every_version_loads_with_its_own_version() {
    for ver in BUILT {
        assert_eq!(vault("v2", ver).sbpf_version, ver);
    }
    assert_eq!(vault("v1", 1).sbpf_version, 1);
}

#[test]
fn backdoor_is_high_in_every_version_and_across_versions() {
    let olds = [
        vault("v1", 0),
        vault("v1", 1),
        vault("v1", 2),
        vault("v1", 3),
    ];
    let news = [vault("v2", 0), vault("v2", 2), vault("v2", 3)];
    for o in &olds {
        for n in &news {
            let r = compare(o, n);
            let ids = high(&r);
            let tag = format!("v{} -> v{}: {ids:?}", o.sbpf_version, n.sbpf_version);
            assert!(ids.contains(&"TM-KEY-ADD"), "{tag}");
            assert!(ids.contains(&"TM-CHECK-GONE"), "{tag}");
            let checks = r.findings.iter().find(|f| f.id == "TM-CHECK-GONE").unwrap();
            assert!(
                checks
                    .detail
                    .iter()
                    .any(|d| d.starts_with("withdraw: ConstraintHasOne")),
                "{tag}: {:?}",
                checks.detail
            );
        }
    }
}

#[test]
fn same_build_is_clean_in_every_version() {
    for ver in BUILT {
        let p = vault("v2", ver);
        assert_eq!(compare(&p, &p).risk, Severity::Info, "v{ver}");
    }
}

#[test]
fn migrating_the_same_source_to_v3_is_flagged_but_not_high() {
    let r = compare(&vault("v1", 1), &vault("v1", 3));
    assert!(r.findings.iter().any(|f| f.id == "TM-VERSION-CHANGE"));
    assert_eq!(r.risk, Severity::Medium, "{:?}", high(&r));
}

#[test]
fn v3_without_section_headers_reads_the_same() {
    let bytes = read("sbpf/demo_vault_v2_sbpfv3.so");
    let mut stripped = bytes.clone();
    stripped[0x28..0x30].fill(0);
    stripped[0x3c..0x40].fill(0);
    let (a, b) = (load(&bytes).unwrap(), load(&stripped).unwrap());
    assert_eq!(a.insn_count, b.insn_count);
    assert_eq!(a.norm, b.norm);
    assert_eq!(a.syscalls, b.syscalls);
    let r = compare(&vault("v1", 3), &b);
    assert!(high(&r).contains(&"TM-KEY-ADD"));
}

#[test]
fn deployed_length_is_found_for_v3() {
    let bytes = read("sbpf/demo_vault_v1_sbpfv3.so");
    let mut padded = bytes.clone();
    padded.extend(std::iter::repeat_n(0u8, 4096));
    assert_eq!(tidemark_core::rpc::elf_len(&padded).unwrap(), bytes.len());
}
