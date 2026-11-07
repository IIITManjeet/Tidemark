use std::path::PathBuf;
use tidemark_core::elf::{load, sbpf_version};

fn fixture() -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/demo_vault_v1.so");
    std::fs::read(p).unwrap()
}

fn with_header(machine: u16, flags: u32) -> Vec<u8> {
    let mut b = fixture();
    b[18..20].copy_from_slice(&machine.to_le_bytes());
    b[48..52].copy_from_slice(&flags.to_le_bytes());
    b
}

#[test]
fn version_table() {
    assert_eq!(sbpf_version(247, 0).unwrap(), 0);
    assert_eq!(sbpf_version(247, 0x20).unwrap(), 2);
    assert_eq!(sbpf_version(263, 1).unwrap(), 1);
    assert_eq!(sbpf_version(263, 3).unwrap(), 3);
    assert_eq!(sbpf_version(247, 3).unwrap(), 3);
    assert!(sbpf_version(263, 9).is_err());
    assert!(sbpf_version(62, 0).is_err());
}

#[test]
fn fixture_is_v0() {
    assert_eq!(load(&fixture()).unwrap().sbpf_version, 0);
}

#[test]
fn v1_is_accepted() {
    assert_eq!(load(&with_header(263, 1)).unwrap().sbpf_version, 1);
}

#[test]
fn v4_and_unknown_flags_are_refused_with_a_clear_message() {
    for (m, f) in [(247u16, 4u32), (263, 4), (247, 9)] {
        assert!(load(&with_header(m, f)).is_err(), "{m} {f:#x}");
    }
}

#[test]
fn non_bpf_elf_is_refused() {
    let e = load(&with_header(62, 0))
        .err()
        .expect("should refuse")
        .to_string();
    assert!(e.contains("not an SBPF program"), "{e}");
}
