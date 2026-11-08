use std::path::PathBuf;
use tidemark_core::diff::{compare, Severity};
use tidemark_core::elf::{load, Program};

fn read(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name);
    std::fs::read(p).unwrap()
}

fn text_offset(bytes: &[u8]) -> usize {
    let elf = goblin::elf::Elf::parse(bytes).unwrap();
    elf.section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".text"))
        .unwrap()
        .sh_offset as usize
}

const HAS_ONE_ENTRY: usize = 0x1aeb;
const HAS_ONE_LIMBS: [usize; 3] = [0x1b0c, 0x1b0f, 0x1b13];

fn line(p: &Program, pc: usize) -> &str {
    let i = p.flow.iter().position(|f| f.pc == pc).unwrap();
    p.lines[i].trim().split_once("  ").unwrap().1
}

fn set_ja(bytes: &mut [u8], pc: usize, off: Option<i16>) {
    let at = text_offset(bytes) + pc * 8;
    bytes[at] = 0x05;
    bytes[at + 1] = 0;
    if let Some(o) = off {
        bytes[at + 2..at + 4].copy_from_slice(&o.to_le_bytes());
    }
}

fn set_off(bytes: &mut [u8], pc: usize, off: i16) {
    let at = text_offset(bytes) + pc * 8 + 2;
    bytes[at..at + 2].copy_from_slice(&off.to_le_bytes());
}

fn guard_gone(old: &Program, new: &Program) -> bool {
    compare(old, new)
        .findings
        .iter()
        .any(|f| f.id == "TM-GUARD-GONE" && f.severity == Severity::High)
}

#[test]
fn fixture_layout_is_the_has_one_check() {
    let old = load(&read("demo_vault_v1.so")).unwrap();
    assert!(line(&old, HAS_ONE_ENTRY).starts_with("jeq r8, r1"));
    for pc in HAS_ONE_LIMBS {
        assert!(line(&old, pc).starts_with("jne"), "{}", line(&old, pc));
    }
}

#[test]
fn has_one_patched_to_unconditional_jumps_is_high() {
    let mut bytes = read("demo_vault_v1.so");
    let old = load(&bytes).unwrap();
    set_ja(&mut bytes, HAS_ONE_ENTRY, None);
    for pc in HAS_ONE_LIMBS {
        set_ja(&mut bytes, pc, Some(0));
    }
    let new = load(&bytes).unwrap();
    assert!(guard_gone(&old, &new));
}

#[test]
fn guard_retargeted_to_fall_through_next_to_another_edit_is_high() {
    let mut bytes = read("demo_vault_v1.so");
    let old = load(&bytes).unwrap();
    set_off(&mut bytes, HAS_ONE_LIMBS[0], 0);
    let at = text_offset(&bytes) + (HAS_ONE_LIMBS[0] - 1) * 8 + 2;
    let o = i16::from_le_bytes([bytes[at], bytes[at + 1]]) - 1;
    bytes[at..at + 2].copy_from_slice(&o.to_le_bytes());
    let new = load(&bytes).unwrap();
    assert!(guard_gone(&old, &new));
}

#[test]
fn real_upgrades_do_not_trip_the_guard_rule_both_ways() {
    let v1 = load(&read("demo_vault_v1.so")).unwrap();
    let v2 = load(&read("demo_vault_v2.so")).unwrap();
    assert!(!guard_gone(&v1, &v2));
    assert!(!guard_gone(&v2, &v1));
    assert!(!guard_gone(&v1, &v1));
}

#[test]
fn a_branch_that_already_fell_through_is_not_a_removed_guard() {
    let mut bytes = read("demo_vault_v1.so");
    for pc in HAS_ONE_LIMBS {
        set_off(&mut bytes, pc, 0);
    }
    let p = load(&bytes).unwrap();
    let report = compare(&p, &load(&bytes).unwrap());
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}
