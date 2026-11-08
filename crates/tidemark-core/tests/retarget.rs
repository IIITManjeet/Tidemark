use std::path::PathBuf;
use tidemark_core::diff::compare;
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

fn shape(p: &Program, pc: usize) -> &str {
    p.norm[pc].split_whitespace().next().unwrap()
}

fn ids(old: &Program, new: &Program) -> Vec<&'static str> {
    compare(old, new).findings.iter().map(|f| f.id).collect()
}

#[test]
fn real_upgrade_has_no_retargets() {
    let old = load(&read("demo_vault_v1.so")).unwrap();
    let new = load(&read("demo_vault_v2.so")).unwrap();
    let found = ids(&old, &new);
    assert!(!found.contains(&"TM-BRANCH-RETARGET"), "{found:?}");
    assert!(!found.contains(&"TM-CALL-RETARGET"), "{found:?}");
}

#[test]
fn bumped_branch_offset_is_caught() {
    let mut bytes = read("demo_vault_v1.so");
    let old = load(&bytes).unwrap();
    let f = old
        .flow
        .iter()
        .filter(|f| f.pc > 0x100 && !f.is_call)
        .find(|f| {
            f.target
                .is_some_and(|t| t + 1 < old.norm.len() && shape(&old, t) != shape(&old, t + 1))
        })
        .copied()
        .unwrap();
    let at = text_offset(&bytes) + f.pc * 8 + 2;
    let off = i16::from_le_bytes([bytes[at], bytes[at + 1]]) + 1;
    bytes[at..at + 2].copy_from_slice(&off.to_le_bytes());
    let new = load(&bytes).unwrap();
    assert!(ids(&old, &new).contains(&"TM-BRANCH-RETARGET"));
}

#[test]
fn swapped_call_target_is_caught() {
    let mut bytes = read("demo_vault_v1.so");
    let old = load(&bytes).unwrap();
    let calls: Vec<_> = old.flow.iter().filter(|f| f.is_call).copied().collect();
    let a = calls[calls.len() / 2];
    let other = calls
        .iter()
        .find(|c| c.target != a.target && c.target.is_some())
        .unwrap()
        .target
        .unwrap();
    let at = text_offset(&bytes) + a.pc * 8 + 4;
    let imm = other as i64 - a.pc as i64 - 1;
    bytes[at..at + 4].copy_from_slice(&(imm as i32).to_le_bytes());
    let new = load(&bytes).unwrap();
    assert!(ids(&old, &new).contains(&"TM-CALL-RETARGET"));
}

#[test]
fn two_calls_trading_targets_is_a_medium_swap() {
    let mut bytes = read("demo_vault_v1.so");
    let old = load(&bytes).unwrap();
    let calls: Vec<_> = old.flow.iter().filter(|f| f.is_call).copied().collect();
    let a = calls[calls.len() / 2];
    let b = *calls
        .iter()
        .rev()
        .find(|c| c.target.is_some() && c.target != a.target)
        .unwrap();
    for (from, to) in [(a, b.target.unwrap()), (b, a.target.unwrap())] {
        let at = text_offset(&bytes) + from.pc * 8 + 4;
        let imm = to as i64 - from.pc as i64 - 1;
        bytes[at..at + 4].copy_from_slice(&(imm as i32).to_le_bytes());
    }
    let report = compare(&old, &load(&bytes).unwrap());
    let swap = report.findings.iter().find(|f| f.id == "TM-TARGET-SWAP");
    assert!(
        swap.is_some_and(|f| f.severity == tidemark_core::diff::Severity::Medium),
        "{:?}",
        report.findings
    );
    assert!(
        !report.findings.iter().any(|f| f.id == "TM-CALL-RETARGET"),
        "{:?}",
        report.findings
    );
}
