use std::collections::{BTreeMap, BTreeSet};
use tidemark_core::diff::{compare, Severity};
use tidemark_core::disasm::{decode, render};
use tidemark_core::elf::{Program, WideLoad};

fn program(norm: &[&str]) -> Program {
    Program {
        sbpf_version: 0,
        sha256: "00".repeat(32),
        size: norm.len() * 8,
        insn_count: norm.len(),
        lines: norm
            .iter()
            .enumerate()
            .map(|(i, s)| format!("{i:6x}  {s}"))
            .collect(),
        norm: norm.iter().map(|s| s.to_string()).collect(),
        syscalls: BTreeMap::new(),
        callx: 0,
        strings: BTreeSet::new(),
        consts32: BTreeSet::new(),
        imm_counts: BTreeMap::new(),
        wide: Vec::new(),
        rodata: Vec::new(),
        security_txt: None,
        flow: Vec::new(),
    }
}

fn ids(r: &tidemark_core::diff::Report) -> Vec<&str> {
    r.findings.iter().map(|f| f.id).collect()
}

#[test]
fn identical_programs_are_info_only() {
    let a = program(&["mov64 r0, 0", "exit"]);
    let b = program(&["mov64 r0, 0", "exit"]);
    let r = compare(&a, &b);
    assert_eq!(r.risk, Severity::Info);
    assert!(r.findings.is_empty());
    assert_eq!(r.changed_instructions, 0);
}

#[test]
fn new_invoke_signed_is_high() {
    let mut a = program(&["exit"]);
    let mut b = program(&["call sol_invoke_signed_rust", "exit"]);
    a.syscalls.insert("sol_invoke_signed_rust".into(), 1);
    b.syscalls.insert("sol_invoke_signed_rust".into(), 2);
    let r = compare(&a, &b);
    assert_eq!(r.risk, Severity::High);
    assert!(ids(&r).contains(&"TM-SYSCALL-ADD"));
}

#[test]
fn new_log_call_is_only_info() {
    let a = program(&["exit"]);
    let mut b = program(&["call sol_log_", "exit"]);
    b.syscalls.insert("sol_log_".into(), 1);
    let r = compare(&a, &b);
    assert_eq!(r.risk, Severity::Info);
}

#[test]
fn hardcoded_key_is_high_but_known_program_is_low() {
    let a = program(&["exit"]);
    let mut b = program(&["exit"]);
    let mut unknown = [0u8; 32];
    for (i, x) in unknown.iter_mut().enumerate() {
        *x = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    b.consts32.insert(unknown);
    let r = compare(&a, &b);
    assert!(ids(&r).contains(&"TM-KEY-ADD"));
    assert_eq!(r.risk, Severity::High);

    let mut c = program(&["exit"]);
    let token: [u8; 32] = bs58::decode("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    c.consts32.insert(token);
    let r = compare(&a, &c);
    assert_eq!(ids(&r), vec!["TM-PROG-REF"]);
    assert_eq!(r.risk, Severity::Low);
}

fn disc(name: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    u64::from_le_bytes(h[..8].try_into().unwrap())
}

fn with_handlers(p: &mut Program, names: &[(&str, &str)]) {
    for (shown, snake) in names {
        p.rodata
            .extend_from_slice(format!("Instruction: {shown}").as_bytes());
        p.wide.push(WideLoad {
            pc: p.wide.len() * 2,
            value: disc(snake),
            slot: None,
        });
    }
}

#[test]
fn new_instruction_handler_is_confirmed_by_discriminator() {
    let mut a = program(&["exit"]);
    let mut b = program(&["exit"]);
    with_handlers(&mut a, &[("Withdraw", "withdraw")]);
    with_handlers(
        &mut b,
        &[("Withdraw", "withdraw"), ("SweepAll", "sweep_all")],
    );
    let r = compare(&a, &b);
    let f = r
        .findings
        .iter()
        .find(|f| f.id == "TM-IX-CHANGE")
        .expect("ix finding");
    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.detail, vec!["+ sweep_all".to_string()]);
}

#[test]
fn log_string_without_discriminator_is_ignored() {
    let a = program(&["exit"]);
    let mut b = program(&["exit"]);
    b.rodata.extend_from_slice(b"Instruction: Fake");
    let r = compare(&a, &b);
    assert!(!ids(&r).contains(&"TM-IX-CHANGE"));
}

#[test]
fn removed_has_one_check_is_high() {
    let mut a = program(&["exit"]);
    let mut b = program(&["exit"]);
    a.imm_counts.insert(2001, 2);
    b.imm_counts.insert(2001, 1);
    let r = compare(&a, &b);
    assert!(ids(&r).contains(&"TM-CHECK-GONE"));
    assert_eq!(r.risk, Severity::High);
}

#[test]
fn key_built_on_stack_is_recovered() {
    let a = program(&["exit"]);
    let mut b = program(&["exit"]);
    let key: [u8; 32] = bs58::decode("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin")
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    for j in 0..4 {
        b.wide.push(WideLoad {
            pc: 10 + j * 3,
            value: u64::from_le_bytes(key[j * 8..j * 8 + 8].try_into().unwrap()),
            slot: Some((10, -64 + 8 * j as i16)),
        });
    }
    let r = compare(&a, &b);
    let f = r
        .findings
        .iter()
        .find(|f| f.id == "TM-KEY-ADD")
        .expect("key finding");
    assert_eq!(
        f.detail,
        vec!["9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"]
    );
}

#[test]
fn scattered_constants_are_not_a_key() {
    let a = program(&["exit"]);
    let mut b = program(&["exit"]);
    for j in 0..4u64 {
        b.wide.push(WideLoad {
            pc: 10 + j as usize * 3,
            value: 0x9a8b_7c6d_5e4f_3021 ^ (j << 40),
            slot: Some((10, -64 + 16 * j as i16)),
        });
    }
    let r = compare(&a, &b);
    assert!(!ids(&r).contains(&"TM-KEY-ADD"));
}

#[test]
fn moved_code_does_not_count_as_changed() {
    let code_a = [0x05u8, 0, 2, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
    let code_b = [0x05u8, 0, 7, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
    let na: Vec<_> = decode(&code_a).iter().map(|i| render(i, None).1).collect();
    let nb: Vec<_> = decode(&code_b).iter().map(|i| render(i, None).1).collect();
    assert_eq!(na, nb);
}

#[test]
fn decoder_handles_lddw_and_alu() {
    let code = [
        0x18, 0x01, 0, 0, 0x88, 0x77, 0x66, 0x55, 0, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0x07, 0x01,
        0, 0, 5, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0,
    ];
    let insns = decode(&code);
    assert_eq!(insns.len(), 3);
    assert_eq!(render(&insns[0], None).0, "lddw r1, 0x1122334455667788");
    assert_eq!(render(&insns[1], None).0, "add64 r1, 5");
    assert_eq!(render(&insns[2], None).0, "exit");
}

#[test]
fn report_hash_is_stable() {
    let a = program(&["exit"]);
    let b = program(&["mov64 r0, 1", "exit"]);
    let h1 = tidemark_core::report_hash(&compare(&a, &b));
    let h2 = tidemark_core::report_hash(&compare(&a, &b));
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
}
