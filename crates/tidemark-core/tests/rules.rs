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
        dispatch: Vec::new(),
        error_codes: Vec::new(),
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
            cmp: false,
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
            cmp: false,
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
            cmp: false,
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

fn limbs(key: &[u8; 32]) -> Vec<u64> {
    key.chunks(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

fn push_key(p: &mut Program, key: &[u8; 32], pc: usize, base: u8, cmp: bool) {
    for (j, v) in limbs(key).into_iter().enumerate() {
        p.wide.push(WideLoad {
            pc: pc + j * 3,
            value: v,
            slot: Some((base, 8 * j as i16)),
            cmp,
        });
    }
}

fn sweep_key() -> [u8; 32] {
    bs58::decode("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin")
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap()
}

fn key_detail(r: &tidemark_core::diff::Report) -> Vec<String> {
    r.findings
        .iter()
        .find(|f| f.id == "TM-KEY-ADD")
        .map(|f| f.detail.clone())
        .unwrap_or_default()
}

#[test]
fn key_used_in_comparison_is_recovered() {
    let a = program(&["exit"]);
    let mut b = program(&["exit"]);
    push_key(&mut b, &sweep_key(), 10, 2, true);
    assert_eq!(
        key_detail(&compare(&a, &b)),
        vec!["9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"]
    );
}

#[test]
fn low_entropy_limb_does_not_hide_a_key() {
    let mut key = sweep_key();
    key[24..].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
    let a = program(&["exit"]);
    let mut b = program(&["exit"]);
    push_key(&mut b, &key, 10, 10, false);
    assert_eq!(key_detail(&compare(&a, &b)).len(), 1);
}

#[test]
fn limbs_planted_earlier_still_count() {
    let key = sweep_key();
    let mut a = program(&["exit"]);
    for (j, v) in limbs(&key).into_iter().enumerate() {
        a.wide.push(WideLoad {
            pc: 10 + j * 200,
            value: v,
            slot: None,
            cmp: false,
        });
    }
    let mut b = program(&["exit"]);
    b.wide = a.wide.clone();
    push_key(&mut b, &key, 2000, 10, false);
    assert_eq!(key_detail(&compare(&a, &b)).len(), 1);
}

#[test]
fn key_already_present_is_not_new() {
    let mut a = program(&["exit"]);
    let mut b = program(&["exit"]);
    push_key(&mut a, &sweep_key(), 10, 10, false);
    push_key(&mut b, &sweep_key(), 90, 10, true);
    assert!(key_detail(&compare(&a, &b)).is_empty());
}

#[test]
fn rodata_blob_is_reported_once() {
    let a = program(&["exit"]);
    let mut b = program(&["exit"]);
    let blob: Vec<u8> = (0..40u8).map(|i| i.wrapping_mul(71) ^ 0x3c).collect();
    for i in 0..=8 {
        b.consts32.insert(blob[i..i + 32].try_into().unwrap());
    }
    let d = key_detail(&compare(&a, &b));
    assert_eq!(d.len(), 1, "{d:?}");
    assert!(d[0].ends_with("(start of a 40-byte blob)"), "{d:?}");
}

fn two_handlers(codes: &[(usize, i64)]) -> Program {
    let mut norm = vec!["mov64 r0, 0"; 40];
    for k in [11, 21] {
        norm[k] = "ja <l>";
    }
    for k in [34, 39] {
        norm[k] = "exit";
    }
    let mut p = program(&norm);
    p.flow = (0..40)
        .map(|pc| tidemark_core::elf::Flow {
            pc,
            ..Default::default()
        })
        .collect();
    for (at, to) in [(10, 30), (20, 35)] {
        p.flow[at].target = Some(to);
        p.flow[at].is_call = true;
    }
    p.dispatch = vec![(0xaaaa, 10, 0), (0xbbbb, 20, 3)];
    p.error_codes = codes.to_vec();
    for (_, c) in codes {
        *p.imm_counts.entry(*c).or_default() += 1;
    }
    p
}

#[test]
fn decoy_check_in_another_handler_does_not_hide_removal() {
    let a = two_handlers(&[(31, 2001)]);
    let b = two_handlers(&[(36, 2001)]);
    let r = compare(&a, &b);
    let f = r
        .findings
        .iter()
        .find(|f| f.id == "TM-CHECK-GONE")
        .expect("check finding");
    assert_eq!(
        f.detail,
        vec!["0x000000000000aaaa: ConstraintHasOne (2001): 1 → 0 check sites"]
    );
}

#[test]
fn removed_custom_error_is_reported() {
    let a = two_handlers(&[(32, 6001)]);
    let b = two_handlers(&[]);
    let r = compare(&a, &b);
    assert!(ids(&r).contains(&"TM-ERR-GONE"));
    assert!(!ids(&r).contains(&"TM-CHECK-GONE"));
}

#[test]
fn handler_without_log_is_found_from_dispatch() {
    let a = two_handlers(&[]);
    let mut b = two_handlers(&[]);
    b.dispatch.push((0xcccc, 20, 6));
    let r = compare(&a, &b);
    let f = r.findings.iter().find(|f| f.id == "TM-IX-CHANGE").unwrap();
    assert_eq!(f.detail, vec!["+ 0x000000000000cccc"]);
}

#[test]
fn handler_name_with_digits_is_matched() {
    let a = program(&["exit"]);
    let mut b = program(&["exit"]);
    with_handlers(&mut b, &[("Sweep1", "sweep_1")]);
    let r = compare(&a, &b);
    let f = r.findings.iter().find(|f| f.id == "TM-IX-CHANGE").unwrap();
    assert_eq!(f.detail, vec!["+ sweep_1"]);
}

fn shared_helper(a_calls_helper: bool) -> Program {
    let mut norm = vec!["mov64 r0, 0"; 60];
    for k in [11, 21] {
        norm[k] = "ja <l>";
    }
    for k in [34, 39, 54] {
        norm[k] = "exit";
    }
    let mut p = program(&norm);
    p.flow = (0..60)
        .map(|pc| tidemark_core::elf::Flow {
            pc,
            ..Default::default()
        })
        .collect();
    let mut calls = vec![(10, 30), (20, 35), (36, 50)];
    if a_calls_helper {
        calls.push((31, 50));
    }
    for (at, to) in calls {
        p.flow[at].target = Some(to);
        p.flow[at].is_call = true;
    }
    p.dispatch = vec![(0xaaaa, 10, 0), (0xbbbb, 20, 3)];
    p.error_codes = vec![(51, 3010)];
    p.imm_counts.insert(3010, 1);
    p
}

#[test]
fn check_dropped_from_one_caller_of_a_shared_helper_is_caught() {
    let r = compare(&shared_helper(true), &shared_helper(false));
    let f = r
        .findings
        .iter()
        .find(|f| f.id == "TM-CHECK-GONE")
        .expect("check finding");
    assert_eq!(
        f.detail,
        vec!["0x000000000000aaaa: AccountNotSigner (3010): 1 → 0 check sites"]
    );
}

fn with_branch(target: usize) -> Program {
    let norm = [
        "mov64 r3, 1",
        "mov64 r4, 2",
        "mov64 r5, 3",
        "mov64 r6, 4",
        "jne r1, r2, <l>",
        "mov64 r7, 5",
        "mov64 r8, 6",
        "mov64 r0, 0",
        "exit",
        "mov64 r9, 7",
        "mov64 r0, 3012",
        "exit",
        "mov64 r2, 8",
        "mov64 r3, 9",
        "mov64 r4, 10",
        "mov64 r5, 11",
        "exit",
    ];
    let mut p = program(&norm);
    p.flow = (0..norm.len())
        .map(|pc| tidemark_core::elf::Flow {
            pc,
            ..Default::default()
        })
        .collect();
    p.flow[4].target = Some(target);
    p
}

#[test]
fn error_branch_sent_to_the_success_return_is_caught() {
    let r = compare(&with_branch(10), &with_branch(7));
    assert!(ids(&r).contains(&"TM-BRANCH-RETARGET"), "{:?}", ids(&r));
}

#[test]
fn check_inlined_far_from_the_dispatch_stub_is_still_counted() {
    let mut a = two_handlers(&[]);
    a.error_codes = vec![(28, 2002)];
    a.imm_counts.insert(2002, 1);
    let b = two_handlers(&[]);
    let r = compare(&a, &b);
    let f = r
        .findings
        .iter()
        .find(|f| f.id == "TM-CHECK-GONE")
        .expect("check finding");
    assert_eq!(
        f.detail,
        vec!["outside any handler: ConstraintSigner (2002): 1 → 0 check sites"]
    );
}

#[test]
fn key_limbs_spread_apart_are_still_assembled() {
    let a = program(&["exit"]);
    let mut b = program(&["exit"]);
    for (j, v) in limbs(&sweep_key()).into_iter().enumerate() {
        b.wide.push(WideLoad {
            pc: 10 + j * 50,
            value: v,
            slot: Some((10, -64 + 8 * j as i16)),
            cmp: false,
        });
    }
    assert_eq!(key_detail(&compare(&a, &b)).len(), 1);
}

#[test]
fn decoy_dispatch_cluster_does_not_hide_a_removed_check() {
    let a = two_handlers(&[(31, 2002)]);
    let mut b = two_handlers(&[]);
    for k in 0..6u64 {
        b.dispatch.push((0xdec0 + k, 30, 100 + k as usize));
    }
    let r = compare(&a, &b);
    let f = r
        .findings
        .iter()
        .find(|f| f.id == "TM-CHECK-GONE")
        .expect("check finding");
    assert_eq!(
        f.detail,
        vec!["outside any handler: ConstraintSigner (2002): 1 → 0 check sites"]
    );
}

#[test]
fn new_discriminator_outside_the_dispatch_table_is_reported() {
    let a = two_handlers(&[]);
    let mut b = two_handlers(&[]);
    b.dispatch.push((0xcafe_f00d_1234_5678, 30, 300));
    let r = compare(&a, &b);
    let f = r.findings.iter().find(|f| f.id == "TM-IX-CHANGE").unwrap();
    assert_eq!(
        f.detail,
        vec!["+ 0xcafef00d12345678 (outside the dispatch table)"]
    );
}

#[test]
fn constants_that_are_only_added_are_reported_low() {
    let mut a = program(&["mov64 r0, 0", "exit"]);
    a.flow = vec![Default::default(); 2];
    let mut b = program(&["lddw r1, 0x12a05f200", "exit"]);
    b.flow = vec![Default::default(); 2];
    b.flow[0].constant = Some(5_000_000_000);
    let r = compare(&a, &b);
    let f = r.findings.iter().find(|f| f.id == "TM-CONST-ADD").unwrap();
    assert_eq!(f.severity, Severity::Low);
    assert_eq!(f.detail, vec!["+ 0x12a05f200"]);
}
