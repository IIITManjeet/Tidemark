use crate::submit::{find_pda, Pubkey};
#[cfg(feature = "net")]
use anyhow::bail;
use anyhow::{Context, Result};
#[cfg(feature = "net")]
use base64::Engine;
use serde::Serialize;
#[cfg(feature = "net")]
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const DISC: usize = 8;
pub const REGISTRY_LEN: usize = DISC + 32 + 32 + 32 + 8 + 32 + 1 + 2 + 1;
pub const REVIEWER_LEN: usize = DISC + 32 + 32 + 1 + 8 + 1;
pub const ATTESTATION_LEN: usize =
    DISC + 32 + 8 + 32 + 32 + 32 + 32 + 1 + 16 + 32 + 32 + 8 + 32 + 32 + 1 + 1 + 1;
pub const APPROVAL_LEN: usize = DISC + 32 + 32 + 8 + 1;
pub const REGISTRY3_LEN: usize = REGISTRY_LEN + 32 + 8;
pub const ATTESTATION3_LEN: usize = ATTESTATION_LEN + 32 + 8 + 8 + 4;
pub const APPROVAL3_LEN: usize = DISC + 32 + 32 + 32 + 8 + 32 + 1;

const REGISTRY_DISC: [u8; 8] = [6, 226, 98, 169, 180, 69, 111, 252];
const REVIEWER_DISC: [u8; 8] = [130, 144, 184, 246, 190, 126, 132, 89];
const ATTESTATION_DISC: [u8; 8] = [46, 168, 155, 156, 20, 220, 145, 188];
const APPROVAL_DISC: [u8; 8] = [233, 9, 153, 49, 11, 222, 59, 130];
const REGISTRY3_DISC: [u8; 8] = [54, 147, 83, 16, 117, 209, 34, 174];
const ATTESTATION3_DISC: [u8; 8] = [218, 182, 88, 51, 72, 67, 171, 139];
const APPROVAL3_DISC: [u8; 8] = [251, 153, 135, 206, 89, 173, 63, 165];

pub const APPROVAL_DOMAIN: &[u8] = b"tidemark/approval/v1";
pub const V2_LEDGERS: [&str; 1] = ["BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc"];

pub fn layout_for(ledger: &str) -> Layout {
    if V2_LEDGERS.contains(&ledger) {
        Layout::V2
    } else {
        Layout::V3
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Layout {
    V2,
    V3,
}

impl Layout {
    pub fn registry_seed(self) -> &'static [u8] {
        match self {
            Layout::V2 => b"registry2",
            Layout::V3 => b"registry3",
        }
    }

    pub fn attestation_seed(self) -> &'static [u8] {
        match self {
            Layout::V2 => b"attest2",
            Layout::V3 => b"attest3",
        }
    }

    pub fn attestation_len(self) -> usize {
        match self {
            Layout::V2 => ATTESTATION_LEN,
            Layout::V3 => ATTESTATION3_LEN,
        }
    }

    pub fn approval_len(self) -> usize {
        match self {
            Layout::V2 => APPROVAL_LEN,
            Layout::V3 => APPROVAL3_LEN,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Deploy {
    pub program_data: Pubkey,
    pub deployed_slot: u64,
    pub config_version: u64,
    pub elf_len: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Attestation {
    pub address: Pubkey,
    pub registry: Pubkey,
    pub index: u64,
    pub program: Pubkey,
    pub old_code_hash: [u8; 32],
    pub new_code_hash: [u8; 32],
    pub report_hash: [u8; 32],
    pub risk: u8,
    pub rules_version: [u8; 16],
    pub model_id: [u8; 32],
    pub reviewer: Pubkey,
    pub slot: u64,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
    pub threshold: u8,
    pub approvals: u8,
    pub deploy: Option<Deploy>,
}

#[derive(Debug, Clone)]
pub struct Registry {
    pub address: Pubkey,
    pub layout: Layout,
    pub seed_key: Pubkey,
    pub authority: Pubkey,
    pub pending_authority: Pubkey,
    pub count: u64,
    pub last_hash: [u8; 32],
    pub threshold: u8,
    pub active_reviewers: u16,
    pub config_version: u64,
}

#[derive(Debug, Clone)]
pub struct Reviewer {
    pub address: Pubkey,
    pub key: Pubkey,
    pub active: bool,
    pub added_slot: u64,
}

#[derive(Debug, Clone)]
pub struct Approval {
    pub address: Pubkey,
    pub registry: Option<Pubkey>,
    pub attestation: Pubkey,
    pub reviewer: Pubkey,
    pub slot: u64,
    pub digest: Option<[u8; 32]>,
}

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let (a, b) = self.0.split_at(N);
        self.0 = b;
        a.try_into().expect("length checked")
    }
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take::<8>())
    }
    fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }
}

fn body<'a>(data: &'a [u8], len: usize, disc: &[u8; 8]) -> Option<Reader<'a>> {
    (data.len() >= len && data[..DISC] == *disc).then(|| Reader(&data[DISC..len]))
}

fn registry_from(address: Pubkey, data: &[u8]) -> Option<Registry> {
    let (mut r, layout) = match body(data, REGISTRY3_LEN, &REGISTRY3_DISC) {
        Some(r) => (r, Layout::V3),
        None => (body(data, REGISTRY_LEN, &REGISTRY_DISC)?, Layout::V2),
    };
    let seed_key = if layout == Layout::V3 {
        Some(r.take())
    } else {
        None
    };
    let authority = r.take();
    let pending_authority = r.take();
    let _name: [u8; 32] = r.take();
    let count = r.u64();
    let last_hash = r.take();
    let threshold = r.u8();
    let active_reviewers = u16::from_le_bytes(r.take());
    let config_version = if layout == Layout::V3 { r.u64() } else { 0 };
    Some(Registry {
        address,
        layout,
        seed_key: seed_key.unwrap_or(authority),
        authority,
        pending_authority,
        count,
        last_hash,
        threshold,
        active_reviewers,
        config_version,
    })
}

fn attestation_from(address: Pubkey, data: &[u8]) -> Option<Attestation> {
    let (mut r, v3) = match body(data, ATTESTATION3_LEN, &ATTESTATION3_DISC) {
        Some(r) => (r, true),
        None => (body(data, ATTESTATION_LEN, &ATTESTATION_DISC)?, false),
    };
    let mut a = Attestation {
        address,
        registry: r.take(),
        index: r.u64(),
        program: r.take(),
        old_code_hash: r.take(),
        new_code_hash: r.take(),
        report_hash: r.take(),
        risk: r.u8(),
        rules_version: r.take(),
        model_id: r.take(),
        reviewer: r.take(),
        slot: r.u64(),
        prev_hash: r.take(),
        entry_hash: r.take(),
        threshold: r.u8(),
        approvals: r.u8(),
        deploy: None,
    };
    if v3 {
        a.deploy = Some(Deploy {
            program_data: r.take(),
            deployed_slot: r.u64(),
            config_version: r.u64(),
            elf_len: u32::from_le_bytes(r.take()),
        });
    }
    Some(a)
}

fn reviewer_from(address: Pubkey, data: &[u8]) -> Option<(Pubkey, Reviewer)> {
    let mut r = body(data, REVIEWER_LEN, &REVIEWER_DISC)?;
    let registry = r.take();
    let key = r.take();
    let active = r.u8() == 1;
    let added_slot = r.u64();
    Some((
        registry,
        Reviewer {
            address,
            key,
            active,
            added_slot,
        },
    ))
}

fn approval_from(address: Pubkey, data: &[u8]) -> Option<Approval> {
    if let Some(mut r) = body(data, APPROVAL3_LEN, &APPROVAL3_DISC) {
        return Some(Approval {
            address,
            registry: Some(r.take()),
            attestation: r.take(),
            reviewer: r.take(),
            slot: r.u64(),
            digest: Some(r.take()),
        });
    }
    let mut r = body(data, APPROVAL_LEN, &APPROVAL_DISC)?;
    Some(Approval {
        address,
        registry: None,
        attestation: r.take(),
        reviewer: r.take(),
        slot: r.u64(),
        digest: None,
    })
}

pub fn parse_registry(address: Pubkey, data: &[u8]) -> Result<Registry> {
    registry_from(address, data).context("not a RegistryV2 or RegistryV3 account")
}

pub fn parse_attestation(address: Pubkey, data: &[u8]) -> Result<Attestation> {
    attestation_from(address, data).context("not an AttestationV2 or AttestationV3 account")
}

pub fn parse_reviewer(address: Pubkey, data: &[u8]) -> Result<(Pubkey, Reviewer)> {
    reviewer_from(address, data).context("not a Reviewer account")
}

pub fn parse_approval(address: Pubkey, data: &[u8]) -> Result<Approval> {
    approval_from(address, data).context("not an Approval account")
}

pub fn entry_hash(a: &Attestation) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a.index.to_le_bytes());
    h.update(a.registry);
    h.update(a.program);
    h.update(a.old_code_hash);
    h.update(a.new_code_hash);
    h.update(a.report_hash);
    h.update([a.risk]);
    h.update(a.rules_version);
    h.update(a.model_id);
    h.update(a.reviewer);
    h.update(a.slot.to_le_bytes());
    h.update(a.prev_hash);
    if let Some(d) = &a.deploy {
        h.update(d.program_data);
        h.update(d.deployed_slot.to_le_bytes());
        h.update(d.config_version.to_le_bytes());
        h.update(d.elf_len.to_le_bytes());
    }
    h.finalize().into()
}

pub fn approval_digest(entry_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(APPROVAL_DOMAIN);
    h.update(entry_hash);
    h.finalize().into()
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    WrongRegistryAddress,
    Gap { expected: u64, found: u64 },
    WrongAddress { index: u64 },
    ForeignEntry { index: u64 },
    BadLink { index: u64 },
    BadHash { index: u64 },
    SlotWentBack { index: u64 },
    UnknownReviewer { index: u64 },
    BadReviewerAccount,
    ApprovalMismatch { index: u64 },
    MixedLayout { index: u64 },
    HeadMismatch,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntryStatus {
    pub index: u64,
    pub approvals: u8,
    pub threshold: u8,
    pub final_: bool,
    pub late_approvals: u8,
}

pub struct Snapshot {
    pub registry: Registry,
    pub attestations: Vec<Attestation>,
    pub reviewers: BTreeMap<Pubkey, Reviewer>,
    pub approvals: Vec<Approval>,
}

pub fn verify(ledger: &Pubkey, s: &Snapshot) -> Result<Vec<EntryStatus>, ChainError> {
    let reg = &s.registry;
    let layout = reg.layout;
    let expect = find_pda(&[layout.registry_seed(), &reg.seed_key], ledger)
        .map_err(|_| ChainError::WrongRegistryAddress)?
        .0;
    if expect != reg.address {
        return Err(ChainError::WrongRegistryAddress);
    }
    for (key, r) in &s.reviewers {
        let want = find_pda(&[b"reviewer", &reg.address, key], ledger)
            .map_err(|_| ChainError::BadReviewerAccount)?
            .0;
        if want != r.address || r.key != *key {
            return Err(ChainError::BadReviewerAccount);
        }
    }
    let mut entries = s.attestations.clone();
    entries.sort_by_key(|a| a.index);

    let mut by_att: BTreeMap<Pubkey, Vec<&Approval>> = BTreeMap::new();
    for ap in &s.approvals {
        by_att.entry(ap.attestation).or_default().push(ap);
    }

    let mut prev = [0u8; 32];
    let mut last_slot = 0u64;
    let mut out = Vec::new();
    for (i, a) in entries.iter().enumerate() {
        let index = a.index;
        if index != i as u64 {
            return Err(ChainError::Gap {
                expected: i as u64,
                found: index,
            });
        }
        if a.registry != reg.address {
            return Err(ChainError::ForeignEntry { index });
        }
        if a.deploy.is_some() != (layout == Layout::V3) {
            return Err(ChainError::MixedLayout { index });
        }
        let want = find_pda(
            &[
                layout.attestation_seed(),
                &reg.address,
                &index.to_le_bytes(),
            ],
            ledger,
        )
        .map_err(|_| ChainError::WrongAddress { index })?
        .0;
        if want != a.address {
            return Err(ChainError::WrongAddress { index });
        }
        if a.prev_hash != prev {
            return Err(ChainError::BadLink { index });
        }
        if entry_hash(a) != a.entry_hash {
            return Err(ChainError::BadHash { index });
        }
        if a.slot < last_slot {
            return Err(ChainError::SlotWentBack { index });
        }
        if !s.reviewers.contains_key(&a.reviewer) {
            return Err(ChainError::UnknownReviewer { index });
        }
        let digest = approval_digest(&a.entry_hash);
        let aps = by_att.get(&a.address).map(Vec::as_slice).unwrap_or(&[]);
        let mut signers: Vec<Pubkey> = Vec::new();
        let mut late = 0u8;
        for ap in aps {
            let want = find_pda(&[b"approval", &a.address, &ap.reviewer], ledger)
                .map_err(|_| ChainError::ApprovalMismatch { index })?
                .0;
            let bound = match layout {
                Layout::V2 => ap.digest.is_none(),
                Layout::V3 => ap.digest == Some(digest) && ap.registry == Some(reg.address),
            };
            let Some(r) = s.reviewers.get(&ap.reviewer) else {
                return Err(ChainError::ApprovalMismatch { index });
            };
            if want != ap.address || !bound || signers.contains(&ap.reviewer) {
                return Err(ChainError::ApprovalMismatch { index });
            }
            if r.added_slot > a.slot {
                late = late.saturating_add(1);
            }
            signers.push(ap.reviewer);
        }
        if signers.len() != a.approvals as usize || !signers.contains(&a.reviewer) {
            return Err(ChainError::ApprovalMismatch { index });
        }
        out.push(EntryStatus {
            index,
            approvals: a.approvals,
            threshold: a.threshold,
            final_: a.approvals >= a.threshold,
            late_approvals: late,
        });
        prev = a.entry_hash;
        last_slot = a.slot;
    }
    if entries.len() as u64 != reg.count || prev != reg.last_hash {
        return Err(ChainError::HeadMismatch);
    }
    Ok(out)
}

#[cfg(feature = "net")]
fn b64(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

#[cfg(feature = "net")]
fn decode_key(s: &str) -> Result<Pubkey> {
    crate::submit::decode_pubkey(s)
}

#[cfg(feature = "net")]
fn program_accounts(
    rpc: &str,
    ledger: &str,
    size: usize,
    filter: Option<(usize, &str)>,
) -> Result<Vec<(Pubkey, Vec<u8>)>> {
    let mut filters = vec![json!({"dataSize": size})];
    if let Some((offset, bytes)) = filter {
        filters.push(json!({"memcmp": {"offset": offset, "bytes": bytes}}));
    }
    let list = crate::rpc::call(
        rpc,
        "getProgramAccounts",
        json!([ledger, {"encoding": "base64", "commitment": "finalized", "filters": filters}]),
    )?;
    let mut out = Vec::new();
    for item in list
        .as_array()
        .context("unexpected getProgramAccounts response")?
    {
        let key = decode_key(item["pubkey"].as_str().context("missing pubkey")?)?;
        let d = item["account"]["data"][0]
            .as_str()
            .context("missing data")?;
        out.push((key, b64(d)?));
    }
    Ok(out)
}

#[cfg(feature = "net")]
pub fn fetch_registry(rpc: &str, ledger: &str, registry: &str) -> Result<Registry> {
    let acc: Value = crate::rpc::call(
        rpc,
        "getAccountInfo",
        json!([registry, {"encoding": "base64", "commitment": "finalized"}]),
    )?;
    let v = &acc["value"];
    if v.is_null() {
        bail!("registry {registry} not found");
    }
    if v["owner"].as_str() != Some(ledger) {
        bail!("registry {registry} is not owned by the ledger program {ledger}");
    }
    let data = v["data"][0].as_str().context("registry has no data")?;
    parse_registry(decode_key(registry)?, &b64(data)?)
}

#[cfg(feature = "net")]
pub fn fetch(rpc: &str, ledger: &str, registry: &str) -> Result<Snapshot> {
    let reg = fetch_registry(rpc, ledger, registry)?;
    let layout = reg.layout;
    let attestations = program_accounts(
        rpc,
        ledger,
        layout.attestation_len(),
        Some((DISC, registry)),
    )?;
    let reviewers = program_accounts(rpc, ledger, REVIEWER_LEN, Some((DISC, registry)))?;
    let approvals = match layout {
        Layout::V2 => program_accounts(rpc, ledger, APPROVAL_LEN, None)?,
        Layout::V3 => program_accounts(rpc, ledger, APPROVAL3_LEN, Some((DISC, registry)))?,
    };
    snapshot_from(reg, &attestations, &reviewers, &approvals)
}

pub type RawAccount = (Pubkey, Vec<u8>);

pub fn snapshot_from(
    registry: Registry,
    attestations: &[RawAccount],
    reviewers: &[RawAccount],
    approvals: &[RawAccount],
) -> Result<Snapshot> {
    let attestations = attestations
        .iter()
        .map(|(k, d)| parse_attestation(*k, d))
        .collect::<Result<Vec<_>>>()?;
    let mut by_key = BTreeMap::new();
    for (k, d) in reviewers {
        let (reg_key, r) = parse_reviewer(*k, d)?;
        if reg_key == registry.address {
            by_key.insert(r.key, r);
        }
    }
    let ours: Vec<Pubkey> = attestations.iter().map(|a| a.address).collect();
    let approvals = approvals
        .iter()
        .map(|(k, d)| parse_approval(*k, d))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|ap| ours.contains(&ap.attestation))
        .collect();
    Ok(Snapshot {
        registry,
        attestations,
        reviewers: by_key,
        approvals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_discriminators_match_anchor() {
        for (name, d) in [
            ("RegistryV2", REGISTRY_DISC),
            ("Reviewer", REVIEWER_DISC),
            ("AttestationV2", ATTESTATION_DISC),
            ("Approval", APPROVAL_DISC),
            ("RegistryV3", REGISTRY3_DISC),
            ("AttestationV3", ATTESTATION3_DISC),
            ("ApprovalV3", APPROVAL3_DISC),
        ] {
            let h = Sha256::digest(format!("account:{name}").as_bytes());
            assert_eq!(h[..8], d, "{name}");
        }
    }

    const LEDGER: Pubkey = [42u8; 32];

    fn chain(n: u64) -> Snapshot {
        chain_in(n, Layout::V2)
    }

    fn chain_in(n: u64, layout: Layout) -> Snapshot {
        let authority = [9u8; 32];
        let reviewer = [6u8; 32];
        let reg_addr = find_pda(&[layout.registry_seed(), &authority], &LEDGER)
            .unwrap()
            .0;
        let mut prev = [0u8; 32];
        let mut atts = Vec::new();
        let mut approvals = Vec::new();
        for i in 0..n {
            let address = find_pda(
                &[layout.attestation_seed(), &reg_addr, &i.to_le_bytes()],
                &LEDGER,
            )
            .unwrap()
            .0;
            let mut a = Attestation {
                address,
                registry: reg_addr,
                index: i,
                program: [2; 32],
                old_code_hash: [3; 32],
                new_code_hash: [i as u8; 32],
                report_hash: [5; 32],
                risk: 3,
                rules_version: *b"tm-rules-0.2\0\0\0\0",
                model_id: [0; 32],
                reviewer,
                slot: 100 + i,
                prev_hash: prev,
                entry_hash: [0; 32],
                threshold: 1,
                approvals: 1,
                deploy: (layout == Layout::V3).then_some(Deploy {
                    program_data: [8; 32],
                    deployed_slot: 90 + i,
                    config_version: 1,
                    elf_len: 1000,
                }),
            };
            a.entry_hash = entry_hash(&a);
            let v3 = layout == Layout::V3;
            prev = a.entry_hash;
            approvals.push(Approval {
                address: find_pda(&[b"approval", &address, &reviewer], &LEDGER)
                    .unwrap()
                    .0,
                registry: v3.then_some(reg_addr),
                attestation: address,
                reviewer,
                slot: 100 + i,
                digest: v3.then(|| approval_digest(&a.entry_hash)),
            });
            atts.push(a);
        }
        let mut reviewers = BTreeMap::new();
        reviewers.insert(
            reviewer,
            Reviewer {
                address: find_pda(&[b"reviewer", &reg_addr, &reviewer], &LEDGER)
                    .unwrap()
                    .0,
                key: reviewer,
                active: true,
                added_slot: 1,
            },
        );
        Snapshot {
            registry: Registry {
                address: reg_addr,
                layout,
                seed_key: authority,
                authority,
                pending_authority: [0; 32],
                count: n,
                last_hash: prev,
                threshold: 1,
                active_reviewers: 1,
                config_version: 0,
            },
            attestations: atts,
            reviewers,
            approvals,
        }
    }

    #[test]
    fn valid_chain_verifies() {
        let s = chain(5);
        let st = verify(&LEDGER, &s).unwrap();
        assert_eq!(st.len(), 5);
        assert!(st.iter().all(|e| e.final_));
    }

    #[test]
    fn edited_entry_is_caught() {
        let mut s = chain(4);
        s.attestations[2].risk = 0;
        assert_eq!(
            verify(&LEDGER, &s).err(),
            Some(ChainError::BadHash { index: 2 })
        );
    }

    #[test]
    fn edited_slot_is_caught() {
        let mut s = chain(3);
        s.attestations[1].slot += 1;
        assert_eq!(
            verify(&LEDGER, &s).err(),
            Some(ChainError::BadHash { index: 1 })
        );
    }

    #[test]
    fn deleted_entry_is_caught() {
        let mut s = chain(4);
        s.attestations.remove(1);
        assert_eq!(
            verify(&LEDGER, &s).err(),
            Some(ChainError::Gap {
                expected: 1,
                found: 2
            })
        );
    }

    #[test]
    fn truncated_tail_is_caught() {
        let mut s = chain(4);
        s.attestations.pop();
        assert_eq!(verify(&LEDGER, &s).err(), Some(ChainError::HeadMismatch));
    }

    #[test]
    fn lookalike_registry_address_is_rejected() {
        let mut s = chain(2);
        s.registry.address = [1u8; 32];
        assert_eq!(
            verify(&LEDGER, &s).err(),
            Some(ChainError::WrongRegistryAddress)
        );
    }

    #[test]
    fn reviewer_account_at_the_wrong_address_is_rejected() {
        let mut s = chain(2);
        for r in s.reviewers.values_mut() {
            r.address = [7; 32];
        }
        assert_eq!(
            verify(&LEDGER, &s).err(),
            Some(ChainError::BadReviewerAccount)
        );
    }

    #[test]
    fn entry_from_unlisted_reviewer_is_rejected() {
        let mut s = chain(2);
        s.reviewers.clear();
        assert_eq!(
            verify(&LEDGER, &s).err(),
            Some(ChainError::UnknownReviewer { index: 0 })
        );
    }

    #[test]
    fn missing_approval_is_caught() {
        let mut s = chain(2);
        s.approvals.pop();
        assert_eq!(
            verify(&LEDGER, &s).err(),
            Some(ChainError::ApprovalMismatch { index: 1 })
        );
    }

    #[test]
    fn quorum_status_is_reported() {
        let mut s = chain(1);
        s.attestations[0].threshold = 2;
        s.attestations[0].entry_hash = entry_hash(&s.attestations[0]);
        s.registry.last_hash = s.attestations[0].entry_hash;
        let st = verify(&LEDGER, &s).unwrap();
        assert!(!st[0].final_);
    }

    #[test]
    fn v3_chain_verifies() {
        let st = verify(&LEDGER, &chain_in(3, Layout::V3)).unwrap();
        assert_eq!(st.len(), 3);
        assert!(st.iter().all(|e| e.final_ && e.late_approvals == 0));
    }

    #[test]
    fn v3_registry_survives_authority_rotation() {
        let mut s = chain_in(2, Layout::V3);
        s.registry.authority = [77; 32];
        assert!(verify(&LEDGER, &s).is_ok());
        let mut s = chain_in(2, Layout::V2);
        s.registry.authority = [77; 32];
        s.registry.seed_key = [77; 32];
        assert_eq!(
            verify(&LEDGER, &s).err(),
            Some(ChainError::WrongRegistryAddress)
        );
    }

    #[test]
    fn v3_approval_with_another_digest_is_rejected() {
        let mut s = chain_in(2, Layout::V3);
        s.approvals[1].digest = Some([0; 32]);
        assert_eq!(
            verify(&LEDGER, &s).err(),
            Some(ChainError::ApprovalMismatch { index: 1 })
        );
        let mut s = chain_in(2, Layout::V3);
        s.approvals[0].registry = Some([1; 32]);
        assert_eq!(
            verify(&LEDGER, &s).err(),
            Some(ChainError::ApprovalMismatch { index: 0 })
        );
    }

    #[test]
    fn v3_deploy_fields_are_bound_by_the_entry_hash() {
        let mut s = chain_in(2, Layout::V3);
        s.attestations[1].deploy.as_mut().unwrap().deployed_slot += 1;
        assert_eq!(
            verify(&LEDGER, &s).err(),
            Some(ChainError::BadHash { index: 1 })
        );
        let mut s = chain_in(2, Layout::V3);
        s.attestations[0].deploy = None;
        assert_eq!(
            verify(&LEDGER, &s).err(),
            Some(ChainError::MixedLayout { index: 0 })
        );
    }

    #[test]
    fn approvals_by_reviewers_added_later_are_counted() {
        let mut s = chain_in(2, Layout::V3);
        for r in s.reviewers.values_mut() {
            r.added_slot = 100;
        }
        let st = verify(&LEDGER, &s).unwrap();
        assert_eq!((st[0].late_approvals, st[1].late_approvals), (0, 0));
        for r in s.reviewers.values_mut() {
            r.added_slot = 500;
        }
        let st = verify(&LEDGER, &s).unwrap();
        assert_eq!((st[0].late_approvals, st[1].late_approvals), (1, 1));
    }

    #[test]
    fn layouts_match_the_program() {
        assert_eq!(REGISTRY_LEN, 8 + 140);
        assert_eq!(REVIEWER_LEN, 8 + 74);
        assert_eq!(ATTESTATION_LEN, 8 + 324);
        assert_eq!(APPROVAL_LEN, 8 + 73);
        assert_eq!(REGISTRY3_LEN, 8 + 180);
        assert_eq!(ATTESTATION3_LEN, 8 + 376);
        assert_eq!(APPROVAL3_LEN, 8 + 137);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(9)]
    fn parse_registry_never_panics() {
        let data: [u8; REGISTRY3_LEN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= REGISTRY3_LEN);
        let r = registry_from([0; 32], &data[..len]);
        let disc = &data[..DISC];
        assert_eq!(
            r.is_some(),
            (len >= REGISTRY3_LEN && disc == REGISTRY3_DISC)
                || (len >= REGISTRY_LEN && disc == REGISTRY_DISC)
        );
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn parse_attestation_never_panics() {
        let data: [u8; ATTESTATION3_LEN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= ATTESTATION3_LEN);
        let a = attestation_from([0; 32], &data[..len]);
        let disc = &data[..DISC];
        assert_eq!(
            a.is_some(),
            (len >= ATTESTATION3_LEN && disc == ATTESTATION3_DISC)
                || (len >= ATTESTATION_LEN && disc == ATTESTATION_DISC)
        );
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn parse_reviewer_never_panics() {
        let data: [u8; REVIEWER_LEN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= REVIEWER_LEN);
        let _ = reviewer_from([0; 32], &data[..len]);
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn parse_approval_never_panics() {
        let data: [u8; APPROVAL3_LEN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= APPROVAL3_LEN);
        let _ = approval_from([0; 32], &data[..len]);
    }
}
