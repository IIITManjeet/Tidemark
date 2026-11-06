use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const DISC: usize = 8;
pub const ATTESTATION_LEN: usize =
    DISC + 32 + 8 + 32 + 32 + 32 + 32 + 1 + 16 + 32 + 32 + 8 + 32 + 32 + 1;
pub const REGISTRY_LEN: usize = DISC + 32 + 32 + 8 + 32 + 1;

fn discriminator(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("account:{name}").as_bytes());
    h[..8].try_into().expect("8 bytes")
}

#[derive(Debug, Clone, Serialize)]
pub struct Attestation {
    pub registry: [u8; 32],
    pub index: u64,
    pub program: [u8; 32],
    pub old_code_hash: [u8; 32],
    pub new_code_hash: [u8; 32],
    pub report_hash: [u8; 32],
    pub risk: u8,
    pub rules_version: [u8; 16],
    pub model_id: [u8; 32],
    pub reviewer: [u8; 32],
    pub slot: u64,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

pub struct Registry {
    pub authority: [u8; 32],
    pub count: u64,
    pub last_hash: [u8; 32],
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let (a, b) = self.0.split_at(N);
        self.0 = b;
        a.try_into().expect("length checked")
    }
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take::<8>())
    }
}

pub fn parse_attestation(data: &[u8]) -> Result<Attestation> {
    if data.len() < ATTESTATION_LEN || data[..DISC] != discriminator("Attestation") {
        bail!("not an Attestation account");
    }
    let mut r = Reader(&data[DISC..]);
    Ok(Attestation {
        registry: r.take(),
        index: r.u64(),
        program: r.take(),
        old_code_hash: r.take(),
        new_code_hash: r.take(),
        report_hash: r.take(),
        risk: r.take::<1>()[0],
        rules_version: r.take(),
        model_id: r.take(),
        reviewer: r.take(),
        slot: r.u64(),
        prev_hash: r.take(),
        entry_hash: r.take(),
    })
}

pub fn parse_registry(data: &[u8]) -> Result<Registry> {
    if data.len() < REGISTRY_LEN || data[..DISC] != discriminator("Registry") {
        bail!("not a Registry account");
    }
    let mut r = Reader(&data[DISC..]);
    let authority = r.take();
    let _name: [u8; 32] = r.take();
    Ok(Registry {
        authority,
        count: r.u64(),
        last_hash: r.take(),
    })
}

pub fn entry_hash(a: &Attestation) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a.index.to_le_bytes());
    h.update(a.program);
    h.update(a.old_code_hash);
    h.update(a.new_code_hash);
    h.update(a.report_hash);
    h.update([a.risk]);
    h.update(a.rules_version);
    h.update(a.model_id);
    h.update(a.reviewer);
    h.update(a.prev_hash);
    h.finalize().into()
}

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    Gap { expected: u64, found: u64 },
    BadLink { index: u64 },
    BadHash { index: u64 },
    HeadMismatch,
}

pub fn verify_chain(reg: &Registry, mut entries: Vec<Attestation>) -> Result<usize, ChainError> {
    entries.sort_by_key(|a| a.index);
    let mut prev = [0u8; 32];
    for (i, a) in entries.iter().enumerate() {
        if a.index != i as u64 {
            return Err(ChainError::Gap {
                expected: i as u64,
                found: a.index,
            });
        }
        if a.prev_hash != prev {
            return Err(ChainError::BadLink { index: a.index });
        }
        if entry_hash(a) != a.entry_hash {
            return Err(ChainError::BadHash { index: a.index });
        }
        prev = a.entry_hash;
    }
    if entries.len() as u64 != reg.count || prev != reg.last_hash {
        return Err(ChainError::HeadMismatch);
    }
    Ok(entries.len())
}

fn rpc_call(rpc: &str, method: &str, params: Value) -> Result<Value> {
    crate::rpc::call(rpc, method, params)
}

fn b64(s: &str) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(s)?)
}

pub fn fetch(
    rpc: &str,
    ledger_program: &str,
    registry: &str,
) -> Result<(Registry, Vec<Attestation>)> {
    let acc = rpc_call(
        rpc,
        "getAccountInfo",
        json!([registry, {"encoding":"base64"}]),
    )?;
    let data = acc["value"]["data"][0]
        .as_str()
        .context("registry account not found")?;
    let reg = parse_registry(&b64(data)?)?;

    let list = rpc_call(
        rpc,
        "getProgramAccounts",
        json!([ledger_program, {
            "encoding": "base64",
            "filters": [
                {"dataSize": ATTESTATION_LEN},
                {"memcmp": {"offset": DISC, "bytes": registry}}
            ]
        }]),
    )?;
    let mut out = Vec::new();
    for item in list
        .as_array()
        .context("unexpected getProgramAccounts response")?
    {
        let d = item["account"]["data"][0]
            .as_str()
            .context("missing data")?;
        out.push(parse_attestation(&b64(d)?)?);
    }
    Ok((reg, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(n: u64) -> (Registry, Vec<Attestation>) {
        let mut prev = [0u8; 32];
        let mut v = Vec::new();
        for i in 0..n {
            let mut a = Attestation {
                registry: [1; 32],
                index: i,
                program: [2; 32],
                old_code_hash: [3; 32],
                new_code_hash: [i as u8; 32],
                report_hash: [5; 32],
                risk: 3,
                rules_version: *b"tm-rules-0.1\0\0\0\0",
                model_id: [0; 32],
                reviewer: [6; 32],
                slot: 100 + i,
                prev_hash: prev,
                entry_hash: [0; 32],
            };
            a.entry_hash = entry_hash(&a);
            prev = a.entry_hash;
            v.push(a);
        }
        (
            Registry {
                authority: [9; 32],
                count: n,
                last_hash: prev,
            },
            v,
        )
    }

    #[test]
    fn valid_chain_verifies() {
        let (r, v) = chain(5);
        assert_eq!(verify_chain(&r, v), Ok(5));
    }

    #[test]
    fn edited_entry_is_caught() {
        let (r, mut v) = chain(4);
        v[2].risk = 0;
        assert_eq!(verify_chain(&r, v), Err(ChainError::BadHash { index: 2 }));
    }

    #[test]
    fn deleted_entry_is_caught() {
        let (r, mut v) = chain(4);
        v.remove(1);
        assert_eq!(
            verify_chain(&r, v),
            Err(ChainError::Gap {
                expected: 1,
                found: 2
            })
        );
    }

    #[test]
    fn truncated_tail_is_caught() {
        let (r, mut v) = chain(4);
        v.pop();
        assert_eq!(verify_chain(&r, v), Err(ChainError::HeadMismatch));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(2)]
    fn parse_registry_never_panics() {
        let data: [u8; REGISTRY_LEN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= REGISTRY_LEN);
        let _ = parse_registry(&data[..len]);
    }

    #[kani::proof]
    #[kani::unwind(2)]
    fn parse_attestation_never_panics() {
        let data: [u8; ATTESTATION_LEN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= ATTESTATION_LEN);
        let _ = parse_attestation(&data[..len]);
    }
}
