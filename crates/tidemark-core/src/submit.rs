use anyhow::{bail, Context, Result};
#[cfg(feature = "net")]
use base64::Engine;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey};
#[cfg(feature = "net")]
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(feature = "net")]
use std::time::{Duration, Instant};

pub type Pubkey = [u8; 32];
pub const SYSTEM_PROGRAM: Pubkey = [0u8; 32];

pub fn decode_pubkey(s: &str) -> Result<Pubkey> {
    let v = bs58::decode(s)
        .into_vec()
        .with_context(|| format!("invalid base58 address: {s}"))?;
    v.try_into()
        .map_err(|_| anyhow::anyhow!("address must be 32 bytes: {s}"))
}

pub fn load_keypair(path: &str) -> Result<SigningKey> {
    let meta = std::fs::metadata(path).with_context(|| format!("cannot read keypair {path}"))?;
    if meta.len() > 4096 {
        bail!("{path} is too large to be a keypair file");
    }
    let raw = std::fs::read_to_string(path)?;
    let bytes: Vec<u8> =
        serde_json::from_str(&raw).context("keypair file must be a JSON byte array")?;
    if bytes.len() != 64 {
        bail!("keypair must contain 64 bytes");
    }
    let secret: [u8; 32] = bytes[..32].try_into()?;
    let key = SigningKey::from_bytes(&secret);
    if key.verifying_key().as_bytes() != &bytes[32..] {
        bail!("keypair public half does not match its secret");
    }
    Ok(key)
}

pub fn pubkey_of(k: &SigningKey) -> Pubkey {
    *k.verifying_key().as_bytes()
}

pub fn on_curve(b: &Pubkey) -> bool {
    CompressedEdwardsY(*b).decompress().is_some()
}

pub fn find_pda(seeds: &[&[u8]], program: &Pubkey) -> Result<(Pubkey, u8)> {
    for bump in (0..=255u8).rev() {
        let mut h = Sha256::new();
        for s in seeds {
            h.update(s);
        }
        h.update([bump]);
        h.update(program);
        h.update(b"ProgramDerivedAddress");
        let out: Pubkey = h.finalize().into();
        if !on_curve(&out) {
            return Ok((out, bump));
        }
    }
    bail!("no viable bump for PDA")
}

pub fn sighash(name: &str) -> [u8; 8] {
    Sha256::digest(format!("global:{name}").as_bytes())[..8]
        .try_into()
        .expect("8 bytes")
}

fn compact_u16(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
}

#[derive(Clone, Copy)]
pub struct Meta {
    pub key: Pubkey,
    pub signer: bool,
    pub writable: bool,
}

impl Meta {
    pub fn w(key: Pubkey) -> Self {
        Meta {
            key,
            signer: false,
            writable: true,
        }
    }
    pub fn r(key: Pubkey) -> Self {
        Meta {
            key,
            signer: false,
            writable: false,
        }
    }
    pub fn s(key: Pubkey) -> Self {
        Meta {
            key,
            signer: true,
            writable: false,
        }
    }
    pub fn sw(key: Pubkey) -> Self {
        Meta {
            key,
            signer: true,
            writable: true,
        }
    }
}

pub struct Compiled {
    pub message: Vec<u8>,
    pub signers: Vec<Pubkey>,
}

pub struct Ix<'a> {
    pub program: Pubkey,
    pub metas: &'a [Meta],
    pub data: &'a [u8],
}

pub fn compile(
    payer: Pubkey,
    program: Pubkey,
    metas: &[Meta],
    data: &[u8],
    blockhash: Pubkey,
) -> Result<Compiled> {
    compile_many(
        payer,
        &[Ix {
            program,
            metas,
            data,
        }],
        blockhash,
    )
}

pub fn compile_many(payer: Pubkey, ixs: &[Ix], blockhash: Pubkey) -> Result<Compiled> {
    let mut merged: Vec<Meta> = vec![Meta::sw(payer)];
    let all = ixs.iter().flat_map(|ix| {
        ix.metas
            .iter()
            .copied()
            .chain(std::iter::once(Meta::r(ix.program)))
    });
    for m in all {
        match merged.iter_mut().find(|x| x.key == m.key) {
            Some(x) => {
                x.signer |= m.signer;
                x.writable |= m.writable;
            }
            None => merged.push(m),
        }
    }
    if merged
        .iter()
        .any(|m| ixs.iter().any(|ix| ix.program == m.key) && (m.signer || m.writable))
    {
        bail!("program id cannot be a signer or writable");
    }
    let group = |m: &Meta| match (m.signer, m.writable) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        (false, false) => 3,
    };
    let payer_first = merged.remove(0);
    merged.sort_by_key(group);
    merged.insert(0, payer_first);
    if merged.len() > 255 {
        bail!("too many accounts");
    }

    let signers: Vec<Pubkey> = merged.iter().filter(|m| m.signer).map(|m| m.key).collect();
    let ro_signed = merged.iter().filter(|m| m.signer && !m.writable).count();
    let ro_unsigned = merged.iter().filter(|m| !m.signer && !m.writable).count();
    let index = |k: &Pubkey| {
        merged
            .iter()
            .position(|m| m.key == *k)
            .expect("key present") as u8
    };

    let mut msg = vec![signers.len() as u8, ro_signed as u8, ro_unsigned as u8];
    compact_u16(merged.len(), &mut msg);
    for m in &merged {
        msg.extend_from_slice(&m.key);
    }
    msg.extend_from_slice(&blockhash);
    compact_u16(ixs.len(), &mut msg);
    for ix in ixs {
        msg.push(index(&ix.program));
        compact_u16(ix.metas.len(), &mut msg);
        for m in ix.metas {
            msg.push(index(&m.key));
        }
        compact_u16(ix.data.len(), &mut msg);
        msg.extend_from_slice(ix.data);
    }
    Ok(Compiled {
        message: msg,
        signers,
    })
}

pub fn sign(c: &Compiled, keys: &[&SigningKey]) -> Result<Vec<u8>> {
    let mut tx = Vec::new();
    compact_u16(c.signers.len(), &mut tx);
    for s in &c.signers {
        let k = keys
            .iter()
            .find(|k| pubkey_of(k) == *s)
            .with_context(|| format!("missing signature for {}", bs58::encode(s).into_string()))?;
        tx.extend_from_slice(&k.sign(&c.message).to_bytes());
    }
    tx.extend_from_slice(&c.message);
    Ok(tx)
}

#[cfg(feature = "net")]
fn rpc(url: &str, method: &str, params: Value) -> Result<Value> {
    crate::rpc::call(url, method, params)
}

#[cfg(feature = "net")]
fn confirm(url: &str, sig: &str) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        let r = rpc(url, "getSignatureStatuses", json!([[sig]]))?;
        let st = &r["value"][0];
        if !st.is_null() {
            if !st["err"].is_null() {
                bail!("transaction {sig} failed: {}", st["err"]);
            }
            if matches!(
                st["confirmationStatus"].as_str(),
                Some("confirmed" | "finalized")
            ) {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(800));
    }
    bail!("transaction {sig} was not confirmed within 60 s")
}

pub const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";
pub const LOADER_V3: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
pub const ATTEST_COMPUTE_UNITS: u32 = 1_400_000;

pub fn program_data_address(program: &Pubkey) -> Result<Pubkey> {
    Ok(find_pda(&[program], &decode_pubkey(LOADER_V3)?)?.0)
}

#[cfg(feature = "net")]
pub struct Ctx<'a> {
    pub url: &'a str,
    pub ledger: Pubkey,
    pub layout: crate::ledger::Layout,
    pub payer: &'a SigningKey,
}

#[cfg(feature = "net")]
impl Ctx<'_> {
    fn send(&self, signer: &SigningKey, metas: &[Meta], data: &[u8]) -> Result<String> {
        self.send_with_budget(signer, metas, data, None)
    }

    fn send_with_budget(
        &self,
        signer: &SigningKey,
        metas: &[Meta],
        data: &[u8],
        units: Option<u32>,
    ) -> Result<String> {
        let bh = rpc(
            self.url,
            "getLatestBlockhash",
            json!([{"commitment": "confirmed"}]),
        )?;
        let blockhash = decode_pubkey(bh["value"]["blockhash"].as_str().context("no blockhash")?)?;
        let budget: Vec<u8> = units
            .map(|u| [&[2u8][..], &u.to_le_bytes()].concat())
            .unwrap_or_default();
        let mut ixs = Vec::new();
        if units.is_some() {
            ixs.push(Ix {
                program: decode_pubkey(COMPUTE_BUDGET)?,
                metas: &[],
                data: &budget,
            });
        }
        ixs.push(Ix {
            program: self.ledger,
            metas,
            data,
        });
        let c = compile_many(pubkey_of(self.payer), &ixs, blockhash)?;
        let tx = sign(&c, &[self.payer, signer])?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(tx);
        let sig = rpc(
            self.url,
            "sendTransaction",
            json!([b64, {"encoding": "base64", "preflightCommitment": "confirmed"}]),
        )?;
        let sig = sig
            .as_str()
            .context("sendTransaction returned no signature")?
            .to_string();
        confirm(self.url, &sig)?;
        Ok(sig)
    }

    fn account_data(&self, key: &Pubkey) -> Result<Option<Vec<u8>>> {
        let r = rpc(
            self.url,
            "getAccountInfo",
            json!([bs58::encode(key).into_string(), {"encoding": "base64", "commitment": "confirmed"}]),
        )?;
        match r["value"]["data"][0].as_str() {
            Some(d) if !r["value"].is_null() => {
                Ok(Some(base64::engine::general_purpose::STANDARD.decode(d)?))
            }
            _ => Ok(None),
        }
    }

    fn exists(&self, key: &Pubkey) -> Result<bool> {
        Ok(self.account_data(key)?.is_some())
    }

    fn require_active_reviewer(&self, registry: &Pubkey, me: &Pubkey) -> Result<()> {
        let who = bs58::encode(me).into_string();
        let addr = self.reviewer_address(registry, me)?;
        let Some(data) = self.account_data(&addr)? else {
            bail!(
                "{who} is not a reviewer of this registry; ask its authority to run add-reviewer"
            );
        };
        let (_, r) = crate::ledger::parse_reviewer(addr, &data)?;
        if !r.active {
            bail!("{who} is a disabled reviewer of this registry");
        }
        Ok(())
    }

    pub fn registry_address(&self, authority: &Pubkey) -> Result<Pubkey> {
        Ok(find_pda(&[self.layout.registry_seed(), authority], &self.ledger)?.0)
    }

    pub fn reviewer_address(&self, registry: &Pubkey, key: &Pubkey) -> Result<Pubkey> {
        Ok(find_pda(&[b"reviewer", registry, key], &self.ledger)?.0)
    }

    pub fn attestation_address(&self, registry: &Pubkey, index: u64) -> Result<Pubkey> {
        Ok(find_pda(
            &[
                self.layout.attestation_seed(),
                registry,
                &index.to_le_bytes(),
            ],
            &self.ledger,
        )?
        .0)
    }

    pub fn approval_address(&self, attestation: &Pubkey, reviewer: &Pubkey) -> Result<Pubkey> {
        Ok(find_pda(&[b"approval", attestation, reviewer], &self.ledger)?.0)
    }

    pub fn init_registry(
        &self,
        authority: &SigningKey,
        name: &str,
        threshold: u8,
    ) -> Result<(Pubkey, String)> {
        let auth = pubkey_of(authority);
        let registry = self.registry_address(&auth)?;
        let mut n = [0u8; 32];
        let mut end = name.len().min(32);
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        n[..end].copy_from_slice(&name.as_bytes()[..end]);
        let mut d = sighash("init_registry").to_vec();
        d.extend_from_slice(&n);
        d.push(threshold);
        let metas = [
            Meta::w(registry),
            Meta::s(auth),
            Meta::sw(pubkey_of(self.payer)),
            Meta::r(SYSTEM_PROGRAM),
        ];
        Ok((registry, self.send(authority, &metas, &d)?))
    }

    pub fn add_reviewer(&self, authority: &SigningKey, key: Pubkey) -> Result<String> {
        let auth = pubkey_of(authority);
        let registry = self.registry_address(&auth)?;
        let reviewer = self.reviewer_address(&registry, &key)?;
        let mut d = sighash("add_reviewer").to_vec();
        d.extend_from_slice(&key);
        let metas = [
            Meta::w(registry),
            Meta::w(reviewer),
            Meta::s(auth),
            Meta::sw(pubkey_of(self.payer)),
            Meta::r(SYSTEM_PROGRAM),
        ];
        self.send(authority, &metas, &d)
    }

    pub fn set_reviewer_active(
        &self,
        authority: &SigningKey,
        key: Pubkey,
        active: bool,
    ) -> Result<String> {
        let auth = pubkey_of(authority);
        let registry = self.registry_address(&auth)?;
        let reviewer = self.reviewer_address(&registry, &key)?;
        let mut d = sighash("set_reviewer_active").to_vec();
        d.push(active as u8);
        self.send(
            authority,
            &[Meta::w(registry), Meta::w(reviewer), Meta::s(auth)],
            &d,
        )
    }

    pub fn set_threshold(&self, authority: &SigningKey, threshold: u8) -> Result<String> {
        let auth = pubkey_of(authority);
        let registry = self.registry_address(&auth)?;
        let mut d = sighash("set_threshold").to_vec();
        d.push(threshold);
        self.send(authority, &[Meta::w(registry), Meta::s(auth)], &d)
    }

    pub fn propose_authority(
        &self,
        authority: &SigningKey,
        new_authority: Pubkey,
    ) -> Result<String> {
        let auth = pubkey_of(authority);
        let registry = self.registry_address(&auth)?;
        let mut d = sighash("propose_authority").to_vec();
        d.extend_from_slice(&new_authority);
        self.send(authority, &[Meta::w(registry), Meta::s(auth)], &d)
    }

    pub fn accept_authority(&self, new_authority: &SigningKey, registry: Pubkey) -> Result<String> {
        let d = sighash("accept_authority").to_vec();
        self.send(
            new_authority,
            &[Meta::w(registry), Meta::s(pubkey_of(new_authority))],
            &d,
        )
    }

    pub fn attest(
        &self,
        signer: &SigningKey,
        registry: Pubkey,
        a: &AttestInput,
    ) -> Result<(Pubkey, u64, String)> {
        let reg = crate::ledger::fetch_registry(
            self.url,
            &bs58::encode(self.ledger).into_string(),
            &bs58::encode(registry).into_string(),
        )?;
        let me = pubkey_of(signer);
        self.require_active_reviewer(&registry, &me)?;
        if reg.layout != self.layout {
            bail!(
                "registry layout {:?} does not match this ledger ({:?})",
                reg.layout,
                self.layout
            );
        }
        let attestation = self.attestation_address(&registry, reg.count)?;
        let v3 = self.layout == crate::ledger::Layout::V3;
        let mut d = sighash("attest").to_vec();
        if !v3 {
            d.extend_from_slice(&a.program);
        }
        d.extend_from_slice(&a.old_code_hash);
        d.extend_from_slice(&a.new_code_hash);
        d.extend_from_slice(&a.report_hash);
        d.push(a.risk);
        d.extend_from_slice(&a.rules_version);
        d.extend_from_slice(&a.model_id);
        let mut metas = vec![
            Meta::w(registry),
            Meta::r(self.reviewer_address(&registry, &me)?),
            Meta::w(attestation),
            Meta::w(self.approval_address(&attestation, &me)?),
        ];
        if v3 {
            d.extend_from_slice(&a.elf_len.to_le_bytes());
            metas.push(Meta::r(a.program));
            metas.push(Meta::r(program_data_address(&a.program)?));
        }
        metas.extend([
            Meta::s(me),
            Meta::sw(pubkey_of(self.payer)),
            Meta::r(SYSTEM_PROGRAM),
        ]);
        let units = v3.then_some(ATTEST_COMPUTE_UNITS);
        let sig = self.send_with_budget(signer, &metas, &d, units)?;
        Ok((attestation, reg.count, sig))
    }

    pub fn approve(
        &self,
        signer: &SigningKey,
        registry: Pubkey,
        index: u64,
        bound: [u8; 32],
    ) -> Result<String> {
        let me = pubkey_of(signer);
        let attestation = self.attestation_address(&registry, index)?;
        self.require_active_reviewer(&registry, &me)?;
        if self.exists(&self.approval_address(&attestation, &me)?)? {
            bail!("you already approved entry #{index}");
        }
        let mut d = sighash("approve").to_vec();
        d.extend_from_slice(&bound);
        let metas = [
            Meta::r(registry),
            Meta::r(self.reviewer_address(&registry, &me)?),
            Meta::w(attestation),
            Meta::w(self.approval_address(&attestation, &me)?),
            Meta::s(me),
            Meta::sw(pubkey_of(self.payer)),
            Meta::r(SYSTEM_PROGRAM),
        ];
        self.send(signer, &metas, &d)
    }
}

pub struct AttestInput {
    pub program: Pubkey,
    pub old_code_hash: [u8; 32],
    pub new_code_hash: [u8; 32],
    pub report_hash: [u8; 32],
    pub risk: u8,
    pub rules_version: [u8; 16],
    pub model_id: [u8; 32],
    pub elf_len: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_u16_encoding() {
        let enc = |n| {
            let mut v = Vec::new();
            compact_u16(n, &mut v);
            v
        };
        assert_eq!(enc(0), vec![0]);
        assert_eq!(enc(0x7f), vec![0x7f]);
        assert_eq!(enc(0x80), vec![0x80, 0x01]);
        assert_eq!(enc(0x3fff), vec![0xff, 0x7f]);
    }

    #[test]
    fn pda_matches_addresses_created_on_devnet() {
        let ledger = decode_pubkey("BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc").unwrap();
        let wallet = decode_pubkey("9fxLpiKzK1zeF42911g5ruKDdTuJFduJSEXcZHh4mCB1").unwrap();
        let registry = find_pda(&[b"registry", &wallet], &ledger).unwrap().0;
        assert_eq!(
            bs58::encode(registry).into_string(),
            "BEeLrroZNSULfZuSUQuneuzetKXtKMvkmPtuH7x7k6qK"
        );
        let att = find_pda(&[b"attest", &registry, &0u64.to_le_bytes()], &ledger)
            .unwrap()
            .0;
        assert_eq!(
            bs58::encode(att).into_string(),
            "84BquZaNLSjHpNY5Ccz2AkyK9wHv2jnj2tZGDNoZWv3R"
        );
    }

    #[test]
    fn anchor_sighash_matches_known_value() {
        assert_eq!(hex::encode(sighash("initialize")), "afaf6d1f0d989bed");
    }

    #[test]
    fn compile_orders_signers_and_counts_header() {
        let payer = [1u8; 32];
        let auth = [2u8; 32];
        let reg = [3u8; 32];
        let prog = [9u8; 32];
        let c = compile(
            payer,
            prog,
            &[
                Meta::w(reg),
                Meta::s(auth),
                Meta::sw(payer),
                Meta::r(SYSTEM_PROGRAM),
            ],
            &[7],
            [0u8; 32],
        )
        .unwrap();
        assert_eq!(&c.message[..3], &[2, 1, 2]);
        assert_eq!(c.signers, vec![payer, auth]);
        let keys: Vec<&[u8]> = c.message[4..4 + 5 * 32].chunks(32).collect();
        assert_eq!(
            keys,
            vec![
                &payer[..],
                &auth[..],
                &reg[..],
                &SYSTEM_PROGRAM[..],
                &prog[..]
            ]
        );
    }

    #[test]
    fn same_payer_and_signer_is_one_signature() {
        let k = [1u8; 32];
        let c = compile(
            k,
            [9u8; 32],
            &[Meta::w([3u8; 32]), Meta::s(k)],
            &[],
            [0u8; 32],
        )
        .unwrap();
        assert_eq!(c.message[0], 1);
        assert_eq!(c.signers, vec![k]);
    }

    #[test]
    fn writable_program_is_rejected() {
        assert!(compile([1u8; 32], [9u8; 32], &[Meta::w([9u8; 32])], &[], [0u8; 32]).is_err());
    }

    #[test]
    fn signing_needs_every_key() {
        let a = SigningKey::from_bytes(&[1u8; 32]);
        let b = SigningKey::from_bytes(&[2u8; 32]);
        let c = compile(
            pubkey_of(&a),
            [9u8; 32],
            &[Meta::s(pubkey_of(&b))],
            &[],
            [0u8; 32],
        )
        .unwrap();
        assert!(sign(&c, &[&a]).is_err());
        assert_eq!(sign(&c, &[&a, &b]).unwrap()[0], 2);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn decode_compact(b: &[u8]) -> (usize, usize) {
        let mut n = 0usize;
        for (i, x) in b.iter().enumerate() {
            n |= ((x & 0x7f) as usize) << (7 * i);
            if x & 0x80 == 0 {
                return (n, i + 1);
            }
        }
        (n, b.len())
    }

    #[kani::proof]
    #[kani::unwind(5)]
    fn compact_u16_roundtrips() {
        let n: u16 = kani::any();
        let mut v = Vec::new();
        compact_u16(n as usize, &mut v);
        assert!(!v.is_empty() && v.len() <= 3);
        assert_eq!(decode_compact(&v), (n as usize, v.len()));
    }
}
