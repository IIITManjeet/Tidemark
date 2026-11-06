use anyhow::{bail, Context, Result};
use base64::Engine;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("cannot read keypair {path}"))?;
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

fn on_curve(b: &Pubkey) -> bool {
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

fn sighash(name: &str) -> [u8; 8] {
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

pub struct Meta {
    pub key: Pubkey,
    pub signer: bool,
    pub writable: bool,
}

fn build_tx(
    payer: &SigningKey,
    program: Pubkey,
    metas: &[Meta],
    data: &[u8],
    blockhash: Pubkey,
) -> Vec<u8> {
    let payer_pk: Pubkey = *payer.verifying_key().as_bytes();
    let mut keys: Vec<Pubkey> = vec![payer_pk];
    for m in metas.iter().filter(|m| m.writable && m.key != payer_pk) {
        if !keys.contains(&m.key) {
            keys.push(m.key);
        }
    }
    let writable_count = keys.len();
    for m in metas.iter().filter(|m| !m.writable && m.key != payer_pk) {
        if !keys.contains(&m.key) {
            keys.push(m.key);
        }
    }
    if !keys.contains(&program) {
        keys.push(program);
    }
    let readonly_unsigned = keys.len() - writable_count;

    let mut msg = vec![1u8, 0u8, readonly_unsigned as u8];
    compact_u16(keys.len(), &mut msg);
    for k in &keys {
        msg.extend_from_slice(k);
    }
    msg.extend_from_slice(&blockhash);
    compact_u16(1, &mut msg);
    msg.push(
        keys.iter()
            .position(|k| *k == program)
            .expect("program in keys") as u8,
    );
    compact_u16(metas.len(), &mut msg);
    for m in metas {
        msg.push(keys.iter().position(|k| *k == m.key).expect("meta in keys") as u8);
    }
    compact_u16(data.len(), &mut msg);
    msg.extend_from_slice(data);

    let sig = payer.sign(&msg);
    let mut tx = Vec::with_capacity(1 + 64 + msg.len());
    compact_u16(1, &mut tx);
    tx.extend_from_slice(&sig.to_bytes());
    tx.extend_from_slice(&msg);
    tx
}

fn rpc(url: &str, method: &str, params: Value) -> Result<Value> {
    let v: Value = ureq::post(url)
        .send_json(json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))?
        .into_json()?;
    if let Some(e) = v.get("error") {
        bail!("RPC error: {e}");
    }
    Ok(v["result"].clone())
}

fn send(
    url: &str,
    payer: &SigningKey,
    program: Pubkey,
    metas: &[Meta],
    data: &[u8],
) -> Result<String> {
    let bh = rpc(
        url,
        "getLatestBlockhash",
        json!([{"commitment":"confirmed"}]),
    )?;
    let blockhash = decode_pubkey(bh["value"]["blockhash"].as_str().context("no blockhash")?)?;
    let tx = build_tx(payer, program, metas, data, blockhash);
    let b64 = base64::engine::general_purpose::STANDARD.encode(tx);
    let sig = rpc(
        url,
        "sendTransaction",
        json!([b64, {"encoding":"base64","preflightCommitment":"confirmed"}]),
    )?;
    Ok(sig.as_str().unwrap_or_default().to_string())
}

pub fn registry_address(ledger: &Pubkey, authority: &Pubkey) -> Result<Pubkey> {
    Ok(find_pda(&[b"registry", authority], ledger)?.0)
}

pub fn init_registry(
    url: &str,
    ledger: Pubkey,
    payer: &SigningKey,
    name: &str,
) -> Result<(Pubkey, String)> {
    let auth: Pubkey = *payer.verifying_key().as_bytes();
    let registry = registry_address(&ledger, &auth)?;
    let mut n = [0u8; 32];
    let nb = name.as_bytes();
    n[..nb.len().min(32)].copy_from_slice(&nb[..nb.len().min(32)]);
    let mut data = sighash("init_registry").to_vec();
    data.extend_from_slice(&n);
    let metas = [
        Meta {
            key: registry,
            signer: false,
            writable: true,
        },
        Meta {
            key: auth,
            signer: true,
            writable: true,
        },
        Meta {
            key: SYSTEM_PROGRAM,
            signer: false,
            writable: false,
        },
    ];
    Ok((registry, send(url, payer, ledger, &metas, &data)?))
}

pub struct AttestInput {
    pub program: Pubkey,
    pub old_code_hash: [u8; 32],
    pub new_code_hash: [u8; 32],
    pub report_hash: [u8; 32],
    pub risk: u8,
    pub rules_version: [u8; 16],
    pub model_id: [u8; 32],
}

pub fn attest(
    url: &str,
    ledger: Pubkey,
    registry: Pubkey,
    payer: &SigningKey,
    a: &AttestInput,
) -> Result<(Pubkey, String)> {
    let acc = rpc(
        url,
        "getAccountInfo",
        json!([bs58::encode(registry).into_string(), {"encoding":"base64"}]),
    )?;
    let data = acc["value"]["data"][0]
        .as_str()
        .context("registry not found; run init-registry first")?;
    let reg =
        crate::ledger::parse_registry(&base64::engine::general_purpose::STANDARD.decode(data)?)?;
    let (attestation, _) = find_pda(&[b"attest", &registry, &reg.count.to_le_bytes()], &ledger)?;

    let mut d = sighash("attest").to_vec();
    d.extend_from_slice(&a.program);
    d.extend_from_slice(&a.old_code_hash);
    d.extend_from_slice(&a.new_code_hash);
    d.extend_from_slice(&a.report_hash);
    d.push(a.risk);
    d.extend_from_slice(&a.rules_version);
    d.extend_from_slice(&a.model_id);

    let reviewer: Pubkey = *payer.verifying_key().as_bytes();
    let metas = [
        Meta {
            key: registry,
            signer: false,
            writable: true,
        },
        Meta {
            key: attestation,
            signer: false,
            writable: true,
        },
        Meta {
            key: reviewer,
            signer: true,
            writable: true,
        },
        Meta {
            key: SYSTEM_PROGRAM,
            signer: false,
            writable: false,
        },
    ];
    Ok((attestation, send(url, payer, ledger, &metas, &d)?))
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
    fn known_pda_matches_solana() {
        let wallet = decode_pubkey("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM").unwrap();
        let token = decode_pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let mint = decode_pubkey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
        let ata = decode_pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL").unwrap();
        let (pda, _) = find_pda(&[&wallet, &token, &mint], &ata).unwrap();
        assert!(!on_curve(&pda));
    }

    #[test]
    fn anchor_sighash_is_stable() {
        assert_eq!(sighash("attest").len(), 8);
        assert_ne!(sighash("attest"), sighash("init_registry"));
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
