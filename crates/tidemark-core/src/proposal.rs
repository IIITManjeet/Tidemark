use crate::census::SQUADS_V4;
use crate::rpc::UPGRADEABLE_LOADER;
use crate::submit::{decode_pubkey, find_pda, Pubkey};
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

const UPGRADE_TAG: [u8; 4] = [3, 0, 0, 0];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upgrade {
    pub program: String,
    pub buffer: String,
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|e| *e <= self.data.len())
            .ok_or_else(|| anyhow::anyhow!("transaction account is truncated"))?;
        let out = &self.data[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?) as usize)
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()?;
        self.take(n)
    }
}

pub fn vault_transaction_discriminator() -> [u8; 8] {
    let h = Sha256::digest(b"account:VaultTransaction");
    h[..8].try_into().expect("8 bytes")
}

pub fn transaction_address(multisig: &str, index: u64) -> Result<String> {
    let ms = decode_pubkey(multisig)?;
    let (pda, _) = find_pda(
        &[b"multisig", &ms, b"transaction", &index.to_le_bytes()],
        &decode_pubkey(SQUADS_V4)?,
    )?;
    Ok(crate::bs58_encode(&pda))
}

pub fn parse_vault_transaction(data: &[u8]) -> Result<Vec<Upgrade>> {
    if data.len() < 8 || data[..8] != vault_transaction_discriminator() {
        bail!("not a Squads v4 VaultTransaction account");
    }
    let mut r = Reader { data, at: 8 };
    r.take(32 + 32 + 8 + 3)?;
    r.bytes()?;
    r.take(3)?;
    let nkeys = r.u32()?;
    let mut keys: Vec<Pubkey> = Vec::new();
    for _ in 0..nkeys {
        keys.push(r.take(32)?.try_into()?);
    }
    let ninsns = r.u32()?;
    let loader = decode_pubkey(UPGRADEABLE_LOADER)?;
    let mut found = Vec::new();
    for _ in 0..ninsns {
        let program_id = r.u8()? as usize;
        let accounts = r.bytes()?;
        let ix_data = r.bytes()?;
        if program_id >= keys.len() && ix_data.get(..4) == Some(&UPGRADE_TAG[..]) {
            bail!("an instruction's program comes from an address lookup table, which is not read yet");
        }
        if keys.get(program_id) != Some(&loader) || ix_data.get(..4) != Some(&UPGRADE_TAG[..]) {
            continue;
        }
        if accounts.len() < 3 {
            bail!("upgrade instruction has too few accounts");
        }
        let key = |i: u8| {
            keys.get(i as usize)
                .ok_or_else(|| anyhow::anyhow!("upgrade instruction references a missing account"))
        };
        found.push(Upgrade {
            program: crate::bs58_encode(key(accounts[1])?),
            buffer: crate::bs58_encode(key(accounts[2])?),
        });
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: &str = "11111111111111111111111111111112";

    fn put_vec(out: &mut Vec<u8>, v: &[u8]) {
        out.extend((v.len() as u32).to_le_bytes());
        out.extend(v);
    }

    fn build(disc: [u8; 8], keys: &[Pubkey], ixs: &[(u8, &[u8], &[u8])]) -> Vec<u8> {
        let mut d = disc.to_vec();
        d.extend([1u8; 32]);
        d.extend([2u8; 32]);
        d.extend(7u64.to_le_bytes());
        d.extend([255, 0, 254]);
        put_vec(&mut d, &[9, 9]);
        d.extend([1, 1, 0]);
        d.extend((keys.len() as u32).to_le_bytes());
        for k in keys {
            d.extend(k);
        }
        d.extend((ixs.len() as u32).to_le_bytes());
        for (p, a, data) in ixs {
            d.push(*p);
            put_vec(&mut d, a);
            put_vec(&mut d, data);
        }
        d.extend(0u32.to_le_bytes());
        d
    }

    fn loader() -> Pubkey {
        decode_pubkey(UPGRADEABLE_LOADER).unwrap()
    }

    #[test]
    fn finds_the_upgrade_instruction() {
        let keys = [[10u8; 32], [11; 32], [12; 32], loader(), [13; 32]];
        let data = build(
            vault_transaction_discriminator(),
            &keys,
            &[(4, &[1], &[0, 0, 0, 0]), (3, &[0, 1, 2, 4], &[3, 0, 0, 0])],
        );
        assert_eq!(
            parse_vault_transaction(&data).unwrap(),
            vec![Upgrade {
                program: crate::bs58_encode(&keys[1]),
                buffer: crate::bs58_encode(&keys[2]),
            }]
        );
    }

    #[test]
    fn ignores_other_instructions() {
        let keys = [[10u8; 32], loader()];
        let data = build(
            vault_transaction_discriminator(),
            &keys,
            &[
                (1, &[0, 0, 0], &[4, 0, 0, 0]),
                (0, &[0, 0, 0], &[3, 0, 0, 0]),
            ],
        );
        assert!(parse_vault_transaction(&data).unwrap().is_empty());
    }

    #[test]
    fn rejects_wrong_discriminator_and_truncation() {
        let keys = [[10u8; 32], loader()];
        let data = build([0; 8], &keys, &[]);
        assert!(parse_vault_transaction(&data).is_err());
        let good = build(vault_transaction_discriminator(), &keys, &[]);
        assert!(parse_vault_transaction(&good[..good.len() - 6]).is_err());
        assert!(parse_vault_transaction(&[]).is_err());
    }

    #[test]
    fn rejects_out_of_range_account_index() {
        let keys = [loader()];
        let data = build(
            vault_transaction_discriminator(),
            &keys,
            &[(0, &[0, 5, 6], &[3, 0, 0, 0])],
        );
        assert!(parse_vault_transaction(&data).is_err());
    }

    #[test]
    fn refuses_an_upgrade_from_a_lookup_table() {
        let keys = [[7u8; 32]];
        let data = build(
            vault_transaction_discriminator(),
            &keys,
            &[(3, &[0, 0, 0], &[3, 0, 0, 0])],
        );
        assert!(parse_vault_transaction(&data).is_err());
    }

    #[test]
    fn transaction_address_is_stable_and_per_index() {
        let a = transaction_address(MS, 1).unwrap();
        assert_eq!(a, transaction_address(MS, 1).unwrap());
        assert_ne!(a, transaction_address(MS, 2).unwrap());
        assert_eq!(decode_pubkey(&a).unwrap().len(), 32);
        assert!(transaction_address("nope", 1).is_err());
    }
}
