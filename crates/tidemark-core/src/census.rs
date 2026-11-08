use crate::submit::{decode_pubkey, find_pda, on_curve};
use serde::Serialize;
use sha2::Digest;

pub const SQUADS_V4: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";
pub const SQUADS_V3: &str = "SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu";
pub const SPL_GOVERNANCE: &str = "GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw";
const SYSTEM: &str = "11111111111111111111111111111111";
#[cfg(feature = "net")]
const LEGACY_LOADERS: [&str; 3] = [
    "BPFLoader1111111111111111111111111111111111",
    "BPFLoader2111111111111111111111111111111111",
    "NativeLoader1111111111111111111111111111111",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Control {
    Immutable,
    SingleKey,
    Multisig {
        program: String,
    },
    SquadsVault {
        multisig: String,
        index: u8,
        config: Option<SquadsConfig>,
    },
    Governance,
    ProgramControlled {
        owner: Option<String>,
    },
}

impl Control {
    pub fn label(&self) -> String {
        match self {
            Control::Immutable => "immutable".into(),
            Control::SingleKey => "single key".into(),
            Control::Multisig { program } if program == SQUADS_V4 => "multisig (Squads v4)".into(),
            Control::Multisig { .. } => "multisig (Squads v3)".into(),
            Control::SquadsVault {
                config: Some(c), ..
            } => format!(
                "multisig (Squads v4, {} of {}, {} timelock)",
                c.threshold,
                c.voters,
                timelock(c.time_lock)
            ),
            Control::SquadsVault { .. } => "multisig (Squads v4)".into(),
            Control::Governance => "governance (SPL Governance)".into(),
            Control::ProgramControlled { owner: Some(o) } => {
                format!("program-controlled (owner {o})")
            }
            Control::ProgramControlled { owner: None } => "program-controlled (PDA)".into(),
        }
    }
}

pub fn classify(authority: Option<&str>, authority_owner: Option<&str>) -> anyhow::Result<Control> {
    let Some(a) = authority else {
        return Ok(Control::Immutable);
    };
    if on_curve(&decode_pubkey(a)?) {
        return Ok(Control::SingleKey);
    }
    match authority_owner {
        Some(o @ (SQUADS_V4 | SQUADS_V3)) => return Ok(Control::Multisig { program: o.into() }),
        Some(SPL_GOVERNANCE) => return Ok(Control::Governance),
        _ => {}
    }
    Ok(Control::ProgramControlled {
        owner: authority_owner.filter(|o| *o != SYSTEM).map(String::from),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SquadsConfig {
    pub threshold: u16,
    pub members: u16,
    pub voters: u16,
    pub time_lock: u32,
}

fn timelock(secs: u32) -> String {
    match secs {
        0 => "no".into(),
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3_600 == 0 => format!("{}h", s / 3_600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

pub fn parse_squads_multisig(data: &[u8]) -> anyhow::Result<SquadsConfig> {
    let disc = sha2::Sha256::digest(b"account:Multisig");
    anyhow::ensure!(
        data.len() >= 8 && data[..8] == disc[..8],
        "not a Squads v4 multisig account"
    );
    let short = || anyhow::anyhow!("Squads multisig account is truncated");
    let at = |o: usize, n: usize| data.get(o..o + n).ok_or_else(short);
    let mut o = 8 + 32 + 32;
    let threshold = u16::from_le_bytes(at(o, 2)?.try_into()?);
    let time_lock = u32::from_le_bytes(at(o + 2, 4)?.try_into()?);
    o += 2 + 4 + 8 + 8;
    o += match at(o, 1)?[0] {
        0 => 1,
        1 => 33,
        _ => anyhow::bail!("bad rent collector in Squads multisig"),
    };
    o += 1;
    let n = u32::from_le_bytes(at(o, 4)?.try_into()?) as usize;
    o += 4;
    let members = at(o, n.checked_mul(33).ok_or_else(short)?)?;
    let voters = members.chunks(33).filter(|m| m[32] & 2 != 0).count();
    Ok(SquadsConfig {
        threshold,
        members: u16::try_from(n)?,
        voters: u16::try_from(voters)?,
        time_lock,
    })
}

pub const SQUADS_VAULTS_CHECKED: u8 = 8;

pub fn squads_v4_vault(multisig: &str, index: u8) -> anyhow::Result<String> {
    let ms = decode_pubkey(multisig)?;
    let (vault, _) = find_pda(
        &[b"multisig", &ms, b"vault", &[index]],
        &decode_pubkey(SQUADS_V4)?,
    )?;
    Ok(crate::bs58_encode(&vault))
}

pub fn squads_vault_of(
    authority: &str,
    multisigs: &[String],
) -> anyhow::Result<Option<(String, u8)>> {
    for ms in multisigs {
        for index in 0..SQUADS_VAULTS_CHECKED {
            if squads_v4_vault(ms, index)? == authority {
                return Ok(Some((ms.clone(), index)));
            }
        }
    }
    Ok(None)
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub program: String,
    pub control: Control,
    pub authority: Option<String>,
    pub last_deploy_slot: Option<u64>,
    pub security_txt: bool,
    pub error: Option<String>,
}

#[cfg(feature = "net")]
fn owner_of(rpc: &str, key: &str) -> anyhow::Result<Option<String>> {
    let r = crate::rpc::call(
        rpc,
        "getAccountInfo",
        serde_json::json!([key, {"encoding": "base64", "commitment": "finalized", "dataSlice": {"offset": 0, "length": 0}}]),
    )?;
    Ok(r["value"]["owner"].as_str().map(String::from))
}

#[cfg(feature = "net")]
fn squads_config(rpc: &str, multisig: &str) -> anyhow::Result<SquadsConfig> {
    use base64::Engine;
    let r = crate::rpc::call(
        rpc,
        "getAccountInfo",
        serde_json::json!([multisig, {"encoding": "base64", "commitment": "finalized"}]),
    )?;
    let data = r["value"]["data"][0]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("multisig {multisig} not found"))?;
    parse_squads_multisig(&base64::engine::general_purpose::STANDARD.decode(data)?)
}

#[cfg(feature = "net")]
pub fn survey(rpc: &str, program: &str, squads: &[String]) -> Entry {
    let mut e = Entry {
        program: program.to_string(),
        control: Control::Immutable,
        authority: None,
        last_deploy_slot: None,
        security_txt: false,
        error: None,
    };
    let run = |e: &mut Entry| -> anyhow::Result<()> {
        let owner = owner_of(rpc, program)?.ok_or_else(|| anyhow::anyhow!("account not found"))?;
        if LEGACY_LOADERS.contains(&owner.as_str()) {
            return Ok(());
        }
        if owner != crate::rpc::UPGRADEABLE_LOADER {
            anyhow::bail!("owned by {owner}, not a loader this census reads");
        }
        let d = crate::rpc::fetch(rpc, program)?;
        e.last_deploy_slot = Some(d.last_deploy_slot);
        e.security_txt = crate::elf::load(&d.elf).is_ok_and(|p| p.security_txt.is_some());
        let auth_owner = match &d.upgrade_authority {
            Some(a) => owner_of(rpc, a)?,
            None => None,
        };
        e.control = classify(d.upgrade_authority.as_deref(), auth_owner.as_deref())?;
        if let (Control::ProgramControlled { .. }, Some(a)) = (&e.control, &d.upgrade_authority) {
            if let Some((multisig, index)) = squads_vault_of(a, squads)? {
                if owner_of(rpc, &multisig)?.as_deref() == Some(SQUADS_V4) {
                    let config = squads_config(rpc, &multisig).ok();
                    e.control = Control::SquadsVault {
                        multisig,
                        index,
                        config,
                    };
                }
            }
        }
        e.authority = d.upgrade_authority;
        Ok(())
    };
    if let Err(err) = run(&mut e) {
        e.error = Some(err.to_string());
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    const WALLET: &str = "9fxLpiKzK1zeF42911g5ruKDdTuJFduJSEXcZHh4mCB1";
    const PDA: &str = "72HSqJR6Y2uiedNWVQxDDRXYr9LjB4cDUn3Me2AtenxU";

    #[test]
    fn squads_vault_is_derived_from_its_multisig() {
        let ms = "8jGmTqcvXfp8taPTq6u5Tmorbu7pByKGDmy4eYU2xki9";
        let vault = "GoEyAVg55y1u327W4x26zwbFoTQ3ChQEHzvQqrkBQCf2";
        assert_eq!(squads_v4_vault(ms, 0).unwrap(), vault);
        assert_eq!(
            squads_vault_of(vault, &[WALLET.to_string(), ms.to_string()]).unwrap(),
            Some((ms.to_string(), 0))
        );
        assert_eq!(squads_vault_of(PDA, &[ms.to_string()]).unwrap(), None);
    }

    fn multisig_account(rent_collector: bool, perms: &[u8]) -> Vec<u8> {
        let mut d = sha2::Sha256::digest(b"account:Multisig")[..8].to_vec();
        d.extend([0u8; 64]);
        d.extend(2u16.to_le_bytes());
        d.extend(3600u32.to_le_bytes());
        d.extend([0u8; 16]);
        if rent_collector {
            d.push(1);
            d.extend([9u8; 32]);
        } else {
            d.push(0);
        }
        d.push(255);
        d.extend((perms.len() as u32).to_le_bytes());
        for p in perms {
            d.extend([5u8; 32]);
            d.push(*p);
        }
        d
    }

    #[test]
    fn squads_multisig_config_is_read() {
        for rc in [false, true] {
            let c = parse_squads_multisig(&multisig_account(rc, &[7, 7, 1])).unwrap();
            assert_eq!(
                c,
                SquadsConfig {
                    threshold: 2,
                    members: 3,
                    voters: 2,
                    time_lock: 3600
                }
            );
        }
        let label = Control::SquadsVault {
            multisig: String::new(),
            index: 0,
            config: Some(parse_squads_multisig(&multisig_account(false, &[7, 7, 7])).unwrap()),
        }
        .label();
        assert_eq!(label, "multisig (Squads v4, 2 of 3, 1h timelock)");
    }

    #[test]
    fn bad_squads_accounts_are_refused() {
        let good = multisig_account(false, &[7, 7, 7]);
        assert!(parse_squads_multisig(&good[..good.len() - 1]).is_err());
        let mut wrong = good.clone();
        wrong[0] ^= 1;
        assert!(parse_squads_multisig(&wrong).is_err());
    }

    #[test]
    fn no_authority_is_immutable() {
        assert_eq!(classify(None, None).unwrap(), Control::Immutable);
    }

    #[test]
    fn on_curve_authority_is_a_single_key() {
        assert_eq!(
            classify(Some(WALLET), Some(SYSTEM)).unwrap(),
            Control::SingleKey
        );
    }

    #[test]
    fn pda_authority_is_program_controlled() {
        assert_eq!(
            classify(Some(PDA), Some(SYSTEM)).unwrap(),
            Control::ProgramControlled { owner: None }
        );
    }

    #[test]
    fn wallet_assigned_to_a_multisig_program_is_still_a_single_key() {
        assert_eq!(
            classify(Some(WALLET), Some(SQUADS_V4)).unwrap(),
            Control::SingleKey
        );
        assert_eq!(
            classify(Some(WALLET), Some(SPL_GOVERNANCE)).unwrap(),
            Control::SingleKey
        );
    }

    #[test]
    fn known_owners_are_named() {
        assert_eq!(
            classify(Some(PDA), Some(SQUADS_V4)).unwrap().label(),
            "multisig (Squads v4)"
        );
        assert_eq!(
            classify(Some(PDA), Some(SPL_GOVERNANCE)).unwrap(),
            Control::Governance
        );
    }
}
