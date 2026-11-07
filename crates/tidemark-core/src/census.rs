use crate::submit::{decode_pubkey, on_curve};
use serde::Serialize;

pub const SQUADS_V4: &str = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf";
pub const SQUADS_V3: &str = "SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu";
pub const SPL_GOVERNANCE: &str = "GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw";
const SYSTEM: &str = "11111111111111111111111111111111";
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
    Multisig { program: String },
    Governance,
    ProgramControlled { owner: Option<String> },
}

impl Control {
    pub fn label(&self) -> String {
        match self {
            Control::Immutable => "immutable".into(),
            Control::SingleKey => "single key".into(),
            Control::Multisig { program } if program == SQUADS_V4 => "multisig (Squads v4)".into(),
            Control::Multisig { .. } => "multisig (Squads v3)".into(),
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
        serde_json::json!([key, {"encoding": "base64", "commitment": "confirmed", "dataSlice": {"offset": 0, "length": 0}}]),
    )?;
    Ok(r["value"]["owner"].as_str().map(String::from))
}

#[cfg(feature = "net")]
pub fn survey(rpc: &str, program: &str) -> Entry {
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
