use anchor_lang::prelude::*;
use anchor_lang::solana_program::bpf_loader_upgradeable::{self, UpgradeableLoaderState};
use anchor_lang::solana_program::hash::hashv;

declare_id!("8f43wqFP4wZ8NLrJgBrGXDrXp92FgxSvM9Ng21GrgPq6");

pub const MAX_RISK: u8 = 4;
pub const APPROVAL_DOMAIN: &[u8] = b"tidemark/approval/v1";
const PROGRAM_DATA_HEADER: usize = 45;

#[program]
pub mod tidemark_ledger {
    use super::*;

    pub fn init_registry(ctx: Context<InitRegistry>, name: [u8; 32], threshold: u8) -> Result<()> {
        require!(threshold >= 1, LedgerError::BadThreshold);
        let reg = &mut ctx.accounts.registry;
        reg.seed_key = ctx.accounts.authority.key();
        reg.authority = ctx.accounts.authority.key();
        reg.pending_authority = Pubkey::default();
        reg.config_version = 0;
        reg.name = name;
        reg.count = 0;
        reg.last_hash = [0u8; 32];
        reg.threshold = threshold;
        reg.active_reviewers = 0;
        reg.bump = ctx.bumps.registry;
        Ok(())
    }

    pub fn add_reviewer(ctx: Context<AddReviewer>, key: Pubkey) -> Result<()> {
        let reg = &mut ctx.accounts.registry;
        let r = &mut ctx.accounts.reviewer;
        r.registry = reg.key();
        r.key = key;
        r.active = true;
        r.added_slot = Clock::get()?.slot;
        r.bump = ctx.bumps.reviewer;
        reg.active_reviewers = reg.active_reviewers.checked_add(1).ok_or(LedgerError::Overflow)?;
        reg.bump_config()?;
        emit!(ReviewerChanged { registry: reg.key(), key, active: true });
        Ok(())
    }

    pub fn set_reviewer_active(ctx: Context<SetReviewer>, active: bool) -> Result<()> {
        let reg = &mut ctx.accounts.registry;
        let r = &mut ctx.accounts.reviewer;
        if r.active == active {
            return Ok(());
        }
        if active {
            reg.active_reviewers = reg.active_reviewers.checked_add(1).ok_or(LedgerError::Overflow)?;
        } else {
            let left = reg.active_reviewers.checked_sub(1).ok_or(LedgerError::Overflow)?;
            require!(left >= reg.threshold as u16, LedgerError::BelowThreshold);
            reg.active_reviewers = left;
        }
        r.active = active;
        reg.bump_config()?;
        emit!(ReviewerChanged { registry: reg.key(), key: r.key, active });
        Ok(())
    }

    pub fn set_threshold(ctx: Context<AuthorityOnly>, threshold: u8) -> Result<()> {
        let reg = &mut ctx.accounts.registry;
        require!(threshold >= 1, LedgerError::BadThreshold);
        require!(threshold as u16 <= reg.active_reviewers, LedgerError::BelowThreshold);
        reg.threshold = threshold;
        reg.bump_config()
    }

    pub fn propose_authority(ctx: Context<AuthorityOnly>, new_authority: Pubkey) -> Result<()> {
        ctx.accounts.registry.pending_authority = new_authority;
        Ok(())
    }

    pub fn accept_authority(ctx: Context<AcceptAuthority>) -> Result<()> {
        let reg = &mut ctx.accounts.registry;
        reg.authority = ctx.accounts.new_authority.key();
        reg.pending_authority = Pubkey::default();
        reg.bump_config()
    }

    pub fn attest(ctx: Context<Attest>, args: AttestArgs) -> Result<()> {
        require!(args.risk <= MAX_RISK, LedgerError::BadRisk);
        let deployed_slot = deployed(
            &ctx.accounts.target_program,
            &ctx.accounts.program_data,
            args.elf_len,
            &args.new_code_hash,
        )?;
        let reg = &mut ctx.accounts.registry;
        let a = &mut ctx.accounts.attestation;

        a.registry = reg.key();
        a.index = reg.count;
        a.program = ctx.accounts.target_program.key();
        a.program_data = ctx.accounts.program_data.key();
        a.deployed_slot = deployed_slot;
        a.config_version = reg.config_version;
        a.elf_len = args.elf_len;
        a.old_code_hash = args.old_code_hash;
        a.new_code_hash = args.new_code_hash;
        a.report_hash = args.report_hash;
        a.risk = args.risk;
        a.rules_version = args.rules_version;
        a.model_id = args.model_id;
        a.reviewer = ctx.accounts.signer.key();
        a.slot = Clock::get()?.slot;
        a.prev_hash = reg.last_hash;
        a.entry_hash = entry_hash(a);
        a.threshold = reg.threshold;
        a.approvals = 1;
        a.bump = ctx.bumps.attestation;

        let ap = &mut ctx.accounts.approval;
        ap.registry = reg.key();
        ap.attestation = a.key();
        ap.reviewer = a.reviewer;
        ap.slot = a.slot;
        ap.digest = approval_digest(&a.entry_hash);
        ap.bump = ctx.bumps.approval;

        reg.last_hash = a.entry_hash;
        reg.count = reg.count.checked_add(1).ok_or(LedgerError::Overflow)?;

        emit!(Attested {
            index: a.index,
            program: a.program,
            risk: a.risk,
            report_hash: a.report_hash,
            entry_hash: a.entry_hash,
            approvals: a.approvals,
            threshold: a.threshold,
        });
        Ok(())
    }

    pub fn approve(ctx: Context<Approve>, digest: [u8; 32]) -> Result<()> {
        let a = &mut ctx.accounts.attestation;
        require!(approval_digest(&a.entry_hash) == digest, LedgerError::DigestMismatch);
        a.approvals = a.approvals.checked_add(1).ok_or(LedgerError::Overflow)?;

        let ap = &mut ctx.accounts.approval;
        ap.registry = ctx.accounts.registry.key();
        ap.attestation = a.key();
        ap.reviewer = ctx.accounts.signer.key();
        ap.slot = Clock::get()?.slot;
        ap.digest = digest;
        ap.bump = ctx.bumps.approval;

        emit!(Approved {
            index: a.index,
            reviewer: ap.reviewer,
            approvals: a.approvals,
            threshold: a.threshold,
        });
        Ok(())
    }
}

fn deployed(
    program: &UncheckedAccount,
    program_data: &UncheckedAccount,
    elf_len: u32,
    want: &[u8; 32],
) -> Result<u64> {
    require!(elf_len > 0, LedgerError::DeployedMismatch);
    require_keys_eq!(*program.owner, bpf_loader_upgradeable::id(), LedgerError::NotUpgradeable);
    require_keys_eq!(*program_data.owner, bpf_loader_upgradeable::id(), LedgerError::NotUpgradeable);
    let pdata = {
        let d = program.try_borrow_data()?;
        match bincode_state(&d)? {
            UpgradeableLoaderState::Program { programdata_address } => programdata_address,
            _ => return err!(LedgerError::NotUpgradeable),
        }
    };
    require_keys_eq!(pdata, program_data.key(), LedgerError::WrongProgramData);
    let d = program_data.try_borrow_data()?;
    let slot = match bincode_state(&d)? {
        UpgradeableLoaderState::ProgramData { slot, .. } => slot,
        _ => return err!(LedgerError::WrongProgramData),
    };
    let end = PROGRAM_DATA_HEADER
        .checked_add(elf_len as usize)
        .filter(|e| *e <= d.len())
        .ok_or(LedgerError::DeployedMismatch)?;
    let got = hashv(&[&d[PROGRAM_DATA_HEADER..end]]).to_bytes();
    require!(got == *want, LedgerError::DeployedMismatch);
    Ok(slot)
}

fn bincode_state(d: &[u8]) -> Result<UpgradeableLoaderState> {
    let tag = d.get(..4).ok_or(LedgerError::NotUpgradeable)?;
    match u32::from_le_bytes(tag.try_into().unwrap()) {
        2 => {
            let k = d.get(4..36).ok_or(LedgerError::NotUpgradeable)?;
            Ok(UpgradeableLoaderState::Program {
                programdata_address: Pubkey::try_from(k).unwrap(),
            })
        }
        3 => {
            let slot = d.get(4..12).ok_or(LedgerError::WrongProgramData)?;
            let slot = u64::from_le_bytes(slot.try_into().unwrap());
            let authority = match d.get(12) {
                Some(1) => Some(Pubkey::try_from(&d[13..45]).unwrap()),
                _ => None,
            };
            Ok(UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority_address: authority,
            })
        }
        _ => err!(LedgerError::NotUpgradeable),
    }
}

pub fn approval_digest(entry_hash: &[u8; 32]) -> [u8; 32] {
    hashv(&[APPROVAL_DOMAIN, entry_hash]).to_bytes()
}

impl RegistryV3 {
    fn bump_config(&mut self) -> Result<()> {
        self.config_version = self.config_version.checked_add(1).ok_or(LedgerError::Overflow)?;
        Ok(())
    }
}

pub fn entry_hash(a: &AttestationV3) -> [u8; 32] {
    hashv(&[
        &a.index.to_le_bytes(),
        a.registry.as_ref(),
        a.program.as_ref(),
        &a.old_code_hash,
        &a.new_code_hash,
        &a.report_hash,
        &[a.risk],
        &a.rules_version,
        &a.model_id,
        a.reviewer.as_ref(),
        &a.slot.to_le_bytes(),
        &a.prev_hash,
        a.program_data.as_ref(),
        &a.deployed_slot.to_le_bytes(),
        &a.config_version.to_le_bytes(),
        &a.elf_len.to_le_bytes(),
    ])
    .to_bytes()
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct AttestArgs {
    pub old_code_hash: [u8; 32],
    pub new_code_hash: [u8; 32],
    pub report_hash: [u8; 32],
    pub risk: u8,
    pub rules_version: [u8; 16],
    pub model_id: [u8; 32],
    pub elf_len: u32,
}

#[derive(Accounts)]
pub struct InitRegistry<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + RegistryV3::INIT_SPACE,
        seeds = [b"registry3", authority.key().as_ref()],
        bump
    )]
    pub registry: Account<'info, RegistryV3>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(key: Pubkey)]
pub struct AddReviewer<'info> {
    #[account(mut, has_one = authority @ LedgerError::NotAuthority)]
    pub registry: Account<'info, RegistryV3>,
    #[account(
        init,
        payer = payer,
        space = 8 + Reviewer::INIT_SPACE,
        seeds = [b"reviewer", registry.key().as_ref(), key.as_ref()],
        bump
    )]
    pub reviewer: Account<'info, Reviewer>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetReviewer<'info> {
    #[account(mut, has_one = authority @ LedgerError::NotAuthority)]
    pub registry: Account<'info, RegistryV3>,
    #[account(
        mut,
        seeds = [b"reviewer", registry.key().as_ref(), reviewer.key.as_ref()],
        bump = reviewer.bump
    )]
    pub reviewer: Account<'info, Reviewer>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct AuthorityOnly<'info> {
    #[account(mut, has_one = authority @ LedgerError::NotAuthority)]
    pub registry: Account<'info, RegistryV3>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct AcceptAuthority<'info> {
    #[account(
        mut,
        constraint = registry.pending_authority == new_authority.key()
            && registry.pending_authority != Pubkey::default() @ LedgerError::NotPendingAuthority
    )]
    pub registry: Account<'info, RegistryV3>,
    pub new_authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Attest<'info> {
    #[account(mut)]
    pub registry: Account<'info, RegistryV3>,
    #[account(
        seeds = [b"reviewer", registry.key().as_ref(), signer.key().as_ref()],
        bump = reviewer.bump,
        constraint = reviewer.active @ LedgerError::NotReviewer
    )]
    pub reviewer: Account<'info, Reviewer>,
    #[account(
        init,
        payer = payer,
        space = 8 + AttestationV3::INIT_SPACE,
        seeds = [b"attest3", registry.key().as_ref(), &registry.count.to_le_bytes()],
        bump
    )]
    pub attestation: Account<'info, AttestationV3>,
    #[account(
        init,
        payer = payer,
        space = 8 + ApprovalV3::INIT_SPACE,
        seeds = [b"approval", attestation.key().as_ref(), signer.key().as_ref()],
        bump
    )]
    pub approval: Account<'info, ApprovalV3>,
    /// CHECK: owner and layout are checked in `deployed`
    pub target_program: UncheckedAccount<'info>,
    /// CHECK: must be the ProgramData named by `target_program`, checked in `deployed`
    pub program_data: UncheckedAccount<'info>,
    pub signer: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Approve<'info> {
    pub registry: Account<'info, RegistryV3>,
    #[account(
        seeds = [b"reviewer", registry.key().as_ref(), signer.key().as_ref()],
        bump = reviewer.bump,
        constraint = reviewer.active @ LedgerError::NotReviewer
    )]
    pub reviewer: Account<'info, Reviewer>,
    #[account(mut, has_one = registry @ LedgerError::WrongRegistry)]
    pub attestation: Account<'info, AttestationV3>,
    #[account(
        init,
        payer = payer,
        space = 8 + ApprovalV3::INIT_SPACE,
        seeds = [b"approval", attestation.key().as_ref(), signer.key().as_ref()],
        bump
    )]
    pub approval: Account<'info, ApprovalV3>,
    pub signer: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct RegistryV3 {
    pub seed_key: Pubkey,
    pub authority: Pubkey,
    pub pending_authority: Pubkey,
    pub name: [u8; 32],
    pub count: u64,
    pub last_hash: [u8; 32],
    pub threshold: u8,
    pub active_reviewers: u16,
    pub config_version: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Reviewer {
    pub registry: Pubkey,
    pub key: Pubkey,
    pub active: bool,
    pub added_slot: u64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct AttestationV3 {
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
    pub program_data: Pubkey,
    pub deployed_slot: u64,
    pub config_version: u64,
    pub elf_len: u32,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct ApprovalV3 {
    pub registry: Pubkey,
    pub attestation: Pubkey,
    pub reviewer: Pubkey,
    pub slot: u64,
    pub digest: [u8; 32],
    pub bump: u8,
}

#[event]
pub struct Attested {
    pub index: u64,
    pub program: Pubkey,
    pub risk: u8,
    pub report_hash: [u8; 32],
    pub entry_hash: [u8; 32],
    pub approvals: u8,
    pub threshold: u8,
}

#[event]
pub struct Approved {
    pub index: u64,
    pub reviewer: Pubkey,
    pub approvals: u8,
    pub threshold: u8,
}

#[event]
pub struct ReviewerChanged {
    pub registry: Pubkey,
    pub key: Pubkey,
    pub active: bool,
}

#[error_code]
pub enum LedgerError {
    #[msg("risk must be 0..=4")]
    BadRisk,
    #[msg("counter overflow")]
    Overflow,
    #[msg("threshold must be at least 1")]
    BadThreshold,
    #[msg("threshold would exceed the number of active reviewers")]
    BelowThreshold,
    #[msg("signer is not the registry authority")]
    NotAuthority,
    #[msg("signer is not the pending authority")]
    NotPendingAuthority,
    #[msg("signer is not an active reviewer of this registry")]
    NotReviewer,
    #[msg("attestation belongs to a different registry")]
    WrongRegistry,
    #[msg("approval digest does not match the attestation")]
    DigestMismatch,
    #[msg("target is not a program owned by the upgradeable loader")]
    NotUpgradeable,
    #[msg("program_data is not the target program's ProgramData")]
    WrongProgramData,
    #[msg("deployed bytes do not hash to the reviewed new_code_hash")]
    DeployedMismatch,
}
