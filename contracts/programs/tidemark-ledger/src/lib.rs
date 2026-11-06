use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;

declare_id!("BFZg7MYzVzz1YypfmF2B6p842CXx33SBFGmSGep2TLLc");

#[program]
pub mod tidemark_ledger {
    use super::*;

    pub fn init_registry(ctx: Context<InitRegistry>, name: [u8; 32]) -> Result<()> {
        let reg = &mut ctx.accounts.registry;
        reg.authority = ctx.accounts.authority.key();
        reg.name = name;
        reg.count = 0;
        reg.last_hash = [0u8; 32];
        reg.bump = ctx.bumps.registry;
        Ok(())
    }

    pub fn attest(ctx: Context<Attest>, args: AttestArgs) -> Result<()> {
        require!(args.risk <= 4, LedgerError::BadRisk);
        let reg = &mut ctx.accounts.registry;
        let a = &mut ctx.accounts.attestation;
        let clock = Clock::get()?;

        a.registry = reg.key();
        a.index = reg.count;
        a.program = args.program;
        a.old_code_hash = args.old_code_hash;
        a.new_code_hash = args.new_code_hash;
        a.report_hash = args.report_hash;
        a.risk = args.risk;
        a.rules_version = args.rules_version;
        a.model_id = args.model_id;
        a.reviewer = ctx.accounts.reviewer.key();
        a.slot = clock.slot;
        a.prev_hash = reg.last_hash;
        a.entry_hash = entry_hash(a);
        a.bump = ctx.bumps.attestation;

        reg.last_hash = a.entry_hash;
        reg.count = reg.count.checked_add(1).ok_or(LedgerError::Overflow)?;

        emit!(Attested {
            index: a.index,
            program: a.program,
            risk: a.risk,
            report_hash: a.report_hash,
            entry_hash: a.entry_hash,
        });
        Ok(())
    }
}

pub fn entry_hash(a: &Attestation) -> [u8; 32] {
    hashv(&[
        &a.index.to_le_bytes(),
        a.program.as_ref(),
        &a.old_code_hash,
        &a.new_code_hash,
        &a.report_hash,
        &[a.risk],
        &a.rules_version,
        &a.model_id,
        a.reviewer.as_ref(),
        &a.prev_hash,
    ])
    .to_bytes()
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct AttestArgs {
    pub program: Pubkey,
    pub old_code_hash: [u8; 32],
    pub new_code_hash: [u8; 32],
    pub report_hash: [u8; 32],
    pub risk: u8,
    pub rules_version: [u8; 16],
    pub model_id: [u8; 32],
}

#[derive(Accounts)]
pub struct InitRegistry<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + Registry::INIT_SPACE,
        seeds = [b"registry", authority.key().as_ref()],
        bump
    )]
    pub registry: Account<'info, Registry>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Attest<'info> {
    #[account(mut, seeds = [b"registry", registry.authority.as_ref()], bump = registry.bump)]
    pub registry: Account<'info, Registry>,
    #[account(
        init,
        payer = reviewer,
        space = 8 + Attestation::INIT_SPACE,
        seeds = [b"attest", registry.key().as_ref(), &registry.count.to_le_bytes()],
        bump
    )]
    pub attestation: Account<'info, Attestation>,
    #[account(mut)]
    pub reviewer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct Registry {
    pub authority: Pubkey,
    pub name: [u8; 32],
    pub count: u64,
    pub last_hash: [u8; 32],
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Attestation {
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
    pub bump: u8,
}

#[event]
pub struct Attested {
    pub index: u64,
    pub program: Pubkey,
    pub risk: u8,
    pub report_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

#[error_code]
pub enum LedgerError {
    #[msg("risk must be 0..=4")]
    BadRisk,
    #[msg("attestation counter overflow")]
    Overflow,
}
