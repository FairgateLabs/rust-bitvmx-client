use crate::{participants::member::Member, wallet::MasterWallet};
use anyhow::Result;

use tracing::info;
use uuid::Uuid;
const FEE_RATE: u64 = 10; // sats/vbyte

pub fn fund_members(wallet: &mut MasterWallet, members: &[Member], amount: u64) -> Result<()> {
    let balance = wallet.wallet.balance();
    info!("Master wallet balance:");
    info!("Confirmed: {} sats", balance.confirmed);
    info!("Untrusted: {} sats", balance.untrusted_pending);
    info!("Trusted: {} sats", balance.trusted_pending);
    info!("Immature: {} sats", balance.immature);

    info!("Funding each member with {} sats", amount);
    for member in members {
        let address = member.get_funding_address()?;

        let checked_address = address
            .require_network(wallet.network())
            .expect("address not valid for this network");

        let tx: bitcoin::Transaction =
            wallet.fund_address_with_fee(&checked_address, amount, Some(FEE_RATE))?;

        member
            .bitvmx
            .dispatch_transaction(Uuid::new_v4(), tx.clone())?;

        let txid = tx.compute_txid();
        info!("Funded member with txid: {}", txid);
    }

    info!("Master wallet balance after funding members:");
    let balance = wallet.wallet.balance();
    info!("Confirmed: {} sats", balance.confirmed);
    info!("Untrusted: {} sats", balance.untrusted_pending);
    info!("Trusted: {} sats", balance.trusted_pending);
    info!("Immature: {} sats", balance.immature);

    Ok(())
}

pub fn print_members_balances(members: &[Member]) -> Result<()> {
    for member in members {
        let balance = member.get_funding_balance()?;
        info!("Member {} balance: {} sats", member.id, balance);
    }
    Ok(())
}
