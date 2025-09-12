use std::thread;

use crate::{
    participants::{common::non_regtest_warning, member::Member},
    MasterWallet,
};
use anyhow::Result;

use tracing::info;
use uuid::Uuid;
const FEE_RATE: u64 = 2; // sats/vbyte

pub fn fund_members(wallet: &mut MasterWallet, members: &[Member], amount: u64) -> Result<()> {
    non_regtest_warning(wallet.network(), "You are about to transfer REAL money.");

    let balance = wallet.wallet.balance();
    info!("Master wallet balance:");
    info!("Confirmed: {} sats", balance.confirmed.to_sat());
    info!("Untrusted: {} sats", balance.untrusted_pending.to_sat());
    info!("Trusted: {} sats", balance.trusted_pending.to_sat());
    info!("Immature: {} sats", balance.immature.to_sat());

    info!("Funding each member with {} sats", amount);
    for member in members {
        let address = member.get_funding_address()?;
        info!("Address: {:?}", address);

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
        thread::sleep(std::time::Duration::from_secs(5));
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
