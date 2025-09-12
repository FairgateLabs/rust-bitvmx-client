use anyhow::Result;
use bitcoin::{Address, Network};
use std::str::FromStr;
use tracing::info;

use super::MasterWallet;

/// Example function demonstrating the new BDK-based MasterWallet
pub fn run_master_wallet_example_regtest() -> Result<()> {
    info!("Running MasterWallet example");

    let mut master_wallet = MasterWallet::new(Some(Network::Regtest), None)?;

    info!("Master wallet created for network: {:?}", master_wallet.network());

    // Sync the wallet first
    master_wallet.sync()?;

    // Get initial balance
    match master_wallet.get_balance() {
        Ok(balance) => info!("Current wallet balance: {} sats", balance),
        Err(e) => info!("Failed to get balance: {}", e),
    }

    // Example funding
    // Use a known valid regtest address
    let address = Address::from_str("bcrt1quaepd6400as98jjs2ghd9mm8rfvlvvxqwtmslt")
        .unwrap()
        .assume_checked();

    let amount_sats = 100_000; // 0.001 BTC
    let fee_rate = Some(10); // Custom fee rate: 10 sat/vB

    info!("Attempting to fund address: {}", address);
    info!("Amount: {} sats", amount_sats);

    // Use the new direct address funding method
    match master_wallet.fund_address_with_fee(&address, amount_sats, fee_rate) {
        Ok(txid) => {
            info!("Successfully funded address. Transaction ID: {}", txid);
        },
        Err(e) => {
            info!("Failed to fund address: {}", e);
        }
    }

    // sync and check balance
    master_wallet.sync()?; // not sure we need this sync

    match master_wallet.get_balance() {
        Ok(balance) => info!("Current wallet balance: {} sats", balance),
        Err(e) => info!("Failed to get balance: {}", e),
    }

    // Fund address without custom fee (uses default)
    let amount_sats = 50_000; // 0.0005 BTC

    info!("Funding address without custom fee: {}", address);
    match master_wallet.fund_address(&address, amount_sats) {
        Ok(txid) => {
            info!("Successfully funded address with default fee. TXID: {}", txid);
        },
        Err(e) => {
            info!("Failed to fund address: {}", e);
        }
    }

    // sync and check balance
    master_wallet.sync()?;

    match master_wallet.get_balance() {
        Ok(balance) => info!("Current wallet balance: {} sats", balance),
        Err(e) => info!("Failed to get balance: {}", e),
    }

    info!("MasterWallet regtest example completed");
    Ok(())
}

/// Example function for testnet wallet - creates wallet and sends funds to itself (to waste the least amount of sats possible when testing)
pub fn run_master_wallet_example_testnet() -> Result<()> {
    info!("Running MasterWallet testnet example");

    // Note: For testnet, you need to provide a private key
    // let private_key = PrivateKey::from_str("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy")?;
    // let mut master_wallet = MasterWallet::new(Some(Network::Testnet), Some(private_key))?;

    info!("Testnet wallet creation commented out, requires private key");
    info!("To use testnet:");
    info!("Uncomment the private key and wallet creation lines above and replace with real testnet private key");

    // Example of self-funding (commented out)
    /*
    info!("Master wallet created for network: {:?}", master_wallet.network());

    // Sync the wallet
    master_wallet.sync()?;

    // Check balance
    match master_wallet.get_balance() {
        Ok(balance) => info!("Current wallet balance: {} sats", balance),
        Err(e) => info!("Failed to get balance: {}", e),
    }

    // Generate our own address to send to
    let self_address = master_wallet.receive_address()?;
    let amount_sats = 10_000; // 0.0001 BTC
    let fee_rate = Some(5); // 5 sat/vB

    info!("Would send {} sats to our own address: {}", amount_sats, self_address);

    // Send funds to ourselves
    // match master_wallet.fund_address_with_fee(&self_address, amount_sats, fee_rate) {
    //     Ok(txid) => info!("Self-funded with TXID: {}", txid),
    //     Err(e) => info!("Failed to self-fund: {}", e),
    // }
    */

    info!("MasterWallet testnet example completed");
    Ok(())
}
