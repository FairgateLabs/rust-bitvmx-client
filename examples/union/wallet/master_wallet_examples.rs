// use anyhow::Result;
// use bitcoin::{Address, Network};
// use std::str::FromStr;
// use tracing::info;

// use crate::wallet::master_wallet::MasterWallet;

// Example function demonstrating the new BDK-based MasterWallet
// pub fn master_wallet_example() -> Result<()> {
//     info!("Running MasterWallet example");

//     let mut master_wallet = MasterWallet::new(Network::Regtest, None, None)?;

//     info!(
//         "Master wallet created for network: {:?}",
//         master_wallet.network()
//     );

//     // Sync the wallet first
//     master_wallet.sync()?;

//     // Get initial balance
//     match master_wallet.get_balance() {
//         Ok(balance) => info!("Current wallet balance: {} sats", balance),
//         Err(e) => info!("Failed to get balance: {}", e),
//     }

//     // Example funding
//     // Use a known valid regtest address
//     let address = Address::from_str("bcrt1quaepd6400as98jjs2ghd9mm8rfvlvvxqwtmslt")
//         .unwrap()
//         .assume_checked();

//     let amount_sats = 100_000; // 0.001 BTC
//     let fee_rate = Some(10); // Custom fee rate: 10 sat/vB

//     info!("Attempting to fund address: {}", address);
//     info!("Amount: {} sats", amount_sats);

//     // Use the new direct address funding method
//     match master_wallet.fund_address_with_fee(&address, amount_sats, fee_rate) {
//         Ok(tx) => {
//             info!(
//                 "Successfully funded address. Transaction ID: {}",
//                 tx.compute_txid()
//             );
//         }
//         Err(e) => {
//             info!("Failed to fund address: {}", e);
//         }
//     }

//     // sync and check balance
//     master_wallet.sync()?; // not sure we need this sync

//     match master_wallet.get_balance() {
//         Ok(balance) => info!("Current wallet balance: {} sats", balance),
//         Err(e) => info!("Failed to get balance: {}", e),
//     }

//     // Fund address without custom fee (uses default)
//     let amount_sats = 50_000; // 0.0005 BTC

//     info!("Funding address without custom fee: {}", address);
//     match master_wallet.fund_address(&address, amount_sats) {
//         Ok(tx) => {
//             info!(
//                 "Successfully funded address with default fee. TXID: {}",
//                 tx.compute_txid()
//             );
//         }
//         Err(e) => {
//             info!("Failed to fund address: {}", e);
//         }
//     }

//     // sync and check balance
//     master_wallet.sync()?;

//     match master_wallet.get_balance() {
//         Ok(balance) => info!("Current wallet balance: {} sats", balance),
//         Err(e) => info!("Failed to get balance: {}", e),
//     }

//     info!("MasterWallet regtest example completed");
//     Ok(())
// }
