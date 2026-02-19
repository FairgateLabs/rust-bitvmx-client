#![cfg(test)]
use anyhow::Result;
use bitcoin::Network;
use bitcoin_coordinator::coordinator::{BitcoinCoordinator, BitcoinCoordinatorApi};
use bitcoin_coordinator::types::CoordinatorNews;
use bitcoind::{bitcoind::Bitcoind, config::BitcoindConfig};
use bitvmx_client::config::Config;
use bitvmx_wallet::{Destination, RegtestWallet, Wallet};
use key_manager::config::KeyManagerConfig;
use key_manager::create_key_manager_from_config;
use std::rc::Rc;
use storage_backend::storage::Storage;
use storage_backend::storage_config::StorageConfig;
use tracing::info;

use crate::common::{clear_db, config_trace};

mod common;

/// TESTNET test: test for retry mechanism of failed transactions in the Bitcoin coordinator.
///
/// This test verifies that the Bitcoin coordinator properly handles and reports
/// transaction dispatch errors when transactions fail to be processed. The test
/// creates two transactions chained together (causing the second one to fail because the first one was not in the mempool).
/// This failure occurs because QuikNode takes time to update or propagate transactions.
#[ignore]
#[test]
fn retry_failed_txs_test() -> Result<()> {
    config_trace();

    let config_path = "config/wallet_testnet.yaml";

    let wallet_config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::wallet::config::Config,
    >(Some(config_path.to_string()))?;

    info!("Wallet settings loaded");

    clear_db(&wallet_config.storage.path);
    clear_db(&wallet_config.key_storage.path);
    Wallet::clear_db(&wallet_config.wallet)?;

    let bitcoind = Bitcoind::new(
        BitcoindConfig::default(),
        wallet_config.bitcoin.clone(),
        None,
    );

    bitcoind.start()?;

    let mut wallet =
        Wallet::from_config(wallet_config.bitcoin.clone(), wallet_config.wallet.clone())?;

    wallet.sync_wallet()?;

    info!("Wallet ready");

    let amount = 20_000;
    let amount2 = 10_000;
    let destination_tx1 = Destination::P2WPKH(wallet.public_key, amount);
    let destination_tx2 = Destination::P2WPKH(wallet.public_key, amount2);
    let fee_rate = 2000;
    let tx1 = wallet.create_tx(destination_tx1, Some(fee_rate))?;
    wallet.update_with_tx(&tx1)?;
    let tx2 = wallet.create_tx(destination_tx2, Some(fee_rate))?;

    // Create storage and key manager
    let network = Network::Regtest;
    let storage_config = StorageConfig::new(wallet_config.storage.path.clone(), None);
    let storage = Rc::new(Storage::new(&storage_config).unwrap());
    let keymanger_config = KeyManagerConfig::new(network.to_string(), None, None);
    let key_manager =
        Rc::new(create_key_manager_from_config(&keymanger_config, &storage_config).unwrap());

    let config = Config::new(Some("config/development.yaml".to_string()))?;
    let settings = config.coordinator_settings.clone().unwrap();
    let coordinator = Rc::new(BitcoinCoordinator::new_with_paths(
        &wallet_config.bitcoin,
        storage.clone(),
        key_manager.clone(),
        Some(settings.clone()),
    )?);

    coordinator.dispatch(tx1, None, "test_1".to_string(), None, Some(1))?;
    coordinator.dispatch(tx2, None, "test_2".to_string(), None, Some(1))?;

    for _ in 0..10 {
        coordinator.tick()?;
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    let news = coordinator.get_news()?;
    let mut has_dispatch_error = false;

    for news_item in news.coordinator_news.iter() {
        if let CoordinatorNews::DispatchTransactionError(_, _, _) = news_item {
            has_dispatch_error = true;
            break;
        }
    }

    assert!(
        has_dispatch_error,
        "Expected at least one DispatchTransactionError"
    );

    Ok(())
}
