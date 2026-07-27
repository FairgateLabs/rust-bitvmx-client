//! Proves the simchain premise before any of the heavier suites depend on it.
//!
//! Four things have to be true for BitVMX to run against simchain at all:
//!
//! 1. The BDK wallet can scan the chain over RPC against a `-disablewallet` node.
//! 2. The master wallet holds the coins the simnet bootstrap sent to `USER_ADDRESS`.
//! 3. A raw transaction broadcast at a fee above the spammer's floor gets mined,
//!    without us asking anybody to mine it.
//! 4. The mining and node-wallet guard rails actually refuse.
//!
//! Requires a running simchain stack (see SIMCHAIN.md):
//!
//! ```text
//! cargo test --release --test simchain_smoke -- --ignored --nocapture --test-threads=1
//! ```
#![cfg(test)]

use anyhow::Result;
use bitcoin::{Amount, Network};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_bitcoin_rpc::rpc_config::NetworkFlavor;
use bitvmx_wallet::wallet::{Destination, RegtestWallet, Wallet};
use std::time::{Duration, Instant};
use tracing::info;

mod common;
use common::config_trace;

const ENV: NetworkFlavor = NetworkFlavor::Simchain;

/// Above simchain's stock 15 sat/vB spam floor, so the transaction is competitive.
const FEE_RATE: u64 = 20;

fn load() -> Result<bitvmx_wallet::wallet::config::Config> {
    Ok(bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::wallet::config::Config,
    >(Some(ENV.wallet_config().to_string()))?)
}

/// Wait for `txid` to reach `min_confirmations`, without asking anyone to mine.
fn wait_for_confirmation(
    client: &BitcoinClient,
    txid: &bitcoin::Txid,
    min_confirmations: u32,
) -> Result<()> {
    let deadline = Instant::now() + ENV.block_wait_timeout();
    let start_height = client.get_best_block()?;

    loop {
        if let Some(entry) = client.get_mempool_entry(txid)? {
            info!(
                "tx {} still in mempool (fee {} sat, height {})",
                txid,
                entry.fees.base.to_sat(),
                client.get_best_block()?
            );
        }

        let height = client.get_best_block()?;
        if height >= start_height + min_confirmations {
            // Confirmed if the node no longer reports it as mempool-only.
            if client.get_mempool_entry(txid)?.is_none() && client.tx_exists(txid) {
                info!("tx {} confirmed by height {}", txid, height);
                return Ok(());
            }
        }

        if Instant::now() >= deadline {
            anyhow::bail!(
                "tx {txid} not confirmed within {:?} (height {} -> {}). \
                 Is the fee above simchain's floor, and is the chain still mining?",
                ENV.block_wait_timeout(),
                start_height,
                height
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[ignore]
#[test]
fn simchain_wallet_syncs_and_is_funded() -> Result<()> {
    config_trace();
    let config = load()?;

    let client = BitcoinClient::new_from_config(&config.bitcoin)?;
    let info = client.get_blockchain_info()?;
    assert_eq!(
        info.chain,
        Network::Regtest,
        "simchain must report itself as regtest"
    );
    info!("simchain height: {}", info.blocks);
    assert!(
        info.blocks >= 200,
        "simchain looks like it is still bootstrapping (height {})",
        info.blocks
    );

    // Fresh local state: proves the wallet can rebuild purely by scanning the chain,
    // which is the only option against a node with no wallet of its own.
    let _ = Wallet::clear_db(&config.wallet);
    let mut wallet = Wallet::from_config(config.bitcoin.clone(), config.wallet.clone())?;

    let address = wallet.receive_address()?;
    info!("master wallet address: {}", address);

    wallet.sync_wallet()?;
    let balance = wallet.balance();
    info!(
        "balance: confirmed {} / trusted pending {} / immature {}",
        balance.confirmed, balance.trusted_pending, balance.immature
    );

    assert!(
        balance.confirmed.to_sat() > 0,
        "master wallet has no confirmed funds. USER_ADDRESS in simchain's .env must \
         be {address}; see SIMCHAIN.md."
    );
    Ok(())
}

#[ignore]
#[test]
fn simchain_confirms_a_raw_broadcast() -> Result<()> {
    config_trace();
    let config = load()?;

    let client = BitcoinClient::new_from_config(&config.bitcoin)?;
    let mut wallet = Wallet::from_config(config.bitcoin.clone(), config.wallet.clone())?;
    wallet.sync_wallet()?;

    let before = wallet.balance().confirmed;
    assert!(before.to_sat() > 0, "run the funding smoke test first");

    // Pay ourselves: no second party needed, and the change path gets exercised too.
    let destination = Destination::P2WPKH(wallet.public_key, 100_000);

    // send_funds broadcasts a raw transaction. Nothing here asks the node to mine.
    let tx = wallet.send_funds(destination, Some(FEE_RATE))?;
    let txid = tx.compute_txid();
    info!("broadcast {} at {} sat/vB", txid, FEE_RATE);

    wait_for_confirmation(&client, &txid, 1)?;

    wallet.sync_wallet()?;
    info!("balance after: {}", wallet.balance().confirmed);
    Ok(())
}

/// The guard rails, exercised against the real node.
///
/// Unlike the unit tests in bitvmx-bitcoin-rpc and bitvmx-wallet, this proves the
/// rejection happens *before* any RPC goes out — simchain's node would genuinely serve
/// `generatetoaddress`, so a passing test here means we never sent it.
#[ignore]
#[test]
fn simchain_refuses_mining_and_node_wallet_calls() -> Result<()> {
    config_trace();
    let config = load()?;

    let client = BitcoinClient::new_from_config(&config.bitcoin)?;
    let height_before = client.get_best_block()?;

    let mut wallet = Wallet::from_config(config.bitcoin.clone(), config.wallet.clone())?;
    let address = wallet.receive_address()?;

    assert!(wallet.mine(1).is_err(), "Wallet::mine must refuse");
    assert!(wallet.fund().is_err(), "Wallet::fund must refuse");
    assert!(
        client.init_wallet("test_wallet").is_err(),
        "init_wallet must refuse"
    );
    assert!(
        client.mine_blocks_to_address(1, &address).is_err(),
        "mine_blocks_to_address must refuse"
    );
    assert!(
        client
            .fund_address(&address, Amount::from_sat(1_000))
            .is_err(),
        "fund_address must refuse"
    );

    // The decisive check: we must not have produced a block. Simchain mines on its own
    // every ~10s, so allow for honest external progress but not for five new blocks.
    let height_after = client.get_best_block()?;
    assert!(
        height_after - height_before < 5,
        "height jumped {} -> {}; a guarded call appears to have mined",
        height_before,
        height_after
    );
    Ok(())
}
