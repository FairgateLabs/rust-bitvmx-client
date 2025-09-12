use anyhow::Result;
use bitcoin::{
    key::{rand::rngs::OsRng, Parity, Secp256k1},
    secp256k1::{All, PublicKey as SecpPublicKey, SecretKey},
    Amount, Network, PublicKey as BitcoinPubKey,
};
use bitcoind::bitcoind::Bitcoind;
use bitvmx_client::types::OutgoingBitVMXApiMessages::FundingAddress;

use crate::macros::wait_for_message_blocking;
use crate::participants::member::Member;
use crate::wait_until_msg;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClientApi;
use bitvmx_client::config::Config;
use bitvmx_wallet::wallet::{RegtestWallet, Wallet};
use tracing::info;
use uuid::Uuid;

/// Number of blocks to mine initially to ensure sufficient coin maturity
pub const INITIAL_BLOCK_COUNT: u64 = 110;

/// Helper function to clear database directories
pub fn clear_db(path: &str) {
    let _ = std::fs::remove_dir_all(path);
}

pub fn stop_existing_bitcoind() -> Result<()> {
    info!("Checking for existing bitcoind instance...");

    let config = Config::new(Some("config/development.yaml".to_string()))?;

    // Create a temporary Bitcoind instance to check if one is running and stop it
    let temp_bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );

    // Attempt to stop any existing instance
    match temp_bitcoind.stop() {
        Ok(_) => info!("Successfully stopped existing bitcoind instance"),
        Err(e) => {
            // This is expected if no instance was running
            info!(
                "No existing bitcoind instance found or error stopping: {}",
                e
            );
        }
    }

    Ok(())
}

pub fn prepare_bitcoin() -> Result<(BitcoinClient, Bitcoind)> {
    let config = Config::new(Some("config/development.yaml".to_string()))?;

    // Clear indexer, monitor, key manager and wallet data.
    clear_db(&config.storage.path);
    clear_db(&config.key_storage.path);
    Wallet::clear_db(&config.wallet)?;

    let bitcoind = Bitcoind::new(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
    );
    info!("Starting bitcoind");

    // Config to trigger speedup transactions in Regtest
    // let bitcoind = Bitcoind::new_with_flags(
    //     "bitcoin-regtest",
    //     "ruimarinho/bitcoin-core",
    //     config.bitcoin.clone(),
    //     BitcoindFlags {
    //         min_relay_tx_fee: 0.00001,
    //         block_min_tx_fee: 0.00008,
    //         debug: 1,
    //         fallback_fee: 0.0002,
    //     },
    // );

    bitcoind.start()?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    let _address = bitcoin_client.init_wallet(&config.bitcoin.wallet)?;
    bitcoin_client.mine_blocks_to_address(INITIAL_BLOCK_COUNT, &_address)?;

    Ok((bitcoin_client, bitcoind))
}

pub fn init_wallets(members: &Vec<Member>) -> Result<BitcoinClient> {
    let config = members[0].config.clone();

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    for member in members {
        let id = Uuid::new_v4();
        member.bitvmx.get_funding_address(id)?;
        let funding_address = wait_until_msg!(
            &member.bitvmx,
            FundingAddress(_, _funding_address) => _funding_address
        );
        bitcoin_client.fund_address(&funding_address.assume_checked(), Amount::from_int_btc(1))?;
    }

    Ok(bitcoin_client)
}

// This method changes the parity of a keypair to be even, this is needed for Taproot.
fn adjust_parity(
    secp: &Secp256k1<All>,
    pubkey: SecpPublicKey,
    seckey: SecretKey,
) -> (SecpPublicKey, SecretKey) {
    let (_, parity) = pubkey.x_only_public_key();

    if parity == Parity::Odd {
        (pubkey.negate(secp), seckey.negate())
    } else {
        (pubkey, seckey)
    }
}

pub fn emulated_user_keypair(
    secp: &Secp256k1<All>,
    bitcoin_client: &BitcoinClient,
    network: Network,
) -> Result<(bitcoin::Address, BitcoinPubKey, SecretKey)> {
    let mut rng = OsRng;

    // emulate the user keypair
    let user_sk = SecretKey::new(&mut rng);
    let user_pk = SecpPublicKey::from_secret_key(secp, &user_sk);
    let (user_pk, user_sk) = adjust_parity(secp, user_pk, user_sk);
    let user_pubkey = BitcoinPubKey {
        compressed: true,
        inner: user_pk,
    };
    let user_address: bitcoin::Address = bitcoin_client.get_new_address(user_pubkey, network);
    info!(
        "User Address({}): {:?}",
        user_address.address_type().unwrap(),
        user_address
    );
    Ok((user_address, user_pubkey, user_sk))
}
