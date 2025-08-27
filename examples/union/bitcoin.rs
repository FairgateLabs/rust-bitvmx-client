use anyhow::Result;
use bitcoin::{
    key::{rand::rngs::OsRng, Parity, Secp256k1},
    secp256k1::{All, PublicKey as SecpPublicKey, SecretKey},
    Network, PublicKey as BitcoinPubKey,
};
use bitcoind::bitcoind::{Bitcoind, BitcoindFlags};
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClientApi;
use bitvmx_client::config::Config;
use bitvmx_wallet::wallet::Wallet;
use tracing::info;

/// Number of blocks to mine initially to ensure sufficient coin maturity
pub const INITIAL_BLOCK_COUNT: u64 = 101;
pub const WALLET_NAME: &str = "wallet";
pub const FEE: u64 = 500;
pub const FUNDING_ID: &str = "fund_1";

/// Helper function to clear database directories
pub fn clear_db(path: &str) {
    let _ = std::fs::remove_dir_all(path);
}

pub fn stop_existing_bitcoind() -> Result<()> {
    info!("Checking for existing bitcoind instance...");

    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

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

pub fn prepare_bitcoin() -> Result<(BitcoinClient, Bitcoind, Wallet)> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    // let bitcoind = Bitcoind::new(
    //     "bitcoin-regtest",
    //     "ruimarinho/bitcoin-core",
    //     config.bitcoin.clone(),
    // );
    info!("Starting bitcoind");

    // Config to trigger speedup transactions in Regtest
    let bitcoind = Bitcoind::new_with_flags(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        config.bitcoin.clone(),
        BitcoindFlags {
            min_relay_tx_fee: 0.00001,
            block_min_tx_fee: 0.00008,
            debug: 1,
            fallback_fee: 0.0002,
        },
    );

    bitcoind.start()?;

    let wallet_config = match config.bitcoin.network {
        Network::Regtest => "config/wallet_regtest.yaml",
        Network::Testnet => "config/wallet_testnet.yaml",
        _ => panic!("Not supported network {}", config.bitcoin.network),
    };

    let wallet_config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::config::WalletConfig,
    >(Some(wallet_config.to_string()))?;
    if config.bitcoin.network == Network::Regtest {
        clear_db(&wallet_config.storage.path);
        clear_db(&wallet_config.key_storage.path);
    }
    let wallet = Wallet::new(wallet_config, true)?;
    wallet.mine(INITIAL_BLOCK_COUNT)?;

    wallet.create_wallet(WALLET_NAME)?;
    wallet.regtest_fund(WALLET_NAME, FUNDING_ID, 100_000_000)?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    Ok((bitcoin_client, bitcoind, wallet))
}

pub fn init_wallet() -> Result<Wallet> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    let wallet_config = match config.bitcoin.network {
        Network::Regtest => "config/wallet_regtest.yaml",
        Network::Testnet => "config/wallet_testnet.yaml",
        _ => panic!("Not supported network {}", config.bitcoin.network),
    };

    let wallet_config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::config::WalletConfig,
    >(Some(wallet_config.to_string()))?;
    if config.bitcoin.network == Network::Regtest {
        clear_db(&wallet_config.storage.path);
        clear_db(&wallet_config.key_storage.path);
    }

    let wallet = Wallet::new(wallet_config, true)?;
    wallet.mine(INITIAL_BLOCK_COUNT)?;

    wallet.create_wallet(WALLET_NAME)?;
    wallet.regtest_fund(WALLET_NAME, FUNDING_ID, 100_000_000)?;

    let _ = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    Ok(wallet)
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
