#![allow(dead_code)]
#![cfg(test)]
use std::str::FromStr;

pub mod dispute;

use anyhow::Result;
use bitcoin::{Amount, PublicKey, XOnlyPublicKey};
use bitcoind::bitcoind::{Bitcoind, BitcoindFlags};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::{
    channel::channel::DualChannel,
    identification::identifier::Identifier,
    rpc::{tls_helper::Cert, BrokerConfig},
};
use bitvmx_client::{
    bitvmx::BitVMX,
    config::{Component, Config},
    program::{participant::CommsAddress, protocols::protocol_handler::external_fund_tx},
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel},
};
use bitvmx_wallet::wallet::{Destination, RegtestWallet, Wallet};
use operator_comms::operator_comms::AllowList;
use protocol_builder::{
    scripts::{self, ProtocolScript, SignMode},
    types::{OutputType, Utxo},
};
use std::sync::Once;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Number of blocks to mine initially in tests to ensure sufficient coin maturity
pub const INITIAL_BLOCK_COUNT: u64 = 101;

pub fn clear_db(path: &str) {
    let _ = std::fs::remove_dir_all(path);
}

pub fn init_bitvmx(
    role: &str,
    emulator_dispatcher: bool,
) -> Result<(BitVMX, CommsAddress, DualChannel, Option<DualChannel>)> {
    let config = Config::new(Some(format!("config/{}.yaml", role)))?;
    let allow_list = AllowList::from_file(&config.broker.allow_list)?;
    let broker_config = BrokerConfig::new(config.broker.port, None, config.broker.get_pubk_hash()?);
    let bridge_client = DualChannel::new(
        &broker_config,
        Cert::from_key_file(&config.components.l2.priv_key)?,
        Some(config.components.l2.id),
        config.components.l2.ip,
        Some(allow_list.clone()),
    )?;
    let dispatcher_channel = if emulator_dispatcher {
        Some(DualChannel::new(
            &broker_config,
            Cert::from_key_file(&config.components.emulator.priv_key)?,
            Some(config.components.emulator.id),
            config.components.emulator.ip,
            Some(allow_list),
        )?)
    } else {
        None
    };

    clear_db(&config.storage.path);
    clear_db(&config.key_storage.path);
    clear_db(&config.broker_storage.path);
    Wallet::clear_db(&config.wallet)?;

    info!("config: {:?}", config.storage.path);

    let bitvmx = BitVMX::new(config)?;

    let address = CommsAddress::new(bitvmx.address(), bitvmx.pubkey_hash()?);
    info!("public key hash {:?}", bitvmx.pubkey_hash());

    //This messages will come from the bridge client.

    Ok((bitvmx, address, bridge_client, dispatcher_channel))
}

pub fn tick(instance: &mut BitVMX) {
    instance.process_api_messages().unwrap();
    instance.process_comms_messages().unwrap();
    instance.process_programs().unwrap();
    instance.process_collaboration().unwrap();
    instance.process_pending_messages().unwrap();
}

pub fn wait_message_from_channel(
    channel: &DualChannel,
    instances: &mut Vec<&mut BitVMX>,
    fake_tick: bool,
) -> Result<(String, Identifier)> {
    //loop to timeout
    for i in 0..40000 {
        if i % 50 == 0 {
            let msg = channel.recv()?;
            if msg.is_some() {
                //info!("Received message from channel: {:?}", msg);
                return Ok(msg.unwrap());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        for instance in instances.iter_mut() {
            if fake_tick {
                tick(instance);
            } else {
                instance.tick()?;
            }
        }
    }
    panic!("Timeout waiting for message from channel");
}

pub const WALLET_NAME: &str = "wallet";
pub const FUNDING_ID: &str = "fund_1";
pub const FEE: u64 = 500;

pub fn prepare_bitcoin() -> Result<(BitcoinClient, Bitcoind, Wallet)> {
    let wallet_config = bitvmx_settings::settings::load_config_file::<bitvmx_wallet::config::Config>(
        Some("config/wallet_regtest.yaml".to_string()),
    )?;

    // Clear indexer, monitor, key manager and wallet data.
    clear_db(&wallet_config.storage.path);
    clear_db(&wallet_config.key_storage.path);
    Wallet::clear_db(&wallet_config.wallet)?;

    let bitcoind = Bitcoind::new_with_flags(
        "bitcoin-regtest",
        "ruimarinho/bitcoin-core",
        wallet_config.bitcoin.clone(),
        BitcoindFlags {
            min_relay_tx_fee: 0.00001,
            block_min_tx_fee: 0.00001,
            debug: 1,
            fallback_fee: 0.0002,
        },
    );
    info!("Starting bitcoind");
    bitcoind.start()?;

    let bitcoin_client = BitcoinClient::new(
        &wallet_config.bitcoin.url,
        &wallet_config.bitcoin.username,
        &wallet_config.bitcoin.password,
    )?;

    // Create a new local wallet
    let mut wallet =
        Wallet::from_config(wallet_config.bitcoin.clone(), wallet_config.wallet.clone())?;
    // Initialize the wallet bitcoin RPC wallet
    let _address = bitcoin_client.init_wallet(&wallet_config.bitcoin.wallet)?;
    // Mine 100 blocks to ensure the coinbase output is mature
    bitcoin_client.mine_blocks_to_address(INITIAL_BLOCK_COUNT, &_address)?;
    // Fund the local wallet with 10 BTC from the bitcoin RPC wallet
    bitcoin_client.fund_address(&wallet.receive_address()?, Amount::from_int_btc(10))?;
    // Sync the wallet with the Bitcoin node to the latest block
    wallet.sync_wallet()?;

    Ok((bitcoin_client, bitcoind, wallet))
}

static INIT: Once = Once::new();

pub fn config_trace() {
    INIT.call_once(|| {
        config_trace_aux();
    });
}

fn config_trace_aux() {
    let default_modules = [
        "info",
        "bitvmx_transaction_monitor=off",
        "bitcoin_indexer=off",
        "bitcoin_coordinator=info",
        "operator_comms=off",
        "tarpc=off",
        "key_manager=off",
        "memory=off",
        "broker=off",
    ];

    let filter = EnvFilter::builder()
        .parse(default_modules.join(","))
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        //.without_time()
        //.with_ansi(false)
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

pub fn send_all(id_channel_pairs: &Vec<ParticipantChannel>, msg: &str) -> Result<()> {
    for id_channel_pair in id_channel_pairs {
        id_channel_pair
            .channel
            .send(id_channel_pair.id.clone(), msg.to_string())?;
    }
    Ok(())
}

pub fn get_all(
    channels: &Vec<DualChannel>,
    instances: &mut Vec<BitVMX>,
    fake_tick: bool,
) -> Result<Vec<OutgoingBitVMXApiMessages>> {
    let mut ret = vec![];
    let mut mutinstances = instances.iter_mut().collect::<Vec<_>>();
    for channel in channels {
        let msg = wait_message_from_channel(&channel, &mut mutinstances, fake_tick)?;
        ret.push(OutgoingBitVMXApiMessages::from_string(&msg.0)?);
    }
    Ok(ret)
}

pub fn mine_and_wait(
    _bitcoin_client: &BitcoinClient,
    channels: &Vec<DualChannel>,
    instances: &mut Vec<BitVMX>,
    wallet: &Wallet,
) -> Result<Vec<OutgoingBitVMXApiMessages>> {
    //MINE AND WAIT
    for i in 0..100 {
        if i % 10 == 0 {
            wallet.mine(1)?;
        }

        for instance in instances.iter_mut() {
            instance.tick()?;
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }
    let msgs = get_all(&channels, instances, false)?;

    Ok(msgs)
}

pub fn init_broker(role: &str) -> Result<ParticipantChannel> {
    let config = Config::new(Some(format!("config/{}.yaml", role)))?;
    let allow_list = AllowList::from_file(&config.broker.allow_list)?;
    let broker_config = BrokerConfig::new(config.broker.port, None, config.broker.get_pubk_hash()?);
    let bridge_client = DualChannel::new(
        &broker_config,
        Cert::from_key_file(&config.components.l2.priv_key)?,
        Some(config.components.l2.id),
        config.components.l2.ip,
        Some(allow_list.clone()),
    )?;
    let particiant_channel = ParticipantChannel {
        id: config.components.get_bitvmx_identifier()?,
        channel: bridge_client,
    };
    Ok(particiant_channel)
}

pub fn init_utxo_new(
    wallet: &mut Wallet,
    internal_key: &PublicKey,
    spending_scripts: Vec<ProtocolScript>,
    amount: u64,
) -> Result<(Utxo, OutputType)> {
    info!("Funding address: {:?} with: {}", internal_key, amount);
    let tx = wallet.fund_destination(Destination::P2TR(
        XOnlyPublicKey::from(internal_key.clone()),
        spending_scripts.clone(),
        amount,
    ))?;
    wallet.mine(1)?;
    let utxo = Utxo::new(tx.compute_txid(), 0, amount, &*internal_key);

    let output_type = external_fund_tx(internal_key, spending_scripts, amount)?;

    info!("UTXO: {:?}", utxo);

    Ok((utxo, output_type))
}

pub fn init_utxo(
    wallet: &mut Wallet,
    aggregated_pub_key: PublicKey,
    secret: Option<Vec<u8>>,
    amount: u64,
) -> Result<Utxo> {
    let spending_scripts = if secret.is_some() {
        vec![scripts::reveal_secret(
            secret.unwrap(),
            &aggregated_pub_key,
            SignMode::Aggregate,
        )]
    } else {
        vec![scripts::check_aggregated_signature(
            &aggregated_pub_key,
            SignMode::Aggregate,
        )]
    };

    let tx = wallet.fund_destination(Destination::P2TR(
        aggregated_pub_key.into(),
        spending_scripts,
        amount,
    ))?;
    wallet.mine(1)?;

    let utxo = Utxo::new(tx.compute_txid(), 0, amount, &aggregated_pub_key);

    info!("UTXO: {:?}", utxo);

    Ok(utxo)
}

pub fn set_speedup_funding(
    amount: u64,
    pub_key: &PublicKey,
    channel: &DualChannel,
    wallet: &mut Wallet,
    bitvmx_id: &Component,
) -> Result<()> {
    let fund_tx = wallet.fund_destination(Destination::P2WPKH(*pub_key, amount))?;

    let funds_utxo_0 = Utxo::new(fund_tx.compute_txid(), 0, amount, pub_key);
    let command = IncomingBitVMXApiMessages::SetFundingUtxo(funds_utxo_0).to_string()?;
    channel.send(bitvmx_id.get_identifier()?, command)?;
    Ok(())
}
