#![allow(dead_code)]
#![cfg(test)]

use anyhow::Result;
use bitcoin::{Amount, Network};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::{
    channel::channel::DualChannel,
    identification::allow_list::AllowList,
    rpc::{tls_helper::Cert, BrokerConfig},
};
use bitvmx_client::{
    bitvmx::BitVMX,
    config::Config,
    program::{
        protocols::dispute::{input_tx_name, program_input},
        variables::VariableTypes,
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel},
};
use bitvmx_job_dispatcher::DispatcherHandler;
use bitvmx_job_dispatcher_types::{
    emulator_messages::EmulatorJobType, garbled_messages::GarbledJobType,
    prover_messages::ProverJobType,
};
use std::{
    sync::mpsc::{channel, Receiver, Sender},
    thread,
    time::Duration,
};
use tracing::{error, info};
use uuid::Uuid;

use bitcoind::{
    bitcoind::{Bitcoind, BitcoindFlags},
    config::BitcoindConfig,
};
use bitvmx_wallet::{RegtestWallet, Wallet};

use crate::common::{clear_db, send_all, INITIAL_BLOCK_COUNT};
const MIN_TX_FEE: f64 = 2.0;

pub struct TestHelper {
    pub bitcoind: Option<Bitcoind>,
    pub wallet: Wallet,
    pub bitvmx_handle: Option<thread::JoinHandle<Result<()>>>,
    pub bitvmx_stop_tx: Sender<()>,
    pub disp_handle: Option<thread::JoinHandle<Result<()>>>,
    pub disp_stop_tx: Sender<()>,
    pub disp_ready_rx: Receiver<usize>,
    pub mine_handle: Option<thread::JoinHandle<Result<()>>>,
    pub mine_stop_tx: Option<Sender<()>>,
    pub mine_block_rx: Option<Receiver<()>>,
    pub zkp_handle: Option<thread::JoinHandle<Result<()>>>,
    pub zkp_stop_tx: Sender<()>,
    pub zkp_ready_rx: Receiver<usize>,
    pub garbled_handle: Option<thread::JoinHandle<Result<()>>>,
    pub garbled_stop_tx: Sender<()>,
    pub garbled_ready_rx: Receiver<usize>,
    pub id_channel_pairs: Vec<ParticipantChannel>,
}

impl TestHelper {
    pub fn new(network: Network, independent: bool, auto_mine: Option<u64>) -> Result<Self> {
        info!(
            "Initializing TestHelper for network: {:?} {}",
            network, independent
        );
        let config_path = match network {
            Network::Regtest => "config/wallet_regtest.yaml",
            Network::Testnet => "config/wallet_testnet.yaml",
            _ => panic!("Not supported network {}", network),
        };

        let wallet_config = bitvmx_settings::settings::load_config_file::<
            bitvmx_wallet::wallet::config::Config,
        >(Some(config_path.to_string()))?;

        info!("Wallet settings loaded");

        let bitcoind = if independent {
            None
        } else {
            assert!(network == Network::Regtest);
            clear_db(&wallet_config.storage.path);
            clear_db(&wallet_config.key_storage.path);
            Wallet::clear_db(&wallet_config.wallet)?;

            let bitcoind_instance = Bitcoind::new(
                BitcoindConfig::default(),
                wallet_config.bitcoin.clone(),
                Some(BitcoindFlags {
                    min_relay_tx_fee: 0.00001,
                    block_min_tx_fee: 0.00001 * MIN_TX_FEE,
                    debug: 1,
                    fallback_fee: 0.0002,
                    maxmempool: None,
                }),
            );

            bitcoind_instance.start()?;
            Some(bitcoind_instance)
        };

        let mut wallet =
            Wallet::from_config(wallet_config.bitcoin.clone(), wallet_config.wallet.clone())?;
        if !independent {
            let bitcoin_client = BitcoinClient::new(
                &wallet_config.bitcoin.url,
                &wallet_config.bitcoin.username,
                &wallet_config.bitcoin.password,
            )?;
            let address = bitcoin_client.init_wallet(&wallet_config.bitcoin.wallet)?;
            bitcoin_client.mine_blocks_to_address(INITIAL_BLOCK_COUNT, &address)?;
            bitcoin_client.fund_address(&wallet.receive_address()?, Amount::from_int_btc(10))?;
            wallet.sync_wallet()?;
        }

        info!("Wallet ready");

        let (bitvmx_stop_tx, bitvmx_stop_rx) = channel::<()>();
        let (bitvmx_ready_tx, bitvmx_ready_rx) = channel::<()>();
        let bitvmx_handle = thread::spawn(move || {
            run_bitvmx(network, independent, bitvmx_stop_rx, bitvmx_ready_tx)
        });
        info!("BitVMX instances started");

        while !bitvmx_ready_rx.try_recv().is_ok() {
            thread::sleep(Duration::from_millis(100));
        }
        info!("Bitvmx instances are ready");

        let (disp_stop_tx, disp_stop_rx) = channel::<()>();
        let (disp_ready_tx, disp_ready_rx) = channel::<usize>();
        let disp_handle = thread::spawn(move || {
            let result = run_emulator(network, disp_stop_rx, disp_ready_tx);
            if let Err(ref e) = result {
                error!("run_emulator failed: {:?}", e);
            }
            result
        });

        let (zkp_stop_tx, zkp_stop_rx) = channel::<()>();
        let (zkp_ready_tx, zkp_ready_rx) = channel::<usize>();
        let zkp_handle = thread::spawn(move || run_zkp(network, zkp_stop_rx, zkp_ready_tx));

        let (garbled_stop_tx, garbled_stop_rx) = channel::<()>();
        let (garbled_ready_tx, garbled_ready_rx) = channel::<usize>();
        let garbled_handle =
            thread::spawn(move || run_garbled(network, garbled_stop_rx, garbled_ready_tx));

        let automine_interval = if network == Network::Regtest {
            if let Some(interval) = auto_mine {
                interval
            } else {
                0
            }
        } else {
            0
        };
        let (mine_handle, mine_stop_tx, mine_block_rx) = if automine_interval > 0 {
            let (mine_stop_tx, mine_stop_rx) = channel::<()>();
            let (mine_ready_tx, mine_ready_rx) = channel::<()>();
            let mine_handle = thread::spawn(move || {
                // if 500 blocks mined, stop
                run_auto_mine(
                    network,
                    mine_stop_rx,
                    mine_ready_tx,
                    automine_interval,
                    Some(500),
                )
            });
            (Some(mine_handle), Some(mine_stop_tx), Some(mine_ready_rx))
        } else {
            (None, None, None)
        };

        let mut id_channel_pairs = vec![];
        let configs = get_configs(network)?;
        for config in &configs {
            let allow_list = AllowList::from_file(&config.broker.allow_list)?;
            let broker_config =
                BrokerConfig::new(config.broker.port, None, config.broker.get_pubk_hash()?);
            let channel = DualChannel::new(
                &broker_config,
                Cert::from_key_file(&config.testing.l2.priv_key)?,
                Some(config.testing.l2.id),
                allow_list.clone(),
            )?;
            let id = config.components.bitvmx.clone();
            id_channel_pairs.push(ParticipantChannel { channel, id });
        }

        Ok(TestHelper {
            bitcoind,
            wallet,
            bitvmx_handle: Some(bitvmx_handle),
            bitvmx_stop_tx,
            disp_handle: Some(disp_handle),
            disp_stop_tx,
            disp_ready_rx,
            mine_handle,
            mine_stop_tx,
            mine_block_rx,
            zkp_handle: Some(zkp_handle),
            zkp_stop_tx,
            zkp_ready_rx,
            garbled_handle: Some(garbled_handle),
            garbled_stop_tx,
            garbled_ready_rx,
            id_channel_pairs,
        })
    }

    pub fn stop(&mut self) -> Result<()> {
        self.disp_stop_tx.send(()).unwrap();
        let handle = self.disp_handle.take().unwrap();
        handle.join().unwrap()?;

        self.zkp_stop_tx.send(()).unwrap();
        let handle = self.zkp_handle.take().unwrap();
        handle.join().unwrap()?;

        self.garbled_stop_tx.send(()).unwrap();
        let handle = self.garbled_handle.take().unwrap();
        handle.join().unwrap()?;

        self.bitvmx_stop_tx.send(()).unwrap();
        let handle = self.bitvmx_handle.take().unwrap();
        handle.join().unwrap()?;

        if let Some(mine_stop_tx) = self.mine_stop_tx.take() {
            mine_stop_tx.send(()).unwrap();
        }
        if let Some(mine_handle) = self.mine_handle.take() {
            mine_handle.join().unwrap()?;
        }

        if let Some(bitcoind) = &self.bitcoind {
            info!("Stopping bitcoind");
            bitcoind.stop()?;
        }
        info!("BitVMX instances stopped");
        Ok(())
    }

    pub fn wait_all_msg(&self) -> Result<Vec<OutgoingBitVMXApiMessages>> {
        let mut msgs = Vec::new();
        for (idx, _channel) in self.id_channel_pairs.iter().enumerate() {
            match self.wait_msg(idx) {
                Ok(msg) => msgs.push(msg),
                Err(e) => {
                    info!("Error receiving message from channel {}: {:?}", idx, e);
                }
            }
        }
        Ok(msgs)
    }

    pub fn wait_msg(&self, idx: usize) -> Result<OutgoingBitVMXApiMessages> {
        let channel = &self.id_channel_pairs[idx].channel;
        loop {
            let msg = channel.recv()?;
            if let Some(msg) = msg {
                //info!("Received message from channel {}: {:?}", idx, msg);
                return Ok(OutgoingBitVMXApiMessages::from_string(&msg.0)?);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn wait_specific_msg(
        &self,
        idx: u32,
        expected_msg_type: &str,
    ) -> Result<OutgoingBitVMXApiMessages> {
        info!(
            "Waiting for specific message type: {} on channel: {}",
            expected_msg_type, idx
        );
        loop {
            let msg = self.wait_msg(idx as usize)?;
            if msg.name() == expected_msg_type {
                return Ok(msg);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn send_all(&self, command: IncomingBitVMXApiMessages) -> Result<()> {
        send_all(&self.id_channel_pairs, &command.to_string()?)
    }

    pub fn wait_tx_name(&self, idx: usize, name: &str) -> Result<OutgoingBitVMXApiMessages> {
        info!(
            "Waiting for transaction with name: {} on channel: {}",
            name, idx
        );
        loop {
            let msg = self.wait_msg(idx)?;
            if let Some((_uuid, _status, tx_name)) = msg.transaction() {
                if let Some(tx_name) = tx_name {
                    if tx_name == name {
                        return Ok(msg);
                    }
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn set_input_and_send(
        &self,
        input_data: Vec<u8>,
        input_idx: u32,
        participant: usize,
        prog_id: Uuid,
    ) -> Result<()> {
        let set_input_1 =
            VariableTypes::Input(input_data).set_msg(prog_id, &program_input(input_idx, None))?;
        let _ = self.id_channel_pairs[participant]
            .channel
            .send(&self.id_channel_pairs[participant].id, set_input_1)?;

        // send the tx
        let _ = self.id_channel_pairs[participant].channel.send(
            &self.id_channel_pairs[participant].id,
            IncomingBitVMXApiMessages::DispatchTransactionName(prog_id, input_tx_name(input_idx))
                .to_string()?,
        );
        Ok(())
    }
}

pub fn get_configs(network: Network) -> Result<Vec<Config>> {
    let config_names = match network {
        Network::Regtest => vec!["op_1", "op_2", "op_3"],
        Network::Testnet => vec!["testnet_op_1", "testnet_op_2", "testnet_op_3"],
        _ => panic!("Network not supported: {}", network),
    };

    let mut configs = Vec::new();
    for name in config_names {
        info!("Loading config: {}", name);
        let config = Config::new(Some(format!("config/{}.yaml", name)))?;
        configs.push(config);
    }
    Ok(configs)
}

fn run_bitvmx(network: Network, independent: bool, rx: Receiver<()>, tx: Sender<()>) -> Result<()> {
    let configs = get_configs(network);
    if configs.is_err() {
        error!("Failed to load configs: {:?}", configs.err());
        panic!("Failed to load configs");
    }
    let configs = configs.unwrap();
    info!("Loaded configs");
    if !independent {
        for config in &configs {
            clear_db(&config.storage.path);
            clear_db(&config.key_storage.path);
            clear_db(&config.broker.storage.path);
            clear_db(&config.comms.storage_path);
            Wallet::clear_db(&config.wallet)?;
        }
    }

    let mut instances = vec![];
    configs.iter().for_each(|config| {
        info!("Initializing BitVMX with config: {:?}", config.broker.port);
        let bitvmx = BitVMX::new(config.clone());
        if bitvmx.is_err() {
            error!("Failed to create BitVMX instance: {:?}", bitvmx.err());
            panic!("Failed to create BitVMX instance");
        }
        instances.push(bitvmx.unwrap());
    });

    let mut ready = false;

    // Main processing loop
    loop {
        if rx.try_recv().is_ok() {
            info!("Signal received, shutting down...");
            break;
        }
        for bitvmx in instances.iter_mut() {
            if ready {
                let ret = bitvmx.tick();
                if ret.is_err() {
                    error!("Error in BitVMX tick: {:?}", ret);
                    return Ok(());
                }
            } else {
                ready = bitvmx.process_bitcoin_updates()?;
                if !ready {
                    //info!("Waiting to get to the top of the Bitcoin chain...");
                } else {
                    info!("Bitcoin updates processed, ready to run.");
                    let _ = tx.send(());
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }

    Ok(())
}

fn run_emulator(network: Network, rx: Receiver<()>, tx: Sender<usize>) -> Result<()> {
    let configs = get_configs(network)?;

    let mut instances = vec![];

    for (i, config) in configs.iter().enumerate() {
        info!(
            "Starting emulator connection with port: {}",
            config.broker.port
        );

        let allow_list = AllowList::from_file(&config.broker.allow_list)?;
        let broker_config =
            BrokerConfig::new(config.broker.port, None, config.broker.get_pubk_hash()?);
        let channel = DualChannel::new(
            &broker_config,
            Cert::from_key_file(&config.testing.emulator.priv_key)?,
            Some(config.testing.emulator.id),
            allow_list.clone(),
        )?;

        //TODO: this is temporal until there are separated storages
        let storage_path = format!("/tmp/emulator_storage_{i}.db");
        clear_db(&storage_path);
        let prover_dispatcher =
            DispatcherHandler::<EmulatorJobType>::new_with_path(channel, &storage_path)?;
        instances.push(prover_dispatcher);
    }

    // Main processing loop
    loop {
        if rx.try_recv().is_ok() {
            info!("Signal received, shutting down...");
            break;
        }
        for (idx, dispatcher) in instances.iter_mut().enumerate() {
            if dispatcher.tick()? {
                let _ = tx.send(idx);
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
    Ok(())
}

fn run_zkp(network: Network, rx: Receiver<()>, tx: Sender<usize>) -> Result<()> {
    let configs = get_configs(network)?;

    let mut instances = vec![];
    for (i, config) in configs.iter().enumerate() {
        info!("Starting zkp connection with port: {}", config.broker.port);
        let allow_list = AllowList::from_file(&config.broker.allow_list)?;
        let broker_config =
            BrokerConfig::new(config.broker.port, None, config.broker.get_pubk_hash()?);
        let channel = DualChannel::new(
            &broker_config,
            Cert::from_key_file(&config.testing.prover.priv_key)?,
            Some(config.testing.prover.id),
            allow_list.clone(),
        )?;

        //TODO: this is temporal until there are separated storages
        let storage_path = format!("/tmp/zkp_storage_{i}.db");
        clear_db(&storage_path);
        let prover_dispatcher =
            DispatcherHandler::<ProverJobType>::new_with_path(channel, &storage_path)?;
        instances.push(prover_dispatcher);
    }

    // Main processing loop
    loop {
        if rx.try_recv().is_ok() {
            info!("Signal received, shutting down...");
            break;
        }
        for (idx, dispatcher) in instances.iter_mut().enumerate() {
            if dispatcher.tick()? {
                let _ = tx.send(idx);
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
    Ok(())
}

fn run_garbled(network: Network, rx: Receiver<()>, tx: Sender<usize>) -> Result<()> {
    // Set GNOVA_BIN path for the correct relative path from rust-bitvmx-client
    std::env::set_var("GNOVA_BIN", "../rust-bitvmx-gc/target/release/gnova");

    let configs = get_configs(network)?;

    let mut instances = vec![];
    for (i, config) in configs.iter().enumerate() {
        info!(
            "Starting garbled dispatcher connection with port: {}",
            config.broker.port
        );
        let allow_list = AllowList::from_file(&config.broker.allow_list)?;
        let broker_config =
            BrokerConfig::new(config.broker.port, None, config.broker.get_pubk_hash()?);
        let channel = DualChannel::new(
            &broker_config,
            Cert::from_key_file(&config.testing.prover.priv_key)?,
            Some(config.testing.prover.id + 10), // Use different ID to avoid conflicts
            allow_list.clone(),
        )?;

        //TODO: this is temporal until there are separated storages
        let storage_path = format!("/tmp/garbled_storage_{i}.db");
        clear_db(&storage_path);
        let garbled_dispatcher =
            DispatcherHandler::<GarbledJobType>::new_with_path(channel, &storage_path)?;
        instances.push(garbled_dispatcher);
    }

    // Main processing loop
    loop {
        if rx.try_recv().is_ok() {
            info!("Signal received, shutting down garbled dispatcher...");
            break;
        }
        for (idx, dispatcher) in instances.iter_mut().enumerate() {
            if dispatcher.tick()? {
                let _ = tx.send(idx);
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
    Ok(())
}

fn run_auto_mine(
    network: Network,
    rx: Receiver<()>,
    tx: Sender<()>,
    interval: u64,
    max_mined_blocks: Option<u64>,
) -> Result<()> {
    let config = &get_configs(network)?[0];

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;
    let address = bitcoin_client.init_wallet("test_wallet");
    let address = address.unwrap();

    // Main processing loop
    loop {
        if rx.try_recv().is_ok() {
            info!("Signal received, shutting down...");
            break;
        }
        bitcoin_client.mine_blocks_to_address(1, &address)?;
        tx.send(())?;
        if let Some(limit) = max_mined_blocks {
            let current = bitcoin_client.get_blockchain_info()?.blocks;
            if current >= limit {
                error!("Max mined blocks reached!");
                std::process::abort();
            }
        }
        thread::sleep(Duration::from_millis(interval));
    }
    Ok(())
}
