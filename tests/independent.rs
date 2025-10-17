#![cfg(test)]
use anyhow::Result;
use bitcoin::{Amount, Network};
use bitcoind::bitcoind::{Bitcoind, BitcoindFlags};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::channel::channel::DualChannel;
use bitvmx_broker::rpc::tls_helper::Cert;
use bitvmx_broker::rpc::BrokerConfig;
use bitvmx_client::program;
use bitvmx_client::program::participant::{CommsAddress, ParticipantRole};
use bitvmx_client::program::protocols::dispute::{
    action_wins, input_tx_name, program_input, program_input_prev_prefix,
    program_input_prev_protocol, protocol_cost,
};
use bitvmx_client::program::variables::{VariableTypes, WitnessTypes};
use bitvmx_client::types::{
    IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel,
};
use bitvmx_client::{bitvmx::BitVMX, config::Config};
use bitvmx_job_dispatcher::DispatcherHandler;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use bitvmx_job_dispatcher_types::prover_messages::ProverJobType;
use bitvmx_operator_comms::operator_comms::AllowList;
use bitvmx_wallet::wallet::{Destination, RegtestWallet, Wallet};
use common::dispute::{prepare_dispute, ForcedChallenges};
use common::{clear_db, init_utxo_new, INITIAL_BLOCK_COUNT};
use common::{config_trace, send_all};
use emulator::decision::challenge::{ForceChallenge, ForceCondition};
use emulator::executor::utils::{FailConfiguration, FailReads};
use key_manager::winternitz::{
    self, checksum_length, to_checksummed_message, WinternitzPublicKey, WinternitzSignature,
    WinternitzType,
};
use protocol_builder::scripts::{self, SignMode};
use protocol_builder::types::Utxo;
use std::sync::mpsc::channel;
use std::time::Duration;
use std::{
    sync::mpsc::{Receiver, Sender},
    thread, vec,
};
use tracing::{error, info};
use uuid::Uuid;

mod common;

const MIN_TX_FEE: f64 = 2.0;

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

fn run_auto_mine(network: Network, rx: Receiver<()>, tx: Sender<()>, interval: u64) -> Result<()> {
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
        thread::sleep(Duration::from_millis(interval));
    }
    Ok(())
}
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

            let bitcoind = Bitcoind::new_with_flags(
                "bitcoin-regtest",
                "bitcoin/bitcoin:29.1",
                wallet_config.bitcoin.clone(),
                BitcoindFlags {
                    min_relay_tx_fee: 0.00001,
                    block_min_tx_fee: 0.00001 * MIN_TX_FEE,
                    debug: 1,
                    fallback_fee: 0.0002,
                },
            );
            bitcoind.start()?;
            Some(bitcoind)
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
        let disp_handle = thread::spawn(move || run_emulator(network, disp_stop_rx, disp_ready_tx));

        let (zkp_stop_tx, zkp_stop_rx) = channel::<()>();
        let (zkp_ready_tx, zkp_ready_rx) = channel::<usize>();
        let zkp_handle = thread::spawn(move || run_zkp(network, zkp_stop_rx, zkp_ready_tx));

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
                run_auto_mine(network, mine_stop_rx, mine_ready_tx, automine_interval)
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
            zkp_stop_tx: zkp_stop_tx,
            zkp_ready_rx,
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
}

pub fn test_all_aux(
    independent: bool,
    network: Network,
    program: Option<String>,
    inputs: Option<(&str, u32, &str, u32)>,
    fail_data: Option<(
        Option<FailConfiguration>,
        Option<FailConfiguration>,
        ForceChallenge,
        ForceCondition,
    )>,
) -> Result<()> {
    config_trace();

    let mut helper = TestHelper::new(network, independent, Some(1000))?;

    let command = IncomingBitVMXApiMessages::GetCommInfo(Uuid::new_v4());
    helper.send_all(command)?;

    let addresses: Vec<CommsAddress> = helper
        .wait_all_msg()?
        .iter()
        .map(|msg| msg.comm_info().unwrap().1)
        .collect::<Vec<_>>();

    info!("Waiting for AggregatedPubkey message from all channels");
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), None, 0);
    helper.send_all(command)?;
    let msgs = helper.wait_all_msg()?;
    let _aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    //one time per bitvmx instance, we need to get the public key for the speedup funding utxo
    let funding_public_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::GetPubKey(funding_public_id, true);
    helper.send_all(command)?;
    let msgs = helper.wait_all_msg()?;
    let funding_key_0 = msgs[0].public_key().unwrap().1;
    let funding_key_1 = msgs[1].public_key().unwrap().1;
    let _funding_key_2 = msgs[2].public_key().unwrap().1;

    info!("Creating speedup funds");
    let speedup_amount = 70_000 * MIN_TX_FEE as u64;

    // let fund_txid_0 = helper.wallet.fund_address(
    //     WALLET_NAME,
    //     FUNDING_ID,
    //     funding_key_0,
    //     &vec![speedup_amount],
    //     1000,
    //     false,
    //     true,
    //     None,
    // )?;
    let fund_tx_0 = helper
        .wallet
        .fund_destination(Destination::P2WPKH(funding_key_0, speedup_amount))?;
    let fund_txid_0 = fund_tx_0.compute_txid();

    helper.wallet.mine(1)?;
    info!("Wait for the fund for operator 0 speedups");

    wait_enter(independent);
    // let fund_txid_1 = helper.wallet.fund_address(
    //     WALLET_NAME,
    //     FUNDING_ID,
    //     funding_key_1,
    //     &vec![speedup_amount],
    //     1000,
    //     false,
    //     true,
    //     None,
    // )?;

    let fund_tx_1 = helper
        .wallet
        .fund_destination(Destination::P2WPKH(funding_key_1, speedup_amount))?;
    let fund_txid_1 = fund_tx_1.compute_txid();
    helper.wallet.mine(1)?;
    info!("Wait for the first funding ready");
    info!("Wait for the fund for operator 1 speedups");
    wait_enter(independent);

    let funds_utxo_0 = Utxo::new(fund_txid_0, 0, speedup_amount, &funding_key_0);
    let command = IncomingBitVMXApiMessages::SetFundingUtxo(funds_utxo_0).to_string()?;
    helper.id_channel_pairs[0]
        .channel
        .send(&helper.id_channel_pairs[0].id, command)?;
    let funds_utxo_1 = Utxo::new(fund_txid_1, 0, speedup_amount, &funding_key_1);
    let command = IncomingBitVMXApiMessages::SetFundingUtxo(funds_utxo_1).to_string()?;
    helper.id_channel_pairs[1]
        .channel
        .send(&helper.id_channel_pairs[1].id, command)?;

    info!("Generate Aggregated from pair");
    let pair_0_1 = vec![addresses[0].clone(), addresses[1].clone()];
    let pair_0_1_agg_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(pair_0_1_agg_id, pair_0_1.clone(), None, 0);
    helper.id_channel_pairs[0]
        .channel
        .send(&helper.id_channel_pairs[0].id, command.to_string()?)?;
    helper.id_channel_pairs[1]
        .channel
        .send(&helper.id_channel_pairs[1].id, command.to_string()?)?;
    let _msg = helper.wait_msg(0)?;
    let msg = helper.wait_msg(1)?;
    let pair_0_1_agg_pub_key = msg.aggregated_pub_key().unwrap();

    // prepare a second fund available so we don't need 2 blocks to get the UTXO

    info!("Initializing UTXO for program");
    let spending_condition = vec![
        scripts::check_aggregated_signature(&pair_0_1_agg_pub_key, SignMode::Aggregate),
        scripts::check_aggregated_signature(&pair_0_1_agg_pub_key, SignMode::Aggregate),
    ];
    let (utxo, initial_out_type) = init_utxo_new(
        &mut helper.wallet,
        &pair_0_1_agg_pub_key,
        spending_condition.clone(),
        protocol_cost(),
    )?;

    info!("Wait for the first funding ready");
    wait_enter(independent);

    info!("Initializing UTXO for the prover action");
    let (prover_win_utxo, prover_win_out_type) = init_utxo_new(
        &mut helper.wallet,
        &pair_0_1_agg_pub_key,
        spending_condition.clone(),
        11_000,
    )?;
    info!("Wait for the action utxo ready");
    wait_enter(independent);

    let pair_0_1_channels = vec![
        helper.id_channel_pairs[0].clone(),
        helper.id_channel_pairs[1].clone(),
    ];
    let prog_id = Uuid::new_v4();

    //simulate a protocol with a prover previous input
    let previous_protocol = Uuid::new_v4();
    let pub_key = derive_winternitz(4, 0);
    let signature = sign_winternitz_message(&hex::decode("00000001").unwrap(), 0);
    let set_pub_key =
        VariableTypes::WinternitzPubKey(pub_key).set_msg(previous_protocol, "previous_input_0")?;
    let set_witness =
        WitnessTypes::Winternitz(signature).set_msg(previous_protocol, "previous_input_0")?;
    send_all(&pair_0_1_channels, &set_pub_key)?;

    //configure the dispute so is able to retrive the data
    let prev_protocol =
        VariableTypes::Uuid(previous_protocol).set_msg(prog_id, &program_input_prev_protocol(0))?;
    let prev_prefix = VariableTypes::String("previous_input_".to_string())
        .set_msg(prog_id, &program_input_prev_prefix(0))?;
    send_all(&pair_0_1_channels, &prev_protocol)?;
    send_all(&pair_0_1_channels, &prev_prefix)?;

    if let Some(input) = inputs {
        let const_input = VariableTypes::Input(hex::decode(input.0).unwrap())
            .set_msg(prog_id, &program_input(input.1))?;
        let _ = send_all(&pair_0_1_channels, &const_input);
    }

    prepare_dispute(
        prog_id,
        pair_0_1,
        pair_0_1_channels.clone(),
        &pair_0_1_agg_pub_key,
        utxo,
        initial_out_type,
        prover_win_utxo,
        prover_win_out_type,
        ForcedChallenges::No,
        fail_data,
        program,
    )?;

    let msg = helper.wait_msg(0)?;
    info!("Setup dispute done: {:?}", msg);
    let msg = helper.wait_msg(1)?;
    info!("Setup dispute done: {:?}", msg);

    // wait input from command line
    info!("Waiting for funding ready");
    wait_enter(independent);

    //the witness is observed and then the challenge is sent
    send_all(&pair_0_1_channels, &set_witness)?;

    let _ = helper.id_channel_pairs[1].channel.send(
        &helper.id_channel_pairs[1].id,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            prog_id,
            program::protocols::dispute::START_CH.to_string(),
        )
        .to_string()?,
    );

    helper.wait_tx_name(1, program::protocols::dispute::START_CH)?;

    let (data, idx) = if let Some(input) = inputs {
        (input.2, input.3)
    } else {
        ("11111111", 0)
    };

    let set_input_1 =
        VariableTypes::Input(hex::decode(data).unwrap()).set_msg(prog_id, &program_input(idx))?;
    let _ = helper.id_channel_pairs[0]
        .channel
        .send(&helper.id_channel_pairs[0].id, set_input_1)?;

    // send the tx
    let _ = helper.id_channel_pairs[0].channel.send(
        &helper.id_channel_pairs[0].id,
        IncomingBitVMXApiMessages::DispatchTransactionName(prog_id, input_tx_name(idx))
            .to_string()?,
    );

    helper.wait_tx_name(1, &action_wins(&ParticipantRole::Prover, 1))?;

    helper.stop()?;

    Ok(())
}

fn wait_enter(independent: bool) {
    if !independent {
        return;
    }
    info!("Waiting for user input to continue...");
    info!("Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
}

pub fn derive_winternitz(message_size_in_bytes: usize, index: u32) -> WinternitzPublicKey {
    let message_digits_length = winternitz::message_digits_length(message_size_in_bytes);
    let checksum_size = checksum_length(message_digits_length);

    let winternitz = winternitz::Winternitz::new();
    let master_secret = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    let public_key = winternitz
        .generate_public_key(
            &master_secret,
            WinternitzType::HASH160,
            message_digits_length,
            checksum_size,
            index,
        )
        .unwrap();

    public_key
}

pub fn sign_winternitz_message(message_bytes: &[u8], index: u32) -> WinternitzSignature {
    let message_digits_length = winternitz::message_digits_length(message_bytes.len());
    let checksummed_message = to_checksummed_message(message_bytes);
    let checksum_size = checksum_length(message_digits_length);
    let message_size = checksummed_message.len() - checksum_size;

    assert!(message_size == message_digits_length);

    let master_secret = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let winternitz = winternitz::Winternitz::new();
    let private_key = winternitz
        .generate_private_key(
            &master_secret,
            WinternitzType::HASH160,
            message_size,
            checksum_size,
            index,
        )
        .unwrap();

    let signature =
        winternitz.sign_message(message_digits_length, &checksummed_message, &private_key);

    signature
}

#[ignore]
#[test]
fn test_independent_testnet() -> Result<()> {
    test_all_aux(true, Network::Testnet, None, None, None)?;
    Ok(())
}
#[ignore]
#[test]
fn test_independent_regtest() -> Result<()> {
    test_all_aux(true, Network::Regtest, None, None, None)?;
    Ok(())
}
#[ignore]
#[test]
fn test_all() -> Result<()> {
    test_all_aux(false, Network::Regtest, None, None, None)?;
    Ok(())
}

#[ignore]
#[test]
fn test_const() -> Result<()> {
    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-const-pre.yaml".to_string()),
        Some(("0000000100000002", 0, "00000003", 1)),
        None,
    )?;

    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-const-post.yaml".to_string()),
        Some(("0000000200000003", 1, "00000001", 0)),
        None,
    )?;

    Ok(())
}

#[ignore]
#[test]
fn test_const_fail_input() -> Result<()> {
    let fail_config = (
        Some(FailConfiguration::new_fail_reads(FailReads::new(
            None,
            Some(&vec![
                "16".to_string(),
                "0xaa000000".to_string(),
                "0x00000002".to_string(),
                "0xaa000000".to_string(),
                "0xffffffffffffffff".to_string(),
            ]),
        ))),
        None,
        ForceChallenge::No,
        ForceCondition::ValidInputWrongStepOrHash,
    );

    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-previous-wots.yaml".to_string()),
        Some(("00000002", 1, "00000003", 2)),
        Some(fail_config.clone()),
    )?;

    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-const-post.yaml".to_string()),
        Some(("0000000200000004", 1, "00000001", 0)),
        Some(fail_config.clone()),
    )?;

    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-const-pre.yaml".to_string()),
        Some(("0000000100000002", 0, "00000004", 1)),
        Some(fail_config),
    )?;

    Ok(())
}

#[ignore]
#[test]
fn test_previous_input() -> Result<()> {
    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-previous-wots.yaml".to_string()),
        Some(("00000002", 1, "00000003", 2)),
        None,
    )?;

    Ok(())
}

#[cfg(target_os = "linux")]
#[ignore]
#[test]
fn test_zkp() -> Result<()> {
    config_trace();
    let mut helper = TestHelper::new(Network::Regtest, false, Some(1000))?;

    let id = Uuid::new_v4();

    let _ = helper.id_channel_pairs[0].channel.send(
        &helper.id_channel_pairs[0].id,
        IncomingBitVMXApiMessages::GenerateZKP(
            id,
            vec![1, 2, 3, 4],
            "../rust-bitvmx-zk-proof/target/riscv-guest/methods/bitvmx/riscv32im-risc0-zkvm-elf/release/bitvmx.bin".to_string()
        ).to_string()?,
    );

    let msg = helper.wait_msg(0)?;
    info!("ZKP generated: {:?}", msg);

    let _ = helper.id_channel_pairs[0].channel.send(
        &helper.id_channel_pairs[0].id,
        IncomingBitVMXApiMessages::GetZKPExecutionResult(id).to_string()?,
    );

    let msg = helper.wait_msg(0)?;
    info!("ZKP result: {:?}", msg);

    helper.stop()?;
    Ok(())
}
