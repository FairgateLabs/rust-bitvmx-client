use anyhow::Result;
use bitcoin::Network;
use bitcoind::bitcoind::Bitcoind;
use bitvmx_broker::channel::channel::DualChannel;
use bitvmx_broker::rpc::BrokerConfig;
use bitvmx_client::program;
use bitvmx_client::program::participant::P2PAddress;
use bitvmx_client::program::variables::VariableTypes;
use bitvmx_client::types::{
    IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, L2_ID,
};
use bitvmx_client::{bitvmx::BitVMX, config::Config, types::EMULATOR_ID};
use bitvmx_job_dispatcher::DispatcherHandler;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use bitvmx_wallet::wallet::Wallet;
use common::dispute::prepare_dispute;
use common::{clear_db, init_utxo_new, FUNDING_ID, INITIAL_BLOCK_COUNT, WALLET_NAME};
use common::{config_trace, send_all};
use protocol_builder::scripts::{self, SignMode};
use std::sync::mpsc::channel;
use std::time::Duration;
use std::{
    sync::mpsc::{Receiver, Sender},
    thread, vec,
};
use tracing::info;
use uuid::Uuid;

mod common;

pub fn get_configs(network: Network) -> Result<Vec<Config>> {
    let config_names = match network {
        Network::Regtest => vec!["op_1", "op_2", "op_3"],
        Network::Testnet => vec!["testnet_op_1", "testnet_op_2", "testnet_op_3"],
        _ => panic!("Network not supported: {}", network),
    };

    let mut configs = Vec::new();
    for name in config_names {
        let config = Config::new(Some(format!("config/{}.yaml", name)))?;
        configs.push(config);
    }
    Ok(configs)
}

fn run_bitvmx(network: Network, independent: bool, rx: Receiver<()>, tx: Sender<()>) -> Result<()> {
    let configs = get_configs(network)?;
    if !independent {
        for config in &configs {
            clear_db(&config.storage.path);
            clear_db(&config.key_storage.path);
            clear_db(&config.broker_storage.path);
        }
    }

    let mut instances = vec![];
    configs.iter().for_each(|config| {
        let bitvmx = BitVMX::new(config.clone()).expect("Failed to initialize BitVMX");
        instances.push(bitvmx);
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
                bitvmx.tick()?;
                thread::sleep(Duration::from_millis(10));
            } else {
                ready = bitvmx.process_bitcoin_updates()?;
                if !ready {
                    //info!("Waiting to get to the top of the Bitcoin chain...");
                } else {
                    info!("Bitcoin updates processed, ready to run.");
                    let _ = tx.send(());
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    Ok(())
}

fn run_emulator(network: Network, rx: Receiver<()>, tx: Sender<usize>) -> Result<()> {
    let configs = get_configs(network)?;

    let mut instances = vec![];
    configs.iter().for_each(|config| {
        let broker_config = BrokerConfig::new(config.broker_port, None);
        let channel = DualChannel::new(&broker_config, EMULATOR_ID);

        let prover_dispatcher = DispatcherHandler::<EmulatorJobType>::new(channel);
        instances.push(prover_dispatcher);
    });

    // Main processing loop
    loop {
        if rx.try_recv().is_ok() {
            info!("Signal received, shutting down...");
            break;
        }
        for (idx, dispatcher) in instances.iter_mut().enumerate() {
            if dispatcher.tick() {
                let _ = tx.send(idx);
            }
            thread::sleep(Duration::from_millis(10));
        }
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
    pub channels: Vec<DualChannel>,
}

impl TestHelper {
    pub fn new(network: Network, independent: bool) -> Result<Self> {
        let wallet_config = match network {
            Network::Regtest => "config/wallet_regtest.yaml",
            Network::Testnet => "config/wallet_testnet.yaml",
            _ => panic!("Not supported network {}", network),
        };

        let wallet_config = bitvmx_settings::settings::load_config_file::<
            bitvmx_wallet::config::Config,
        >(Some(wallet_config.to_string()))?;

        let bitcoind = if independent {
            None
        } else {
            assert!(network == Network::Regtest);
            clear_db(&wallet_config.storage.path);
            clear_db(&wallet_config.key_storage.path);

            let bitcoind = Bitcoind::new(
                "bitcoin-regtest",
                "ruimarinho/bitcoin-core",
                wallet_config.bitcoin.clone(),
            );
            bitcoind.start()?;
            Some(bitcoind)
        };

        let wallet = Wallet::new(wallet_config, true)?;
        if !independent {
            wallet.mine(INITIAL_BLOCK_COUNT)?;
            wallet.create_wallet(WALLET_NAME)?;
            wallet.regtest_fund(WALLET_NAME, FUNDING_ID, 100_000_000)?;
        }

        let (bitvmx_stop_tx, bitvmx_stop_rx) = channel::<()>();
        let (bitvmx_ready_tx, bitvmx_ready_rx) = channel::<()>();
        let bitvmx_handle = thread::spawn(move || {
            run_bitvmx(network, independent, bitvmx_stop_rx, bitvmx_ready_tx)
        });

        if bitvmx_ready_rx.try_recv().is_ok() {
            info!("Bitvmx instances are ready");
        }

        let (disp_stop_tx, disp_stop_rx) = channel::<()>();
        let (disp_ready_tx, disp_ready_rx) = channel::<usize>();
        let disp_handle = thread::spawn(move || run_emulator(network, disp_stop_rx, disp_ready_tx));

        let mut channels = vec![];
        let configs = get_configs(network)?;
        configs.iter().for_each(|config| {
            let broker_config = BrokerConfig::new(config.broker_port, None);
            let channel = DualChannel::new(&broker_config, L2_ID);
            channels.push(channel);
        });

        Ok(TestHelper {
            bitcoind,
            wallet,
            bitvmx_handle: Some(bitvmx_handle),
            bitvmx_stop_tx,
            disp_handle: Some(disp_handle),
            disp_stop_tx,
            disp_ready_rx,
            channels,
        })
    }

    pub fn stop(&mut self) -> Result<()> {
        self.disp_stop_tx.send(()).unwrap();
        self.bitvmx_stop_tx.send(()).unwrap();
        let handle = self.bitvmx_handle.take().unwrap();
        handle.join().unwrap()?;
        let handle = self.disp_handle.take().unwrap();
        handle.join().unwrap()?;

        if let Some(bitcoind) = &self.bitcoind {
            info!("Stopping bitcoind");
            bitcoind.stop()?;
        }
        info!("BitVMX instances stopped");
        Ok(())
    }

    pub fn wait_all_msg(&self) -> Result<Vec<OutgoingBitVMXApiMessages>> {
        let mut msgs = Vec::new();
        for (idx, _channel) in self.channels.iter().enumerate() {
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
        let channel = &self.channels[idx];
        loop {
            let msg = channel.recv()?;
            if let Some(msg) = msg {
                info!("Received message from channel {}: {:?}", idx, msg);
                return Ok(OutgoingBitVMXApiMessages::from_string(&msg.0)?);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn send_all(&self, command: IncomingBitVMXApiMessages) -> Result<()> {
        send_all(&self.channels, &command.to_string()?)
    }
}

#[ignore]
#[test]
pub fn test_all() -> Result<()> {
    config_trace();

    let independent = true;
    const NETWORK: Network = Network::Regtest;
    let mut helper = TestHelper::new(NETWORK, independent)?;

    let command = IncomingBitVMXApiMessages::GetCommInfo();
    helper.send_all(command)?;

    let addresses: Vec<P2PAddress> = helper
        .wait_all_msg()?
        .iter()
        .map(|msg| msg.comm_info().unwrap())
        .collect::<Vec<_>>();

    info!("Waiting for AggregatedPubkey message from all channels");
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), 0);
    helper.send_all(command)?;
    let msgs = helper.wait_all_msg()?;
    let _aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    info!("Generate Aggregated from pair");
    let pair_0_1 = vec![addresses[0].clone(), addresses[1].clone()];
    let pair_0_1_agg_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(pair_0_1_agg_id, pair_0_1.clone(), 0);
    helper.channels[0].send(BITVMX_ID, command.to_string()?)?;
    helper.channels[1].send(BITVMX_ID, command.to_string()?)?;
    let _msg = helper.wait_msg(0)?;
    let msg = helper.wait_msg(1)?;
    let pair_0_1_agg_pub_key = msg.aggregated_pub_key().unwrap();

    // prepare a second fund available so we don't need 2 blocks to get the UTXO
    if !independent {
        helper
            .wallet
            .regtest_fund(WALLET_NAME, "second", 100_000_000)?;
    }

    info!("Initializing UTXO for program");
    let spending_condition = vec![
        scripts::check_aggregated_signature(&pair_0_1_agg_pub_key, SignMode::Aggregate),
        scripts::check_aggregated_signature(&pair_0_1_agg_pub_key, SignMode::Aggregate),
    ];
    let (utxo, initial_out_type) = init_utxo_new(
        &helper.wallet,
        &pair_0_1_agg_pub_key,
        spending_condition.clone(),
        200_000,
        None,
    )?;

    info!("Initializing UTXO for the prover action");
    let (prover_win_utxo, prover_win_out_type) = init_utxo_new(
        &helper.wallet,
        &pair_0_1_agg_pub_key,
        spending_condition.clone(),
        11_000,
        Some("second"),
    )?;

    let pair_0_1_channels = vec![helper.channels[0].clone(), helper.channels[1].clone()];
    let prog_id = prepare_dispute(
        pair_0_1,
        pair_0_1_channels,
        &pair_0_1_agg_pub_key,
        utxo,
        initial_out_type,
        prover_win_utxo,
        prover_win_out_type,
        10_000,
        false,
        true,
    )?;

    let msg = helper.wait_msg(0)?;
    info!("Setup dispute done: {:?}", msg);

    // wait input from command line
    wait_enter(independent);

    let _ = helper.channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            prog_id,
            program::protocols::dispute::START_CH.to_string(),
        )
        .to_string()?,
    );

    helper.wallet.mine(1)?;
    wait_enter(independent);

    let data = "11111111";
    let set_input_1 =
        VariableTypes::Input(hex::decode(data).unwrap()).set_msg(prog_id, "program_input")?;
    let _ = helper.channels[0].send(BITVMX_ID, set_input_1)?;

    // send the tx
    let _ = helper.channels[0].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            prog_id,
            program::protocols::dispute::INPUT_1.to_string(),
        )
        .to_string()?,
    );

    //move this to the helper auto mining
    if !independent {
        for _ in 0..200 {
            helper.wallet.mine(1)?;
            thread::sleep(Duration::from_millis(1000));
        }
    }

    wait_enter(independent);
    //thread::sleep(Duration::from_secs(5)); // Wait for the instances to be ready

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
