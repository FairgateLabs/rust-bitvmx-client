use anyhow::Result;
use bitcoin::Network;
use bitcoind::bitcoind::Bitcoind;
use bitvmx_broker::channel::channel::DualChannel;
use bitvmx_broker::rpc::BrokerConfig;
use bitvmx_client::{bitvmx::BitVMX, config::Config, types::EMULATOR_ID};
use bitvmx_job_dispatcher::DispatcherHandler;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use bitvmx_wallet::wallet::Wallet;
use common::config_trace;
use common::{clear_db, FUNDING_ID, INITIAL_BLOCK_COUNT, WALLET_NAME};
use std::sync::mpsc::channel;
use std::time::Duration;
use std::{
    sync::mpsc::{Receiver, Sender},
    thread, vec,
};
use tracing::info;

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
                    info!("Waiting to get to the top of the Bitcoin chain...");
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

            Some(Bitcoind::new(
                "bitcoin-regtest",
                "ruimarinho/bitcoin-core",
                wallet_config.bitcoin.clone(),
            ))
        };

        info!("wallet config: {:?}", wallet_config);
        let wallet = Wallet::new(wallet_config, true)?;
        if !independent {
            info!("Starting bitcoind");
            bitcoind.as_ref().unwrap().start()?;
            wallet.mine(INITIAL_BLOCK_COUNT)?;
            thread::sleep(Duration::from_secs(1));
            wallet.create_wallet(WALLET_NAME)?;
            thread::sleep(Duration::from_secs(1));
            info!("Created wallet");
            wallet.regtest_fund(WALLET_NAME, FUNDING_ID, 100_000)?;
            thread::sleep(Duration::from_secs(1));
            info!("Regttest fund");
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

        Ok(TestHelper {
            bitcoind,
            wallet,
            bitvmx_handle: Some(bitvmx_handle),
            bitvmx_stop_tx,
            disp_handle: Some(disp_handle),
            disp_stop_tx,
            disp_ready_rx,
        })
    }

    pub fn stop(&mut self) -> Result<()> {
        if let Some(bitcoind) = &self.bitcoind {
            info!("Stopping bitcoind");
            bitcoind.stop()?;
        }
        self.disp_stop_tx.send(()).unwrap();
        self.bitvmx_stop_tx.send(()).unwrap();
        let handle = self.bitvmx_handle.take().unwrap();
        handle.join().unwrap()?;
        let handle = self.disp_handle.take().unwrap();
        handle.join().unwrap()?;

        info!("BitVMX instances stopped");
        Ok(())
    }
}

#[ignore]
#[test]
pub fn test_all() -> Result<()> {
    config_trace();

    let independent = false;
    const NETWORK: Network = Network::Regtest;
    let mut helper = TestHelper::new(NETWORK, independent)?;

    //let broker_config = BrokerConfig::new(config.broker_port, None);
    //let channel = DualChannel::new(&broker_config, EMULATOR_ID);

    thread::sleep(Duration::from_secs(5)); // Wait for the instances to be ready

    helper.stop()?;

    Ok(())
}
