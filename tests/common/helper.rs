#![allow(dead_code)]
#![cfg(test)]

use anyhow::Result;
use bitcoin::{Amount, Transaction};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_bitcoin_rpc::rpc_config::NetworkFlavor;
use bitvmx_broker::{
    channel::channel::DualChannel,
    identification::allow_list::AllowList,
    rpc::{tls_helper::Cert, BrokerConfig},
};
use bitvmx_client::{
    bitvmx::BitVMX,
    config::Config,
    errors::BitVMXError,
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
use bitvmx_settings::settings;
use std::{
    sync::mpsc::{channel, Receiver, Sender},
    thread,
    time::Duration,
};
use tracing::{error, info, info_span};
use uuid::Uuid;

use bitcoind::{
    bitcoind::{Bitcoind, BitcoindFlags},
    config::BitcoindConfig,
};
use bitvmx_wallet::{wallet::errors::WalletError, Destination, RegtestWallet, Wallet};

use crate::common::{clear_db, send_all, INITIAL_BLOCK_COUNT};
const MIN_TX_FEE: f64 = 2.0;

fn get_fee_rate_from_env(network_flavor: NetworkFlavor) -> u64 {
    match std::env::var("FEE_RATE") {
        Ok(rate_str) => match rate_str.parse::<u64>() {
            Ok(rate) => rate,
            Err(_) => {
                error!(
                    "Invalid FEE_RATE value: {}. Using {} default.",
                    rate_str, network_flavor
                );
                get_default_fee_rate(network_flavor)
            }
        },
        Err(_) => get_default_fee_rate(network_flavor),
    }
}

fn get_default_fee_rate(network_flavor: NetworkFlavor) -> u64 {
    match network_flavor {
        // Historical regtest value, kept exactly as it was.
        NetworkFlavor::Regtest => MIN_TX_FEE.ceil() as u64,
        // Simchain runs a spammer holding the mempool at a fee floor, so the 1 sat/vB
        // used on the live testnets would never confirm there.
        other => other.default_fee_rate(),
    }
}

/// How many sats to give each operator for speedups, per 100k of protocol budget.
///
/// Sizing this by the fee rate is not enough. The coordinator will pay up to
/// `max_feerate_sat_vb` when the mempool is busy, and a run that exhausts its funding
/// fails deep inside the protocol with `Insufficient funds`, nowhere near the cause.
/// On a chain we run ourselves the coins are worthless, so be generous and remove the
/// failure mode entirely rather than tune it.
///
/// Regtest keeps the historical value (the old hardcoded `MIN_TX_FEE` of 2), so its
/// funding amounts are byte-identical to before this existed.
pub fn speedup_funding_factor(network_flavor: NetworkFlavor) -> u64 {
    match network_flavor {
        NetworkFlavor::Regtest => 2,
        // Play money and a spammer that can push fees to `max_feerate_sat_vb` (100):
        // 100x headroom costs nothing and makes funding a non-issue across the whole
        // fee ladder, spam on or off.
        NetworkFlavor::Simchain => 200,
        // Real coins: keep the conservative historical amount.
        NetworkFlavor::Testnet
        | NetworkFlavor::Testnet4
        | NetworkFlavor::Signet
        | NetworkFlavor::Bitcoin => 2,
    }
}

pub struct InternalWallet {
    network_flavor: NetworkFlavor,
    wallet: Wallet,
    client: BitcoinClient,
}

impl InternalWallet {
    pub fn new(network_flavor: NetworkFlavor, client: BitcoinClient, wallet: Wallet) -> Self {
        assert_eq!(
            wallet.network,
            network_flavor.bitcoin_network(),
            "wallet config network does not match the {network_flavor} run target"
        );
        Self {
            network_flavor,
            wallet,
            client,
        }
    }

    pub fn sync_wallet(&mut self) -> Result<()> {
        self.wallet.sync_wallet()?;
        Ok(())
    }

    /// Advance the chain by `num_blocks`.
    ///
    /// On regtest we mint them. Everywhere else — simchain included — blocks are
    /// somebody else's business, so we wait for the height to advance instead.
    pub fn mine(&self, num_blocks: u64) -> Result<Vec<Transaction>, BitVMXError> {
        if self.network_flavor.can_mine_on_demand() {
            return Ok(self.wallet.mine(num_blocks)?);
        }

        self.wait_for_blocks(num_blocks)?;
        Ok(vec![])
    }

    /// Block until the chain tip has advanced by `num_blocks`.
    ///
    /// Waits for *every* requested block, not just the first. The protocols under test
    /// use timelocks of `TIMELOCK_BLOCKS` (15) blocks, so a caller asking for ten
    /// blocks and silently getting one would fail in a way that looks like a protocol
    /// bug rather than a harness bug.
    fn wait_for_blocks(&self, num_blocks: u64) -> Result<(), BitVMXError> {
        if num_blocks == 0 {
            return Ok(());
        }

        let best_block = || {
            self.client
                .get_best_block()
                .map_err(bitvmx_client::errors::BitcoinClientError::RpcError)
        };

        let initial = best_block()?;
        let target = initial + num_blocks as u32;

        info!(
            "Waiting for {} block(s) on {}: height {} -> {}",
            num_blocks, self.network_flavor, initial, target
        );

        // Bound the wait on *lack of progress* rather than on total elapsed time.
        // A total budget would have to be `per_block * num_blocks`, so a chain that
        // died would hang for the whole budget before failing; this way a stalled
        // miner is reported after one block's worth of silence however long the
        // overall wait legitimately takes.
        let mut last_seen = initial;
        let mut stall_deadline =
            std::time::Instant::now() + self.network_flavor.block_wait_timeout();
        loop {
            let current = best_block()?;
            if current >= target {
                return Ok(());
            }
            if current > last_seen {
                info!(
                    "{}: height {} / {} ({} to go)",
                    self.network_flavor,
                    current,
                    target,
                    target - current
                );
                last_seen = current;
                stall_deadline =
                    std::time::Instant::now() + self.network_flavor.block_wait_timeout();
            }
            if std::time::Instant::now() >= stall_deadline {
                return Err(BitVMXError::from(
                    bitvmx_client::errors::BitcoinClientError::RpcError(
                        bitvmx_bitcoin_rpc::errors::BitcoinClientError::FailedToMineBlocks {
                            error: format!(
                                "no new block on {} for {:?} while waiting for {} block(s): \
                                 height stuck at {} of {}. Is the chain still producing blocks?",
                                self.network_flavor,
                                self.network_flavor.block_wait_timeout(),
                                num_blocks,
                                current,
                                target
                            ),
                        },
                    ),
                ));
            }
            thread::sleep(self.network_flavor.block_poll_interval());
        }
    }

    pub fn fund_destination(
        &mut self,
        destination: Destination,
    ) -> Result<Transaction, WalletError> {
        if self.network_flavor.can_mine_on_demand() {
            // Sends and then mines a block to confirm it.
            self.wallet.fund_destination(destination)
        } else {
            // No mining rights here: broadcast a raw transaction and let the chain
            // confirm it in its own time.
            let fee_rate = get_fee_rate_from_env(self.network_flavor);
            self.wallet.send_funds(destination, Some(fee_rate))
        }
    }

    /// Confirmed, spendable balance in satoshis.
    pub fn confirmed_sats(&self) -> u64 {
        self.wallet.balance().confirmed.to_sat()
    }

    pub fn network_flavor(&self) -> NetworkFlavor {
        self.network_flavor
    }

    /// Whether blocks are ours to mint, or somebody else's to deliver.
    pub fn can_mine_on_demand(&self) -> bool {
        self.network_flavor.can_mine_on_demand()
    }

    pub fn block_wait_timeout(&self) -> Duration {
        self.network_flavor.block_wait_timeout()
    }

    pub fn best_block(&self) -> Result<u32, BitVMXError> {
        Ok(self
            .client
            .get_best_block()
            .map_err(bitvmx_client::errors::BitcoinClientError::RpcError)?)
    }
}

pub struct TestHelper {
    pub bitcoind: Option<Bitcoind>,
    pub wallet: InternalWallet,
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
    pub fn clear_local_dbs(network_flavor: NetworkFlavor) -> Result<()> {
        let wallet_config = bitvmx_settings::settings::load_config_file::<
            bitvmx_wallet::wallet::config::Config,
        >(Some(network_flavor.wallet_config().to_string()))?;

        // Safe on simchain too: local state is rebuilt by rescanning from
        // `start_height`, and the coins themselves live on chain.
        assert!(
            network_flavor.is_disposable_chain(),
            "refusing to wipe local databases for {network_flavor}"
        );
        clear_db(&wallet_config.storage.path);
        clear_db(&wallet_config.key_storage.path);
        Wallet::clear_db(&wallet_config.wallet)?;

        Ok(())
    }

    pub fn new(
        network_flavor: NetworkFlavor,
        independent: bool,
        auto_mine: Option<u64>,
    ) -> Result<Self> {
        info!(
            "Initializing TestHelper for {} (independent: {})",
            network_flavor, independent
        );

        let wallet_config = bitvmx_settings::settings::load_config_file::<
            bitvmx_wallet::wallet::config::Config,
        >(Some(network_flavor.wallet_config().to_string()))?;

        info!("Wallet settings loaded");

        let bitcoind = if independent {
            None
        } else {
            clear_db(&wallet_config.storage.path);
            clear_db(&wallet_config.key_storage.path);
            Wallet::clear_db(&wallet_config.wallet)?;

            // In CI, bitcoind is provided by docker-compose on the same port.
            // Spawning another container would collide on 0.0.0.0:18443.
            if !network_flavor.spawns_own_bitcoind() || std::env::var("GITHUB_ACTIONS").is_ok() {
                info!("Using an externally managed node for {}", network_flavor);
                None
            } else {
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
            }
        };

        let mut wallet =
            Wallet::from_config(wallet_config.bitcoin.clone(), wallet_config.wallet.clone())?;
        // Built from the config, so the client knows its network_flavor and the simchain guard
        // rails in bitvmx-bitcoin-rpc are armed.
        let bitcoin_client = BitcoinClient::new_from_config(&wallet_config.bitcoin)?;

        if !independent {
            if network_flavor.has_node_wallet() {
                let address = bitcoin_client.init_wallet(&wallet_config.bitcoin.wallet)?;
                if std::env::var("GITHUB_ACTIONS").is_err() {
                    // Locally we control bitcoind; in CI the shared bitcoind is already
                    // funded by the test harness, so skip the extra mining.
                    bitcoin_client.mine_blocks_to_address(INITIAL_BLOCK_COUNT, &address)?;
                }
                bitcoin_client
                    .fund_address(&wallet.receive_address()?, Amount::from_int_btc(10))?;
            } else {
                // No node wallet and no mining rights: the chain must already be up
                // and the master wallet already funded.
                preflight_external_chain(network_flavor, &bitcoin_client)?;
            }
            wallet.sync_wallet()?;

            if network_flavor.needs_prefunded_wallet() {
                assert_funded(network_flavor, &mut wallet)?;
            }
        }

        info!("Wallet ready");

        let (bitvmx_stop_tx, bitvmx_stop_rx) = channel::<()>();
        let (bitvmx_ready_tx, bitvmx_ready_rx) = channel::<()>();
        let bitvmx_handle = thread::spawn(move || {
            run_bitvmx(network_flavor, independent, bitvmx_stop_rx, bitvmx_ready_tx)
        });
        info!("BitVMX instances started");

        while !bitvmx_ready_rx.try_recv().is_ok() {
            thread::sleep(Duration::from_millis(100));
        }
        info!("Bitvmx instances are ready");

        let (disp_stop_tx, disp_stop_rx) = channel::<()>();
        let (disp_ready_tx, disp_ready_rx) = channel::<usize>();
        let disp_handle = thread::spawn(move || {
            let result = run_emulator(network_flavor, disp_stop_rx, disp_ready_tx);
            if let Err(ref e) = result {
                error!("run_emulator failed: {:?}", e);
            }
            result
        });

        let (zkp_stop_tx, zkp_stop_rx) = channel::<()>();
        let (zkp_ready_tx, zkp_ready_rx) = channel::<usize>();
        let zkp_handle = thread::spawn(move || run_zkp(network_flavor, zkp_stop_rx, zkp_ready_tx));

        let (garbled_stop_tx, garbled_stop_rx) = channel::<()>();
        let (garbled_ready_tx, garbled_ready_rx) = channel::<usize>();
        let garbled_handle =
            thread::spawn(move || run_garbled(network_flavor, garbled_stop_rx, garbled_ready_tx));

        // Only meaningful where blocks are ours to mint. Simchain mines itself, and
        // asking it for a block would defeat the point of testing against it.
        let automine_interval = if network_flavor.can_mine_on_demand() {
            auto_mine.unwrap_or(0)
        } else {
            0
        };
        let (mine_handle, mine_stop_tx, mine_block_rx) = if automine_interval > 0 {
            let (mine_stop_tx, mine_stop_rx) = channel::<()>();
            let (mine_ready_tx, mine_ready_rx) = channel::<()>();
            let mine_handle = thread::spawn(move || {
                // if 500 blocks mined, stop
                run_auto_mine(
                    network_flavor,
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
        let configs = get_configs(network_flavor)?;
        for config in &configs {
            let allow_list = AllowList::from_file(&config.broker.allow_list)?;
            let broker_config = BrokerConfig::new(
                config.broker.port,
                None,
                config.broker.get_pubk_hash()?,
                Some(config.broker.settings.clone()),
            );
            let channel = DualChannel::new(
                &broker_config,
                Cert::new_with_privk(
                    settings::decrypt_or_read_file(&config.testing.l2.priv_key)?.as_str(),
                )?,
                Some(config.testing.l2.id),
                allow_list.clone(),
            )?;
            let id = config.components.bitvmx.clone();
            id_channel_pairs.push(ParticipantChannel { channel, id });
        }

        Ok(TestHelper {
            bitcoind,
            wallet: InternalWallet::new(network_flavor, bitcoin_client, wallet),
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

pub fn get_configs(network_flavor: NetworkFlavor) -> Result<Vec<Config>> {
    let mut configs = Vec::new();
    for name in network_flavor.op_configs() {
        info!("Loading config: {}", name);
        let config = Config::new(Some(format!("config/{}.yaml", name)))?;
        configs.push(config);
    }
    Ok(configs)
}

/// Fail early, and legibly, when an externally managed chain is not usable.
///
/// Without this, a stopped simchain stack surfaces as a connection error from deep
/// inside wallet sync, which reads like a bug in the code under test.
fn preflight_external_chain(network_flavor: NetworkFlavor, client: &BitcoinClient) -> Result<()> {
    let info = client.get_blockchain_info().map_err(|e| {
        anyhow::anyhow!(
            "cannot reach the {network_flavor} node: {e}.\n\
             Bring the chain up first — for simchain see SIMCHAIN.md \
             (`docker compose up -d` in the simchain repo)."
        )
    })?;

    if info.chain != network_flavor.bitcoin_network() {
        anyhow::bail!(
            "the node at the configured URL reports chain {:?}, but {network_flavor} expects {:?}. \
             Wrong node, or wrong config file?",
            info.chain,
            network_flavor.bitcoin_network()
        );
    }

    // Simchain bootstraps past coinbase maturity before it is usable; a chain still
    // catching up would give the wallet nothing spendable to find.
    const MIN_USABLE_HEIGHT: u64 = 200;
    if network_flavor == NetworkFlavor::Simchain && info.blocks < MIN_USABLE_HEIGHT {
        anyhow::bail!(
            "simchain is only at height {} (need >= {}). \
             The stack is probably still bootstrapping — wait, or check \
             `docker compose logs -ft btc-simnet-mining-controller`.",
            info.blocks,
            MIN_USABLE_HEIGHT
        );
    }

    info!("{} preflight ok: height {}", network_flavor, info.blocks);
    Ok(())
}

/// Confirm the master wallet actually holds spendable coins.
///
/// On a chain we cannot mine, an empty wallet is unrecoverable, so say so up front
/// rather than failing on the first funding transaction.
fn assert_funded(network_flavor: NetworkFlavor, wallet: &mut Wallet) -> Result<()> {
    let balance = wallet.balance();
    if balance.confirmed.to_sat() == 0 {
        anyhow::bail!(
            "the {network_flavor} master wallet at {} has no confirmed funds \
             (trusted pending {}, immature {}).\n\
             For simchain, USER_ADDRESS in the simnet's .env must be this address; \
             see SIMCHAIN.md and `cargo test --test print_env_address -- --nocapture`.",
            wallet.receive_address()?,
            balance.trusted_pending,
            balance.immature,
        );
    }
    info!(
        "{} master wallet balance: {}",
        network_flavor, balance.confirmed
    );
    Ok(())
}

fn run_bitvmx(
    network_flavor: NetworkFlavor,
    independent: bool,
    rx: Receiver<()>,
    tx: Sender<()>,
) -> Result<()> {
    let configs = get_configs(network_flavor);
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
        for (i, bitvmx) in instances.iter_mut().enumerate() {
            let _span = info_span!("", id = i).entered();
            if ready {
                let ret = bitvmx.tick();
                if ret.is_err() {
                    error!("Error in BitVMX tick: {:?}", ret);
                    return Ok(());
                }
            } else {
                ready = bitvmx.process_bitcoin_updates_with_throttle()?;
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

fn run_emulator(network_flavor: NetworkFlavor, rx: Receiver<()>, tx: Sender<usize>) -> Result<()> {
    let configs = get_configs(network_flavor)?;

    let mut instances = vec![];

    for (i, config) in configs.iter().enumerate() {
        info!(
            "Starting emulator connection with port: {}",
            config.broker.port
        );

        let allow_list = AllowList::from_file(&config.broker.allow_list)?;
        let broker_config = BrokerConfig::new(
            config.broker.port,
            None,
            config.broker.get_pubk_hash()?,
            Some(config.broker.settings.clone()),
        );
        let channel = DualChannel::new(
            &broker_config,
            Cert::new_with_privk(
                settings::decrypt_or_read_file(&config.testing.emulator.priv_key)?.as_str(),
            )?,
            Some(config.testing.emulator.id),
            allow_list.clone(),
        )?;

        //TODO: this is temporal until there are separated storages
        let storage_path = format!("/tmp/emulator_storage_{i}.db");
        clear_db(&storage_path);
        let prover_dispatcher = DispatcherHandler::<EmulatorJobType>::new_with_path(
            channel,
            &storage_path,
            None,
            true,
        )?;
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

fn run_zkp(network_flavor: NetworkFlavor, rx: Receiver<()>, tx: Sender<usize>) -> Result<()> {
    let configs = get_configs(network_flavor)?;

    let mut instances = vec![];
    for (i, config) in configs.iter().enumerate() {
        info!("Starting zkp connection with port: {}", config.broker.port);
        let allow_list = AllowList::from_file(&config.broker.allow_list)?;
        let broker_config = BrokerConfig::new(
            config.broker.port,
            None,
            config.broker.get_pubk_hash()?,
            Some(config.broker.settings.clone()),
        );
        let channel = DualChannel::new(
            &broker_config,
            Cert::new_with_privk(
                settings::decrypt_or_read_file(&config.testing.prover.priv_key)?.as_str(),
            )?,
            Some(config.testing.prover.id),
            allow_list.clone(),
        )?;

        //TODO: this is temporal until there are separated storages
        let storage_path = format!("/tmp/zkp_storage_{i}.db");
        clear_db(&storage_path);
        let prover_dispatcher =
            DispatcherHandler::<ProverJobType>::new_with_path(channel, &storage_path, None, true)?;
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

fn run_garbled(network_flavor: NetworkFlavor, rx: Receiver<()>, tx: Sender<usize>) -> Result<()> {
    // Set GNOVA_BIN path for the correct relative path from rust-bitvmx-client
    std::env::set_var("GNOVA_BIN", "../rust-bitvmx-gc/target/release/gnova");

    let configs = get_configs(network_flavor)?;

    let mut instances = vec![];
    for (i, config) in configs.iter().enumerate() {
        info!(
            "Starting garbled dispatcher connection with port: {}",
            config.broker.port
        );
        let allow_list = AllowList::from_file(&config.broker.allow_list)?;
        let broker_config = BrokerConfig::new(
            config.broker.port,
            None,
            config.broker.get_pubk_hash()?,
            Some(config.broker.settings.clone()),
        );
        let channel = DualChannel::new(
            &broker_config,
            Cert::from_key_file(&config.testing.garbler.priv_key)?,
            Some(config.testing.garbler.id), // Use different ID to avoid conflicts
            allow_list.clone(),
        )?;

        //TODO: this is temporal until there are separated storages
        let storage_path = format!("/tmp/garbled_storage_{i}.db");
        clear_db(&storage_path);
        let garbled_dispatcher =
            DispatcherHandler::<GarbledJobType>::new_with_path(channel, &storage_path, None, true)?;
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
    network_flavor: NetworkFlavor,
    rx: Receiver<()>,
    tx: Sender<()>,
    interval: u64,
    max_mined_blocks: Option<u64>,
) -> Result<()> {
    // Belt and braces: the caller already gates on this, but auto-mining a chain we
    // do not own is the exact failure this port is trying to make impossible.
    assert!(
        network_flavor.can_mine_on_demand(),
        "run_auto_mine called for {network_flavor}, which mines its own blocks"
    );

    let config = &get_configs(network_flavor)?[0];

    let bitcoin_client = BitcoinClient::new_from_config(&config.bitcoin)?;
    let address = bitcoin_client.init_wallet("test_wallet");
    let address = address.unwrap();

    // Track how many blocks *this* auto_mine has produced, not the absolute
    // chain height. The chain may already be tall when tests run sequentially
    // in CI (previous test binaries share the same bitcoind), so comparing
    // against absolute height would abort immediately.
    let start_height = bitcoin_client.get_blockchain_info()?.blocks;
    let mut mined: u64 = 0;

    // Main processing loop
    loop {
        if rx.try_recv().is_ok() {
            info!("Signal received, shutting down...");
            break;
        }
        bitcoin_client.mine_blocks_to_address(1, &address)?;
        mined += 1;
        tx.send(())?;
        if let Some(limit) = max_mined_blocks {
            if mined >= limit {
                error!(
                    "Max mined blocks reached! (mined {} since start_height {})",
                    mined, start_height
                );
                std::process::abort();
            }
        }
        thread::sleep(Duration::from_millis(interval));
    }
    Ok(())
}
