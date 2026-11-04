mod api;
mod job_handler;
mod news;
mod peer_messages;
mod steps;
#[cfg(test)]
mod test_support;
mod timeouts;

use crate::{
    comms_allow_list,
    comms_helper::CommsMessageType,
    config::{ComponentsConfig, Config},
    error_handling::{classify, Reporter, Severity},
    errors::BitVMXError,
    expected_job::ExpectedJobs,
    leader_broadcast::LeaderBroadcastHelper,
    message_queue::MessageQueue,
    operation_timeout::OperationTimeouts,
    ping_helper::PingHelper,
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    program::{
        program::{is_active_program, Program},
        variables::{Globals, WitnessVars},
    },
    throttle::Throttle,
    types::{OutgoingBitVMXApiMessages, ProgramContext, ProgramStatus},
};
use bitcoin_coordinator::{coordinator::BitcoinCoordinator, TypesToMonitor};
use bitvmx_broker::{identification::identifier::Identifier, retry::RetryPolicy, BrokerNode};
use bitvmx_settings::settings;
use bitvmx_wallet::wallet::Wallet;
use key_manager::{
    create_key_manager_from_config, key_manager::KeyManager, key_type::BitcoinKeyType,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, rc::Rc, thread::sleep, time::Duration};
use storage_backend::{
    key::StorageKey,
    storage::{KeyValueStore, Storage},
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

pub const WALLET_INDEX: u32 = 100;
pub const WALLET_CHANGE_INDEX: u32 = 101;
pub const CLIENT_GLOBAL_SETTINGS_UUID: Uuid = Uuid::from_bytes(*b"GLOBAL_SETTINGS-");
pub const SEND_NEW_BLOCK_NEWS: &str = "send_new_block_news";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    Syncing,
    CaughtUp,
    Operating,
    Stopping,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Context {
    ProgramId(Uuid),
    RequestId(Uuid, Identifier),
    Protocol(Uuid, String),
    SetupStep(Uuid, String, String, CommsMessageType), // protocol_id, step_name, optional sub_step
    ProgramStep(Uuid, String), // program_id, step identifier (for job deduplication)
}

impl Context {
    pub fn to_string(&self) -> Result<String, BitVMXError> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn from_string(msg: &str) -> Result<Self, BitVMXError> {
        let msg: Context = serde_json::from_str(msg)?;
        Ok(msg)
    }
}

pub struct BitVMX<BC: BitcoinCoordinatorApi = BitcoinCoordinator> {
    config: Config,
    program_context: ProgramContext<BC>,
    store: Rc<Storage>,
    tick_count: u32,
    message_queue: MessageQueue,
    coordinator_throttle: Throttle,
    bitvmx_throttle: Throttle,
    wallet: Option<Wallet>,
    ping_helper: PingHelper,
    reporter: Reporter,
    shutdown: bool,
    /// Set once the indexer reaches the chain tip; until then a tick only syncs.
    chain_synced: bool,
}

impl<BC: BitcoinCoordinatorApi> Drop for BitVMX<BC> {
    fn drop(&mut self) {
        self.program_context.broker_channel.close();
        sleep(Duration::from_millis(100));
    }
}

enum StoreKey {
    Programs,
    ZKPExecution(Uuid),
}

impl StoreKey {
    fn get_key(&self) -> Result<StorageKey, BitVMXError> {
        match self {
            StoreKey::Programs => Ok(StorageKey::new(["bitvmx", "program", "list"])?),
            StoreKey::ZKPExecution(id) => Ok(StorageKey::new([
                "bitvmx",
                "zkp",
                id.to_string().as_str(),
                "execution",
            ])?),
        }
    }
}

fn print_version_info() {
    info!("BitVMX Client build information:");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    info!("Commit date: {}", env!("GIT_DATE"));
    info!("Git hash: {}", env!("GIT_HASH"));
    info!("Git message: {}", env!("GIT_MESSAGE"));
    info!("Git tag: {}", env!("GIT_TAG"));
}

impl BitVMX<BitcoinCoordinator> {
    pub fn new(config: Config) -> Result<Self, BitVMXError> {
        Self::new_with_coordinator_factory(config, true, |config, store, key_manager| {
            Ok(BitcoinCoordinator::new_with_paths(
                &config.bitcoin,
                store,
                key_manager,
                config.coordinator_settings.clone(),
            )?)
        })
    }
}

impl<BC: BitcoinCoordinatorApi> BitVMX<BC> {
    fn new_with_coordinator_factory<F>(
        config: Config,
        wallet_enabled: bool,
        factory: F,
    ) -> Result<Self, BitVMXError>
    where
        F: FnOnce(&Config, Rc<Storage>, Rc<KeyManager>) -> Result<BC, BitVMXError>,
    {
        print_version_info();
        let store = Rc::new(Storage::new(&config.storage)?);
        let key_manager = create_key_manager_from_config(&config.key_manager, &config.key_storage)?;
        let key_manager = Rc::new(key_manager);
        let rsa_public_key = key_manager
            .import_rsa_private_key(&settings::decrypt_or_read_file(config.comms_key())?)?;

        let comms_allow_list = comms_allow_list::build(&store, &config.comms.allow_list)?;

        info!("Comms allow list built successfully");

        let comms = BrokerNode::new_peers(
            "comms",
            config.comms.address,
            &settings::decrypt_or_read_file(&config.comms.priv_key)?,
            store.clone(),
            &config.comms.storage_path,
            comms_allow_list,
            config.broker.settings.clone(),
        )?;

        info!("Comms broker node initialized successfully");

        let wallet = if wallet_enabled {
            let wallet = Wallet::from_derive_keypair(
                config.bitcoin.clone(),
                config.wallet.clone(),
                key_manager.clone(),
                BitcoinKeyType::P2tr,
                WALLET_INDEX,
                Some(WALLET_CHANGE_INDEX),
            )?;
            info!("Wallet initialized successfully");
            Some(wallet)
        } else {
            info!("Wallet is disabled");
            None
        };

        let bitcoin_coordinator = factory(&config, store.clone(), key_manager.clone())?;
        info!("Bitcoin coordinator initialized successfully");

        //Also the broker could be run independently if needed
        let broker_channel = BrokerNode::new_services_with_paths(
            "services",
            SocketAddr::new(config.broker.ip, config.broker.port),
            &config.broker.priv_key,
            store.clone(),
            &config.broker.storage.path,
            &config.broker.allow_list,
            &config.broker.routing_table,
            config.components.bitvmx.clone(),
            config.broker.settings.clone(),
        )?;
        info!("Broker services initialized successfully");

        bitcoin_coordinator.monitor(TypesToMonitor::NewBlock)?;

        let leader_broadcast_helper = LeaderBroadcastHelper::new(store.clone());
        let operation_timeouts = OperationTimeouts::new(store.clone());
        let expected_jobs = ExpectedJobs::new(store.clone());

        let program_context = ProgramContext::new(
            comms,
            key_manager,
            rsa_public_key,
            bitcoin_coordinator,
            broker_channel,
            Globals::new(store.clone()),
            WitnessVars::new(store.clone()),
            config.components.clone(),
            leader_broadcast_helper,
            operation_timeouts,
            expected_jobs,
        );

        info!("Program context initialized successfully");

        let ping_helper = PingHelper::new(config.job_dispatcher_ping.clone())?;
        info!("Ping helper initialized successfully");

        let message_queue = MessageQueue::new(
            store.clone(),
            RetryPolicy::new(&config.broker.settings.broker_node_config)?,
        );
        info!("Message queue initialized successfully");

        let coordinator_throttle = Throttle::new(config.coordinator_throttle.clone());
        let bitvmx_throttle = Throttle::new(config.bitvmx_throttle.clone());

        info!("Coordinator and BitVMX throttle initialized successfully");

        let reporter = Reporter::new(config.components.l2.clone());
        Ok(Self {
            config,
            program_context,
            store,
            tick_count: 0,
            message_queue,
            coordinator_throttle,
            bitvmx_throttle,
            wallet,
            ping_helper,
            reporter,
            shutdown: false,
            chain_synced: false,
        })
    }

    pub fn shutdown(&mut self) -> Result<(), BitVMXError> {
        info!("Shutdown requested");
        self.shutdown = true;

        // Begin shutdown on subcomponents
        self.program_context.broker_channel.close();
        self.program_context.comms.close();
        info!("Shutdown completed");
        Ok(())
    }

    pub fn address(&self) -> SocketAddr {
        self.program_context.comms.get_address()
    }

    pub fn pubkey_hash(&self) -> Result<String, BitVMXError> {
        Ok(self.program_context.comms.get_pubk_hash())
    }

    pub fn get_components_config(&self) -> &ComponentsConfig {
        &self.config.components
    }

    pub fn get_store(&self) -> Rc<Storage> {
        self.store.clone()
    }

    pub fn load_program(&self, program_id: &Uuid) -> Result<Option<Program>, BitVMXError> {
        Program::load(self.store.clone(), program_id)
    }

    pub fn tick(&mut self) -> Result<TickOutcome, BitVMXError> {
        let result = self.tick_inner();

        if let Err(e) = &result {
            Self::log_error_chain(e);
            if !self.report_tick_error(e) {
                return Ok(TickOutcome::Operating);
            }
        }

        result
    }

    fn log_error_chain(e: &BitVMXError) {
        error!("Error in tick(): {e:#?}");
        let mut source = std::error::Error::source(e);
        while let Some(err) = source {
            error!("  Caused by: {err}");
            source = std::error::Error::source(err);
        }
    }

    /// Reports the error by severity and returns whether the node should stop.
    fn report_tick_error(&mut self, e: &BitVMXError) -> bool {
        match classify(e) {
            Severity::Fatal => {
                self.reporter.fatal(e, &self.program_context.broker_channel);
                true
            }
            Severity::BitcoinNodeUnreachable => {
                self.reporter
                    .rpc_unavailable(e, &self.program_context.broker_channel);
                false
            }
            Severity::Other => {
                self.reporter
                    .non_fatal(e, &self.program_context.broker_channel);
                false
            }
        }
    }

    fn tick_inner(&mut self) -> Result<TickOutcome, BitVMXError> {
        debug!("Ticking BitVMX: {}", self.tick_count);

        if self.shutdown {
            info!("BitVMX is shutdown, stopping tick processing.");
            return Ok(TickOutcome::Stopping);
        }

        self.tick_count += 1;

        // Nothing else can run against a chain we have not caught up with, so until the
        // coordinator reaches the tip a tick only advances the sync.
        if !self.chain_synced {
            self.process_bitcoin_updates_with_throttle()?;
            return Ok(if self.chain_synced {
                TickOutcome::CaughtUp
            } else {
                TickOutcome::Syncing
            });
        }

        if self.bitvmx_throttle.should_call() {
            self.process_application_phase()?;
        }

        Self::measure_time("bitcoin updates", || {
            self.run_step(
                "bitcoin updates",
                Self::process_bitcoin_updates_with_throttle,
            )
        })?;

        self.run_tx_step("dispatcher liveness", |this| {
            this.ping_helper
                .check_job_dispatchers_liveness(&this.program_context, &this.config.components)
        })?;

        Ok(TickOutcome::Operating)
    }

    fn process_application_phase(&mut self) -> Result<(), BitVMXError> {
        self.process_broker_queues()?;

        let mut had_work = false;

        had_work |= Self::measure_time("operation timeouts", || self.process_operation_timeouts())?;

        had_work |= self.timed_tx_step("dispatcher retries", |this| {
            Ok(this.program_context.expected_jobs.redispatch_due(
                &this.program_context.operation_timeouts,
                &this.program_context.broker_channel,
            )? > 0)
        })?;

        had_work |= self.timed_step("programs", Self::process_programs)?;

        had_work |= self.timed_tx_step("pending messages", Self::process_pending_messages)?;

        had_work |= Self::measure_time("comms messages", || self.process_comms_messages())?;

        had_work |= self.timed_step("API messages", Self::process_api_messages)?;

        self.bitvmx_throttle.record(had_work);
        Ok(())
    }

    pub fn process_broker_queues(&mut self) -> Result<(), BitVMXError> {
        // Deliver committed outgoing work before processing application messages.
        // Rollback cannot undo delivery, so transport retries may send duplicates.
        self.run_tx_step("comms transport", |this| {
            this.program_context.comms.tick().map_err(BitVMXError::from)
        })?;
        self.run_tx_step("service transport", |this| {
            this.program_context
                .broker_channel
                .tick()
                .map_err(BitVMXError::from)
        })?;
        Ok(())
    }

    /// Advances each program in its own transaction, reporting nonfatal failures locally.
    /// Must be called without an active global transaction.
    pub fn process_programs(&mut self) -> Result<bool, BitVMXError> {
        let all_programs = self.get_programs()?;

        let mut had_work = false;

        for status in all_programs {
            let program_id = status.program_id;
            had_work |= self
                .run_tx_step(&format!("program {program_id}"), |this| {
                    if !is_active_program(&this.store, &program_id)? {
                        return Ok(false);
                    }
                    let Some(mut program) = this.load_program(&program_id)? else {
                        warn!("Active program {} not found", program_id);
                        return Ok(false);
                    };
                    program.tick(&mut this.program_context)?;
                    Ok(true)
                })?
                .unwrap_or(true);
        }
        Ok(had_work)
    }

    fn get_programs(&self) -> Result<Vec<ProgramStatus>, BitVMXError> {
        let programs_ids: Option<Vec<ProgramStatus>> =
            self.store.get(StoreKey::Programs.get_key()?, None)?;

        Ok(programs_ids.unwrap_or_default())
    }

    fn reply(&self, to: Identifier, message: OutgoingBitVMXApiMessages) -> Result<(), BitVMXError> {
        debug!("> {:?}", message);
        self.program_context
            .broker_channel
            .send_service(&to, serde_json::to_string(&message)?)?;

        Ok(())
    }

    pub fn sync_wallet(&mut self) -> Result<(), BitVMXError> {
        let Some(wallet) = self.wallet.as_mut() else {
            return Ok(());
        };

        info!("Starting wallet sync...");
        wallet.sync_wallet()?;
        info!("Wallet sync completed.");
        Ok(())
    }
}
