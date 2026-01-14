use crate::config::ComponentsConfig;
use crate::message_queue::QueuedMessage;
use crate::ping_helper::{JobDispatcherType, PingHelper};
use crate::program::program::is_active_program;
use crate::program::protocols::protocol_handler::ProtocolHandler;
use crate::shutdown::GracefulShutdown;
use crate::spv_proof::get_spv_proof;
use crate::timestamp_verifier::TimestampVerifier;
use crate::{
    api::BitVMXApi,
    collaborate::Collaboration,
    comms_helper::{deserialize_msg, CommsMessageType},
    config::Config,
    errors::BitVMXError,
    keychain::KeyChain,
    leader_broadcast::{LeaderBroadcastHelper, OriginalMessage},
    message_queue::MessageQueue,
    program::{
        participant::CommsAddress,
        program::Program,
        variables::{Globals, WitnessVars},
    },
    signature_verifier::SignatureVerifier,
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ProgramContext, ProgramStatus},
};
use bitcoin::secp256k1::Message;
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use bitcoin_coordinator::{
    coordinator::{BitcoinCoordinator, BitcoinCoordinatorApi},
    types::{AckCoordinatorNews, AckNews, CoordinatorNews},
    AckMonitorNews, MonitorNews, TypesToMonitor,
};
use bitvmx_broker::channel::queue_channel::{QueueChannel, ReceiveHandlerChannel};
use bitvmx_broker::channel::retry_helper::RetryPolicy;
use bitvmx_broker::identification::allow_list::AllowList;
use bitvmx_broker::identification::routing::RoutingTable;
use bitvmx_broker::{identification::identifier::Identifier, rpc::tls_helper::Cert};
use bitvmx_job_dispatcher::helper::PingMessage;
use key_manager::key_type::BitcoinKeyType;
use protocol_builder::graph::graph::GraphOptions;

use bitvmx_broker::{
    broker_storage::BrokerStorage,
    channel::channel::LocalChannel,
    rpc::{sync_server::BrokerSync, BrokerConfig},
};
use bitvmx_cpu_definitions::challenge::EmulatorResultType;
use bitvmx_job_dispatcher::dispatcher_job::{DispatcherJob, ResultMessage};

use bitvmx_job_dispatcher_types::prover_messages::ProverJobType;
use bitvmx_wallet::wallet::Wallet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashSet,
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
    time::Instant,
};
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

pub const THROTTLE_TICKS: u32 = 2;
pub const WALLET_INDEX: u32 = 100;
pub const WALLET_CHANGE_INDEX: u32 = 101;

#[derive(Debug)]
struct BitcoinUpdateState {
    last_update: Instant,
    was_synced: bool,
}

pub struct BitVMX {
    config: Config,
    program_context: ProgramContext,
    store: Rc<Storage>,
    broker: BrokerSync,
    count: u32,
    message_queue: MessageQueue,
    timestamp_verifier: TimestampVerifier,
    notified_request: HashSet<(Uuid, (Txid, Option<u32>))>,
    notified_rsk_pegin: HashSet<Txid>, //workaround for RSK pegin transactions because ack seems to be not working
    bitcoin_update: BitcoinUpdateState,
    wallet: Wallet,
    ping_helper: PingHelper,
    shutdown: bool,
}

impl Drop for BitVMX {
    fn drop(&mut self) {
        self.broker.close();
        sleep(Duration::from_millis(100));
    }
}
enum StoreKey {
    Programs,
    Collaboration(Uuid),
    CompleteCollaboration(Uuid),
    ZKPProof(Uuid),
    ZKPStatus(Uuid),
    ZKPFrom(Uuid),
    ZKPJournal(Uuid),
}

impl StoreKey {
    fn get_key(&self) -> String {
        match self {
            StoreKey::Programs => "bitvmx/programs/all".to_string(),
            StoreKey::Collaboration(id) => format!("bitvmx/collaboration/{}", id),
            StoreKey::CompleteCollaboration(id) => format!("bitvmx/collaboration_complete/{}", id),
            StoreKey::ZKPProof(id) => format!("bitvmx/zkp/{}/proof", id),
            StoreKey::ZKPStatus(id) => format!("bitvmx/zkp/{}/status", id),
            StoreKey::ZKPFrom(id) => format!("bitvmx/zkp/{}/from", id),
            StoreKey::ZKPJournal(id) => format!("bitvmx/zkp/{}/journal", id),
        }
    }
}

impl BitVMX {
    pub fn new(config: Config) -> Result<Self, BitVMXError> {
        let store = Rc::new(Storage::new(&config.storage)?);
        let key_chain = KeyChain::new(&config, store.clone())?;

        let comms = QueueChannel::new_with_paths(
            "comms",
            config.comms.address,
            &config.comms.priv_key,
            store.clone(),
            Some(config.comms.storage_path.clone()),
            &config.broker.allow_list, //TODO: should be different from broker
            &config.broker.routing_table,
        )?;

        let wallet = Wallet::from_derive_keypair(
            config.bitcoin.clone(),
            config.wallet.clone(),
            key_chain.key_manager.clone(),
            BitcoinKeyType::P2tr,
            WALLET_INDEX,
            Some(WALLET_CHANGE_INDEX),
        )?;

        let bitcoin_coordinator = BitcoinCoordinator::new_with_paths(
            &config.bitcoin,
            store.clone(),
            key_chain.key_manager.clone(),
            config.coordinator_settings.clone(),
        )?;

        //TODO: This could be moved to a simplified helper inside brokerstorage new
        //Also the broker could be run independently if needed
        let allow_list = AllowList::from_file(&config.broker.allow_list)?;
        let routing_table = RoutingTable::from_file(&config.broker.routing_table)?;
        let broker_backend = Storage::new(&config.broker.storage)?;
        let broker_backend = Arc::new(Mutex::new(broker_backend));
        let broker_storage = Arc::new(Mutex::new(BrokerStorage::new(broker_backend)));
        let cert = Cert::from_key_file(&config.broker.priv_key)?;
        let broker_config = BrokerConfig::new(
            config.broker.port,
            Some(config.broker.ip),
            config.broker.get_pubk_hash()?,
        );
        let broker = BrokerSync::new(
            &broker_config,
            broker_storage.clone(),
            cert,
            allow_list,
            routing_table,
        )?;

        let broker_channel =
            LocalChannel::new(config.components.bitvmx.clone(), broker_storage.clone());

        bitcoin_coordinator.monitor(TypesToMonitor::NewBlock)?;

        let leader_broadcast_helper = LeaderBroadcastHelper::new(store.clone());

        let program_context = ProgramContext::new(
            comms,
            key_chain,
            bitcoin_coordinator,
            broker_channel,
            Globals::new(store.clone()),
            WitnessVars::new(store.clone()),
            config.components.clone(),
            leader_broadcast_helper,
        );

        let ping_helper = PingHelper::new(config.job_dispatcher_ping.clone());
        let timestamp_config = config
            .timestamp_verifier
            .as_ref()
            .map(|c| c.clone())
            .unwrap_or_default();
        let timestamp_verifier =
            TimestampVerifier::new(timestamp_config.enabled, timestamp_config.max_drift_ms);

        let message_queue = MessageQueue::new(store.clone(), RetryPolicy::default());

        Ok(Self {
            config,
            program_context,
            store: store.clone(),
            broker,
            count: 0,
            message_queue,
            timestamp_verifier,
            notified_request: HashSet::new(),
            notified_rsk_pegin: HashSet::new(),
            bitcoin_update: BitcoinUpdateState {
                last_update: Instant::now(),
                was_synced: false,
            },
            wallet,
            ping_helper,
            shutdown: false,
        })
    }

    pub fn shutdown(&mut self, timeout: Duration) -> Result<(), BitVMXError> {
        info!("Shutdown requested");
        self.shutdown = true;
        let deadline = Instant::now() + timeout;
        self.begin_shutdown();

        // Begin shutdown on subcomponents
        self.program_context.comms.begin_shutdown();
        self.program_context.bitcoin_coordinator.begin_shutdown();
        self.broker.begin_shutdown();
        // Drain global in-flight
        self.drain_until_idle(deadline);

        // Drain subcomponents best-effort
        self.program_context.comms.drain_until_idle(deadline);
        self.program_context
            .bitcoin_coordinator
            .drain_until_idle(deadline);
        self.broker.drain_until_idle(deadline);

        // Drain active programs: ensure we don't schedule new work and persist state
        if let Ok(programs) = self.get_programs() {
            for status in programs {
                if let Ok(mut program) = self.load_program(&status.program_id) {
                    program.begin_shutdown();
                    program.drain_until_idle(deadline);
                    program.shutdown_now();
                }
            }
        }
        // Finalize subcomponents shutdown first
        self.program_context.comms.shutdown_now();
        self.program_context.bitcoin_coordinator.shutdown_now();
        self.broker.shutdown_now();

        // Finalize BitVMX shutdown
        self.shutdown_now();
        info!("Shutdown completed");
        Ok(())
    }

    pub fn address(&self) -> SocketAddr {
        self.program_context.comms.get_address()
    }

    pub fn pubkey_hash(&self) -> Result<String, BitVMXError> {
        Ok(self.program_context.comms.get_pubk_hash()?)
    }

    pub fn get_components_config(&self) -> &ComponentsConfig {
        &self.config.components
    }

    pub fn get_store(&self) -> Rc<Storage> {
        self.store.clone()
    }

    pub fn load_program(&self, program_id: &Uuid) -> Result<Program, BitVMXError> {
        let program = Program::load(self.store.clone(), program_id)?;
        Ok(program)
    }

    /// Step 1: Verifies the message signature.
    /// Returns Ok(true) if verification succeeded, Ok(false) if the message needs to be buffered
    /// (e.g., missing verification key), or Err if there was an error.
    fn verify_message_signature(
        &self,
        identifier: &Identifier,
        program_id: &Uuid,
        version: &String,
        msg_type: &CommsMessageType,
        data: &Value,
        timestamp: i64,
        signature: &Vec<u8>,
    ) -> Result<bool, BitVMXError> {
        match SignatureVerifier::verify_and_get_key(
            &self.program_context.comms,
            &self.program_context.globals,
            &self.program_context.key_chain,
            &identifier.pubkey_hash,
            program_id,
            msg_type,
            data,
            timestamp,
            signature,
            version,
        ) {
            Ok(_) => Ok(true),
            Err(BitVMXError::MissingVerificationKey { .. }) => Ok(false),
            Err(err) => Err(err),
        }
    }

    /// Processes a message for a Program.
    /// Returns Ok(true) if message was processed, Ok(false) if it needs to be buffered,
    /// or Err if there was an error.
    fn process_program_message(
        &self,
        program_id: &Uuid,
        msg_type: CommsMessageType,
        data: Value,
        peer_address: CommsAddress,
        program: &mut Program,
        timestamp: i64,
        signature: Vec<u8>,
        version: String,
    ) -> Result<bool, BitVMXError> {
        let my_pubkey_hash = self.program_context.comms.get_pubk_hash()?;
        let participants: Vec<_> = program
            .participants
            .iter()
            .filter(|p| p.comms_address.pubkey_hash != my_pubkey_hash)
            .map(|p| p.comms_address.pubkey_hash.clone())
            .collect();
        if !SignatureVerifier::has_all_keys(&self.program_context.globals, &participants)? {
            info!("Missing verification keys for program: {:?}", program_id);
            return Ok(false);
        }

        // If this operator is the leader and the message type should be broadcast, store the original message
        if program.my_idx == program.leader {
            let should_store = matches!(
                msg_type,
                CommsMessageType::Keys
                    | CommsMessageType::PublicNonces
                    | CommsMessageType::PartialSignatures
            );
            if should_store {
                let original_msg = OriginalMessage {
                    sender_pubkey_hash: peer_address.pubkey_hash.clone(),
                    msg_type,
                    data: data.clone(),
                    original_timestamp: timestamp,
                    original_signature: signature.clone(),
                    version: version.clone(),
                };
                self.program_context
                    .leader_broadcast_helper
                    .store_original_message(program_id, msg_type, original_msg)?;
            }
        }

        // Step 3: Process normal messages (non-verification)
        program.process_comms_message(
            peer_address,
            msg_type,
            data,
            &self.program_context,
            timestamp,
            signature,
            version,
        )?;
        Ok(true)
    }

    /// Processes a message for a Collaboration.
    /// Returns Ok(true) if message was processed, Ok(false) if it needs to be buffered,
    /// or Err if there was an error.
    fn process_collaboration_message(
        &self,
        program_id: &Uuid,
        msg_type: CommsMessageType,
        data: Value,
        peer_address: CommsAddress,
        collaboration: &mut Collaboration,
        timestamp: i64,
        signature: Vec<u8>,
        version: String,
    ) -> Result<bool, BitVMXError> {
        let my_pubkey_hash = self.program_context.comms.get_pubk_hash()?;
        let participants: Vec<_> = collaboration
            .participants
            .iter()
            .filter(|p| p.pubkey_hash != my_pubkey_hash)
            .map(|p| p.pubkey_hash.clone())
            .collect();
        if !SignatureVerifier::has_all_keys(&self.program_context.globals, &participants)? {
            info!(
                "Missing verification keys for collaboration: {:?}",
                program_id
            );
            return Ok(false);
        }
        // If this operator is the leader and the message type should be broadcast, store the original message
        if collaboration.im_leader {
            let should_store = matches!(
                msg_type,
                CommsMessageType::Keys
                    | CommsMessageType::PublicNonces
                    | CommsMessageType::PartialSignatures
            );
            if should_store {
                let original_msg = OriginalMessage {
                    sender_pubkey_hash: peer_address.pubkey_hash.clone(),
                    msg_type,
                    data: data.clone(),
                    original_timestamp: timestamp,
                    original_signature: signature.clone(),
                    version: version.clone(),
                };
                info!(
                    "Storing original message from peer: {:?}, msg_type: {:?}",
                    peer_address, msg_type
                );
                self.program_context
                    .leader_broadcast_helper
                    .store_original_message(program_id, msg_type, original_msg)?;
            }
        }

        // Step 3: Process normal messages (non-verification)
        collaboration.process_comms_message(
            peer_address,
            msg_type,
            data,
            &self.program_context,
            timestamp,
            signature,
            version,
        )?;
        Ok(true)
    }

    pub fn process_msg(&mut self, msg: QueuedMessage) -> Result<(), BitVMXError> {
        let is_new_message = msg.retry_state.get_attempts() == 0;
        let (version, msg_type, program_id, data, timestamp, signature) =
            deserialize_msg(msg.data.clone())?;

        // Handle Broadcasted messages specially - they contain original messages to process recursively
        if msg_type == CommsMessageType::Broadcasted {
            info!("Processing Broadcasted message...");
            return self
                .program_context
                .leader_broadcast_helper
                .process_broadcasted_message(
                    &self.program_context,
                    msg.identifier,
                    program_id,
                    data,
                    &self.message_queue,
                );
        }

        let is_verification_msg = matches!(
            msg_type,
            CommsMessageType::VerificationKey | CommsMessageType::VerificationKeyRequest
        );
        if !is_verification_msg {
            let verified = self.verify_message_signature(
                &msg.identifier,
                &program_id,
                &version,
                &msg_type,
                &data,
                timestamp,
                &signature,
            )?;
            if !verified {
                info!(
                    "Buffering message due to missing verification key: {:?} {:?}",
                    program_id, msg_type
                );
                self.message_queue.push_back(msg)?;
                return Ok(());
            }
        }
        if is_new_message {
            self.timestamp_verifier
                .ensure_fresh(&msg.identifier.pubkey_hash, timestamp)?;
        }
        let (program, collaboration, peer_address) = if let Some(program) =
            self.load_program(&program_id).ok()
        {
            let peer_address = program.get_address_from_pubkey_hash(&msg.identifier.pubkey_hash)?;

            (Some(program), None, Some(peer_address))
        } else if let Some(collaboration) = self.get_collaboration(&program_id)? {
            let peer_address =
                collaboration.get_address_from_pubkey_hash(&msg.identifier.pubkey_hash)?;
            (None, Some(collaboration), Some(peer_address))
        } else {
            (None, None, None)
        };

        let message_consumed = match peer_address {
            Some(peer_address) => {
                if is_verification_msg {
                    let handled = SignatureVerifier::handle_verification_messages(
                        &self.program_context,
                        &program_id,
                        &msg_type,
                        &data,
                        &peer_address,
                    );
                    if handled.is_err() {
                        error!(
                            "Error handling verification message: {:?}",
                            handled.err().unwrap()
                        );
                        false
                    } else {
                        true
                    }
                } else {
                    if let Some(mut program) = program {
                        let message_consumed = self.process_program_message(
                            &program_id,
                            msg_type,
                            data,
                            peer_address,
                            &mut program,
                            timestamp,
                            signature,
                            version,
                        )?;
                        message_consumed
                    } else if let Some(mut collaboration) = collaboration {
                        let message_consumed = self.process_collaboration_message(
                            &program_id,
                            msg_type,
                            data,
                            peer_address,
                            &mut collaboration,
                            timestamp,
                            signature,
                            version,
                        )?;
                        if message_consumed {
                            self.save_collaboration(&collaboration)?;
                        }
                        message_consumed
                    } else {
                        error!("Invalid state");
                        false
                    }
                }
            }
            None => false,
        };

        if message_consumed {
            self.timestamp_verifier
                .record(&msg.identifier.pubkey_hash, timestamp);
        } else {
            // Message needs to be buffered (not processed or program/collaboration not found)
            info!("Pending message to back: {:?}", msg_type);
            self.message_queue.push_back(msg)?;
        }
        Ok(())
    }

    pub fn process_pending_messages(&mut self) -> Result<(), BitVMXError> {
        if self.message_queue.is_empty()? {
            return Ok(());
        }

        if let Some(msg) = self.message_queue.pop_front()? {
            self.process_msg(msg)?;
        }
        Ok(())
    }

    pub fn process_comms_messages(&mut self) -> Result<(), BitVMXError> {
        //Send enqueued messages
        self.program_context.comms.tick()?;

        let messages = self.program_context.comms.check_receive();
        if messages.is_err() {
            error!("Error receiving messages: {:?}", messages.err().unwrap());
            return Ok(());
        }

        for message in messages.unwrap() {
            match message {
                ReceiveHandlerChannel::Msg(identifier, msg) => {
                    let msg: QueuedMessage = QueuedMessage::new(identifier, msg)?;
                    self.process_msg(msg)?;
                }
                ReceiveHandlerChannel::Error(e) => {
                    info!("Error receiving message {}", e);
                }
            }
        }

        let deadletter_messages = self.program_context.comms.check_deadletter();
        if deadletter_messages.is_err() {
            error!(
                "Error receiving deadletter messages: {:?}",
                deadletter_messages.err().unwrap()
            );
            return Ok(());
        }
        for deadletter in deadletter_messages.unwrap() {
            match deadletter {
                (ReceiveHandlerChannel::Msg(identifier, _msg), ctx) => {
                    let context = Context::from_string(&ctx)?;
                    warn!(
                        "Processing deadletter message for context: {:?} and identifier: {:?}",
                        context, identifier
                    );
                    // TODO: Add a function in protocol handler to process deadletter messages
                }
                (ReceiveHandlerChannel::Error(e), _) => {
                    info!("Error receiving deadletter message {}", e);
                }
            }
        }

        Ok(())
    }

    pub fn handle_news(
        &mut self,
        tx_id: Txid,
        tx_status: TransactionStatus,
        context_data: String,
        vout: Option<u32>,
    ) -> Result<bool, BitVMXError> {
        let context = Context::from_string(&context_data)?;
        debug!(
            "Transaction Found: {:?} {:?} for context: {:?}",
            tx_id, tx_status, context
        );

        match &context {
            Context::ProgramId(program_id) => {
                if !self
                    .notified_request
                    .contains(&(*program_id, (tx_id, vout)))
                {
                    let program = self.load_program(program_id)?;

                    program.notify_news(
                        tx_id,
                        vout,
                        tx_status,
                        context_data,
                        &self.program_context,
                    )?;
                    self.notified_request.insert((*program_id, (tx_id, vout)));
                }
            }
            Context::RequestId(request_id, from) => {
                if !self
                    .notified_request
                    .contains(&(*request_id, (tx_id, vout)))
                {
                    info!("Sending News: {:?} for context: {:?}", tx_id, context);
                    self.program_context.broker_channel.send(
                        from,
                        OutgoingBitVMXApiMessages::Transaction(*request_id, tx_status, None)
                            .to_string()?,
                    )?;
                    self.notified_request.insert((*request_id, (tx_id, vout)));
                }
            }
            Context::Protocol(_, _) => {}
        }
        Ok(true)
    }

    pub fn process_bitcoin_updates(&mut self) -> Result<bool, BitVMXError> {
        self.program_context.bitcoin_coordinator.tick()?;
        self.process_wallet_updates()?;

        if !self.program_context.bitcoin_coordinator.is_ready()? {
            return Ok(false);
        }

        let news = self.program_context.bitcoin_coordinator.get_news()?;

        if !news.monitor_news.is_empty() || !news.coordinator_news.is_empty() {
            //info!("Processing news: {:?}", news);
        }

        for monitor_news in news.monitor_news {
            let ack_news: AckNews;

            match monitor_news {
                MonitorNews::Transaction(tx_id, tx_status, context_data) => {
                    self.handle_news(tx_id, tx_status, context_data, None)?;
                    ack_news = AckNews::Monitor(AckMonitorNews::Transaction(tx_id));
                }
                MonitorNews::SpendingUTXOTransaction(
                    tx_id,
                    output_index,
                    tx_status,
                    context_data,
                ) => {
                    self.handle_news(tx_id, tx_status, context_data, Some(output_index))?;
                    ack_news = AckNews::Monitor(AckMonitorNews::SpendingUTXOTransaction(
                        tx_id,
                        output_index,
                    ));
                }
                MonitorNews::RskPeginTransaction(tx_id, tx_status) => {
                    let data = serde_json::to_string(
                        &OutgoingBitVMXApiMessages::PeginTransactionFound(tx_id, tx_status),
                    )?;
                    if !self.notified_rsk_pegin.contains(&tx_id) {
                        self.program_context
                            .broker_channel
                            .send(&self.config.components.l2, data)?;
                        self.notified_rsk_pegin.insert(tx_id);
                    }
                    ack_news = AckNews::Monitor(AckMonitorNews::RskPeginTransaction(tx_id));
                }
                MonitorNews::NewBlock(block_id, block_height) => {
                    debug!("New block: {:?} {}", block_id, block_height);
                    ack_news = AckNews::Monitor(AckMonitorNews::NewBlock);
                }
            }

            self.program_context
                .bitcoin_coordinator
                .ack_news(ack_news)?;
        }

        for coordinator_news in news.coordinator_news {
            let ack_news: AckNews;

            match coordinator_news {
                CoordinatorNews::InsufficientFunds(tx_id, _available, _required) => {
                    // Complete new params
                    let data =
                        OutgoingBitVMXApiMessages::SpeedUpProgramNoFunds(tx_id).to_string()?;

                    info!(
                        "Sending funds request to broker: {} available {} required {}",
                        tx_id, _available, _required
                    );
                    self.program_context
                        .broker_channel
                        .send(&self.config.components.l2, data)?;
                    ack_news = AckNews::Coordinator(AckCoordinatorNews::InsufficientFunds(tx_id));
                }
                CoordinatorNews::DispatchTransactionError(txid, _context_data, _counter) => {
                    error!(
                        "Dispatch Transaction Error: {:?} {:?} {}",
                        txid, _context_data, _counter
                    );
                    match self.wallet.get_wallet_tx(txid) {
                        Ok(Some(wallet_tx)) => {
                            self.wallet.cancel_tx(&wallet_tx.tx_node.tx)?;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            error!("Error fetching transaction from wallet: {:?}", e);
                        }
                    }

                    ack_news =
                        AckNews::Coordinator(AckCoordinatorNews::DispatchTransactionError(txid));
                }
                CoordinatorNews::DispatchSpeedUpError(
                    _tx_id,
                    _context_data,
                    _counter,
                    _block_height,
                ) => {
                    // Complete

                    ack_news =
                        AckNews::Coordinator(AckCoordinatorNews::DispatchSpeedUpError(_counter));
                }
                CoordinatorNews::FundingNotFound => {
                    // Complete
                    error!("Funding not found for speed-up transaction. This is a critical error.");

                    ack_news = AckNews::Coordinator(AckCoordinatorNews::FundingNotFound);
                }
                CoordinatorNews::EstimateFeerateTooHigh(estimate_fee, max_allowed) => {
                    // Complete
                    warn!(
                        "Estimate feerate too high: {:?} {:?}",
                        estimate_fee, max_allowed
                    );

                    ack_news = AckNews::Coordinator(AckCoordinatorNews::EstimateFeerateTooHigh(
                        estimate_fee,
                        max_allowed,
                    ));
                }
            }

            self.program_context
                .bitcoin_coordinator
                .ack_news(ack_news)?;
        }

        Ok(true)
    }

    pub fn process_api_messages(&mut self) -> Result<(), BitVMXError> {
        if let Some((msg, from)) = self.program_context.broker_channel.recv()? {
            BitVMXApi::handle_message(self, msg, from)?;
        }

        Ok(())
    }

    pub fn process_collaboration(&mut self) -> Result<(), BitVMXError> {
        //TOOD: manage state of the collaborations once persisted
        let collaborations = self.store.partial_compare(&"bitvmx/collaboration/")?;
        for (_, collaboration) in collaborations.iter() {
            let mut collaboration: Collaboration = serde_json::from_str(collaboration)?;
            if collaboration.tick(&self.program_context)? {
                self.mark_collaboration_as_complete(&collaboration)?;
            };
        }
        Ok(())
    }

    pub fn tick(&mut self) -> Result<(), BitVMXError> {
        //info!("Ticking BitVMX: {}", self.count);
        if self.shutdown {
            return Ok(());
        }

        self.count += 1;
        self.process_programs()?;

        if self.count % THROTTLE_TICKS == 0 {
            self.process_pending_messages()?;
            self.process_comms_messages()?;
            self.process_api_messages()?;
        }

        self.process_bitcoin_updates_with_throttle()?;
        self.process_collaboration()?;

        self.ping_helper
            .check_job_dispatchers_liveness(&self.program_context, &self.config.components)?;

        Ok(())
    }

    pub fn process_wallet_updates(&mut self) -> Result<(), BitVMXError> {
        let result = self.wallet.tick();
        if result.is_err() {
            error!("Error updating wallet: {:?}", result.err().unwrap());
        }
        Ok(())
    }

    pub fn process_bitcoin_updates_with_throttle(&mut self) -> Result<(), BitVMXError> {
        let now = Instant::now();
        let throttle_secs = if !self.bitcoin_update.was_synced {
            self.config.coordinator.throtthle_bitcoin_updates_until_sync
        } else {
            self.config.coordinator.throtthle_bitcoin_updates
        };

        let should_update = if throttle_secs == 0 {
            self.count % THROTTLE_TICKS == 0
        } else {
            now.duration_since(self.bitcoin_update.last_update)
                >= Duration::from_secs(throttle_secs)
        };

        if should_update {
            let updated = self.process_bitcoin_updates();
            self.bitcoin_update.last_update = now;
            if updated.is_err() {
                error!(
                    "Critical error processing bitcoin updates: {:?}",
                    updated.err().unwrap()
                );
                return Ok(());
            }
            if updated.unwrap() {
                self.bitcoin_update.was_synced = true;

                // info!(
                //     "Throttling Bitcoin updates ({}): {}s",
                //     if self.bitcoin_update.was_synced {
                //         "post-sync"
                //     } else {
                //         "pre-sync"
                //     },
                //     throttle_secs
                // );
            }
        }
        Ok(())
    }
    pub fn process_programs(&self) -> Result<(), BitVMXError> {
        let programs = self.get_active_programs()?;

        for mut program in programs {
            program.tick(&self.program_context)?
        }
        Ok(())
    }

    fn get_programs(&self) -> Result<Vec<ProgramStatus>, BitVMXError> {
        let programs_ids: Option<Vec<ProgramStatus>> = self
            .store
            .get(StoreKey::Programs.get_key())
            .map_err(BitVMXError::StorageError)?;

        if programs_ids.is_none() {
            let empty_programs: Vec<ProgramStatus> = vec![];

            return Ok(empty_programs);
        }

        Ok(programs_ids.unwrap())
    }

    fn get_active_programs(&self) -> Result<Vec<Program>, BitVMXError> {
        let all_programs = self
            .get_programs()?
            .iter()
            .map(|p| p.program_id)
            .collect::<Vec<Uuid>>();
        let mut active_programs = vec![];
        for program_id in all_programs {
            if is_active_program(&self.store, &program_id)? {
                let program = self.load_program(&program_id)?;
                active_programs.push(program);
            }
        }

        Ok(active_programs)
    }

    fn add_new_program(&self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let mut programs = self.get_programs()?;

        if programs.iter().any(|p| p.program_id == *program_id) {
            return Err(BitVMXError::ProgramAlreadyExists(*program_id));
        }

        programs.push(ProgramStatus::new(*program_id));

        self.store
            .set(StoreKey::Programs.get_key(), programs, None)?;

        Ok(())
    }

    fn program_exists(&self, program_id: &Uuid) -> Result<bool, BitVMXError> {
        let programs = self.get_programs()?;
        Ok(programs.iter().any(|p| p.program_id == *program_id))
    }

    fn get_collaboration(&self, id: &Uuid) -> Result<Option<Collaboration>, BitVMXError> {
        let key = StoreKey::Collaboration(*id).get_key();
        let mut result = self.store.get(&key)?;

        if result.is_none() {
            let key = StoreKey::CompleteCollaboration(*id).get_key();
            result = self.store.get(&key)?;
        }

        Ok(result)
    }

    fn mark_collaboration_as_complete(
        &self,
        collaboration: &Collaboration,
    ) -> Result<(), BitVMXError> {
        let transaction_id = self.store.begin_transaction();

        self.store.set(
            StoreKey::CompleteCollaboration(collaboration.collaboration_id).get_key(),
            collaboration,
            Some(transaction_id),
        )?;
        self.store.transactional_delete(
            &StoreKey::Collaboration(collaboration.collaboration_id).get_key(),
            transaction_id,
        )?;

        self.store.commit_transaction(transaction_id)?;
        Ok(())
    }

    fn save_collaboration(&self, collaboration: &Collaboration) -> Result<(), BitVMXError> {
        let key = StoreKey::Collaboration(collaboration.collaboration_id).get_key();
        self.store.set(key, collaboration, None)?;
        Ok(())
    }

    /// send replies via the broker channel
    fn reply(&self, to: Identifier, message: OutgoingBitVMXApiMessages) -> Result<(), BitVMXError> {
        debug!("> {:?}", message);
        self.program_context
            .broker_channel
            .send(&to, serde_json::to_string(&message)?)?;

        Ok(())
    }

    pub fn sync_wallet(&mut self) -> Result<(), BitVMXError> {
        info!("Starting wallet sync...");
        self.wallet.sync_wallet()?;
        info!("Wallet sync completed.");
        Ok(())
    }
}

impl GracefulShutdown for BitVMX {
    fn begin_shutdown(&mut self) {
        // Future: signal programs/protocols/coordinator to quiesce
    }

    fn drain_until_idle(&mut self, deadline: Instant) {
        while Instant::now() < deadline {
            if let Err(e) = self.process_pending_messages() {
                warn!("drain pending msg err: {:?}", e);
            }
            if let Err(e) = self.process_collaboration() {
                warn!("drain collaboration err: {:?}", e);
            }

            if self.message_queue.is_empty().unwrap() {
                break;
            }
            sleep(Duration::from_millis(10));
        }
    }

    fn shutdown_now(&mut self) {
        self.broker.close();
    }
}

impl BitVMXApi for BitVMX {
    fn ping(&mut self, from: Identifier, uuid: Uuid) -> Result<Uuid, BitVMXError> {
        self.reply(from, OutgoingBitVMXApiMessages::Pong(uuid))?;
        Ok(uuid)
    }

    fn get_var(&mut self, from: Identifier, id: Uuid, key: &str) -> Result<(), BitVMXError> {
        info!("Getting variable {}", key);
        let value = self.program_context.globals.get_var(&id, key)?;

        let response = match value {
            Some(var) => OutgoingBitVMXApiMessages::Variable(id, key.to_string(), var),
            None => OutgoingBitVMXApiMessages::NotFound(id, key.to_string()),
        };

        self.reply(from, response)?;
        Ok(())
    }

    fn get_witness(&mut self, from: Identifier, id: Uuid, key: &str) -> Result<(), BitVMXError> {
        info!("Getting witness {}", key);
        let value = self.program_context.witness.get_witness(&id, key)?;

        // Create response based on whether we found a value
        let response = match value {
            Some(witness) => OutgoingBitVMXApiMessages::Witness(id, key.to_string(), witness),
            None => OutgoingBitVMXApiMessages::NotFound(id, key.to_string()),
        };

        self.reply(from, response)?;
        Ok(())
    }

    fn setup_key(
        &mut self,
        from: Identifier,
        id: Uuid,
        participants: Vec<CommsAddress>,
        participants_keys: Option<Vec<PublicKey>>,
        leader_idx: u16,
    ) -> Result<(), BitVMXError> {
        info!("Setting up key for program: {:?}", id);

        // Check if participants vector is empty or leader_idx is out of bounds
        if participants.is_empty() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        if leader_idx as usize >= participants.len() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        let leader = participants[leader_idx as usize].clone();
        let collab = Collaboration::setup_aggregated_key(
            &id,
            participants,
            participants_keys,
            leader,
            &mut self.program_context,
            from,
        )?;
        self.save_collaboration(&collab)?;
        info!("Key setup finished for program: {:?}", id);
        Ok(())
    }

    fn get_aggregated_pubkey(&mut self, from: Identifier, id: Uuid) -> Result<(), BitVMXError> {
        info!("Getting aggregated pubkey for collaboration: {:?}", id);

        let response = if let Some(collaboration) = self.get_collaboration(&id)? {
            if let Some(aggregated_pubkey) = &collaboration.aggregated_key {
                OutgoingBitVMXApiMessages::AggregatedPubkey(id, aggregated_pubkey.clone())
            } else {
                OutgoingBitVMXApiMessages::AggregatedPubkeyNotReady(id)
            }
        } else {
            OutgoingBitVMXApiMessages::AggregatedPubkeyNotReady(id)
        };

        self.reply(from, response)?;

        Ok(())
    }

    fn generate_zkp(
        &mut self,
        from: Identifier,
        id: Uuid,
        input: Vec<u8>,
        elf_file_path: String,
    ) -> Result<(), BitVMXError> {
        info!("Generating ZKP for input: {:?}", input);

        // Store the 'from' parameter
        self.store
            .set(StoreKey::ZKPFrom(id).get_key(), from, None)?;

        let msg = serde_json::to_string(&DispatcherJob {
            job_id: id.to_string(),
            job_type: ProverJobType::Prove(input, elf_file_path, format!("./zkp-jobs/{}", id)),
        })?;

        info!("Sending dispatcher job message: {}", msg);
        self.program_context
            .broker_channel
            .send(&self.config.components.prover, msg)?;

        Ok(())
    }

    fn proof_ready(&mut self, from: Identifier, id: Uuid) -> Result<(), BitVMXError> {
        info!("Checking if proof is ready for job: {}", id);

        // Get the status from storage
        let status_key = StoreKey::ZKPStatus(id).get_key();
        let status: Option<String> = self.store.get(&status_key)?;

        let response = match status {
            Some(status_str) => {
                if status_str == "OK" {
                    OutgoingBitVMXApiMessages::ProofReady(id)
                } else {
                    OutgoingBitVMXApiMessages::ProofGenerationError(id, status_str)
                }
            }
            None => OutgoingBitVMXApiMessages::ProofNotReady(id),
        };

        self.reply(from, response)?;

        Ok(())
    }

    fn get_zkp_execution_result(&mut self, from: Identifier, id: Uuid) -> Result<(), BitVMXError> {
        // Check if the proof is ready
        info!("Checking if {} ZKP job is ready", id);
        let status_key = StoreKey::ZKPStatus(id).get_key();
        let status: Option<String> = self.store.get(&status_key)?;

        let response = match status {
            Some(status_str) => {
                if status_str == "OK" {
                    info!("Getting ZKP execution result for job: {}", id);
                    let seal: Vec<u8> = match self.store.get(&StoreKey::ZKPProof(id).get_key())? {
                        Some(seal) => seal,
                        None => return Err(BitVMXError::InconsistentZKPData(id)),
                    };

                    let journal: Vec<u8> =
                        match self.store.get(&StoreKey::ZKPJournal(id).get_key())? {
                            Some(journal) => journal,
                            None => {
                                return Err(BitVMXError::InconsistentZKPData(id));
                            }
                        };
                    OutgoingBitVMXApiMessages::ZKPResult(id, seal, journal)
                } else {
                    OutgoingBitVMXApiMessages::ProofGenerationError(id, status_str)
                }
            }
            None => OutgoingBitVMXApiMessages::ProofNotReady(id),
        };

        self.reply(from, response)?;

        Ok(())
    }

    fn subscribe_to_tx(
        &mut self,
        from: Identifier,
        id: Uuid,
        txid: Txid,
    ) -> Result<(), BitVMXError> {
        info!(
            "Subscribing to transaction: {:?} from: {} id: {}",
            txid, from, id
        );
        self.program_context
            .bitcoin_coordinator
            .monitor(TypesToMonitor::Transactions(
                vec![txid],
                Context::RequestId(id, from).to_string()?,
            ))?;

        Ok(())
    }

    fn subscribe_utxo(&mut self, uuid: Uuid) -> Result<Uuid, BitVMXError> {
        Ok(uuid)
    }

    fn subscribe_to_rsk_pegin(&mut self) -> Result<(), BitVMXError> {
        // Enable RSK pegin transaction monitoring
        self.program_context
            .bitcoin_coordinator
            .monitor(TypesToMonitor::RskPeginTransaction)?;
        Ok(())
    }

    fn setup(
        &mut self,
        id: Uuid,
        program_type: String,
        peer_address: Vec<CommsAddress>,
        leader: u16,
    ) -> Result<(), BitVMXError> {
        if self.program_exists(&id)? {
            warn!("Program already exists");
            return Err(BitVMXError::ProgramAlreadyExists(id));
        }

        info!("Setting up program: {:?} type {}", id, program_type);
        Program::setup(
            &id,
            &program_type,
            peer_address,
            leader as usize,
            &mut self.program_context,
            self.store.clone(),
            &self.config.client,
        )?;
        self.add_new_program(&id)?;
        info!(
            "Program Setup Finished {}",
            self.program_context.comms.get_pubk_hash()?
        );

        Ok(())
    }

    fn get_transaction(
        &mut self,
        from: Identifier,
        id: Uuid,
        txid: Txid,
    ) -> Result<(), BitVMXError> {
        let response = match self
            .program_context
            .bitcoin_coordinator
            .get_transaction(txid)
        {
            Ok(tx_status) => OutgoingBitVMXApiMessages::Transaction(id, tx_status, None),
            Err(e) => {
                info!("Transaction not found: {:?}. Error: {}", txid, e);
                OutgoingBitVMXApiMessages::NotFound(id, txid.to_string())
            }
        };

        self.reply(from, response)?;
        Ok(())
    }

    fn dispatch_transaction(
        &mut self,
        from: Identifier,
        id: Uuid,
        tx: Transaction,
    ) -> Result<(), BitVMXError> {
        info!("Dispatching transaction: {:?} for instance: {:?}", tx, id);

        self.program_context.bitcoin_coordinator.dispatch(
            tx,
            None,
            Context::RequestId(id, from).to_string()?,
            None,
        )?;

        Ok(())
    }

    fn dispatch_transaction_name(&mut self, id: Uuid, name: &str) -> Result<(), BitVMXError> {
        self.load_program(&id)?
            .dispatch_transaction_name(&self.program_context, name)?;
        Ok(())
    }

    fn handle_prover_message(&mut self, msg: String) -> Result<(), BitVMXError> {
        if let Some(message) = serde_json::from_str::<PingMessage>(&msg).ok() {
            self.ping_helper
                .received_message(JobDispatcherType::ZKP, &message);
        } else {
            let result_message = ResultMessage::from_str(&msg)?;
            let parsed: serde_json::Value = result_message.result_as_value()?;
            let data = parsed.get("data").ok_or_else(|| {
                warn!("Missing data field in result. Raw message: {}", msg);
                BitVMXError::InvalidMessageFormat
            })?;

            let id = Uuid::parse_str(&result_message.job_id)
                .map_err(|_| BitVMXError::InvalidMessageFormat)?;
            // Extract status and vec from data
            let status = data["status"].as_str().ok_or_else(|| {
                warn!("Missing status field in data. Raw message: {}", msg);
                BitVMXError::InvalidMessageFormat
            })?;

            let journal = data["journal"].as_array().ok_or_else(|| {
                warn!("Missing journal field in data. Raw message: {}", msg);
                BitVMXError::InvalidMessageFormat
            })?;

            let seal = data["seal"].as_array().ok_or_else(|| {
                warn!("Missing seal field in data. Raw message: {}", msg);
                BitVMXError::InvalidMessageFormat
            })?;

            // Convert seal to Vec<u8>
            let seal: Vec<u8> = seal
                .iter()
                .filter_map(|v| v.as_u64())
                .map(|v| v as u8)
                .collect();

            // Store the proof data and status
            let transaction_id = self.store.begin_transaction();

            self.store
                .set(StoreKey::ZKPProof(id).get_key(), seal, Some(transaction_id))?;

            self.store.set(
                StoreKey::ZKPJournal(id).get_key(),
                journal,
                Some(transaction_id),
            )?;

            self.store.set(
                StoreKey::ZKPStatus(id).get_key(),
                status.to_string(),
                Some(transaction_id),
            )?;

            self.store.commit_transaction(transaction_id)?;

            // Get the stored 'from' parameter
            let from: Identifier = self
                .store
                .get(StoreKey::ZKPFrom(id).get_key())?
                .ok_or_else(|| {
                    warn!("Missing 'from' parameter for ZKP request: {}", id);
                    BitVMXError::InvalidMessageFormat
                })?;

            self.proof_ready(from, id)?;
        }
        Ok(())
    }

    fn handle_emulator_message(&mut self, msg: &String) -> Result<(), BitVMXError> {
        if let Some(message) = serde_json::from_str::<PingMessage>(&msg).ok() {
            self.ping_helper
                .received_message(JobDispatcherType::Emulator, &message);
        } else {
            let result_message = ResultMessage::from_str(&msg)?;
            let parsed: serde_json::Value = result_message.result_as_value()?;
            let decoded = EmulatorResultType::from_value(parsed)?;
            let job_id = Uuid::parse_str(&result_message.job_id)
                .map_err(|_| BitVMXError::InvalidMessageFormat)?;
            self.load_program(&job_id)?
                .protocol
                .dispute()?
                .execution_result(&decoded, &self.program_context)?;
        }
        Ok(())
    }

    fn get_spv_proof(&mut self, from: Identifier, txid: Txid) -> Result<(), BitVMXError> {
        let tx_info = self
            .program_context
            .bitcoin_coordinator
            .get_transaction(txid);

        match tx_info {
            Ok(utx) => {
                let proof = get_spv_proof(txid, utx.block_info.unwrap())?;

                self.reply(from, OutgoingBitVMXApiMessages::SPVProof(txid, Some(proof)))?;
            }
            Err(e) => {
                warn!(
                    "Failed to retrieve transaction info for txid {}: {:?}",
                    txid, e
                );

                self.reply(from, OutgoingBitVMXApiMessages::SPVProof(txid, None))?;
            }
        };

        Ok(())
    }

    fn handle_message(&mut self, msg: String, from: Identifier) -> Result<(), BitVMXError> {
        if from == self.config.components.emulator {
            self.handle_emulator_message(&msg)?;
            return Ok(());
        }

        if from == self.config.components.prover {
            self.handle_prover_message(msg)?;
            return Ok(());
        }

        let decoded: IncomingBitVMXApiMessages = serde_json::from_str(&msg)?;
        debug!("< {:?}", decoded);

        match decoded {
            IncomingBitVMXApiMessages::GetHashedMessage(id, name, vout, leaf) => {
                let hashed = self
                    .load_program(&id)?
                    .protocol
                    .get_hashed_message(&name, vout, leaf)?;
                self.reply(
                    from,
                    OutgoingBitVMXApiMessages::HashedMessage(id, name, vout, leaf, hashed),
                )?;
            }
            IncomingBitVMXApiMessages::GetCommInfo(uuid) => {
                let comm_info = OutgoingBitVMXApiMessages::CommInfo(
                    uuid,
                    CommsAddress {
                        address: self.program_context.comms.get_address(),
                        pubkey_hash: self.program_context.comms.get_pubk_hash()?,
                    },
                );
                self.reply(from, comm_info)?;
            }
            IncomingBitVMXApiMessages::Ping(uuid) => {
                BitVMXApi::ping(self, from, uuid)?;
            }
            IncomingBitVMXApiMessages::SetVar(uuid, key, value) => {
                debug!("Setting variable {}: {:?}", key, value);
                self.program_context.globals.set_var(&uuid, &key, value)?;
            }
            IncomingBitVMXApiMessages::SetWitness(uuid, key, value) => {
                debug!("Setting witness {}: {:?}", key, value);
                self.program_context
                    .witness
                    .set_witness(&uuid, &key, value)?;
            }
            IncomingBitVMXApiMessages::SetFundingUtxo(utxo) => {
                info!("Setting funding utxo {:?}", utxo);
                self.program_context.bitcoin_coordinator.add_funding(utxo)?;
            }
            IncomingBitVMXApiMessages::GetFundingAddress(id) => {
                debug!("Getting funding address uuid: {:?}", id);
                let result = self.wallet.receive_address();
                if result.is_err() {
                    let error = result.as_ref().err().unwrap();
                    error!("Error getting funding address uuid: {:?}: {:?}", id, error);
                    self.program_context.broker_channel.send(
                        &from,
                        serde_json::to_string(&OutgoingBitVMXApiMessages::WalletError(
                            id,
                            error.to_string(),
                        ))?,
                    )?;
                }
                let address = result?;

                self.program_context.broker_channel.send(
                    &from,
                    serde_json::to_string(&OutgoingBitVMXApiMessages::FundingAddress(
                        id,
                        address.into_unchecked(),
                    ))?,
                )?;
            }
            IncomingBitVMXApiMessages::GetFundingBalance(id) => {
                debug!("Getting funding balance uuid: {:?}", id);
                if !self.wallet.is_ready {
                    warn!("Wallet is not ready, to get funding balance uuid: {:?}", id);
                    self.program_context.broker_channel.send(
                        &from,
                        serde_json::to_string(&OutgoingBitVMXApiMessages::WalletNotReady(id))?,
                    )?;
                    return Ok(());
                }
                let balance = self.wallet.balance();
                self.program_context.broker_channel.send(
                    &from,
                    serde_json::to_string(&OutgoingBitVMXApiMessages::FundingBalance(
                        id,
                        balance.trusted_spendable().to_sat(),
                    ))?,
                )?;
            }
            IncomingBitVMXApiMessages::SendFunds(id, destination, fee_rate) => {
                info!("Sending funds to {:?}", destination);
                if !self.wallet.is_ready {
                    warn!("Wallet is not ready, to send funds uuid: {:?}", id);
                    self.program_context.broker_channel.send(
                        &from,
                        serde_json::to_string(&OutgoingBitVMXApiMessages::WalletNotReady(id))?,
                    )?;
                    return Ok(());
                }
                // Use the fee_rate parameter passed in the message
                let tx = match self.wallet.create_tx(destination.clone(), fee_rate) {
                    Ok(tx) => tx,
                    Err(e) => {
                        error!("Failed sending funds to {:?}. Error: {:?}", destination, e);
                        self.program_context.broker_channel.send(
                            &from.clone(),
                            serde_json::to_string(&OutgoingBitVMXApiMessages::WalletError(
                                id,
                                e.to_string(),
                            ))?,
                        )?;
                        return Ok(());
                    }
                };

                let txid = tx.compute_txid();
                self.dispatch_transaction(from.clone(), id, tx.clone())?;
                self.wallet.update_with_tx(&tx)?;

                self.program_context.broker_channel.send(
                    &from,
                    serde_json::to_string(&OutgoingBitVMXApiMessages::FundsSent(id, txid))?,
                )?;
            }

            IncomingBitVMXApiMessages::GetVar(uuid, key) => {
                BitVMXApi::get_var(self, from, uuid, &key)?;
            }
            IncomingBitVMXApiMessages::GetWitness(uuid, key) => {
                BitVMXApi::get_witness(self, from, uuid, &key)?;
            }
            IncomingBitVMXApiMessages::GetTransaction(id, txid) => {
                BitVMXApi::get_transaction(self, from, id, txid)?
            }
            IncomingBitVMXApiMessages::GetTransactionInfoByName(id, name) => {
                let program = self.load_program(&id);
                let response = match program {
                    Ok(prog) => match prog.get_transaction_by_name(&self.program_context, &name) {
                        Ok(tx) => OutgoingBitVMXApiMessages::TransactionInfo(id, name, tx),
                        Err(err) => {
                            error!(
                                "Transaction not found: {} in program {:?}. Error: {}",
                                name, id, err
                            );
                            OutgoingBitVMXApiMessages::NotFound(
                                id,
                                format!("Transaction not found: {}", name),
                            )
                        }
                    },
                    Err(err) => {
                        error!("Program not found: {:?}. Error: {}", id, err);
                        OutgoingBitVMXApiMessages::NotFound(
                            id,
                            format!("Program not found: {}", name),
                        )
                    }
                };

                self.reply(from, response)?;
            }
            IncomingBitVMXApiMessages::Setup(id, program_type, participants, leader) => {
                BitVMXApi::setup(self, id, program_type, participants, leader)?
            }
            IncomingBitVMXApiMessages::SubscribeToTransaction(uuid, txid) => {
                BitVMXApi::subscribe_to_tx(self, from, uuid, txid)?
            }
            IncomingBitVMXApiMessages::SubscribeUTXO(uuid) => {
                BitVMXApi::subscribe_utxo(self, uuid)?;
            }

            IncomingBitVMXApiMessages::SubscribeToRskPegin() => {
                BitVMXApi::subscribe_to_rsk_pegin(self)?
            }

            IncomingBitVMXApiMessages::GetSPVProof(txid) => {
                BitVMXApi::get_spv_proof(self, from, txid)?
            }

            IncomingBitVMXApiMessages::DispatchTransactionName(id, tx) => {
                BitVMXApi::dispatch_transaction_name(self, id, &tx)?
            }
            IncomingBitVMXApiMessages::DispatchTransaction(id, tx) => {
                BitVMXApi::dispatch_transaction(self, from, id, tx)?;
            }
            IncomingBitVMXApiMessages::SetupKey(
                id,
                participants,
                participants_keys,
                leader_idx,
            ) => BitVMXApi::setup_key(self, from, id, participants, participants_keys, leader_idx)?,
            IncomingBitVMXApiMessages::GetKeyPair(id) => {
                let collaboration = self
                    .get_collaboration(&id)?
                    .ok_or(BitVMXError::ProgramNotFound(id))?;
                let aggregated = collaboration
                    .aggregated_key
                    .ok_or(BitVMXError::ProgramNotFound(id))?;
                let pair = self
                    .program_context
                    .key_chain
                    .key_manager
                    .get_key_pair_for_too_insecure(&aggregated)?;
                self.reply(from, OutgoingBitVMXApiMessages::KeyPair(id, pair.0, pair.1))?;
                //RETURN PK
                //TODO: Revisit this as it might be insecure
            }
            IncomingBitVMXApiMessages::GetPubKey(id, new) => {
                if new {
                    let public = self
                        .program_context
                        .key_chain
                        .derive_keypair(BitcoinKeyType::P2tr)?;
                    self.reply(from, OutgoingBitVMXApiMessages::PubKey(id, public))?;
                } else {
                    let collaboration = self
                        .get_collaboration(&id)?
                        .ok_or(BitVMXError::ProgramNotFound(id))?;
                    let aggregated = collaboration
                        .aggregated_key
                        .ok_or(BitVMXError::ProgramNotFound(id))?;
                    let pubkey = self
                        .program_context
                        .key_chain
                        .key_manager
                        .get_my_public_key(&aggregated)?;
                    self.reply(from, OutgoingBitVMXApiMessages::PubKey(id, pubkey))?;
                }
            }
            IncomingBitVMXApiMessages::SignMessage(id, payload, public_key) => {
                // Create message from the payload
                let message = Message::from_digest_slice(&payload)
                    .map_err(|_| BitVMXError::InvalidMessageFormat)?;

                // Sign the message with the provided public key
                let recoverable_signature = self
                    .program_context
                    .key_chain
                    .key_manager
                    .sign_ecdsa_recoverable_message(&message, &public_key)?;

                let (recovery_id, compact) = recoverable_signature.serialize_compact();
                let (r_bytes, s_bytes) = compact.split_at(32);

                // Convert to fixed-size arrays
                // Convert to fixed-size arrays
                let signature_r: [u8; 32] = r_bytes
                    .try_into()
                    .map_err(|_| BitVMXError::InvalidMessageFormat)?;
                let signature_s: [u8; 32] = s_bytes
                    .try_into()
                    .map_err(|_| BitVMXError::InvalidMessageFormat)?;

                self.reply(
                    from,
                    OutgoingBitVMXApiMessages::SignedMessage(
                        id,
                        signature_r,
                        signature_s,
                        recovery_id.to_i32() as u8,
                    ),
                )?;
            }
            IncomingBitVMXApiMessages::GetAggregatedPubkey(id) => {
                BitVMXApi::get_aggregated_pubkey(self, from, id)?
            }
            IncomingBitVMXApiMessages::GenerateZKP(id, input, elf_file_path) => {
                BitVMXApi::generate_zkp(self, from, id, input, elf_file_path)?
            }
            IncomingBitVMXApiMessages::ProofReady(id) => BitVMXApi::proof_ready(self, from, id)?,
            IncomingBitVMXApiMessages::GetZKPExecutionResult(id) => {
                BitVMXApi::get_zkp_execution_result(self, from, id)?
            }
            IncomingBitVMXApiMessages::Encrypt(id, message, pub_key) => {
                let encrypted = self
                    .program_context
                    .key_chain
                    .key_manager
                    .encrypt_rsa_message(&message, &pub_key)?;
                self.reply(from, OutgoingBitVMXApiMessages::Encrypted(id, encrypted))?;
            }
            IncomingBitVMXApiMessages::Decrypt(id, message, pub_key) => {
                let decrypted = self
                    .program_context
                    .key_chain
                    .key_manager
                    .decrypt_rsa_message(&message, &pub_key)?;
                self.reply(from, OutgoingBitVMXApiMessages::Decrypted(id, decrypted))?;
            }
            IncomingBitVMXApiMessages::Backup(id, backup_path, dek_path, password) => {
                let message = match self.store.backup(&backup_path, &dek_path, password) {
                    Ok(_) => OutgoingBitVMXApiMessages::BackupResult(
                        id,
                        true,
                        "Backup successful".to_string(),
                    ),
                    Err(e) => OutgoingBitVMXApiMessages::BackupResult(id, false, e.to_string()),
                };

                self.reply(from, message)?;
            }
            IncomingBitVMXApiMessages::GetProtocolVisualization(id) => {
                let message = match self.load_program(&id) {
                    Ok(program) => {
                        let protocol_str = program
                            .protocol
                            .load_protocol()?
                            .visualize(GraphOptions::EdgeArrows)?;
                        OutgoingBitVMXApiMessages::ProtocolVisualization(id, protocol_str)
                    }
                    Err(e) => {
                        warn!("Failed to load protocol: {:?}", e);
                        OutgoingBitVMXApiMessages::ProtocolVisualization(id, String::default())
                    }
                };
                self.reply(from, message)?;
            }
            IncomingBitVMXApiMessages::Shutdown(timeout) => {
                info!("Shutdown message received. Initiating shutdown...");
                self.shutdown(timeout)?;
            }
            #[cfg(feature = "testpanic")]
            IncomingBitVMXApiMessages::Test(s) => {
                if s == "panic" {
                    panic!("test-induced panic");
                }
                if s == "fatal" {
                    use storage_backend::error::StorageError as KVStorageError;
                    return Err(BitVMXError::from(KVStorageError::WriteError));
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Context {
    ProgramId(Uuid),
    RequestId(Uuid, Identifier),
    Protocol(Uuid, String),
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
