use crate::comms_allow_list;
use crate::config::ComponentsConfig;
use crate::ping_helper::{JobDispatcherType, PingHelper};
use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use crate::program::program::{is_active_program, Program};
use crate::program::protocols::protocol_handler::ProtocolHandler;
use crate::program::variables::VariableTypes;
use crate::spv_proof::get_spv_proof;
use crate::throttle::Throttle;
use crate::{
    comms_helper::{deserialize_msg, CommsMessageType},
    config::Config,
    errors::BitVMXError,
    leader_broadcast::{LeaderBroadcastHelper, OriginalMessage},
    message_queue::{MessageQueue, PushOutcome, QueuedMessage},
    program::{
        participant::CommsAddress,
        variables::{Globals, WitnessVars},
    },
    signature_verifier::SignatureVerifier,
    types::{
        IncomingBitVMXApiMessages, MessageDisposition, OutgoingBitVMXApiMessages, ProgramContext,
        ProgramStatus, SetupFailureReason, PROGRAM_TYPE_AGGREGATED_KEY, RSK_PEGIN_TAG,
    },
};
use bitcoin::secp256k1::Message;
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use bitcoin_coordinator::{
    coordinator::BitcoinCoordinator,
    types::{AckNews, CoordinatorNews},
    AckMonitorNews, MonitorNews, TypesToMonitor,
};
use bitvmx_broker::identification::allow_list::AllowList;
use bitvmx_broker::identification::identifier::{Identifier, PubkHash};
use bitvmx_broker::retry::RetryPolicy;
use bitvmx_broker::{BrokerNode, ReceivedMessage};
use bitvmx_dispatcher_utils::PingMessage;
use bitvmx_settings::settings;
use key_manager::create_key_manager_from_config;
use key_manager::key_type::BitcoinKeyType;
use protocol_builder::graph::graph::GraphOptions;

use bitvmx_job_dispatcher::dispatcher_job::{DispatcherJob, ResultMessage};

use bitvmx_job_dispatcher_types::prover_messages::ProverJobType;
use bitvmx_wallet::wallet::Wallet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Instant;
use std::{net::SocketAddr, rc::Rc, thread::sleep, time::Duration};
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

pub const WALLET_INDEX: u32 = 100;
pub const WALLET_CHANGE_INDEX: u32 = 101;
pub const CLIENT_GLOBAL_SETTINGS_UUID: Uuid = Uuid::from_bytes(*b"GLOBAL_SETTINGS-");
pub const SEND_NEW_BLOCK_NEWS: &str = "send_new_block_news";

pub struct BitVMX {
    config: Config,
    program_context: ProgramContext,
    store: Rc<Storage>,
    count: u32,
    message_queue: MessageQueue,
    coordinator_throttle: Throttle,
    bitvmx_throttle: Throttle,
    wallet: Wallet,
    ping_helper: PingHelper,
    shutdown: bool,
}

impl Drop for BitVMX {
    fn drop(&mut self) {
        self.program_context.broker_channel.close();
        sleep(Duration::from_millis(100));
    }
}
enum StoreKey {
    Programs,
    ZKPProof(Uuid),
    ZKPStatus(Uuid),
    ZKPFrom(Uuid),
    ZKPJournal(Uuid),
}

impl StoreKey {
    fn get_key(&self) -> String {
        match self {
            StoreKey::Programs => "bitvmx/programs/all".to_string(),
            StoreKey::ZKPProof(id) => format!("bitvmx/zkp/{}/proof", id),
            StoreKey::ZKPStatus(id) => format!("bitvmx/zkp/{}/status", id),
            StoreKey::ZKPFrom(id) => format!("bitvmx/zkp/{}/from", id),
            StoreKey::ZKPJournal(id) => format!("bitvmx/zkp/{}/journal", id),
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

impl BitVMX {
    pub fn new(config: Config) -> Result<Self, BitVMXError> {
        print_version_info();
        let store = Rc::new(Storage::new(&config.storage)?);
        let key_manager =
            create_key_manager_from_config(&config.key_manager, &config.key_storage.clone())?;
        let key_manager = Rc::new(key_manager);
        let rsa_public_key = key_manager
            .import_rsa_private_key(&settings::decrypt_or_read_file(config.comms_key())?)?;

        let comms_allow_list = comms_allow_list::build(&store, &config.comms.allow_list)?;

        let comms = BrokerNode::new_peers(
            "comms",
            config.comms.address,
            &settings::decrypt_or_read_file(&config.comms.priv_key)?,
            store.clone(),
            &config.comms.storage_path,
            comms_allow_list,
            config.broker.settings.clone(),
        )?;

        let wallet = Wallet::from_derive_keypair(
            config.bitcoin.clone(),
            config.wallet.clone(),
            key_manager.clone(),
            BitcoinKeyType::P2tr,
            WALLET_INDEX,
            Some(WALLET_CHANGE_INDEX),
        )?;

        let bitcoin_coordinator = BitcoinCoordinator::new_with_paths(
            &config.bitcoin,
            store.clone(),
            key_manager.clone(),
            config.coordinator_settings.clone(),
        )?;

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

        bitcoin_coordinator.monitor(TypesToMonitor::NewBlock)?;

        let leader_broadcast_helper = LeaderBroadcastHelper::new(store.clone());

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
        );

        let ping_helper = PingHelper::new(config.job_dispatcher_ping.clone());

        let message_queue = MessageQueue::new(
            store.clone(),
            RetryPolicy::new(&config.broker.settings.broker_node_config)?,
        );

        let coordinator_throttle = Throttle::new(config.coordinator_throttle.clone());
        let bitvmx_throttle = Throttle::new(config.bitvmx_throttle.clone());

        Ok(Self {
            config,
            program_context,
            store: store.clone(),
            count: 0,
            message_queue,
            coordinator_throttle,
            bitvmx_throttle,
            wallet,
            ping_helper,
            shutdown: false,
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

    /// Reports a setup failure for a message the node knows it has lost. Unlike the errors
    /// `Program` catches itself, nothing here raised an error: the message simply never
    /// arrived or never left, so setup would otherwise wait for it forever.
    fn fail_program_setup(
        &mut self,
        program_id: &Uuid,
        peer: Option<PubkHash>,
        reason: SetupFailureReason,
    ) -> Result<(), BitVMXError> {
        match self.load_program(program_id) {
            Ok(mut program) => program.fail_setup(peer, reason, &mut self.program_context),
            // No local program means no setup to fail, and nobody waiting on one. Any other
            // load failure is raised: swallowing it would drop the report and stall silently.
            Err(BitVMXError::ProgramNotFound(_)) => {
                debug!(
                    "BitVMX::fail_program_setup() - Program {} not found, nothing to fail",
                    program_id
                );
                Ok(())
            }
            Err(e) => Err(e),
        }
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
            &self.program_context.rsa_public_key,
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

    /// Processes a message for a Program and reports whether it was processed
    /// or should be retried later.
    fn process_program_message(
        &mut self,
        program_id: &Uuid,
        msg_type: CommsMessageType,
        data: Value,
        peer_address: CommsAddress,
        program: &mut Program,
        timestamp: i64,
        signature: Vec<u8>,
        version: String,
    ) -> Result<MessageDisposition, BitVMXError> {
        debug!(
            "BitVMX::process_program_message() - Processing {:?} for program {} from {}",
            msg_type, program_id, peer_address.pubkey_hash
        );

        let my_pubkey_hash = self.program_context.comms.get_pubk_hash()?;
        let participants: Vec<_> = program
            .participants
            .iter()
            .filter(|p| p.pubkey_hash != my_pubkey_hash)
            .map(|p| p.pubkey_hash.clone())
            .collect();
        if !SignatureVerifier::has_all_keys(&self.program_context.globals, &participants)? {
            info!(
                "BitVMX::process_program_message() - Missing verification keys for program: {:?}",
                program_id
            );
            return Ok(MessageDisposition::RetryLater);
        }

        // If this operator is the leader and the message type should be broadcast, store the original message
        if program.my_idx == program.leader {
            let should_store = msg_type.should_store();
            if should_store {
                let original_msg = OriginalMessage {
                    sender_pubkey_hash: peer_address.pubkey_hash.clone(),
                    msg_type,
                    data: data.clone(),
                    original_timestamp: timestamp,
                    original_signature: signature.clone(),
                    version: version.clone(),
                };
                if !self
                    .program_context
                    .leader_broadcast_helper
                    .store_original_message(program_id, msg_type, original_msg)?
                {
                    info!(
                        "There is a message already stored for program {}",
                        program_id
                    );
                    return Ok(MessageDisposition::RetryLater);
                }
            }
        }

        // Process the message
        /*let data_bytes: Vec<u8> = serde_json::from_value(data.clone()).map_err(|e| {
            BitVMXError::InvalidMessage(format!(
                "Failed to parse message data as byte array: {}. Expected JSON array of integers [0-255], got: {}",
                e,
                serde_json::to_string(&data).unwrap_or_else(|_| "<unparseable>".to_string())
            ))
        })?;*/
        program.process_comms_message(
            &peer_address.pubkey_hash,
            &msg_type,
            data,
            &mut self.program_context,
        )
    }

    pub fn process_msg(&mut self, msg: QueuedMessage) -> Result<(), BitVMXError> {
        let (version, msg_type, program_id, data, timestamp, signature) = deserialize_msg(
            msg.data.clone(),
            self.config
                .broker
                .settings
                .msg_size_config
                .max_frame_size_kb
                - 4, // Payload
        )?;

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
                let peer = msg.identifier.pubkey_hash.clone();
                if self.message_queue.push_back(msg)? == PushOutcome::Dropped {
                    self.fail_program_setup(
                        &program_id,
                        Some(peer),
                        SetupFailureReason::VerificationKeyMissing,
                    )?;
                }
                return Ok(());
            }
        }
        let disposition = if let Ok(mut program) = self.load_program(&program_id) {
            let peer_address = program.get_address_from_pubkey_hash(&msg.identifier.pubkey_hash)?;

            if is_verification_msg {
                match SignatureVerifier::handle_verification_messages(
                    &self.program_context,
                    &program_id,
                    &msg_type,
                    &data,
                    &peer_address,
                ) {
                    Ok(_) => MessageDisposition::Processed,
                    Err(e) => {
                        error!("Error handling verification message: {:?}", e);
                        MessageDisposition::RetryLater
                    }
                }
            } else {
                self.process_program_message(
                    &program_id,
                    msg_type,
                    data,
                    peer_address,
                    &mut program,
                    timestamp,
                    signature,
                    version,
                )?
            }
        } else {
            debug!("Program {} not found", program_id);
            MessageDisposition::RetryLater
        };

        if disposition == MessageDisposition::RetryLater {
            // Preserve the previous false outcome by buffering for retry.
            info!(
                "Pending message to back: {:?} for program {:?} from: {:?}",
                msg_type, program_id, msg.identifier.pubkey_hash,
            );
            let peer = msg.identifier.pubkey_hash.clone();
            if self.message_queue.push_back(msg)? == PushOutcome::Dropped {
                self.fail_program_setup(&program_id, Some(peer), SetupFailureReason::MessageLost)?;
            }
        }
        Ok(())
    }

    pub fn process_pending_messages(&mut self) -> Result<bool, BitVMXError> {
        if self.message_queue.is_empty()? {
            return Ok(false);
        }

        if let Some(msg) = self.message_queue.pop_front()? {
            self.process_msg(msg)?;
        }
        Ok(true)
    }

    pub fn process_comms_messages(&mut self) -> Result<bool, BitVMXError> {
        //Send enqueued messages
        self.program_context.comms.tick()?;

        let messages = match self.program_context.comms.check_receive(None) {
            Ok(messages) => messages,
            Err(e) => {
                error!("Error receiving messages: {:?}", e);
                return Ok(true);
            }
        };

        let mut had_work = false;
        if messages.len() > 0 {
            had_work = true;
        }
        for message in messages {
            match message {
                ReceivedMessage::Msg(identifier, msg) => {
                    let msg: QueuedMessage = QueuedMessage::new(identifier, msg)?;
                    self.process_msg(msg)?;
                }
            }
        }

        let deadletter_messages = match self.program_context.comms.check_deadletter(None) {
            Ok(messages) => messages,
            Err(e) => {
                error!("Error receiving deadletter messages: {:?}", e);
                return Ok(true);
            }
        };
        if deadletter_messages.len() > 0 {
            had_work = true;
        }
        for deadletter in deadletter_messages {
            match deadletter {
                (ReceivedMessage::Msg(identifier, _msg), ctx) => {
                    let context = Context::from_string(&ctx)?;
                    warn!(
                        "Processing deadletter message for context: {:?} and identifier: {:?}",
                        context, identifier
                    );
                    // Setup traffic is sent with Context::ProgramId; other contexts have no
                    // program to fail.
                    if let Context::ProgramId(program_id) = context {
                        self.fail_program_setup(
                            &program_id,
                            Some(identifier.pubkey_hash.clone()),
                            SetupFailureReason::Undeliverable,
                        )?;
                    }
                }
            }
        }

        Ok(had_work)
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
                if let Ok(program) = self.load_program(program_id) {
                    program.notify_news(
                        tx_id,
                        vout,
                        tx_status,
                        context_data,
                        &self.program_context,
                    )?;
                } else {
                    warn!("handle_news: Program {} not found", program_id);
                }
            }
            Context::RequestId(request_id, from) => {
                info!("Sending News: {:?} for context: {:?}", tx_id, context);
                self.program_context.broker_channel.send_service(
                    from,
                    OutgoingBitVMXApiMessages::Transaction(*request_id, tx_status, None)
                        .to_string()?,
                )?;
            }
            _ => {}
        }
        Ok(true)
    }

    fn process_bitcoin_updates(&mut self) -> Result<bool, BitVMXError> {
        self.program_context.bitcoin_coordinator.tick()?;
        self.process_wallet_updates()?;

        if !self.program_context.bitcoin_coordinator.is_ready()? {
            return Ok(true);
        }

        let news = self.program_context.bitcoin_coordinator.get_news()?;

        if news.monitor_news.is_empty() && news.coordinator_news.is_empty() {
            return Ok(false);
        }

        for monitor_news in news.monitor_news {
            let ack_news: AckNews;

            match monitor_news {
                MonitorNews::Transaction(n) => {
                    self.handle_news(n.tx_id, n.status, n.context.clone(), None)?;
                    ack_news = AckNews::Monitor(AckMonitorNews::Transaction(n.tx_id, n.context));
                    //TODO: Handle reorg case with n.resent_due_to_reorg
                }
                MonitorNews::SpendingUTXOTransaction(
                    tx_id,
                    output_index,
                    tx_status,
                    context_data,
                ) => {
                    self.handle_news(tx_id, tx_status, context_data.clone(), Some(output_index))?;
                    ack_news = AckNews::Monitor(AckMonitorNews::SpendingUTXOTransaction(
                        tx_id,
                        output_index,
                        context_data,
                    ));
                }
                MonitorNews::OutputPatternTransaction(tx_id, tx_status, tag) => {
                    if tag == RSK_PEGIN_TAG {
                        let legacy = OutgoingBitVMXApiMessages::PeginTransactionFound(
                            tx_id,
                            tx_status.clone(),
                        );
                        let data = serde_json::to_string(&legacy)?;
                        self.program_context
                            .broker_channel
                            .send_service(&self.config.components.l2, data)?;
                    }
                    let outgoing = OutgoingBitVMXApiMessages::OutputPatternTransactionFound(
                        tx_id,
                        tx_status,
                        tag.clone(),
                    );
                    let data = serde_json::to_string(&outgoing)?;
                    self.program_context
                        .broker_channel
                        .send_service(&self.config.components.l2, data)?;
                    ack_news =
                        AckNews::Monitor(AckMonitorNews::OutputPatternTransaction(tx_id, tag));
                }
                MonitorNews::NewBlock(block_height, block_hash) => {
                    debug!("New block: {} {}", block_height, block_hash);
                    ack_news = AckNews::Monitor(AckMonitorNews::NewBlock);

                    if self.send_new_block_news(&self.program_context) {
                        let data = serde_json::to_string(&OutgoingBitVMXApiMessages::NewBlock(
                            block_hash,
                            block_height,
                        ))?;
                        self.program_context
                            .broker_channel
                            .send_service(&self.config.components.l2, data)?;
                    }
                }
            }

            self.program_context
                .bitcoin_coordinator
                .ack_news(ack_news)?;
        }

        for coordinator_news in news.coordinator_news {
            match coordinator_news.clone() {
                CoordinatorNews::InsufficientFunds {
                    available,
                    required,
                } => {
                    info!(
                        "Insufficient funds for transaction. Available: {}, Required: {}",
                        available, required
                    );
                    let data = OutgoingBitVMXApiMessages::SpeedUpProgramNoFunds().to_string()?;
                    self.program_context
                        .broker_channel
                        .send_service(&self.config.components.l2, data)?;
                }
                CoordinatorNews::DispatchError { txid, context } => {
                    error!("Dispatch Transaction Error: {:?} {:?}", txid, context);
                    match self.wallet.get_wallet_tx(txid) {
                        Ok(Some(wallet_tx)) => {
                            self.wallet.cancel_tx(&wallet_tx.tx_node.tx)?;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            error!("Error fetching transaction from wallet: {:?}", e);
                        }
                    }
                }
                _ => {
                    warn!(
                        "Received unhandled coordinator news: {:?}",
                        coordinator_news
                    );
                } //TODO: Complete handling other news types
            }

            self.program_context
                .bitcoin_coordinator
                .ack_news(AckNews::Coordinator(coordinator_news))?;
        }
        Ok(true)
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
                .get(StoreKey::ZKPFrom(id).get_key(), None)?
                .ok_or_else(|| {
                    warn!("Missing 'from' parameter for ZKP request: {}", id);
                    BitVMXError::InvalidMessageFormat
                })?;

            self.proof_ready(from, id)?;
        }
        Ok(())
    }

    fn handle_dispatcher_message(
        &mut self,
        dispatcher: JobDispatcherType,
        msg: &String,
    ) -> Result<(), BitVMXError> {
        if let Some(message) = serde_json::from_str::<PingMessage>(&msg).ok() {
            self.ping_helper.received_message(dispatcher, &message);
        } else {
            let result_message = ResultMessage::from_str(&msg)?;
            let parsed: serde_json::Value = result_message.result_as_value()?;
            let context = Context::from_string(&result_message.job_id)?;
            info!("Received result from dispatcher {}", parsed);
            let program_id = match &context {
                Context::ProgramId(program_id) => *program_id,
                Context::SetupStep(program_id, _, _, _) => *program_id,
                Context::ProgramStep(program_id, _) => *program_id,
                _ => {
                    warn!(
                        "Invalid context for dispatcher result: {:?}. Expected ProgramId.",
                        context
                    );
                    return Err(BitVMXError::InvalidMessageFormat);
                }
            };

            self.load_program(&program_id)?.receive_dispatcher_result(
                parsed,
                context,
                dispatcher,
                &mut self.program_context,
            )?;
        }
        Ok(())
    }

    pub fn process_api_messages(&mut self) -> Result<bool, BitVMXError> {
        const MAX_MESSAGES_PER_TICK: usize = 20;

        // Moves whatever the components left on the broker into the in queue
        self.program_context.broker_channel.tick()?;

        // Takes only a bounded slice of it, the rest waits for the next tick
        let messages = self
            .program_context
            .broker_channel
            .check_receive(Some(MAX_MESSAGES_PER_TICK))?;
        let processed = !messages.is_empty();

        for message in messages {
            let (from, msg) = match message {
                ReceivedMessage::Msg(identifier, msg) => (identifier, msg),
            };

            match from {
                identifier if identifier == self.config.components.garbler => {
                    self.handle_dispatcher_message(JobDispatcherType::Garbler, &msg)?;
                }
                identifier if identifier == self.config.components.emulator => {
                    self.handle_dispatcher_message(JobDispatcherType::Emulator, &msg)?;
                }
                identifier if identifier == self.config.components.prover => {
                    self.handle_prover_message(msg)?;
                }
                _ => {
                    self.handle_api_message(msg, from)?;
                }
            };
        }
        Ok(processed)
    }

    pub fn tick(&mut self) -> Result<bool, BitVMXError> {
        debug!("Ticking BitVMX: {}", self.count);

        self.store.begin_global_transaction()?;

        if self.shutdown {
            info!("BitVMX is shutdown, stopping tick processing.");
            return Ok(false);
        }

        self.count += 1;
        const WARN_THRESHOLD: Duration = Duration::from_secs(10);

        if self.bitvmx_throttle.should_call() {
            let mut had_work = false;

            let instant = Instant::now();
            had_work |= self.process_programs()?;
            let duration = instant.elapsed();
            if duration > WARN_THRESHOLD {
                warn!(
                    "Processing programs took {:?} which is above the threshold",
                    duration
                );
            }

            let instant = Instant::now();
            had_work |= self.process_pending_messages()?;
            let duration = instant.elapsed();
            if duration > WARN_THRESHOLD {
                warn!(
                    "Processing pending messages took {:?} which is above the threshold",
                    duration
                );
            }

            let instant = Instant::now();
            had_work |= self.process_comms_messages()?;
            let duration = instant.elapsed();
            if duration > WARN_THRESHOLD {
                warn!(
                    "Processing comms messages took {:?} which is above the threshold",
                    duration
                );
            }

            let instant = Instant::now();
            had_work |= self.process_api_messages()?;
            let duration = instant.elapsed();
            if duration > WARN_THRESHOLD {
                warn!(
                    "Processing API messages took {:?} which is above the threshold",
                    duration
                );
            }

            self.bitvmx_throttle.record(had_work);
        }

        let instant = Instant::now();
        self.process_bitcoin_updates_with_throttle()?;
        let duration = instant.elapsed();
        if duration > WARN_THRESHOLD {
            warn!(
                "Processing bitcoin updates took {:?} which is above the threshold",
                duration
            );
        }

        self.ping_helper
            .check_job_dispatchers_liveness(&self.program_context, &self.config.components)?;

        self.store.commit_global_transaction()?;

        Ok(true)
    }

    pub fn process_wallet_updates(&mut self) -> Result<(), BitVMXError> {
        if let Err(e) = self.wallet.tick() {
            error!("Error updating wallet: {:?}", e);
        }
        Ok(())
    }

    pub fn process_bitcoin_updates_with_throttle(&mut self) -> Result<bool, BitVMXError> {
        if self.coordinator_throttle.should_call() {
            let result = self.process_bitcoin_updates();
            if let Err(e) = result {
                error!("Critical error processing bitcoin updates: {:?}", e);
                return Ok(false);
            }
            let had_work = result.unwrap_or(false);
            self.coordinator_throttle.record(had_work);
            return Ok(had_work);
        }
        Ok(false)
    }
    pub fn process_programs(&mut self) -> Result<bool, BitVMXError> {
        let all_programs = self.get_programs()?;

        let mut had_work = false;

        for status in all_programs {
            let program_id = status.program_id;

            if !is_active_program(&self.store, &program_id)? {
                continue;
            }
            had_work = true;
            let mut program = self.load_program(&program_id)?;
            program.tick(&mut self.program_context)?;
        }
        Ok(had_work)
    }

    fn get_programs(&self) -> Result<Vec<ProgramStatus>, BitVMXError> {
        let programs_ids: Option<Vec<ProgramStatus>> = self
            .store
            .get(StoreKey::Programs.get_key(), None)
            .map_err(BitVMXError::StorageError)?;

        Ok(programs_ids.unwrap_or_default())
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

    fn setup_internal(
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

        Program::new(
            id,
            &program_type,
            peer_address,
            leader as usize,
            &mut self.program_context,
            self.store.clone(),
        )?;

        self.add_new_program(&id)?;
        info!(
            "Program Setup Finished {}",
            self.program_context.comms.get_pubk_hash()?,
        );

        Ok(())
    }

    fn program_exists(&self, program_id: &Uuid) -> Result<bool, BitVMXError> {
        let programs = self.get_programs()?;
        Ok(programs.iter().any(|p| p.program_id == *program_id))
    }

    /// send replies via the broker channel
    //TODO: the change itself cannot fail, but a poisoned allow list lock makes
    //this return Err before replying, so the caller waiting on `id` gets
    //nothing back at all. Same for the ListAllowList arm. Should we reply with
    //an error instead?
    fn mutate_allow_list<F>(&self, id: Uuid, from: Identifier, change: F) -> Result<(), BitVMXError>
    where
        F: FnOnce(&mut AllowList),
    {
        let allow_list = self.program_context.comms.get_allow_list();
        let persisted = comms_allow_list::mutate(&self.store, &allow_list, change)?;
        self.reply(
            from,
            OutgoingBitVMXApiMessages::AllowListUpdated(id, persisted),
        )
    }

    fn reply(&self, to: Identifier, message: OutgoingBitVMXApiMessages) -> Result<(), BitVMXError> {
        debug!("> {:?}", message);
        self.program_context
            .broker_channel
            .send_service(&to, serde_json::to_string(&message)?)?;

        Ok(())
    }

    pub fn sync_wallet(&mut self) -> Result<(), BitVMXError> {
        info!("Starting wallet sync...");
        self.wallet.sync_wallet()?;
        info!("Wallet sync completed.");
        Ok(())
    }

    fn send_new_block_news<BC: BitcoinCoordinatorApi>(&self, context: &ProgramContext<BC>) -> bool {
        context
            .globals
            .get_var(&CLIENT_GLOBAL_SETTINGS_UUID, SEND_NEW_BLOCK_NEWS)
            .unwrap_or(None)
            .unwrap_or(VariableTypes::Bool(false))
            .bool()
            .unwrap_or(false)
    }

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
        id: Uuid,
        participants: Vec<CommsAddress>,
        participants_keys: Option<Vec<PublicKey>>,
        leader_idx: u16,
    ) -> Result<(), BitVMXError> {
        info!("Setting up key for program: {:?}", id);

        // Check if program already exists BEFORE storing any data
        if self.program_exists(&id)? {
            warn!("Program {} already exists", id);
            return Err(BitVMXError::ProgramAlreadyExists(id));
        }

        // Check if participants vector is empty or leader_idx is out of bounds
        if participants.is_empty() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        if leader_idx as usize >= participants.len() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        //TODO: in reality I should avoid exchanging public keys and just generate the aggregated directly
        // Save optional keys
        let optional_keys = serde_json::to_string(&participants_keys)?;

        self.program_context.globals.set_var(
            &id,
            "optional_keys",
            VariableTypes::String(optional_keys),
        )?;

        // Use Program with AggregatedKeyProtocol for key aggregation
        Program::new(
            id,
            PROGRAM_TYPE_AGGREGATED_KEY,
            participants,
            leader_idx as usize,
            &mut self.program_context,
            self.store.clone(),
        )?;

        // Add the program to the programs list
        self.add_new_program(&id)?;

        info!("Key setup finished for program: {:?}", id);
        Ok(())
    }

    fn get_aggregated_pubkey(&mut self, from: Identifier, id: Uuid) -> Result<(), BitVMXError> {
        info!("Getting aggregated pubkey for program: {:?}", id);

        // Read from globals (protocol-based approach via AggregatedKeyProtocol)
        let response = if let Some(key_var) = self
            .program_context
            .globals
            .get_var(&id, "final_aggregated_key")?
        {
            match key_var.pubkey() {
                Ok(aggregated_pubkey) => {
                    info!("Found aggregated pubkey in globals for program: {:?}", id);
                    OutgoingBitVMXApiMessages::AggregatedPubkey(id, aggregated_pubkey)
                }
                Err(e) => {
                    warn!("Failed to read aggregated key from globals: {}", e);
                    OutgoingBitVMXApiMessages::AggregatedPubkeyNotReady(id)
                }
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
            .send_service(&self.config.components.prover, msg)?;

        Ok(())
    }

    fn proof_ready(&mut self, from: Identifier, id: Uuid) -> Result<(), BitVMXError> {
        info!("Checking if proof is ready for job: {}", id);

        // Get the status from storage
        let status_key = StoreKey::ZKPStatus(id).get_key();
        let status: Option<String> = self.store.get(&status_key, None)?;

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
        let status: Option<String> = self.store.get(&status_key, None)?;

        let response = match status {
            Some(status_str) => {
                if status_str == "OK" {
                    info!("Getting ZKP execution result for job: {}", id);
                    let seal: Vec<u8> =
                        match self.store.get(&StoreKey::ZKPProof(id).get_key(), None)? {
                            Some(seal) => seal,
                            None => return Err(BitVMXError::InconsistentZKPData(id)),
                        };

                    let journal: Vec<u8> =
                        match self.store.get(&StoreKey::ZKPJournal(id).get_key(), None)? {
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
        confirmation_threshold: Option<u32>,
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
                confirmation_threshold,
            ))?;

        Ok(())
    }

    fn subscribe_to_output_pattern(
        &mut self,
        filter: bitcoin_coordinator::OutputPatternFilter,
        confirmation_threshold: Option<u32>,
    ) -> Result<(), BitVMXError> {
        self.program_context
            .bitcoin_coordinator
            .monitor(TypesToMonitor::OutputPattern(
                filter,
                confirmation_threshold,
            ))?;
        Ok(())
    }

    fn setup(
        &mut self,
        id: Uuid,
        program_type: String,
        peer_address: Vec<CommsAddress>,
        leader: u16,
    ) -> Result<(), BitVMXError> {
        self.setup_internal(id, program_type, peer_address, leader)
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
        confirmation_threshold: Option<u32>,
        stuck_in_mempool_blocks: Option<u32>,
    ) -> Result<(), BitVMXError> {
        info!("Dispatching transaction: {:?} for instance: {:?}", tx, id);

        self.program_context
            .bitcoin_coordinator
            .dispatch_without_speedup(
                tx,
                Context::RequestId(id, from).to_string()?,
                None,
                confirmation_threshold,
                stuck_in_mempool_blocks,
            )?;

        Ok(())
    }

    fn dispatch_transaction_name(&mut self, id: Uuid, name: &str) -> Result<(), BitVMXError> {
        self.load_program(&id)?
            .dispatch_transaction_name(name, &mut self.program_context)?;
        Ok(())
    }

    fn get_spv_proof(&mut self, from: Identifier, txid: Txid) -> Result<(), BitVMXError> {
        let tx_info = self
            .program_context
            .bitcoin_coordinator
            .get_transaction(txid);

        match tx_info {
            Ok(utx) => match utx.block_info {
                Some(block_info) => {
                    let proof = get_spv_proof(txid, block_info)?;
                    self.reply(from, OutgoingBitVMXApiMessages::SPVProof(txid, Some(proof)))?;
                }
                None => {
                    warn!("Missing block info for txid {}", txid);
                    self.reply(from, OutgoingBitVMXApiMessages::SPVProof(txid, None))?;
                }
            },
            Err(e) => {
                warn!(
                    "Failed to retrieve transaction info for txid {}: {:?}",
                    txid, e
                );
                self.reply(from, OutgoingBitVMXApiMessages::SPVProof(txid, None))?;
            }
        }

        Ok(())
    }

    fn handle_api_message(&mut self, msg: String, from: Identifier) -> Result<(), BitVMXError> {
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
                self.ping(from, uuid)?;
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
                let address = match self.wallet.receive_address() {
                    Ok(address) => address,
                    Err(e) => {
                        error!("Error getting funding address uuid: {:?}: {:?}", id, e);
                        self.program_context.broker_channel.send_service(
                            &from,
                            serde_json::to_string(&OutgoingBitVMXApiMessages::WalletError(
                                id,
                                e.to_string(),
                            ))?,
                        )?;
                        return Ok(());
                    }
                };

                self.program_context.broker_channel.send_service(
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
                    self.program_context.broker_channel.send_service(
                        &from,
                        serde_json::to_string(&OutgoingBitVMXApiMessages::WalletNotReady(id))?,
                    )?;
                    return Ok(());
                }
                let balance = self.wallet.balance();
                self.program_context.broker_channel.send_service(
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
                    self.program_context.broker_channel.send_service(
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
                        self.program_context.broker_channel.send_service(
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
                //TODO: Is this confirmation threshold of 1 appropriate here? What about stuck_in_mempool_blocks?
                self.dispatch_transaction(from.clone(), id, tx.clone(), Some(1), None)?;
                self.wallet.update_with_tx(&tx)?;

                self.program_context.broker_channel.send_service(
                    &from,
                    serde_json::to_string(&OutgoingBitVMXApiMessages::FundsSent(id, txid))?,
                )?;
            }

            IncomingBitVMXApiMessages::GetVar(uuid, key) => {
                self.get_var(from, uuid, &key)?;
            }
            IncomingBitVMXApiMessages::GetWitness(uuid, key) => {
                self.get_witness(from, uuid, &key)?;
            }
            IncomingBitVMXApiMessages::GetTransaction(id, txid) => {
                self.get_transaction(from, id, txid)?
            }
            IncomingBitVMXApiMessages::GetTransactionInfoByName(id, name) => {
                let response = match self.load_program(&id) {
                    Ok(prog) => match prog.get_transaction_by_name(&name, &self.program_context) {
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
                self.setup(id, program_type, participants, leader)?
            }
            IncomingBitVMXApiMessages::SubscribeToTransaction(
                uuid,
                txid,
                confirmation_threshold,
            ) => self.subscribe_to_tx(from, uuid, txid, confirmation_threshold)?,
            IncomingBitVMXApiMessages::SubscribeToOutputPattern(filter, confirmation_threshold) => {
                self.subscribe_to_output_pattern(filter, confirmation_threshold)?
            }
            IncomingBitVMXApiMessages::SubscribeToRskPegin(confirmation_threshold) => self
                .subscribe_to_output_pattern(
                    bitcoin_coordinator::OutputPatternFilter {
                        output_index: 1,
                        tag: RSK_PEGIN_TAG.to_vec(),
                        max_outputs: None,
                    },
                    confirmation_threshold,
                )?,
            IncomingBitVMXApiMessages::GetSPVProof(txid) => self.get_spv_proof(from, txid)?,

            IncomingBitVMXApiMessages::DispatchTransactionName(id, tx) => {
                self.dispatch_transaction_name(id, &tx)?
            }
            IncomingBitVMXApiMessages::DispatchTransaction(
                id,
                tx,
                confirmation_threshold,
                stuck_in_mempool_blocks,
            ) => {
                self.dispatch_transaction(
                    from,
                    id,
                    tx,
                    confirmation_threshold,
                    stuck_in_mempool_blocks,
                )?;
            }
            IncomingBitVMXApiMessages::SetupKey(
                id,
                participants,
                participants_keys,
                leader_idx,
            ) => self.setup_key(id, participants, participants_keys, leader_idx)?,
            IncomingBitVMXApiMessages::GetKeyPair(id) => {
                // Get aggregated key from globals (set by AggregatedKeyProtocol)
                let aggregated = self
                    .program_context
                    .globals
                    .get_var(&id, "final_aggregated_key")?
                    .and_then(|v| v.pubkey().ok())
                    .ok_or(BitVMXError::ProgramNotFound(id))?;
                let pair = self
                    .program_context
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
                        .key_manager
                        .next_keypair(BitcoinKeyType::P2tr)?;
                    self.reply(from, OutgoingBitVMXApiMessages::PubKey(id, public))?;
                } else {
                    // Get aggregated key from globals (set by AggregatedKeyProtocol)
                    let aggregated = self
                        .program_context
                        .globals
                        .get_var(&id, "final_aggregated_key")?
                        .and_then(|v| v.pubkey().ok())
                        .ok_or(BitVMXError::ProgramNotFound(id))?;
                    let pubkey = self
                        .program_context
                        .key_manager
                        .get_my_public_key(&aggregated)?;
                    self.reply(from, OutgoingBitVMXApiMessages::PubKey(id, pubkey))?;
                }
            }
            IncomingBitVMXApiMessages::GetEvenPubKey(id) => {
                let public = self
                    .program_context
                    .key_manager
                    .next_keypair_adjusted(BitcoinKeyType::P2tr)?;
                self.reply(from, OutgoingBitVMXApiMessages::PubKey(id, public))?;
            }
            IncomingBitVMXApiMessages::SignMessage(id, payload, public_key) => {
                // Create message from the payload
                let message = Message::from_digest_slice(&payload)
                    .map_err(|_| BitVMXError::InvalidMessageFormat)?;

                // Sign the message with the provided public key
                let recoverable_signature = self
                    .program_context
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
                self.get_aggregated_pubkey(from, id)?
            }
            IncomingBitVMXApiMessages::GenerateZKP(id, input, elf_file_path) => {
                self.generate_zkp(from, id, input, elf_file_path)?
            }
            IncomingBitVMXApiMessages::ProofReady(id) => self.proof_ready(from, id)?,
            IncomingBitVMXApiMessages::GetZKPExecutionResult(id) => {
                self.get_zkp_execution_result(from, id)?
            }
            IncomingBitVMXApiMessages::Encrypt(id, message, pub_key) => {
                let encrypted = self
                    .program_context
                    .key_manager
                    .encrypt_rsa_message(&message, &pub_key)?;
                self.reply(from, OutgoingBitVMXApiMessages::Encrypted(id, encrypted))?;
            }
            IncomingBitVMXApiMessages::Decrypt(id, message, pub_key) => {
                let decrypted = self
                    .program_context
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
            IncomingBitVMXApiMessages::ListAllowList(id) => {
                let allow_list = self.program_context.comms.get_allow_list();
                let (entries, allow_all) = comms_allow_list::snapshot(&allow_list)?;
                self.reply(
                    from,
                    OutgoingBitVMXApiMessages::AllowListEntries(id, entries, allow_all),
                )?;
            }
            IncomingBitVMXApiMessages::AddToAllowList(id, pubk_hash, addr) => {
                info!("Allowing comms peer {} from {:?}", pubk_hash, addr);
                self.mutate_allow_list(id, from, |allow_list| {
                    allow_list.add_entry(pubk_hash, addr)
                })?;
            }
            IncomingBitVMXApiMessages::RemoveFromAllowList(id, pubk_hash) => {
                info!("Removing comms peer {}", pubk_hash);
                self.mutate_allow_list(id, from, |allow_list| allow_list.remove(&pubk_hash))?;
            }
            IncomingBitVMXApiMessages::SetAllowAll(id, allow_all) => {
                info!("Setting comms allow_all to {}", allow_all);
                self.mutate_allow_list(id, from, |allow_list| allow_list.set_allow_all(allow_all))?;
            }
            IncomingBitVMXApiMessages::Shutdown() => {
                info!("Shutdown message received. Initiating shutdown...");
                self.shutdown()?;
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
