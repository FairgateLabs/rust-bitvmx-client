use crate::comms_allow_list;
use crate::config::ComponentsConfig;
use crate::error_handling::{classify, Reporter, Severity};
use crate::ping_helper::PingHelper;
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
        ErrorReportKind, IncomingBitVMXApiMessages, JobDispatcherType, MessageDisposition,
        OutgoingBitVMXApiMessages, ProgramContext, ProgramStatus, SetupFailureReason,
        PROGRAM_TYPE_AGGREGATED_KEY, RSK_PEGIN_TAG,
    },
};
use bitcoin::hashes::{sha256, Hash};
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
use std::str::FromStr;
use std::time::Instant;
use std::{net::SocketAddr, rc::Rc, thread::sleep, time::Duration};
use storage_backend::storage::{KeyValueStore, Storage};
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
    reporter: Reporter,
    shutdown: bool,
    /// Set once the indexer reaches the chain tip; until then a tick only syncs.
    chain_synced: bool,
}

impl Drop for BitVMX {
    fn drop(&mut self) {
        self.program_context.broker_channel.close();
        sleep(Duration::from_millis(100));
    }
}
const MAX_REJECTED_INPUTS: usize = 100;
const MAX_REJECTION_REASON_CHARS: usize = 1024;

#[derive(Debug, Serialize, Deserialize)]
enum RejectedInputSource {
    Api,
    Comms,
    DeadLetterContext,
}

/// Recent rejection diagnostics, not a replay queue. Payloads are identified by hash.
#[derive(Debug, Serialize, Deserialize)]
struct RejectedInput {
    source: RejectedInputSource,
    sender: Identifier,
    payload_hash: String,
    reason: String,
}

enum StoreKey {
    Programs,
    RejectedInputs,
    ZKPProof(Uuid),
    ZKPStatus(Uuid),
    ZKPFrom(Uuid),
    ZKPJournal(Uuid),
}

impl StoreKey {
    fn get_key(&self) -> String {
        match self {
            StoreKey::Programs => "bitvmx/programs/all".to_string(),
            StoreKey::RejectedInputs => "bitvmx/rejected_inputs".to_string(),
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

        let ping_helper = PingHelper::new(config.job_dispatcher_ping.clone())?;

        let message_queue = MessageQueue::new(
            store.clone(),
            RetryPolicy::new(&config.broker.settings.broker_node_config)?,
        );

        let coordinator_throttle = Throttle::new(config.coordinator_throttle.clone());
        let bitvmx_throttle = Throttle::new(config.bitvmx_throttle.clone());

        let reporter = Reporter::new(config.components.l2.clone());
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
        let decoded = deserialize_msg(
            msg.data.clone(),
            self.config
                .broker
                .settings
                .msg_size_config
                .max_frame_size_kb
                - 4, // Payload
        );
        let Some((version, msg_type, program_id, data, timestamp, signature)) =
            Self::accept_decoded_input(
                &self.store,
                RejectedInputSource::Comms,
                &msg.identifier,
                &msg.data,
                decoded,
            )?
        else {
            return Ok(());
        };

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
        let disposition = match self.load_program(&program_id) {
            Ok(mut program) => {
                let peer_address =
                    program.get_address_from_pubkey_hash(&msg.identifier.pubkey_hash)?;

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
            }
            Err(BitVMXError::ProgramNotFound(_)) => {
                debug!("Program {} not found", program_id);
                MessageDisposition::RetryLater
            }
            Err(err) => return Err(err),
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

    /// Processes up to 20 inputs from each comms queue, committing each independently.
    /// Must be called without an active global transaction.
    pub fn process_comms_messages(&mut self) -> Result<bool, BitVMXError> {
        let incoming = self
            .run_step("comms inbox", Self::process_comms_inbox)?
            .unwrap_or(true);
        let deadletters = self
            .run_step("comms dead letters", Self::process_deadletters)?
            .unwrap_or(true);
        Ok(incoming || deadletters)
    }

    fn process_comms_inbox(&mut self) -> Result<bool, BitVMXError> {
        const MAX_MESSAGES: usize = 20;
        let store = self.store.clone();
        let mut had_work = false;
        for _ in 0..MAX_MESSAGES {
            if !Self::run_transaction(&store, || self.process_one_comms_message())? {
                break;
            }
            had_work = true;
        }
        Ok(had_work)
    }

    fn process_deadletters(&mut self) -> Result<bool, BitVMXError> {
        const MAX_MESSAGES: usize = 20;
        let store = self.store.clone();
        let mut had_work = false;
        for _ in 0..MAX_MESSAGES {
            if !Self::run_transaction(&store, || self.process_one_deadletter())? {
                break;
            }
            had_work = true;
        }
        Ok(had_work)
    }

    fn process_one_comms_message(&mut self) -> Result<bool, BitVMXError> {
        let messages = self.program_context.comms.check_receive(Some(1))?;
        let had_work = !messages.is_empty();
        for message in messages {
            match message {
                ReceivedMessage::Msg(identifier, msg) => {
                    let msg: QueuedMessage = QueuedMessage::new(identifier, msg)?;
                    self.process_msg(msg)?;
                }
            }
        }

        Ok(had_work)
    }

    fn process_one_deadletter(&mut self) -> Result<bool, BitVMXError> {
        let deadletter_messages = self.program_context.comms.check_deadletter(Some(1))?;
        let had_work = !deadletter_messages.is_empty();
        for deadletter in deadletter_messages {
            match deadletter {
                (ReceivedMessage::Msg(identifier, _msg), ctx) => {
                    let Some(context) = Self::accept_decoded_input(
                        &self.store,
                        RejectedInputSource::DeadLetterContext,
                        &identifier,
                        &ctx,
                        Context::from_string(&ctx),
                    )? else {
                        continue;
                    };
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
                match self.load_program(program_id) {
                    Ok(program) => {
                        program.notify_news(
                            tx_id,
                            vout,
                            tx_status,
                            context_data,
                            &self.program_context,
                        )?;
                    }
                    Err(BitVMXError::ProgramNotFound(_)) => {
                        warn!("handle_news: Program {} not found", program_id);
                    }
                    Err(err) => return Err(err),
                }
            }
            Context::RequestId(request_id, from) => {
                info!("Sending News: {:?} for context: {:?}", tx_id, context);
                // Only a UTXO subscription carries a vout.
                let response = match vout {
                    Some(vout) => OutgoingBitVMXApiMessages::SpendingUTXOTransactionFound(
                        *request_id,
                        tx_id,
                        vout,
                        tx_status,
                    ),
                    None => OutgoingBitVMXApiMessages::Transaction(*request_id, tx_status, None),
                };
                self.program_context
                    .broker_channel
                    .send_service(from, response.to_string()?)?;
            }
            _ => {}
        }
        Ok(true)
    }

    fn process_bitcoin_updates(&mut self) -> Result<bool, BitVMXError> {
        let store = self.store.clone();
        let (ready, monitor_news, coordinator_news) = Self::run_transaction(&store, || {
            self.program_context.bitcoin_coordinator.tick()?;
            self.wallet.tick()?;
            if !self.program_context.bitcoin_coordinator.is_ready()? {
                return Ok((false, Vec::new(), Vec::new()));
            }
            if !self.chain_synced {
                return Ok((true, Vec::new(), Vec::new()));
            }

            let news = self.program_context.bitcoin_coordinator.get_news()?;
            Ok((true, news.monitor_news, news.coordinator_news))
        })?;

        self.reporter
            .rpc_recovered(&self.program_context.broker_channel);
        if !ready {
            return Ok(true);
        }
        if !self.chain_synced {
            info!("Sync complete, starting normal operation");
            self.chain_synced = true;
            return Ok(true);
        }

        let had_monitor_news = !monitor_news.is_empty();
        for news in monitor_news {
            self.run_step("monitor news", |this| {
                Self::run_transaction(&store, || this.process_monitor_news(news))
            })?;
        }
        let had_coordinator_news = !coordinator_news.is_empty();
        // Unacknowledged items remain in coordinator storage for the next fetch.
        for news in coordinator_news {
            self.run_step("coordinator news", |this| {
                Self::run_transaction(&store, || this.process_coordinator_news(news))
            })?;
        }
        Ok(had_monitor_news || had_coordinator_news)
    }

    fn process_monitor_news(&mut self, news: MonitorNews) -> Result<(), BitVMXError> {
        let ack_news = match news {
            MonitorNews::Transaction(n) => {
                self.handle_news(n.tx_id, n.status, n.context.clone(), None)?;
                //TODO: Handle reorg case with n.resent_due_to_reorg
                AckMonitorNews::Transaction(n.tx_id, n.context)
            }
            MonitorNews::SpendingUTXOTransaction(
                tx_id,
                output_index,
                tx_status,
                context_data,
            ) => {
                self.handle_news(tx_id, tx_status, context_data.clone(), Some(output_index))?;
                AckMonitorNews::SpendingUTXOTransaction(tx_id, output_index, context_data)
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
                AckMonitorNews::OutputPatternTransaction(tx_id, tag)
            }
            MonitorNews::NewBlock(block_height, block_hash) => {
                debug!("New block: {} {}", block_height, block_hash);
                if self.send_new_block_news(&self.program_context) {
                    let data = serde_json::to_string(&OutgoingBitVMXApiMessages::NewBlock(
                        block_hash,
                        block_height,
                    ))?;
                    self.program_context
                        .broker_channel
                        .send_service(&self.config.components.l2, data)?;
                }
                AckMonitorNews::NewBlock
            }
        };

        self.program_context
            .bitcoin_coordinator
            .ack_news(AckNews::Monitor(ack_news))?;
        Ok(())
    }

    fn process_coordinator_news(
        &mut self,
        coordinator_news: CoordinatorNews,
    ) -> Result<(), BitVMXError> {
        match coordinator_news.clone() {
            CoordinatorNews::InsufficientFunds {
                available,
                required,
            } => {
                info!(
                    "Insufficient funds for transaction. Available: {}, Required: {}",
                    available, required
                );
                // No txid or context, so the program cannot be identified.
                self.reporter.coordinator_news(
                    None,
                    ErrorReportKind::InsufficientFunds {
                        available,
                        required,
                    },
                    &self.program_context.broker_channel,
                )?;
            }
            CoordinatorNews::DispatchError { txid, context } => {
                error!("Dispatch Transaction Error: {:?} {:?}", txid, context);
                if let Some(wallet_tx) = self.wallet.get_wallet_tx(txid)? {
                    self.wallet.cancel_tx(&wallet_tx.tx_node.tx)?;
                }
                self.reporter.coordinator_news(
                    Some(&context),
                    ErrorReportKind::TransactionDispatchFailed { txid },
                    &self.program_context.broker_channel,
                )?;
            }
            CoordinatorNews::SpeedupDispatchError { txid, context } => {
                error!("Speedup dispatch error: {:?} {:?}", txid, context);
                self.reporter.coordinator_news(
                    Some(&context),
                    ErrorReportKind::SpeedupDispatchFailed { txid },
                    &self.program_context.broker_channel,
                )?;
            }
            CoordinatorNews::TransactionStuckInMempool { txid, context } => {
                warn!("Transaction stuck in mempool: {:?} {:?}", txid, context);
                self.reporter.coordinator_news(
                    Some(&context),
                    ErrorReportKind::TransactionStuckInMempool { txid },
                    &self.program_context.broker_channel,
                )?;
            }
            CoordinatorNews::MaxFeeRateReached {
                txid,
                effective_fee_rate,
                context,
            } => {
                warn!(
                    "Speedup for {:?} reached the fee rate cap at {} sat/vB. No further boosts",
                    txid, effective_fee_rate
                );
                self.reporter.coordinator_news(
                    Some(&context),
                    ErrorReportKind::MaxFeeRateReached {
                        txid,
                        effective_fee_rate,
                    },
                    &self.program_context.broker_channel,
                )?;
            }
            CoordinatorNews::EstimateFeerateTooHigh {
                estimated_fee_rate,
                max_fee_rate,
            } => {
                warn!(
                    "Estimated fee rate {} exceeds the configured maximum {}",
                    estimated_fee_rate, max_fee_rate
                );
                self.reporter.coordinator_news(
                    None,
                    ErrorReportKind::FeeRateTooHigh {
                        estimated: estimated_fee_rate,
                        max: max_fee_rate,
                    },
                    &self.program_context.broker_channel,
                )?;
            }
            CoordinatorNews::FundingNotAvailable => {
                error!("No funding UTXO is available");
                self.reporter.coordinator_news(
                    None,
                    ErrorReportKind::FundingNotAvailable,
                    &self.program_context.broker_channel,
                )?;
            }
            CoordinatorNews::InvalidFundingUtxo {
                amount,
                min_required,
            } => {
                error!(
                    "Funding UTXO of {} is below the {} minimum",
                    amount, min_required
                );
                self.reporter.coordinator_news(
                    None,
                    ErrorReportKind::InvalidFundingUtxo {
                        amount,
                        min_required,
                    },
                    &self.program_context.broker_channel,
                )?;
            }
            // Not reported: our own invariant broke, which is not L2's problem.
            CoordinatorNews::InvalidStateTransition { txid, from, to } => {
                error!(
                    "Invalid state transition for {:?}: {:?} -> {:?}",
                    txid, from, to
                );
            }
            // Not reported: bookkeeping after the tx already finalized or failed.
            CoordinatorNews::TransactionEvicted { txid, context } => {
                debug!(
                    "Transaction evicted from tracking: {:?} {:?}",
                    txid, context
                );
            }
            // Not reported: the caller asked for something invalid.
            CoordinatorNews::InvalidCancel { txid, reason } => {
                warn!("Cancel rejected for {:?}: {}", txid, reason);
            }
            // Not reported: the coordinator's own store has no row for this txid, which
            // is internal bookkeeping and not a statement about the chain.
            CoordinatorNews::TxNotFound { txid } => {
                error!("Coordinator has no record of transaction {:?}", txid);
            }
        }

        self.program_context
            .bitcoin_coordinator
            .ack_news(AckNews::Coordinator(coordinator_news))?;
        Ok(())
    }

    fn handle_prover_message(&mut self, msg: String) -> Result<(), BitVMXError> {
        if let Some(message) = serde_json::from_str::<PingMessage>(&msg).ok() {
            self.ping_helper.received_message(
                JobDispatcherType::ZKP,
                &message,
                &self.program_context,
                &self.config.components,
            );
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

            // Store the proof data and status.
            self.store
                .set(StoreKey::ZKPProof(id).get_key(), seal, None)?;
            self.store
                .set(StoreKey::ZKPJournal(id).get_key(), journal, None)?;
            self.store
                .set(StoreKey::ZKPStatus(id).get_key(), status.to_string(), None)?;

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
            self.ping_helper.received_message(
                dispatcher,
                &message,
                &self.program_context,
                &self.config.components,
            );
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

    /// Processes a bounded number of inputs, committing each independently.
    /// Must be called without an active global transaction.
    pub fn process_api_messages(&mut self) -> Result<bool, BitVMXError> {
        const MAX_MESSAGES_PER_TICK: usize = 20;

        let store = self.store.clone();
        let mut processed = false;
        for _ in 0..MAX_MESSAGES_PER_TICK {
            if !Self::run_transaction(&store, || self.process_one_api_message())? {
                break;
            }
            processed = true;
        }
        Ok(processed)
    }

    fn process_one_api_message(&mut self) -> Result<bool, BitVMXError> {
        // Receive one input so rollback restores it without consuming unvisited messages.
        let messages = self
            .program_context
            .broker_channel
            .check_receive(Some(1))?;
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

    pub fn tick(&mut self) -> Result<TickOutcome, BitVMXError> {
        let result = self.tick_inner();

        if let Err(e) = &result {
            error!("Error in tick(): {e:#?}");
            let mut source = std::error::Error::source(e);
            while let Some(err) = source {
                error!("  Caused by: {err}");
                source = std::error::Error::source(err);
            }

            // decide type of error to send
            let should_stop = match classify(e) {
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
            };

            if !should_stop {
                return Ok(TickOutcome::Operating);
            }
        }

        result
    }

    /// Accepts pure decoding results before handler state changes. Invalid inputs are
    /// consumed only when their diagnostic record commits with the receive transaction.
    /// Do not pass results from effectful handlers: their errors require rollback.
    fn accept_decoded_input<T, E: std::fmt::Display>(
        store: &Storage,
        source: RejectedInputSource,
        sender: &Identifier,
        payload: &str,
        decoded: Result<T, E>,
    ) -> Result<Option<T>, BitVMXError> {
        match decoded {
            Ok(value) => Ok(Some(value)),
            Err(error) => {
                let rejection = RejectedInput {
                    source,
                    sender: sender.clone(),
                    payload_hash: sha256::Hash::hash(payload.as_bytes()).to_string(),
                    reason: error
                        .to_string()
                        .chars()
                        .take(MAX_REJECTION_REASON_CHARS)
                        .collect(),
                };
                let key = StoreKey::RejectedInputs.get_key();
                let mut records: Vec<RejectedInput> = store.get(&key, None)?.unwrap_or_default();
                records.push(rejection);
                let excess = records.len().saturating_sub(MAX_REJECTED_INPUTS);
                records.drain(..excess);
                store.set(&key, &records, None)?;
                warn!("Rejected malformed input: {:?}", records.last().unwrap());
                Ok(None)
            }
        }
    }

    /// Reports nonfatal step failures without preventing independent work from running.
    /// The work owns its transactions and must close them before returning.
    fn run_step<T>(
        &mut self,
        name: &str,
        work: impl FnOnce(&mut Self) -> Result<T, BitVMXError>,
    ) -> Result<Option<T>, BitVMXError> {
        let result = work(self);
        Self::finish_step(
            name,
            result,
            &mut self.reporter,
            &self.program_context.broker_channel,
        )
    }

    fn finish_step<T>(
        name: &str,
        result: Result<T, BitVMXError>,
        reporter: &mut Reporter,
        broker_channel: &BrokerNode,
    ) -> Result<Option<T>, BitVMXError> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error) => {
                match classify(&error) {
                    // Let tick report fatal errors once and stop processing.
                    Severity::Fatal => return Err(error),
                    Severity::BitcoinNodeUnreachable => {
                        reporter.rpc_unavailable(&error, broker_channel);
                    }
                    Severity::Other => reporter.non_fatal(&error, broker_channel),
                }
                error!("Error in {name}: {error:#?}");
                Ok(None)
            }
        }
    }

    /// Commits the work on success and rolls it back on error.
    /// Requires no active global transaction. Rollback covers database writes only,
    /// not live memory or external effects.
    fn run_transaction<T>(
        store: &Storage,
        work: impl FnOnce() -> Result<T, BitVMXError>,
    ) -> Result<T, BitVMXError> {
        store.begin_global_transaction()?;
        match work() {
            Ok(value) => {
                // Storage consumes the transaction even when commit fails.
                store.commit_global_transaction()?;
                Ok(value)
            }
            Err(error) => {
                if let Err(rollback) = store.rollback_global_transaction() {
                    error!(
                        "Could not roll back transaction step after {:?}: {:?}",
                        error, rollback
                    );
                    return Err(BitVMXError::TransactionRollbackError(rollback));
                }
                Err(error)
            }
        }
    }

    fn tick_inner(&mut self) -> Result<TickOutcome, BitVMXError> {
        debug!("Ticking BitVMX: {}", self.count);

        if self.shutdown {
            info!("BitVMX is shutdown, stopping tick processing.");
            return Ok(TickOutcome::Stopping);
        }

        self.count += 1;

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

        let process_application = self.bitvmx_throttle.should_call();
        if process_application {
            // Deliver committed outgoing work before processing application messages.
            // Rollback cannot undo delivery, so transport retries may send duplicates.
            self.run_step("comms transport", |this| {
                Self::run_transaction(&this.store, || {
                    this.program_context.comms.tick().map_err(BitVMXError::from)
                })
            })?;
            self.run_step("service transport", |this| {
                Self::run_transaction(&this.store, || {
                    this.program_context
                        .broker_channel
                        .tick()
                        .map_err(BitVMXError::from)
                })
            })?;
        }

        // Each step commits independently.
        let store = self.store.clone();

        const WARN_THRESHOLD: Duration = Duration::from_secs(10);

        if process_application {
            // Failed work stays pending; do not count a failed phase as idle.
            let mut had_work = false;

            let instant = Instant::now();
            had_work |= self
                .run_step("programs", Self::process_programs)?
                .unwrap_or(true);
            let duration = instant.elapsed();
            if duration > WARN_THRESHOLD {
                warn!(
                    "Processing programs took {:?} which is above the threshold",
                    duration
                );
            }

            let instant = Instant::now();
            had_work |= self
                .run_step("pending messages", |this| {
                    Self::run_transaction(&store, || this.process_pending_messages())
                })?
                .unwrap_or(true);
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
            had_work |= self
                .run_step("API messages", Self::process_api_messages)?
                .unwrap_or(true);
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
        self.run_step("bitcoin updates", Self::process_bitcoin_updates_with_throttle)?;
        let duration = instant.elapsed();
        if duration > WARN_THRESHOLD {
            warn!(
                "Processing bitcoin updates took {:?} which is above the threshold",
                duration
            );
        }

        self.run_step("dispatcher liveness", |this| {
            Self::run_transaction(&store, || {
                this.ping_helper
                    .check_job_dispatchers_liveness(&this.program_context, &this.config.components)
            })
        })?;

        Ok(TickOutcome::Operating)
    }

    /// Owns the coordinator and news transactions; requires no active global transaction.
    pub fn process_bitcoin_updates_with_throttle(&mut self) -> Result<(), BitVMXError> {
        if self.coordinator_throttle.should_call() {
            let had_work = self.process_bitcoin_updates()?;
            self.coordinator_throttle.record(had_work);
            return Ok(());
        }
        Ok(())
    }

    /// Advances each program in its own transaction, reporting nonfatal failures locally.
    /// Must be called without an active global transaction.
    pub fn process_programs(&mut self) -> Result<bool, BitVMXError> {
        let all_programs = self.get_programs()?;

        let mut had_work = false;

        let store = self.store.clone();
        for status in all_programs {
            let program_id = status.program_id;
            had_work |= self
                .run_step(&format!("program {program_id}"), |this| {
                    Self::run_transaction(&store, || {
                        if !is_active_program(&this.store, &program_id)? {
                            return Ok(false);
                        }
                        let mut program = this.load_program(&program_id)?;
                        program.tick(&mut this.program_context)?;
                        Ok(true)
                    })
                })?
                .unwrap_or(true);
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

    fn subscribe_to_spending_utxo(
        &mut self,
        from: Identifier,
        id: Uuid,
        txid: Txid,
        vout: u32,
        confirmation_threshold: Option<u32>,
    ) -> Result<(), BitVMXError> {
        info!(
            "Subscribing to spending of UTXO: {:?}:{} from: {} id: {}",
            txid, vout, from, id
        );
        self.program_context.bitcoin_coordinator.monitor(
            TypesToMonitor::SpendingUTXOTransaction(
                txid,
                vout,
                Context::RequestId(id, from).to_string()?,
                confirmation_threshold,
            ),
        )?;

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
        let Some(decoded) = Self::accept_decoded_input(
            &self.store,
            RejectedInputSource::Api,
            &from,
            &msg,
            serde_json::from_str::<IncomingBitVMXApiMessages>(&msg),
        )? else {
            return Ok(());
        };
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
                    Err(err @ BitVMXError::ProgramNotFound(_)) => {
                        error!("Program not found: {:?}. Error: {}", id, err);
                        OutgoingBitVMXApiMessages::NotFound(
                            id,
                            format!("Program not found: {}", name),
                        )
                    }
                    Err(err) => return Err(err),
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
            IncomingBitVMXApiMessages::SubscribeToSpendingUTXO(
                uuid,
                txid,
                vout,
                confirmation_threshold,
            ) => self.subscribe_to_spending_utxo(from, uuid, txid, vout, confirmation_threshold)?,
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
                    Err(e @ BitVMXError::ProgramNotFound(_)) => {
                        warn!("Failed to load protocol: {:?}", e);
                        OutgoingBitVMXApiMessages::ProtocolVisualization(id, String::default())
                    }
                    Err(err) => return Err(err),
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

#[cfg(test)]
mod transaction_tests {
    use super::*;
    use crate::test_utils::TestStorageDir;
    use storage_backend::error::StorageError;

    #[test]
    fn news_handler_and_acknowledgement_commit_independently_per_item() {
        let dir = TestStorageDir::new("news-independent-transactions");
        let store = dir.storage();
        let result: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
            store.set("handler-first", true, None)?;
            store.set("ack-first", true, None)?;
            Err(BitVMXError::InvalidMessageFormat)
        });
        assert!(result.is_err());
        BitVMX::run_transaction(&store, || {
            store.set("handler-second", true, None)?;
            store.set("ack-second", true, None)?;
            Ok(())
        })
        .unwrap();

        drop(store);
        let store = dir.storage();
        assert_eq!(store.get::<_, bool>("handler-first", None).unwrap(), None);
        assert_eq!(store.get::<_, bool>("ack-first", None).unwrap(), None);
        assert_eq!(store.get::<_, bool>("handler-second", None).unwrap(), Some(true));
        assert_eq!(store.get::<_, bool>("ack-second", None).unwrap(), Some(true));
    }

    #[test]
    fn malformed_input_is_consumed_and_the_next_input_can_commit() {
        let dir = TestStorageDir::new("reject-malformed-input");
        let store = dir.storage();
        let sender = Identifier::new("11".repeat(32), 1);
        let valid = serde_json::to_string(&IncomingBitVMXApiMessages::Ping(Uuid::new_v4()))
            .unwrap();
        store.set("bad-input", "not JSON", None).unwrap();
        store.set("next-input", &valid, None).unwrap();

        for key in ["bad-input", "next-input"] {
            BitVMX::run_transaction(&store, || {
                let payload: String = store.get(key, None)?.unwrap();
                store.remove(key, None)?;
                if BitVMX::accept_decoded_input(
                    &store,
                    RejectedInputSource::Api,
                    &sender,
                    &payload,
                    serde_json::from_str::<IncomingBitVMXApiMessages>(&payload),
                )?
                .is_some()
                {
                    store.set("handled", true, None)?;
                }
                Ok(())
            })
            .unwrap();
        }

        assert_eq!(store.get::<_, String>("bad-input", None).unwrap(), None);
        assert_eq!(store.get::<_, String>("next-input", None).unwrap(), None);
        assert_eq!(store.get::<_, bool>("handled", None).unwrap(), Some(true));
        let records: Vec<RejectedInput> = store
            .get(StoreKey::RejectedInputs.get_key(), None)
            .unwrap()
            .unwrap();
        assert_eq!(records.len(), 1);
        assert!(matches!(records[0].source, RejectedInputSource::Api));
        assert_eq!(records[0].sender, sender);
        assert_eq!(
            records[0].payload_hash,
            sha256::Hash::hash(b"not JSON").to_string()
        );
    }

    #[test]
    fn rejection_storage_error_restores_the_input() {
        let dir = TestStorageDir::new("reject-storage-error");
        let store = dir.storage();
        let sender = Identifier::new("11".repeat(32), 1);
        store.set("input", "bad", None).unwrap();
        // An unreadable diagnostics record must not turn rejection into silent loss.
        store.set(StoreKey::RejectedInputs.get_key(), true, None).unwrap();
        let result = BitVMX::run_transaction(&store, || {
            store.remove("input", None)?;
            BitVMX::accept_decoded_input(
                &store,
                RejectedInputSource::DeadLetterContext,
                &sender,
                "bad",
                Context::from_string("bad"),
            )
        });
        assert!(matches!(result, Err(BitVMXError::StorageError(_))));
        assert_eq!(store.get::<_, String>("input", None).unwrap(), Some("bad".into()));
    }

    #[test]
    fn rejection_and_input_consumption_roll_back_together() {
        let dir = TestStorageDir::new("reject-rollback");
        let store = dir.storage();
        let sender = Identifier::new("11".repeat(32), 1);
        store.set("input", "[]", None).unwrap();
        let result: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
            store.remove("input", None)?;
            assert!(BitVMX::accept_decoded_input(
                &store,
                RejectedInputSource::Comms,
                &sender,
                "[]",
                deserialize_msg("[]".into(), 1024),
            )?
            .is_none());
            Err(BitVMXError::StorageError(StorageError::WriteError))
        });
        assert!(result.is_err());
        assert_eq!(store.get::<_, String>("input", None).unwrap(), Some("[]".into()));
        assert!(store
            .get::<_, Vec<RejectedInput>>(StoreKey::RejectedInputs.get_key(), None)
            .unwrap()
            .is_none());
    }

    #[test]
    fn rejection_diagnostics_are_bounded() {
        let dir = TestStorageDir::new("reject-bounded");
        let store = dir.storage();
        let sender = Identifier::new("11".repeat(32), 1);
        BitVMX::run_transaction(&store, || {
            for index in 0..=MAX_REJECTED_INPUTS {
                BitVMX::accept_decoded_input::<(), _>(
                    &store,
                    RejectedInputSource::Api,
                    &sender,
                    &index.to_string(),
                    Err("é".repeat(MAX_REJECTION_REASON_CHARS + 1)),
                )?;
            }
            Ok(())
        })
        .unwrap();
        let records: Vec<RejectedInput> = store
            .get(StoreKey::RejectedInputs.get_key(), None)
            .unwrap()
            .unwrap();
        assert_eq!(records.len(), MAX_REJECTED_INPUTS);
        assert_eq!(records[0].payload_hash, sha256::Hash::hash(b"1").to_string());
        assert!(records
            .iter()
            .all(|record| record.reason.chars().count() == MAX_REJECTION_REASON_CHARS));
    }

    #[test]
    fn nonfatal_step_reports_after_rollback_and_allows_independent_work() {
        let env = crate::test_utils::TestProgramContextEnv::new("nonfatal-step").unwrap();
        let mut reporter = Reporter::new(env.context.components_config.l2.clone());
        let dir = TestStorageDir::new("nonfatal-step-storage");
        let store = dir.storage();
        store.set("input", true, None).unwrap();

        let failed: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
            store.remove("input", None)?;
            store.set("partial", true, None)?;
            Err(BitVMXError::InvalidMessageFormat)
        });
        assert_eq!(
            BitVMX::finish_step("input", failed, &mut reporter, &env.context.broker_channel)
                .unwrap(),
            None
        );
        assert_eq!(store.get::<_, bool>("input", None).unwrap(), Some(true));
        assert_eq!(store.get::<_, bool>("partial", None).unwrap(), None);
        assert_eq!(env.l2_messages().unwrap().len(), 1);

        let next = BitVMX::run_transaction(&store, || {
            store.set("independent", true, None)?;
            Ok(true)
        });
        assert_eq!(
            BitVMX::finish_step("next", next, &mut reporter, &env.context.broker_channel)
                .unwrap(),
            Some(true)
        );
        assert_eq!(store.get::<_, bool>("independent", None).unwrap(), Some(true));
        assert_eq!(env.l2_messages().unwrap().len(), 1);
    }

    #[test]
    fn fatal_step_propagates_without_reporting_twice() {
        let env = crate::test_utils::TestProgramContextEnv::new("fatal-step").unwrap();
        let mut reporter = Reporter::new(env.context.components_config.l2.clone());
        let result = BitVMX::finish_step::<()>(
            "storage",
            Err(BitVMXError::StorageError(StorageError::WriteError)),
            &mut reporter,
            &env.context.broker_channel,
        );
        assert!(matches!(
            result,
            Err(BitVMXError::StorageError(StorageError::WriteError))
        ));
        // Fatal reporting belongs to tick, not the individual step.
        assert!(env.l2_messages().unwrap().is_empty());
    }

    #[test]
    fn broker_commit_survives_application_rollback() {
        let dir = TestStorageDir::new("broker-tick-commit");
        let store = dir.storage();
        BitVMX::run_transaction(&store, || {
            store.set("broker", true, None)?;
            Ok(())
        })
        .unwrap();

        store.begin_global_transaction().unwrap();
        store.set("application", true, None).unwrap();
        store.rollback_global_transaction().unwrap();
        assert_eq!(store.get::<_, bool>("broker", None).unwrap(), Some(true));
        assert_eq!(store.get::<_, bool>("application", None).unwrap(), None);
    }

    #[test]
    fn failed_second_broker_does_not_undo_first_broker() {
        let dir = TestStorageDir::new("broker-tick-independent");
        let store = dir.storage();
        BitVMX::run_transaction(&store, || {
            store.set("comms", true, None)?;
            Ok(())
        })
        .unwrap();

        let result: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
            store.set("services", true, None)?;
            Err(BitVMXError::InvalidMessageFormat)
        });
        assert!(matches!(result, Err(BitVMXError::InvalidMessageFormat)));
        assert_eq!(store.get::<_, bool>("comms", None).unwrap(), Some(true));
        assert_eq!(store.get::<_, bool>("services", None).unwrap(), None);
        // No leaked transaction blocks the next phase.
        store.begin_global_transaction().unwrap();
        store.rollback_global_transaction().unwrap();
    }

    #[test]
    fn failed_item_preserves_previous_commit_and_unvisited_input() {
        let dir = TestStorageDir::new("application-item-transactions");
        let store = dir.storage();
        for key in ["input-a", "input-b", "input-c"] {
            store.set(key, true, None).unwrap();
        }

        let value = BitVMX::run_transaction(&store, || {
            store.remove("input-a", None)?;
            store.set("state-a", true, None)?;
            Ok(42)
        })
        .unwrap();
        assert_eq!(value, 42);

        let result: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
            store.remove("input-b", None)?;
            store.set("partial-b", true, None)?;
            Err(BitVMXError::InvalidMessageFormat)
        });
        assert!(matches!(result, Err(BitVMXError::InvalidMessageFormat)));
        assert_eq!(store.get::<_, bool>("input-a", None).unwrap(), None);
        assert_eq!(store.get::<_, bool>("state-a", None).unwrap(), Some(true));
        assert_eq!(store.get::<_, bool>("partial-b", None).unwrap(), None);
        assert_eq!(store.get::<_, bool>("input-b", None).unwrap(), Some(true));
        assert_eq!(store.get::<_, bool>("input-c", None).unwrap(), Some(true));

        // The next step can open its own transaction after the failure.
        BitVMX::run_transaction(&store, || {
            store.set("next-step", true, None)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(store.get::<_, bool>("next-step", None).unwrap(), Some(true));
    }

    #[test]
    fn rollback_failure_is_fatal_even_if_the_original_error_was_not() {
        let dir = TestStorageDir::new("transaction-rollback-failure");
        let store = dir.storage();
        let result: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
            // Simulate a handler incorrectly consuming its owner's transaction.
            store.rollback_global_transaction()?;
            Err(BitVMXError::InvalidMessageFormat)
        });
        let error = result.unwrap_err();
        assert!(matches!(error, BitVMXError::TransactionRollbackError(_)));
        assert!(matches!(classify(&error), Severity::Fatal));
    }

    #[test]
    fn fatal_broker_error_also_rolls_back() {
        let dir = TestStorageDir::new("broker-tick-fatal");
        let store = dir.storage();
        store.set("incoming", true, None).unwrap();
        let result: Result<(), BitVMXError> = BitVMX::run_transaction(&store, || {
            store.remove("incoming", None)?;
            Err(BitVMXError::StorageError(StorageError::WriteError))
        });
        assert!(matches!(
            result,
            Err(BitVMXError::StorageError(StorageError::WriteError))
        ));
        assert_eq!(store.get::<_, bool>("incoming", None).unwrap(), Some(true));
        store.begin_global_transaction().unwrap();
        store.rollback_global_transaction().unwrap();
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
