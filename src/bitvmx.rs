use crate::program::protocols::protocol_handler::ProtocolHandler;
use crate::types::EMULATOR_ID;
use crate::{
    api::BitVMXApi,
    collaborate::Collaboration,
    config::Config,
    errors::BitVMXError,
    keychain::KeyChain,
    p2p_helper::deserialize_msg,
    program::{
        participant::P2PAddress,
        program::Program,
        variables::{Globals, WitnessVars},
    },
    types::{
        IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ProgramContext, ProgramStatus,
        BITVMX_ID, L2_ID,
    },
};
use bitcoin::{Transaction, Txid};
use bitcoin_coordinator::{
    coordinator::{BitcoinCoordinator, BitcoinCoordinatorApi},
    types::{AckCoordinatorNews, AckNews, CoordinatorNews},
    AckMonitorNews, MonitorNews, TypesToMonitor,
};

use bitvmx_broker::channel::channel::DualChannel;
use bitvmx_broker::{
    broker_storage::BrokerStorage,
    channel::channel::LocalChannel,
    rpc::{sync_server::BrokerSync, BrokerConfig},
};
use bitvmx_job_dispatcher::dispatcher_job::{DispatcherJob, ResultMessage};
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorResultType;
use bitvmx_job_dispatcher_types::prover_messages::ProverJobType;
use p2p_handler::{LocalAllowList, P2pHandler, PeerId, ReceiveHandlerChannel};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashSet, VecDeque},
    path::PathBuf,
    rc::Rc,
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};
use storage_backend::storage::{KeyValueStore, Storage};

use tracing::{debug, info, warn};
use uuid::Uuid;

pub const THROTTLE_TICKS: u32 = 5;

pub struct BitVMX {
    _config: Config,
    program_context: ProgramContext,
    store: Rc<Storage>,
    broker: BrokerSync,
    count: u32,
    pending_messages: VecDeque<(PeerId, Vec<u8>)>,
    notified_request: HashSet<(Uuid, Txid)>,
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
}

impl StoreKey {
    fn get_key(&self) -> String {
        match self {
            StoreKey::Programs => "bitvmx/programs/all".to_string(),
            StoreKey::Collaboration(id) => format!("bitvmx/collaboration/{}", id),
            StoreKey::CompleteCollaboration(id) => format!("bitvmx/collaboration_complete/{}", id),
            StoreKey::ZKPProof(id) => format!("bitvmx/zkp/{}/proof", id),
            StoreKey::ZKPStatus(id) => format!("bitvmx/zkp/{}/status", id),
        }
    }
}

impl BitVMX {
    pub fn new(config: Config) -> Result<Self, BitVMXError> {
        let store = Rc::new(Storage::new_with_path(&PathBuf::from(&config.storage.db))?);
        let key_chain = KeyChain::new(&config, store.clone())?;
        let communications_key = key_chain.communications_key.clone();
        let comms = P2pHandler::new::<LocalAllowList>(
            config.p2p_address().to_string(),
            communications_key,
        )?;

        let bitcoin_coordinator = BitcoinCoordinator::new_with_paths(
            &config.bitcoin,
            store.clone(),
            key_chain.key_manager.clone(),
            config.monitor.checkpoint_height,
            config.monitor.confirmation_threshold,
            config.bitcoin.network,
        )?;

        //TOOD: This could be moved to a simplified helper inside brokerstorage new
        //Also the broker could be run independently if needed
        let broker_backend = Storage::new_with_path(&PathBuf::from(&config.broker_storage))?;
        let broker_backend = Arc::new(Mutex::new(broker_backend));
        let broker_storage = Arc::new(Mutex::new(BrokerStorage::new(broker_backend)));
        let broker_config = BrokerConfig::new(config.broker_port, None);
        let broker = BrokerSync::new(&broker_config, broker_storage.clone());

        //TODO: A channel that talks directly with the broker without going through localhost loopback could be implemented
        let broker_channel = LocalChannel::new(BITVMX_ID, broker_storage.clone());

        let program_context = ProgramContext::new(
            comms,
            key_chain,
            bitcoin_coordinator,
            broker_channel,
            Globals::new(store.clone()),
            WitnessVars::new(store.clone()),
        );

        Ok(Self {
            _config: config,
            program_context,
            store: store.clone(),
            broker,
            count: 0,
            pending_messages: VecDeque::new(),
            notified_request: HashSet::new(),
        })
    }

    pub fn address(&self) -> String {
        self.program_context.comms.get_address()
    }

    pub fn peer_id(&self) -> String {
        self.program_context.comms.get_peer_id().to_string()
    }

    pub fn load_program(&self, program_id: &Uuid) -> Result<Program, BitVMXError> {
        let program = Program::load(self.store.clone(), program_id)?;
        Ok(program)
    }

    pub fn process_msg(
        &mut self,
        peer: PeerId,
        msg: Vec<u8>,
        pend_to_back: bool,
    ) -> Result<(), BitVMXError> {
        let (_version, msg_type, program_id, data) = deserialize_msg(msg.clone())?;

        if let Some(mut program) = self.load_program(&program_id).ok() {
            program.process_p2p_message(peer, msg_type, data, &self.program_context)?;
        } else if let Some(mut collaboration) = self.get_collaboration(&program_id)? {
            collaboration.process_p2p_message(peer, msg_type, data, &self.program_context)?;
            self.save_collaboration(&collaboration)?;
        } else {
            if pend_to_back {
                info!("Pending message to back: {:?}", msg_type);
                self.pending_messages.push_back((peer, msg));
            } else {
                info!("Pending message to front: {:?}", msg_type);
                self.pending_messages.push_front((peer, msg));
            }
        }

        Ok(())
    }

    pub fn process_pending_messages(&mut self) -> Result<(), BitVMXError> {
        if self.pending_messages.is_empty() {
            return Ok(());
        }

        let (peer, msg) = self.pending_messages.pop_front().unwrap();
        self.process_msg(peer, msg, false)?;
        Ok(())
    }

    pub fn process_p2p_messages(&mut self) -> Result<(), BitVMXError> {
        let message = self.program_context.comms.check_receive();

        if message.is_none() {
            return Ok(());
        }

        let message = message.unwrap();

        //TODO: handle priority
        // let _priority = self.comms.check_piority();

        match message {
            ReceiveHandlerChannel::Msg(peer_id, msg) => {
                self.process_msg(peer_id, msg, true)?;
                return Ok(());
            }
            ReceiveHandlerChannel::Error(e) => {
                info!("Error receiving message {}", e);
            } //TODO: handle error
        }

        Ok(())
    }

    pub fn process_bitcoin_updates(&mut self) -> Result<bool, BitVMXError> {
        self.program_context.bitcoin_coordinator.tick()?;

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
                    let context = Context::from_string(&context_data)?;
                    debug!(
                        "Transaction Found: {:?} {:?} for context: {:?}",
                        tx_id, tx_status, context
                    );

                    match context {
                        Context::ProgramId(program_id) => {
                            if !self.notified_request.contains(&(program_id, tx_id)) {
                                let program = self.load_program(&program_id)?;

                                program.notify_news(
                                    tx_id,
                                    tx_status,
                                    context_data,
                                    &self.program_context,
                                )?;
                                self.notified_request.insert((program_id, tx_id));
                            }
                        }
                        Context::RequestId(request_id, from) => {
                            if !self.notified_request.contains(&(request_id, tx_id)) {
                                info!("Sending News: {:?} for context: {:?}", tx_id, context);
                                self.program_context.broker_channel.send(
                                    from,
                                    OutgoingBitVMXApiMessages::Transaction(
                                        request_id, tx_status, None,
                                    )
                                    .to_string()?,
                                )?;
                                self.notified_request.insert((request_id, tx_id));
                            }
                        }
                    }

                    ack_news = AckNews::Monitor(AckMonitorNews::Transaction(tx_id));
                }
                MonitorNews::SpendingUTXOTransaction(
                    tx_id,
                    output_index,
                    _tx_status,
                    _context_data,
                ) => {
                    /*info!(
                        "Spending UTXO Transaction Found: {:?} {}",
                        tx_id, _context_data
                    );

                    let data = serde_json::to_string(
                        &OutgoingBitVMXApiMessages::SpendingUTXOTransactionFound(
                            tx_id,
                            output_index,
                            tx_status,
                        ),
                    )?;

                    self.program_context.broker_channel.send(L2_ID, data)?;
                    */
                    ack_news = AckNews::Monitor(AckMonitorNews::SpendingUTXOTransaction(
                        tx_id,
                        output_index,
                    ));
                }
                MonitorNews::RskPeginTransaction(tx_id, tx_status) => {
                    let data = serde_json::to_string(
                        &OutgoingBitVMXApiMessages::PeginTransactionFound(tx_id, tx_status),
                    )?;

                    self.program_context.broker_channel.send(L2_ID, data)?;
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
                CoordinatorNews::InsufficientFunds(
                    tx_id,
                    context_data,
                    _funding_tx_id,
                    _funding_context_data,
                ) => {
                    // Complete new params
                    let data =
                        OutgoingBitVMXApiMessages::SpeedUpProgramNoFunds(tx_id, context_data)
                            .to_string()?;

                    info!("Sending funds request to broker");
                    self.program_context.broker_channel.send(L2_ID, data)?;
                    ack_news = AckNews::Coordinator(AckCoordinatorNews::InsufficientFunds(tx_id));
                }
                CoordinatorNews::NewSpeedUp(_tx_id, _context_data, _counter) => {
                    // Complete

                    ack_news = AckNews::Coordinator(AckCoordinatorNews::NewSpeedUp(_tx_id));
                }
                CoordinatorNews::DispatchTransactionError(_tx_id, _context_data, _counter) => {
                    info!(
                        "Dispatch Transaction Error: {:?} {:?} {}",
                        _tx_id, _context_data, _counter
                    );
                    // Complete

                    ack_news =
                        AckNews::Coordinator(AckCoordinatorNews::DispatchTransactionError(_tx_id));
                }
                CoordinatorNews::DispatchSpeedUpError(_tx_id, _context_data, _counter) => {
                    // Complete

                    ack_news =
                        AckNews::Coordinator(AckCoordinatorNews::DispatchSpeedUpError(_tx_id));
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
        self.count += 1;
        self.process_programs()?;

        if self.count % THROTTLE_TICKS == 0 {
            self.process_p2p_messages()?;
            self.process_api_messages()?;
            self.process_bitcoin_updates()?;
            self.process_pending_messages()?;
        }

        self.process_collaboration()?;

        Ok(())
    }

    pub fn process_programs(&mut self) -> Result<(), BitVMXError> {
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

            self.store
                .set(StoreKey::Programs.get_key(), empty_programs.clone(), None)?;
            return Ok(empty_programs);
        }

        Ok(programs_ids.unwrap())
    }

    fn get_active_programs(&self) -> Result<Vec<Program>, BitVMXError> {
        let programs = self.get_programs()?;

        let mut active_programs = vec![];

        for program_status in programs {
            let program = self.load_program(&program_status.program_id)?;

            if program.state.is_active() {
                active_programs.push(program);
            }
        }

        Ok(active_programs)
    }

    fn add_new_program(&mut self, program_id: &Uuid) -> Result<(), BitVMXError> {
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
        &mut self,
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

    fn save_collaboration(&mut self, collaboration: &Collaboration) -> Result<(), BitVMXError> {
        let key = StoreKey::Collaboration(collaboration.collaboration_id).get_key();
        self.store.set(key, collaboration, None)?;
        Ok(())
    }
}

impl BitVMXApi for BitVMX {
    fn ping(&mut self, from: u32) -> Result<(), BitVMXError> {
        self.program_context.broker_channel.send(
            from,
            serde_json::to_string(&OutgoingBitVMXApiMessages::Pong())?,
        )?;
        info!("> {:?}", OutgoingBitVMXApiMessages::Pong());
        Ok(())
    }

    fn get_var(&mut self, from: u32, id: Uuid, key: &str) -> Result<(), BitVMXError> {
        info!("Getting variable {}", key);
        let value = self.program_context.globals.get_var(&id, key)?;

        self.program_context.broker_channel.send(
            from,
            serde_json::to_string(&OutgoingBitVMXApiMessages::Variable(
                id,
                key.to_string(),
                value,
            ))?,
        )?;
        Ok(())
    }

    fn get_witness(&mut self, from: u32, id: Uuid, key: &str) -> Result<(), BitVMXError> {
        info!("Getting witness {}", key);
        let value = self.program_context.witness.get_witness(&id, key)?;

        // Create response based on whether we found a value
        let response = match value {
            Some(witness) => OutgoingBitVMXApiMessages::Witness(id, key.to_string(), witness),
            None => OutgoingBitVMXApiMessages::NotFound(id, key.to_string()),
        };

        self.program_context
            .broker_channel
            .send(from, serde_json::to_string(&response)?)?;
        Ok(())
    }

    fn setup_key(
        &mut self,
        from: u32,
        id: Uuid,
        participants: Vec<P2PAddress>,
        leader_idx: u16,
    ) -> Result<(), BitVMXError> {
        info!("Setting up key for program: {:?}", id);
        let leader = participants[leader_idx as usize].clone();
        let collab = Collaboration::setup_aggregated_signature(
            &id,
            participants,
            leader,
            &mut self.program_context,
            from,
        )?;
        self.save_collaboration(&collab)?;
        info!("Key setup finished for program: {:?}", id);
        Ok(())
    }

    fn get_aggregated_pubkey(&mut self, from: u32, id: Uuid) -> Result<(), BitVMXError> {
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

        self.program_context
            .broker_channel
            .send(from, serde_json::to_string(&response)?)?;

        Ok(())
    }

    fn generate_zkp(&mut self, id: Uuid, input: u32) -> Result<(), BitVMXError> {
        info!("Generating ZKP for input: {}", input);

        let channel = DualChannel::new(&BrokerConfig::new(10000, None), 2);
        let msg = serde_json::to_string(&DispatcherJob {
            job_id: id.to_string(),
            job_type: ProverJobType::Prove(
                input.to_be_bytes().to_vec(),
                "./a.elf".to_string(),
                "./output.json".to_string(),
            ),
        })?;
        channel.send(10, msg)?;

        loop {
            if let Some((msg, _from)) = channel.recv()? {
                info!("Received: {}", msg);
                let result = zk_result::ResultType::from_json_string(msg)
                    .map_err(|_e| BitVMXError::InvalidMessageFormat)?;
                info!("Result: {:?}", result);

                // Store the result in storage
                match result {
                    zk_result::ResultType::ProveResult { seal, status } => {
                        // Store the proof data
                        self.store
                            .set(StoreKey::ZKPProof(id).get_key(), seal, None)?;
                        // Store the status
                        self.store
                            .set(StoreKey::ZKPStatus(id).get_key(), status, None)?;
                    }
                }
                break;
            } else {
                info!("Waiting for job {} to finish", id);
                sleep(Duration::from_secs(3));
            }
        }

        Ok(())
    }

    fn proof_ready(&mut self, from: u32, id: Uuid) -> Result<(), BitVMXError> {
        info!("Checking if proof is ready for job: {}", id);

        // Get the status from storage
        let status: Option<String> = self.store.get(StoreKey::ZKPStatus(id).get_key())?;

        let response = match status {
            Some(status_str) if status_str == "OK" => OutgoingBitVMXApiMessages::ProofReady(id),
            _ => OutgoingBitVMXApiMessages::ProofNotReady(id),
        };

        self.program_context
            .broker_channel
            .send(from, serde_json::to_string(&response)?)?;

        Ok(())
    }

    fn execute_zkp(&mut self) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn get_zkp_execution_result(&mut self) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn subscribe_to_tx(&mut self, from: u32, id: Uuid, txid: Txid) -> Result<(), BitVMXError> {
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

    fn subscribe_utxo(&mut self) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn setup(
        &mut self,
        id: Uuid,
        program_type: String,
        peer_address: Vec<P2PAddress>,
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
            &self._config.client,
        )?;
        self.add_new_program(&id)?;
        info!(
            "Program Setup Finished {}",
            self.program_context.comms.get_peer_id()
        );

        Ok(())
    }

    fn get_transaction(&mut self, from: u32, id: Uuid, txid: Txid) -> Result<(), BitVMXError> {
        let tx_status = self
            .program_context
            .bitcoin_coordinator
            .get_transaction(txid)?;

        self.program_context.broker_channel.send(
            from,
            serde_json::to_string(&OutgoingBitVMXApiMessages::Transaction(id, tx_status, None))?,
        )?;
        Ok(())
    }

    fn dispatch_transaction(
        &mut self,
        from: u32,
        id: Uuid,
        tx: Transaction,
    ) -> Result<(), BitVMXError> {
        info!("Dispatching transaction: {:?} for instance: {:?}", tx, id);

        self.program_context.bitcoin_coordinator.dispatch(
            tx,
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

    fn handle_message(&mut self, msg: String, from: u32) -> Result<(), BitVMXError> {
        if from == EMULATOR_ID {
            let result_message = ResultMessage::from_str(&msg)?;
            let value = result_message.result_as_value()?;
            let decoded = EmulatorResultType::from_value(value)?;
            let job_id = Uuid::parse_str(&result_message.job_id)
                .map_err(|_| BitVMXError::InvalidMessageFormat)?;
            self.load_program(&job_id)?
                .protocol
                .dispute()?
                .execution_result(&decoded, &self.program_context)?;
            return Ok(());
        }

        let decoded: IncomingBitVMXApiMessages = serde_json::from_str(&msg)?;
        info!("< {:?}", decoded);

        match decoded {
            IncomingBitVMXApiMessages::GetHashedMessage(id, name, vout, leaf) => {
                let hashed = self
                    .load_program(&id)?
                    .protocol
                    .get_hashed_message(&name, vout, leaf)?;
                self.program_context.broker_channel.send(
                    from,
                    serde_json::to_string(&OutgoingBitVMXApiMessages::HashedMessage(
                        id, name, vout, leaf, hashed,
                    ))?,
                )?;
            }
            IncomingBitVMXApiMessages::GetCommInfo() => {
                let comm_info = OutgoingBitVMXApiMessages::CommInfo(P2PAddress {
                    address: self.program_context.comms.get_address(),
                    peer_id: self.program_context.comms.get_peer_id(),
                });
                self.program_context
                    .broker_channel
                    .send(from, serde_json::to_string(&comm_info)?)?;
            }
            IncomingBitVMXApiMessages::Ping() => BitVMXApi::ping(self, from)?,
            IncomingBitVMXApiMessages::SetVar(uuid, key, value) => {
                info!("Setting variable {}: {:?}", key, value);
                self.program_context.globals.set_var(&uuid, &key, value)?;
            }
            IncomingBitVMXApiMessages::SetWitness(uuid, key, value) => {
                info!("Setting witness {}: {:?}", key, value);
                self.program_context
                    .witness
                    .set_witness(&uuid, &key, value)?;
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
            IncomingBitVMXApiMessages::GetTransactionInofByName(id, name) => {
                let tx = self
                    .load_program(&id)?
                    .get_transaction_by_name(&self.program_context, &name)?;
                self.program_context.broker_channel.send(
                    from,
                    serde_json::to_string(&OutgoingBitVMXApiMessages::TransactionInfo(
                        id, name, tx,
                    ))?,
                )?;
            }
            IncomingBitVMXApiMessages::Setup(id, program_type, participants, leader) => {
                BitVMXApi::setup(self, id, program_type, participants, leader)?
            }
            IncomingBitVMXApiMessages::SubscribeToTransaction(uuid, txid) => {
                BitVMXApi::subscribe_to_tx(self, from, uuid, txid)?
            }
            IncomingBitVMXApiMessages::SubscribeUTXO() => BitVMXApi::subscribe_utxo(self)?,
            IncomingBitVMXApiMessages::DispatchTransactionName(id, tx) => {
                BitVMXApi::dispatch_transaction_name(self, id, &tx)?
            }
            IncomingBitVMXApiMessages::DispatchTransaction(id, tx) => {
                BitVMXApi::dispatch_transaction(self, from, id, tx)?
            }
            IncomingBitVMXApiMessages::SetupKey(id, participants, leader_idx) => {
                BitVMXApi::setup_key(self, from, id, participants, leader_idx)?
            }
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
                self.program_context.broker_channel.send(
                    from,
                    serde_json::to_string(&OutgoingBitVMXApiMessages::KeyPair(id, pair.0, pair.1))?,
                )?;
                //RETURN PK
                //TODO: Revisit this as it might be insecure
            }
            IncomingBitVMXApiMessages::GetAggregatedPubkey(id) => {
                BitVMXApi::get_aggregated_pubkey(self, from, id)?
            }
            IncomingBitVMXApiMessages::GenerateZKP(id, input) => {
                BitVMXApi::generate_zkp(self, id, input)?
            }
            IncomingBitVMXApiMessages::ProofReady(id) => BitVMXApi::proof_ready(self, from, id)?,
            IncomingBitVMXApiMessages::ExecuteZKP() => BitVMXApi::execute_zkp(self)?,
            IncomingBitVMXApiMessages::GetZKPExecutionResult() => {
                BitVMXApi::get_zkp_execution_result(self)?
            }
            IncomingBitVMXApiMessages::Finalize() => BitVMXApi::finalize(self)?,
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Context {
    ProgramId(Uuid),
    RequestId(Uuid, u32),
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
