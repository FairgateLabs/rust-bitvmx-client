use crate::{
    api::BitVMXApi,
    collaborate::Collaboration,
    config::Config,
    errors::BitVMXError,
    keychain::KeyChain,
    p2p_helper::deserialize_msg,
    program::{
        participant::{P2PAddress, ParticipantRole},
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
    types::AckNews,
    AckMonitorNews, MonitorNews,
};

use bitvmx_broker::{
    broker_storage::BrokerStorage,
    channel::channel::LocalChannel,
    rpc::{sync_server::BrokerSync, BrokerConfig},
};
use p2p_handler::{LocalAllowList, P2pHandler, ReceiveHandlerChannel};
use protocol_builder::types::Utxo;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    rc::Rc,
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};
use storage_backend::storage::{KeyValueStore, Storage};

use tracing::{debug, info, warn};
use uuid::Uuid;

pub struct BitVMX {
    _config: Config,
    program_context: ProgramContext,
    store: Rc<Storage>,
    broker: BrokerSync,
    count: u32,
    collaborations: HashMap<Uuid, Collaboration>,
}

impl Drop for BitVMX {
    fn drop(&mut self) {
        self.broker.close();
        sleep(Duration::from_millis(100));
    }
}
enum StoreKey {
    Programs,
}

impl StoreKey {
    fn get_key(&self) -> String {
        match self {
            StoreKey::Programs => "bitvmx/programs/all".to_string(),
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
            collaborations: HashMap::new(), //deserialize from storage
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
                let (_version, msg_type, program_id, data) = deserialize_msg(msg)?;

                //TODO: If program is not found it's is possible that is a new program that is not yet in the store
                //Should I queue the message until the program is created for some secs?
                if let Some(mut program) = self.load_program(&program_id).ok() {
                    program.process_p2p_message(peer_id, msg_type, data, &self.program_context)?;
                } else {
                    if self.collaborations.contains_key(&program_id) {
                        let collaboration = self.collaborations.get_mut(&program_id).unwrap();
                        collaboration.process_p2p_message(
                            peer_id,
                            msg_type,
                            data,
                            &self.program_context,
                        )?;
                    }
                }
                return Ok(());
            }
            ReceiveHandlerChannel::Error(e) => {
                info!("Error receiving message {}", e);
            } //TODO: handle error
        }

        Ok(())
    }

    pub fn process_bitcoin_updates(&mut self) -> Result<(), BitVMXError> {
        self.program_context.bitcoin_coordinator.tick()?;

        if !self.program_context.bitcoin_coordinator.is_ready()? {
            return Ok(());
        }

        let news = self.program_context.bitcoin_coordinator.get_news()?;
        // info!("News: {:?}", news);

        if !news.monitor_news.is_empty() || !news.insufficient_funds.is_empty() {
            //info!("Processing news: {:?}", news);
        }

        for monitor_news in news.monitor_news {
            let ack_news: AckNews;

            match monitor_news {
                MonitorNews::Transaction(tx_id, tx_status, context_data) => {
                    let context = Context::from_string(&context_data)?;

                    match context {
                        Context::ProgramId(program_id) => {
                            let program = self.load_program(&program_id)?;

                            program.notify_news(
                                tx_id,
                                tx_status,
                                context_data,
                                &self.program_context,
                            )?;
                        }
                        Context::RequestId(request_id, from) => {
                            self.program_context.broker_channel.send(
                                from,
                                serde_json::to_string(&OutgoingBitVMXApiMessages::Transaction(
                                    request_id, tx_status,
                                ))?,
                            )?;
                        }
                    }

                    ack_news = AckNews::Transaction(AckMonitorNews::Transaction(tx_id));
                }
                MonitorNews::SpendingUTXOTransaction(
                    tx_id,
                    output_index,
                    tx_status,
                    _context_data,
                ) => {
                    info!(
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
                    ack_news = AckNews::Transaction(AckMonitorNews::SpendingUTXOTransaction(
                        tx_id,
                        output_index,
                    ));
                }
                MonitorNews::RskPeginTransaction(tx_id, tx_status) => {
                    let data = serde_json::to_string(
                        &OutgoingBitVMXApiMessages::PeginTransactionFound(tx_id, tx_status),
                    )?;

                    self.program_context.broker_channel.send(L2_ID, data)?;
                    ack_news = AckNews::Transaction(AckMonitorNews::RskPeginTransaction(tx_id));
                }
                MonitorNews::NewBlock(block_id, block_height) => {
                    debug!("New block: {:?} {}", block_id, block_height);
                    ack_news = AckNews::NewBlock;
                }
            }

            self.program_context
                .bitcoin_coordinator
                .ack_news(ack_news)?;
        }

        for (tx_id, context_data) in news.insufficient_funds {
            let data = serde_json::to_string(&OutgoingBitVMXApiMessages::SpeedUpProgramNoFunds(
                tx_id,
                context_data,
            ))?;

            info!("Sending funds request to broker");
            self.program_context.broker_channel.send(L2_ID, data)?;

            let ack_news = AckNews::InsufficientFunds(tx_id);
            self.program_context
                .bitcoin_coordinator
                .ack_news(ack_news)?;
        }

        Ok(())
    }

    pub fn process_api_messages(&mut self) -> Result<(), BitVMXError> {
        if let Some((msg, from)) = self.program_context.broker_channel.recv()? {
            BitVMXApi::handle_message(self, msg, from)?;
        }

        Ok(())
    }

    pub fn process_collaboration(&mut self) -> Result<(), BitVMXError> {
        //TOOD: manage state of the collaborations once persisted
        if self.collaborations.len() > 0 {
            for (_, collaboration) in self.collaborations.iter_mut() {
                collaboration.tick(&self.program_context)?;
            }
        }
        Ok(())
    }

    pub fn tick(&mut self) -> Result<(), BitVMXError> {
        self.count += 1;
        self.process_p2p_messages()?;
        self.process_programs()?;

        //throthle (check values)
        if self.count % 5 == 0 {
            self.process_api_messages()?;
            self.process_bitcoin_updates()?;
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
        self.collaborations.insert(id, collab);
        info!("Key setup finished for program: {:?}", id);
        Ok(())
    }

    fn get_aggregated_pubkey(&mut self, from: u32, id: Uuid) -> Result<(), BitVMXError> {
        info!("Getting aggregated pubkey for collaboration: {:?}", id);

        let response = if let Some(collaboration) = self.collaborations.get(&id) {
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

    fn generate_zkp(&mut self) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn proof_ready(&mut self) -> Result<(), BitVMXError> {
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

    fn subscribe_to_tx(&mut self) -> Result<(), BitVMXError> {
        // TODO will not implment, for now. We may not need this.
        Ok(())
    }

    fn subscribe_utxo(&mut self) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn setup_slot(
        &mut self,
        id: Uuid,
        peer_address: Vec<P2PAddress>,
        leader: u16,
    ) -> Result<(), BitVMXError> {
        if self.program_exists(&id)? {
            warn!("Program already exists");
            return Err(BitVMXError::ProgramAlreadyExists(id));
        }

        info!("Setting up program: {:?}", id);
        Program::setup_slot(
            &id,
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

    fn setup_program(
        &mut self,
        id: Uuid,
        role: ParticipantRole,
        peer_address: P2PAddress,
        utxo: Utxo,
    ) -> Result<(), BitVMXError> {
        if self.program_exists(&id)? {
            info!("{}: Program already exists", role);
            return Err(BitVMXError::ProgramAlreadyExists(id));
        }

        info!("Setting up program: {:?}", id);
        Program::setup_program(
            &id,
            role.clone(),
            &peer_address,
            utxo,
            &mut self.program_context,
            self.store.clone(),
            &self._config.client,
        )?;
        self.add_new_program(&id)?;
        info!("{}: Program Setup Finished", role);

        Ok(())
    }

    fn get_transaction(&mut self, from: u32, id: Uuid, txid: Txid) -> Result<(), BitVMXError> {
        let tx_status = self
            .program_context
            .bitcoin_coordinator
            .get_transaction(txid)?;

        self.program_context.broker_channel.send(
            from,
            serde_json::to_string(&OutgoingBitVMXApiMessages::Transaction(id, tx_status))?,
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

        self.program_context
            .bitcoin_coordinator
            .dispatch(tx, Context::RequestId(id, from).to_string()?)?;
        Ok(())
    }

    fn dispatch_transaction_name(&mut self, id: Uuid, name: &str) -> Result<(), BitVMXError> {
        self.load_program(&id)?
            .dispatch_transaction_name(&self.program_context, name)?;
        Ok(())
    }

    fn handle_message(&mut self, msg: String, from: u32) -> Result<(), BitVMXError> {
        let decoded: IncomingBitVMXApiMessages = serde_json::from_str(&msg)?;
        info!("< {:#?}", decoded);

        match decoded {
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
            IncomingBitVMXApiMessages::SetupProgram(id, role, peer_address, utxo) => {
                BitVMXApi::setup_program(self, id, role, peer_address, utxo)?
            }
            IncomingBitVMXApiMessages::GetTransaction(id, txid) => {
                BitVMXApi::get_transaction(self, from, id, txid)?
            }
            IncomingBitVMXApiMessages::SetupSlot(id, participants, leader) => {
                BitVMXApi::setup_slot(self, id, participants, leader)?
            }
            IncomingBitVMXApiMessages::SubscribeToTransaction(_txid) => {
                BitVMXApi::subscribe_to_tx(self)?
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
            IncomingBitVMXApiMessages::GetAggregatedPubkey(id) => {
                BitVMXApi::get_aggregated_pubkey(self, from, id)?
            }
            IncomingBitVMXApiMessages::GenerateZKP() => BitVMXApi::generate_zkp(self)?,
            IncomingBitVMXApiMessages::ProofReady() => BitVMXApi::proof_ready(self)?,
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
