use crate::{
    api::BitVMXApi,
    collaborate::Collaboration,
    config::Config,
    errors::BitVMXError,
    keychain::KeyChain,
    p2p_helper::deserialize_msg,
    program::{
        participant::{P2PAddress, ParticipantData, ParticipantKeys, ParticipantRole},
        program::Program,
    },
    types::{
        IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ProgramContext, ProgramStatus, L2_ID,
    },
};

use bitcoin::Transaction;
use bitcoin_coordinator::{
    coordinator::{BitcoinCoordinator, BitcoinCoordinatorApi},
    types::ProcessedNews,
};

use bitvmx_broker::{
    broker_storage::BrokerStorage,
    channel::channel::DualChannel,
    rpc::{sync_server::BrokerSync, BrokerConfig},
};
use p2p_handler::{LocalAllowList, P2pHandler, ReceiveHandlerChannel};
use protocol_builder::builder::Utxo;
use std::{
    collections::HashMap,
    path::PathBuf,
    rc::Rc,
    sync::{Arc, Mutex},
    thread::sleep,
    time::Duration,
};
use storage_backend::storage::{KeyValueStore, Storage};

use tracing::info;
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
        let broker = BrokerSync::new(&broker_config, broker_storage);

        //TODO: A channel that talks directly with the broker without going through localhost loopback could be implemented
        let broker_channel = DualChannel::new(&broker_config, 1);

        let program_context =
            ProgramContext::new(comms, key_chain, bitcoin_coordinator, broker_channel);

        Ok(Self {
            _config: config,
            program_context,
            store,
            broker,
            count: 0,
            collaborations: HashMap::new(), //deserialize from storage
        })
    }

    pub fn setup_program(
        &mut self,
        id: &Uuid,
        my_role: ParticipantRole,
        peer_address: &P2PAddress,
        utxo: Utxo,
    ) -> Result<(), BitVMXError> {
        // Generate my keys.
        let my_keys = self.generate_keys(&my_role)?;

        let p2p_address = P2PAddress::new(
            &self.program_context.comms.get_address(),
            self.program_context.comms.get_peer_id(),
        );
        // Create a participant that represents me with the specified role (Prover or Verifier).
        let me = ParticipantData::new(&p2p_address, Some(my_keys.clone()));

        // Create a participant that represents the counterparty with the opposite role.
        let other = ParticipantData::new(peer_address, None);

        // Create a program with the utxo information, and the dispute resolution search parameters.
        Program::new(
            *id,
            my_role,
            me,
            other,
            utxo,
            self.store.clone(),
            self._config.client.clone(),
        )?;

        self.add_new_program(&id)?;

        Ok(())
    }

    /// Sends the pre-kickoff transaction to the Bitcoin network, the program is now ready for the prover to
    /// claim its funds using the kickoff transaction.
    /*pub fn deploy_program(&mut self, program_id: &Uuid) -> Result<bool, BitVMXError> {
        let program = self.load_program(program_id)?;
        let transaction = program.prekickoff_transaction()?;

        let instance: BitvmxInstance<TransactionPartialInfo> = BitvmxInstance::new(
            *program_id,
            vec![TransactionPartialInfo::from(transaction.compute_txid())],
            None,
        );

        self.program_context
            .bitcoin_coordinator
            .monitor_instance(&instance)?;

        self.program_context
            .bitcoin_coordinator
            .send_tx_instance(*program_id, &transaction)?;

        info!("Attempt to deploy program: {}", program_id);

        /*let deployed = self.wait_deployment(&transaction)?;
        let mut program = self.load_program(program_id)?;

        if deployed {
            program.deploy();
        }

        info!("Program deployed: {}", program_id);

        */
        Ok(true)
    }*/

    /// Sends the kickoff transaction to the Bitcoin network, the program is now ready for the verifier to
    /// challenge its execution.
    /*pub fn claim_program(&mut self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let program = self.load_program(program_id)?;
        let transaction = program.kickoff_transaction()?;
        self.monitor_claim_transaction(&transaction)?;

        // TODO: Claim transaction detection should happen during bitcoin coordinator news processing,
        // when we verify the claim transaction appears on the blockchain

        Ok(())
    }*/

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

    fn generate_keys(&mut self, _role: &ParticipantRole) -> Result<ParticipantKeys, BitVMXError> {
        //TODO: define which keys are generated for each role
        let message_size = 2;
        let one_time_keys_count = 10;
        let protocol = self.program_context.key_chain.derive_keypair()?;
        let speedup = self.program_context.key_chain.derive_keypair()?;
        let timelock = self.program_context.key_chain.derive_keypair()?;

        let program_input = self
            .program_context
            .key_chain
            .derive_winternitz_hash160(message_size)?;
        let program_ending_state = self
            .program_context
            .key_chain
            .derive_winternitz_hash160(message_size)?;
        let program_ending_step_number = self
            .program_context
            .key_chain
            .derive_winternitz_hash160(message_size)?;
        let dispute_resolution = self
            .program_context
            .key_chain
            .derive_winternitz_hash160_keys(message_size, one_time_keys_count)?;

        let keys = ParticipantKeys::new_old(
            protocol,
            speedup,
            timelock,
            program_input,
            program_ending_state,
            program_ending_step_number,
            dispute_resolution,
        );

        Ok(keys)
    }

    /*fn _search_params(&self) -> SearchParams {
        SearchParams::new(0, 0)
    }*/

    /*fn _decode_witness_data(
        &self,
        winternitz_message_sizes: Vec<usize>,
        winternitz_type: winternitz::WinternitzType,
        witness: bitcoin::Witness,
    ) -> Result<Vec<winternitz::WinternitzSignature>, BitVMXError> {
        witness::decode_witness(winternitz_message_sizes, winternitz_type, witness)
    }*/

    /*fn _wait_deployment(
        &mut self,
        _deployment_transaction: &Transaction,
    ) -> Result<(), BitVMXError> {
        // 1. Wait for the prekickoff transaction to be confirmed
        // it should introduce the transaction to the bitcoin coordinator and what for news.

        Ok(())
    }*/

    /*fn monitor_claim_transaction(
        &mut self,
        _claim_transaction: &Transaction,
    ) -> Result<(), BitVMXError> {
        // 1. Wait for the kickoff transaction to be confirmed
        // it should introduce the transaction to the bitcoin coordinator and what for news.

        Ok(())
    }*/

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

                if self.collaborations.contains_key(&program_id) {
                    let collaboration = self.collaborations.get_mut(&program_id).unwrap();
                    collaboration.process_p2p_message(
                        peer_id,
                        msg_type,
                        data,
                        &self.program_context,
                    )?;
                    return Ok(());
                }

                let mut program = self.load_program(&program_id)?;
                program.process_p2p_message(msg_type, data, &self.program_context)?;
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

        if !news.instance_txs.is_empty()
            || !news.single_txs.is_empty()
            || !news.funds_requests.is_empty()
        {
            info!("Processing news: {:?}", news);
        }

        let mut instance_txs = vec![];

        for (program_id, txs) in news.instance_txs {
            let program = self.load_program(&program_id)?;

            program.notify_news(txs.clone())?;

            instance_txs.push((
                program_id,
                txs.iter().map(|tx| tx.tx.compute_txid()).collect(),
            ));
        }

        let mut single_txs = vec![];

        for tx_new in news.single_txs {
            // Call broker (main thread) to process the news , for now dest is 100 (is hardcoded).
            let data = serde_json::to_string(&OutgoingBitVMXApiMessages::PeginTransactionFound(
                tx_new.clone(),
            ))?;
            info!("Sending pegin tx to broker found");
            self.program_context.broker_channel.send(L2_ID, data)?;
            single_txs.push(tx_new.tx.compute_txid());
        }

        if !news.funds_requests.is_empty() {
            let data = serde_json::to_string(&OutgoingBitVMXApiMessages::SpeedUpProgramNoFunds(
                news.funds_requests.clone(),
            ))?;

            info!("Sending funds request to broker");
            self.program_context.broker_channel.send(L2_ID, data)?;
        }

        // acknowledge news to the bitcoin coordinator means won't be notified again about the same news
        if !instance_txs.is_empty() || !single_txs.is_empty() || !news.funds_requests.is_empty() {
            let processed_news = ProcessedNews {
                instance_txs,
                single_txs,
                funds_requests: news.funds_requests,
            };
            self.program_context
                .bitcoin_coordinator
                .acknowledge_news(processed_news)?;
        }

        Ok(())
    }

    pub fn process_api_messages(&mut self) -> Result<(), BitVMXError> {
        if let Some((msg, from)) = self.program_context.broker_channel.recv()? {
            BitVMXApi::handle_message(self, msg, from)?;
        }

        Ok(())
    }

    pub fn tick(&mut self) -> Result<(), BitVMXError> {
        self.count += 1;
        self.process_p2p_messages()?;
        self.process_programs()?;

        //throthle (check values)
        if self.count % 100 == 0 {
            self.process_api_messages()?;
        }
        if self.count % 50 == 0 {
            self.process_bitcoin_updates()?;
        }

        //TOOD: manage state of the collaborations once persisted
        if self.collaborations.len() > 0 {
            for (_, collaboration) in self.collaborations.iter_mut() {
                collaboration.tick(&self.program_context)?;
            }
        }

        Ok(())
    }

    fn process_programs(&mut self) -> Result<(), BitVMXError> {
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

            if program.is_active() {
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

    fn setup_key(&mut self) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn get_aggregated_pubkey(&mut self) -> Result<(), BitVMXError> {
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

    fn get_tx(&mut self) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn subscribe_to_tx(&mut self) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn subscribe_utxo(&mut self) -> Result<(), BitVMXError> {
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
        //TODO: This should be done in a single atomic operation
        self.setup_program(&id, role.clone(), &peer_address, utxo)?;
        info!("{}: Program Setup Finished", role);

        Ok(())
    }

    fn dispatch_transaction_name(&mut self, id: Uuid, name: &str) -> Result<(), BitVMXError> {
        self.load_program(&id)?
            .dispatch_transaction_name(&self.program_context, name)?;
        Ok(())
    }

    fn dispatch_transaction(&mut self, id: Uuid, tx: Transaction) -> Result<(), BitVMXError> {
        info!("Dispatching transaction: {:?} for instance: {:?}", tx, id);
        self.program_context
            .bitcoin_coordinator
            .include_tx_to_instance(id, &tx)?;
        self.program_context
            .bitcoin_coordinator
            .send_tx_instance(id, &tx)?;
        Ok(())
    }

    fn handle_message(&mut self, msg: String, from: u32) -> Result<(), BitVMXError> {
        let decoded: IncomingBitVMXApiMessages = serde_json::from_str(&msg)?;
        info!("< {:#?}", decoded);

        match decoded {
            IncomingBitVMXApiMessages::Ping() => BitVMXApi::ping(self, from)?,
            IncomingBitVMXApiMessages::SetupProgram(id, role, peer_address, utxo) => {
                BitVMXApi::setup_program(self, id, role, peer_address, utxo)?
            }
            IncomingBitVMXApiMessages::GetTransaction(_txid) => BitVMXApi::get_tx(self)?,
            IncomingBitVMXApiMessages::SubscribeToTransaction(_txid) => {
                BitVMXApi::subscribe_to_tx(self)?
            }
            IncomingBitVMXApiMessages::SubscribeUTXO() => BitVMXApi::subscribe_utxo(self)?,
            IncomingBitVMXApiMessages::DispatchTransactionName(id, tx) => {
                BitVMXApi::dispatch_transaction_name(self, id, &tx)?
            }
            IncomingBitVMXApiMessages::DispatchTransaction(id, tx) => {
                BitVMXApi::dispatch_transaction(self, id, tx)?
            }
            IncomingBitVMXApiMessages::SetupKey() => BitVMXApi::setup_key(self)?,

            IncomingBitVMXApiMessages::GenerateAggregatedPubkey(id, participants, leader_idx) => {
                let leader = participants[leader_idx as usize].clone();
                let collab = Collaboration::setup_aggregated_signature(
                    &id,
                    participants,
                    leader,
                    &mut self.program_context,
                    from,
                )?;
                self.collaborations.insert(id, collab);
            }
            IncomingBitVMXApiMessages::GetAggregatedPubkey() => {
                BitVMXApi::get_aggregated_pubkey(self)?
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
