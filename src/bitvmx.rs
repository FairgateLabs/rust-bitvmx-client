use crate::{
    config::Config,
    errors::BitVMXError,
    helper::{parse_keys, parse_nonces, parse_signatures},
    keychain::KeyChain,
    p2p_helper::{deserialize_msg, P2PMessageType},
    program::{
        dispute::{Funding, SearchParams},
        participant::{P2PAddress, ParticipantData, ParticipantKeys, ParticipantRole},
        program::{Program, ProgramState, SettingUpState},
        witness,
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ProgramContext, ProgramStatus},
};

use bitcoin::{PublicKey, Transaction};
use bitcoin_coordinator::{
    coordinator::{BitcoinCoordinator, BitcoinCoordinatorApi},
    types::{BitcoinCoordinatorType, BitvmxInstance, ProcessedNews, TransactionPartialInfo},
};
use bitvmx_broker::{
    broker_storage::BrokerStorage,
    channel::channel::DualChannel,
    rpc::{sync_server::BrokerSync, BrokerConfig},
};
use key_manager::winternitz;
use p2p_handler::{LocalAllowList, P2pHandler, ReceiveHandlerChannel};
use std::{
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
    bitcoin_coordinator: BitcoinCoordinatorType,
    broker: BrokerSync,
    broker_channel: DualChannel,
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

        let program_context = ProgramContext::new(comms, key_chain);

        Ok(Self {
            _config: config,
            program_context,
            store,
            bitcoin_coordinator,
            broker,
            broker_channel,
        })
    }

    pub fn setup_program(
        &mut self,
        id: &Uuid,
        my_role: ParticipantRole,
        funding: Funding,
        peer_address: &P2PAddress,
    ) -> Result<(), BitVMXError> {
        // Generate my keys.
        let my_keys = self.generate_keys(&funding.pubkey, &my_role)?;

        let p2p_address = P2PAddress::new(
            &self.program_context.comms.get_address(),
            self.program_context.comms.get_peer_id(),
        );
        // Create a participant that represents me with the specified role (Prover or Verifier).
        let me = ParticipantData::new(&p2p_address, Some(my_keys.clone()));

        // Create a participant that represents the counterparty with the opposite role.
        let other = ParticipantData::new(peer_address, None);

        // Create a program with the funding information, and the dispute resolution search parameters.
        Program::new(
            *id,
            my_role,
            me,
            other,
            funding,
            self.store.clone(),
            self._config.client.clone(),
        )?;

        Ok(())
    }

    pub fn read_bitcoin_updates() -> bool {
        // Pseudo code, this code needs to be in Bitvmx in the method read_bitcoin_updates()
        // self.blockchain.tick();
        // let news = self.blockchain.get_news();

        // // process news

        // self.blockchain.acknowledge(ProcessedNews {
        //     txs_by_id: vec![],
        //     txs_by_address: vec![],
        //     funds_requests: vec![],
        // });

        false
    }

    /// Sends the pre-kickoff transaction to the Bitcoin network, the program is now ready for the prover to
    /// claim its funds using the kickoff transaction.
    pub fn deploy_program(&mut self, program_id: &Uuid) -> Result<bool, BitVMXError> {
        let program = self.load_program(program_id)?;
        let transaction = program.prekickoff_transaction()?;

        let instance: BitvmxInstance<TransactionPartialInfo> = BitvmxInstance::new(
            *program_id,
            vec![TransactionPartialInfo::from(transaction.compute_txid())],
            None,
        );

        self.bitcoin_coordinator.monitor_instance(&instance)?;

        self.bitcoin_coordinator
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
    }

    /// Sends the kickoff transaction to the Bitcoin network, the program is now ready for the verifier to
    /// challenge its execution.
    pub fn claim_program(&mut self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let program = self.load_program(program_id)?;
        let transaction = program.kickoff_transaction()?;
        self.monitor_claim_transaction(&transaction)?;

        // TODO: Claim transaction detection should happen during bitcoin coordinator news processing,
        // when we verify the claim transaction appears on the blockchain

        Ok(())
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

    fn generate_keys(
        &mut self,
        pre_kickoff: &PublicKey,
        _role: &ParticipantRole,
    ) -> Result<ParticipantKeys, BitVMXError> {
        //TODO: define which keys are generated for each role
        let message_size = 2;
        let one_time_keys_count = 10;

        let protocol = self.program_context.key_chain.derive_keypair()?;
        let speedup = self.program_context.key_chain.derive_keypair()?;
        let timelock = self.program_context.key_chain.derive_keypair()?;
        let internal = self.program_context.key_chain.unspendable_key()?;
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

        let keys = ParticipantKeys::new(
            *pre_kickoff,
            internal,
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

    fn _search_params(&self) -> SearchParams {
        SearchParams::new(0, 0)
    }

    fn _decode_witness_data(
        &self,
        winternitz_message_sizes: Vec<usize>,
        winternitz_type: winternitz::WinternitzType,
        witness: bitcoin::Witness,
    ) -> Result<Vec<winternitz::WinternitzSignature>, BitVMXError> {
        witness::decode_witness(winternitz_message_sizes, winternitz_type, witness)
    }

    fn _wait_deployment(
        &mut self,
        _deployment_transaction: &Transaction,
    ) -> Result<(), BitVMXError> {
        // 1. Wait for the prekickoff transaction to be confirmed
        // it should introduce the transaction to the bitcoin coordinator and what for news.

        Ok(())
    }

    fn monitor_claim_transaction(
        &mut self,
        _claim_transaction: &Transaction,
    ) -> Result<(), BitVMXError> {
        // 1. Wait for the kickoff transaction to be confirmed
        // it should introduce the transaction to the bitcoin coordinator and what for news.

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
            ReceiveHandlerChannel::Msg(_peer_id, msg) => {
                let (_version, msg_type, program_id, data) = deserialize_msg(msg)?;
                let mut program = self.load_program(&program_id)?;

                info!("{}: Message received: {:?} ", program.my_role, msg_type);

                match msg_type {
                    P2PMessageType::Keys => {
                        if !Self::should_handle_msg(&program.state, &msg_type) {
                            if Self::should_answer_ack(&program.state, &msg_type, &program.my_role)
                            {
                                program.send_ack(&self.program_context, P2PMessageType::KeysAck)?;
                            }
                            return Ok(());
                        }

                        // Parse the keys received
                        let keys =
                            parse_keys(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;

                        // Build the protocol
                        program.build_protocol(&self.program_context, keys)?;

                        // Send ack to the other party
                        program.send_ack(&self.program_context, P2PMessageType::KeysAck)?;
                    }
                    P2PMessageType::PublicNonces => {
                        // TODO: Review this condition
                        if !Self::should_handle_msg(&program.state, &msg_type) {
                            if Self::should_answer_ack(&program.state, &msg_type, &program.my_role)
                            {
                                program.send_ack(
                                    &self.program_context,
                                    P2PMessageType::PublicNoncesAck,
                                )?;
                            }
                            return Ok(());
                        }

                        let nonces =
                            parse_nonces(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;

                        program.receive_participant_nonces(nonces, &self.program_context)?;

                        program.send_ack(&self.program_context, P2PMessageType::PublicNoncesAck)?;
                    }
                    P2PMessageType::PartialSignatures => {
                        // TODO: Review this condition
                        if !Self::should_handle_msg(&program.state, &msg_type) {
                            if Self::should_answer_ack(&program.state, &msg_type, &program.my_role)
                            {
                                program.send_ack(
                                    &self.program_context,
                                    P2PMessageType::PartialSignaturesAck,
                                )?;
                            }
                            return Ok(());
                        }

                        let signatures = parse_signatures(data)
                            .map_err(|_| BitVMXError::InvalidMessageFormat)?;

                        program.sign_protocol(signatures, &self.program_context)?;

                        //TODO Integration.
                        //let signatures = program.get_aggregated_signatures();
                        //self.program.save_signatures(signatures)?;

                        program.send_ack(
                            &self.program_context,
                            P2PMessageType::PartialSignaturesAck,
                        )?;
                    }
                    P2PMessageType::KeysAck
                    | P2PMessageType::PublicNoncesAck
                    | P2PMessageType::PartialSignaturesAck => {
                        if !Self::should_handle_msg(&program.state, &msg_type) {
                            info!(
                                "Ignoring message {} {:?} {:?}",
                                program.my_role, msg_type, program.state
                            );
                            return Ok(());
                        }

                        program.move_program_to_next_state()?;
                    }
                }
            }
            ReceiveHandlerChannel::Error(e) => {
                info!("Error receiving message {}", e);
            } //TODO: handle error
        }

        Ok(())
    }

    pub fn process_bitcoin_updates(&mut self) -> Result<(), BitVMXError> {
        self.bitcoin_coordinator.tick()?;

        if !self.bitcoin_coordinator.is_ready()? {
            return Ok(());
        }

        let news = self.bitcoin_coordinator.get_news()?;

        if !news.instance_txs.is_empty() {
            info!("Processing news: {:?}", news);
        };

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
            self.broker_channel.send(100, data)?;
            single_txs.push(tx_new.tx.compute_txid());
        }

        if !news.funds_requests.is_empty() {
            let data = serde_json::to_string(&OutgoingBitVMXApiMessages::SpeedUpProgramNoFunds(
                news.funds_requests.clone(),
            ))?;

            info!("Sending funds request to broker");
            self.broker_channel.send(100, data)?;
        }

        // acknowledge news to the bitcoin coordinator means won't be notified again about the same news
        if !instance_txs.is_empty() || !single_txs.is_empty() || !news.funds_requests.is_empty() {
            let processed_news = ProcessedNews {
                instance_txs,
                single_txs,
                funds_requests: news.funds_requests,
            };
            self.bitcoin_coordinator.acknowledge_news(processed_news)?;
        }

        Ok(())
    }

    // TODO: move to separate trait
    pub fn process_api_messages(&mut self) -> Result<(), BitVMXError> {
        if let Some((msg, from)) = self.broker_channel.recv()? {
            let decoded: IncomingBitVMXApiMessages = serde_json::from_str(&msg)?;
            info!("< {:#?}", decoded);

            match decoded {
                IncomingBitVMXApiMessages::Ping() => self._ping(from)?,
                IncomingBitVMXApiMessages::SetupProgram(id, role, peer_address, funding) =>
                    self._setup_program(id, role, peer_address, funding)?,
                IncomingBitVMXApiMessages::GetTransaction(txid) => todo!("Implement get transaction"),
                IncomingBitVMXApiMessages::SubscribeToTransaction(txid) => todo!("Implement subscribe"),
                IncomingBitVMXApiMessages::DispatchTransaction(id, tx) => self._dispatch_transaction(id, tx)?,
                IncomingBitVMXApiMessages::SentTransaction(id, txid) => {
                    let program = self.load_program(&id)?;
                    let tx = program.get_tx_by_id(txid)?;
                    self.bitcoin_coordinator.send_tx_instance(id, &tx)?;
                }
            }
        }

        Ok(())
    }

    fn _ping(&mut self, from: u32) -> Result<(), BitVMXError> {
        self.broker_channel.send(
            from,
            serde_json::to_string(&OutgoingBitVMXApiMessages::Pong())?,
        )?;
        info!("> {:?}", OutgoingBitVMXApiMessages::Pong());
        Ok(())
    }

    fn _setup_program(
        &mut self,
        id: Uuid,
        role: ParticipantRole,
        peer_address: P2PAddress,
        funding: Funding,
    ) -> Result<(), BitVMXError> {
        if self.program_exists(&id)? {
            info!("{}: Program already exists", role);
            return Err(BitVMXError::ProgramAlreadyExists(id));
        }

        info!("Setting up program: {:?}", id);
        //TODO: This should be done in a single atomic operation
        self.setup_program(&id, role.clone(), funding, &peer_address)?;
        self.add_new_program(&id)?;
        info!("{}: Program Setup Finished", role);

        Ok(())
    }

    fn _dispatch_transaction(&mut self, id: Uuid, tx: Transaction) -> Result<(), BitVMXError> {
        info!("Dispatching transaction: {:?} for instance: {:?}", tx, id);
        self.bitcoin_coordinator.include_tx_to_instance(id, &tx)?;
        self.bitcoin_coordinator.send_tx_instance(id, &tx)?;
        Ok(())
    }

    pub fn tick(&mut self) -> Result<(), BitVMXError> {
        self.process_p2p_messages()?;
        self.process_programs()?;
        self.process_api_messages()?;
        self.process_bitcoin_updates()?;
        Ok(())
    }

    pub fn should_answer_ack(
        state: &ProgramState,
        msg_type: &P2PMessageType,
        role: &ParticipantRole,
    ) -> bool {
        if role == &ParticipantRole::Prover {
            // Prover flow:
            // 1. Sends keys and waits for KeysAck
            // 2. Waits for Keys from verifier
            // 3. Sends nonces and waits for NoncesAck
            // 4. Waits for nonces from verifier
            // 5. Sends signatures and waits for SignaturesAck
            // 6. Waits for signatures from verifier
            match (state, msg_type) {
                (ProgramState::SettingUp(SettingUpState::SendingNonces), P2PMessageType::Keys) => {
                    true
                }
                (
                    ProgramState::SettingUp(SettingUpState::SendingSignatures),
                    P2PMessageType::PublicNonces,
                ) => true,
                _ => false,
            }
        } else {
            // Verifier flow:
            // 1. Waits for keys from prover
            // 2. Sends keys and waits for KeysAck
            // 3. Waits for nonces from prover
            // 4. Sends nonces and waits for NoncesAck
            // 5. Waits for signatures from prover
            // 6. Sends signatures and waits for SignaturesAck
            match (state, msg_type) {
                (ProgramState::SettingUp(SettingUpState::SendingKeys), P2PMessageType::Keys) => {
                    true
                }
                (
                    ProgramState::SettingUp(SettingUpState::SendingNonces),
                    P2PMessageType::PublicNonces,
                ) => true,
                (
                    ProgramState::SettingUp(SettingUpState::SendingSignatures),
                    P2PMessageType::PartialSignatures,
                ) => true,
                _ => false,
            }
        }
    }

    pub fn should_handle_msg(state: &ProgramState, msg_type: &P2PMessageType) -> bool {
        match (state, msg_type) {
            (ProgramState::SettingUp(SettingUpState::WaitingKeys), P2PMessageType::Keys) => true,
            (
                ProgramState::SettingUp(SettingUpState::WaitingNonces),
                P2PMessageType::PublicNonces,
            ) => true,
            (
                ProgramState::SettingUp(SettingUpState::WaitingSignatures),
                P2PMessageType::PartialSignatures,
            ) => true,
            (ProgramState::SettingUp(SettingUpState::SendingKeys), P2PMessageType::KeysAck) => true,
            (
                ProgramState::SettingUp(SettingUpState::SendingNonces),
                P2PMessageType::PublicNoncesAck,
            ) => true,
            (
                ProgramState::SettingUp(SettingUpState::SendingSignatures),
                P2PMessageType::PartialSignaturesAck,
            ) => true,
            _ => false,
        }
    }

    fn process_programs(&mut self) -> Result<(), BitVMXError> {
        let programs = self.get_active_programs()?;

        for mut program in programs {
            // info!("Program state: {:?}", program.state);
            if program.is_setting_up() {
                // info!("Program state is_setting_up: {:?}", program.state);
                // TODO: Improvement, I think this tick function we should have different name.
                // I think a better name could be proceed_with_setting_up
                // Besides that I think tick only exist as a function for a library to use it outside of the library.
                program.tick(&self.program_context)?;

                return Ok(());
            }

            if program.is_monitoring() {
                // info!("Program state is_monitoring: {:?}", program.state);
                // After the program is ready, we need to monitor the transactions
                let txns_to_monitor = program.get_txs_to_monitor()?;

                // TODO : COMPLETE THE FUNDING TX FOR SPEED UP
                let txs_to_monitor: BitvmxInstance<TransactionPartialInfo> = BitvmxInstance::new(
                    program.program_id,
                    txns_to_monitor
                        .iter()
                        .map(|tx| TransactionPartialInfo::from(*tx))
                        .collect(),
                    None,
                );

                self.bitcoin_coordinator.monitor_instance(&txs_to_monitor)?;

                program.move_program_to_next_state()?;

                return Ok(());
            }

            if program.is_dispatching() {
                // info!("Program state is_dispatching: {:?}", program.state);
                let tx_to_dispatch: Option<Transaction> = program.get_tx_to_dispatch()?;

                if let Some(tx) = tx_to_dispatch {
                    self.bitcoin_coordinator
                        .send_tx_instance(program.program_id, &tx)?;
                }
                return Ok(());
            }
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
