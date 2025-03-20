use crate::{
    config::Config,
    errors::BitVMXError,
    helper::{parse_keys, parse_nonces, parse_signatures},
    keychain::KeyChain,
    p2p_helper::{deserialize_msg, P2PMessageType},
    program::{
        dispute::{Funding, SearchParams},
        participant::{P2PAddress, ParticipantData, ParticipantKeys, ParticipantRole},
        program::{Program, ProgramState},
        witness,
    },
    types::{
        IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ProgramContext, ProgramStatus,
        ProgramStatusStore,
    },
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
use bitvmx_musig2::musig::{MuSig2Signer, MuSig2SignerApi};
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

    pub fn partial_sign(&mut self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let program = self.load_program(program_id)?.clone();

        // Generate the program partial signatures.

        self.sign_program(&program)?;
        Ok(())
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

    // fn get_counterparty(&mut self, role: &ParticipantRole, address: &P2PAddress, my_keys: &ParticipantKeys) -> Result<Participant, BitVMXError> {
    //     // 1. Connect with the counterparty using the address
    //     // 2. Send my keys to counterparty
    //     // 3. Receive counterparty keys as a response
    //     // 4. Build counterparty participant with received keys and return it
    //     Ok(Participant::new(
    //         role,
    //         address,
    //         self.generate_keys()?,
    //     ))
    // }

    fn sign_program(&mut self, program: &Program) -> Result<(), BitVMXError> {
        self.program_context.key_chain.sign_program(program)?;

        // 1. Send signatures to counterparty
        // 2. Receive signatures from counterparty
        // 3. Verify signatures

        Ok(())
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

                info!("{}: Message recieved: {:?} ", program.my_role, msg_type);

                match msg_type {
                    P2PMessageType::Keys => {
                        if !Self::should_handle_msg(&program.state, &msg_type) {
                            if Self::should_answer_ack(&program.state, &msg_type, &program.my_role)
                            {
                                program.send_ack(&self.program_context, P2PMessageType::KeysAck)?;
                            }
                            return Ok(());
                        }

                        // Receive keys from the other party
                        let participant_keys =
                            parse_keys(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;

                        program.save_other_keys(participant_keys.clone())?;

                        let my_protocol_key = program.me.keys.as_ref().unwrap().protocol;
                        let other_protocol_key = program.other.keys.as_ref().unwrap().protocol;

                        let participant_keys = vec![my_protocol_key, other_protocol_key];
                        let aggregated_key =
                            MuSig2Signer::get_aggregated_pubkey(participant_keys.clone())?;

                        program.build_protocol(&aggregated_key)?;

                        // TODO Return a different structure that preserves the relationship between messages, txs, inputs and taproot leaves
                        let mut messages: Vec<Vec<u8>> = program
                            .protocol_sighashes()?
                            .iter()
                            .map(|m| m.as_ref().to_vec())
                            .collect();
                        messages.sort();

                        self.program_context.key_chain.init_musig2(
                            program.program_id,
                            participant_keys,
                            my_protocol_key,
                            messages,
                        )?;

                        //TODO: Once the keys are exchanged, the program should be able to send the nonces
                        // in order to get the nonces messages should be set in musig2
                        self.program_context
                            .key_chain
                            .set_musig2_messages(program.program_id)?;

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

                        program
                            .recieve_participant_nonces(nonces, &self.program_context.key_chain)?;

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

                        program.recieve_participant_partial_signatures(
                            signatures,
                            &self.program_context.key_chain,
                        )?;

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

        if !news.txs_by_id.is_empty() {
            info!("Processing news: {:?}", news);
        };

        let mut txs_by_id = vec![];

        for (program_id, txs) in news.txs_by_id {
            let program = self.load_program(&program_id)?;

            program.inform_news(txs.clone())?;

            txs_by_id.push((
                program_id,
                txs.iter().map(|tx| tx.tx.compute_txid()).collect(),
            ));
        }

        let mut txs_by_address = vec![];

        for (address, txs) in news.txs_by_address {
            // Call broker (main thread) to process the news , for now dest is 100 (is hardcoded).
            let data = serde_json::to_string(&OutgoingBitVMXApiMessages::PegInAddressFound(txs))?;
            self.broker_channel.send(100, data)?;
            txs_by_address.push(address);
        }

        if !news.funds_requests.is_empty() {
            let data = serde_json::to_string(&OutgoingBitVMXApiMessages::SpeedUpProgramNoFunds(
                news.funds_requests.clone(),
            ))?;

            self.broker_channel.send(100, data)?;
        }

        let processed_news = ProcessedNews {
            txs_by_id,
            txs_by_address,
            funds_requests: news.funds_requests,
        };

        // acknowledge news to the bitcoin coordinator means won't be notified again about the same news
        self.bitcoin_coordinator.acknowledge_news(processed_news)?;

        Ok(())
    }

    pub fn process_api_messages(&mut self) -> Result<(), BitVMXError> {
        //TODO: Dedice if we want to process all message in a while or just one per tick
        if let Some((msg, _from)) = self.broker_channel.recv()? {
            let decoded: IncomingBitVMXApiMessages = serde_json::from_str(&msg)?;
            // info!("Processing api message {:#?}", decoded);

            match decoded {
                IncomingBitVMXApiMessages::SetupProgram(id, role, peer_address, funding) => {
                    if self.program_exists(&id)? {
                        return Err(BitVMXError::ProgramAlreadyExists(id));
                    }

                    //TODO: This should be done in a single atomic operation
                    self.add_new_program(&id)?;
                    self.setup_program(&id, role.clone(), funding, &peer_address)?;
                    info!("{}: Program Setup", role);
                }
            }
        }

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
            return match (state, msg_type) {
                (ProgramState::SendingNonces, P2PMessageType::Keys) => true,
                (ProgramState::SendingSignatures, P2PMessageType::PublicNonces) => true,
                _ => false,
            };
        } else {
            // Verifier flow:
            // 1. Waits for keys from prover
            // 2. Sends keys and waits for KeysAck
            // 3. Waits for nonces from prover
            // 4. Sends nonces and waits for NoncesAck
            // 5. Waits for signatures from prover
            // 6. Sends signatures and waits for SignaturesAck
            return match (state, msg_type) {
                (ProgramState::SendingKeys, P2PMessageType::Keys) => true,
                (ProgramState::SendingNonces, P2PMessageType::PublicNonces) => true,
                (ProgramState::SendingSignatures, P2PMessageType::PartialSignatures) => true,
                _ => false,
            };
        }
    }

    pub fn should_handle_msg(state: &ProgramState, msg_type: &P2PMessageType) -> bool {
        match (state, msg_type) {
            (ProgramState::WaitingKeys, P2PMessageType::Keys) => true,
            (ProgramState::WaitingNonces, P2PMessageType::PublicNonces) => true,
            (ProgramState::WaitingSignatures, P2PMessageType::PartialSignatures) => true,
            (ProgramState::SendingKeys, P2PMessageType::KeysAck) => true,
            (ProgramState::SendingNonces, P2PMessageType::PublicNoncesAck) => true,
            (ProgramState::SendingSignatures, P2PMessageType::PartialSignaturesAck) => true,
            _ => false,
        }
    }

    fn process_programs(&mut self) -> Result<(), BitVMXError> {
        let programs = self.get_setting_up_programs()?;
        for mut program in programs {
            program.tick(&self.program_context)?;

            if program.is_ready() {
                // After the program is ready, we need to monitor the transactions
                self.change_program_status(
                    &program.program_id,
                    ProgramStatusStore::MonitorTransactions,
                )?;

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

                self.change_program_status(
                    &program.program_id,
                    ProgramStatusStore::WaitingForTransactions,
                )?;
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

    fn get_setting_up_programs(&self) -> Result<Vec<Program>, BitVMXError> {
        let programs = self.get_programs()?;

        let mut active_programs = vec![];

        for program_status in programs {
            if program_status.state == ProgramStatusStore::SettingUp {
                let program = self.load_program(&program_status.program_id)?;
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

    fn change_program_status(
        &mut self,
        program_id: &Uuid,
        state: ProgramStatusStore,
    ) -> Result<(), BitVMXError> {
        let mut programs = self.get_programs()?;

        if let Some(program) = programs.iter_mut().find(|p| p.program_id == *program_id) {
            program.state = state;
        }

        self.store
            .set(StoreKey::Programs.get_key(), programs, None)?;
        Ok(())
    }

    fn program_exists(&self, program_id: &Uuid) -> Result<bool, BitVMXError> {
        let programs = self.get_programs()?;
        Ok(programs.iter().any(|p| p.program_id == *program_id))
    }
}
