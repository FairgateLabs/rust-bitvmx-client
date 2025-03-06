use crate::{
    config::Config,
    errors::BitVMXError,
    helper::{bytes_to_nonces, bytes_to_participant_keys, bytes_to_signatures},
    keychain::KeyChain,
    p2p_helper::{deserialize_msg, P2PMessageType},
    program::{
        dispute::{Funding, SearchParams},
        participant::{P2PAddress, ParticipantData, ParticipantKeys, ParticipantRole},
        program::{Program, ProgramState},
        witness,
    },
    types::{ProgramContext, ProgramStatus},
};

use bitcoin::{PublicKey, Transaction};
use bitvmx_broker::{
    broker_storage::BrokerStorage,
    channel::channel::DualChannel,
    rpc::{sync_server::BrokerSync, BrokerConfig},
};
use bitvmx_orchestrator::{
    orchestrator::{Orchestrator, OrchestratorApi},
    types::{BitvmxInstance, OrchestratorType, ProcessedNews, TransactionPartialInfo},
};
use key_manager::winternitz;
use p2p_handler::{LocalAllowList, P2pHandler, ReceiveHandlerChannel};
use serde::{Deserialize, Serialize};
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

//TODO: This should be moved to a common place that could be used to share the messages api
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum BitVMXApiMessages {
    SetupProgram(Uuid, ParticipantRole, P2PAddress, Funding),
}

pub struct BitVMX {
    _config: Config,
    program_context: ProgramContext,
    store: Rc<Storage>,
    orchestrator: OrchestratorType,
    broker: BrokerSync,
    broker_channel: DualChannel,
}

impl Drop for BitVMX {
    fn drop(&mut self) {
        self.broker.close();
        sleep(Duration::from_millis(100));
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

        let orchestrator = Orchestrator::new_with_paths(
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
            orchestrator,
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
        Program::new(*id, my_role, me, other, funding, self.store.clone())?;

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

        let instance: BitvmxInstance<TransactionPartialInfo> =
            bitvmx_orchestrator::types::BitvmxInstance::new(
                *program_id,
                vec![TransactionPartialInfo::from(transaction.compute_txid())],
                None,
            );

        self.orchestrator.monitor_instance(&instance)?;

        self.orchestrator
            .send_tx_instance(*program_id, &transaction)?;

        info!("Attempt to deploy program: {}", program_id);

        /*let deployed = self.wait_deployment(&transaction)?;
        let mut program = self.load_program(program_id)?;

        if deployed {
            program.deploy();
        }



        info!("Program deployed: {}", program_id);

        Ok(program.is_ready())*/
        Ok(true)
    }

    /// Executes the program offchain using the BitVMX CPU to generate the program trace, ending state and
    /// ending step number.
    pub fn run_program(&mut self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let program = self.load_program(program_id)?;
        if !program.is_ready() {
            return Err(BitVMXError::ProgramNotReady(*program_id));
        }

        // Run program on the CPU and store the execution result (end step, end state and trace) in the program instance
        Ok(())
    }

    /// Sends the kickoff transaction to the Bitcoin network, the program is now ready for the verifier to
    /// challenge its execution.
    pub fn claim_program(&mut self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let program = self.load_program(program_id)?;
        let transaction = program.kickoff_transaction()?;
        self.monitor_claim_transaction(&transaction)?;

        // TODO: Claim transaction detection should happen during orchestrator news processing,
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
        // it should introduce the transaction to the orchestrator and what for news.

        Ok(())
    }

    fn monitor_claim_transaction(
        &mut self,
        _claim_transaction: &Transaction,
    ) -> Result<(), BitVMXError> {
        // 1. Wait for the kickoff transaction to be confirmed
        // it should introduce the transaction to the orchestrator and what for news.

        Ok(())
    }

    pub fn process_p2p_messages(&mut self) -> Result<(), BitVMXError> {
        let message = self.program_context.comms.check_receive();

        info!("Message recieved? >>>>>>>>>>>>>>>>>>>>>>>>>");

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

                match msg_type {
                    P2PMessageType::Keys => {
                        info!("{:?}: RECIEVE KEYSSS", program.my_role);

                        if !Self::should_program_handle_msg(&program.state, &msg_type) {
                            // Just send ack to the other party
                            info!("{:?}: SEND KEYS ACK", program.my_role);
                            program.send_keys_ack(&self.program_context)?;
                            return Ok(());
                        }

                        info!("{:?}: SAVING KEYS", program.my_role);
                        // Receive keys from the other party
                        let participant_keys = bytes_to_participant_keys(data)
                            .map_err(|_| BitVMXError::InvalidMessageFormat)?;

                        program.recieve_participant_keys(participant_keys.clone())?;

                        // Send ack to the other party
                        program.send_keys_ack(&self.program_context)?;
                    }
                    P2PMessageType::PublicNonces => {
                        info!("{:?}: RECIEVE NONCES", program.my_role);

                        if !Self::should_program_handle_msg(&program.state, &msg_type) {
                            // Just send ack to the other party
                            program.send_nonces_ack(&self.program_context)?;

                            info!("{:?}: SEND NONCES ACK", program.my_role);
                            return Ok(());
                        }

                        let nonces =
                            bytes_to_nonces(data).map_err(|_| BitVMXError::InvalidMessageFormat)?;
                        program
                            .recieve_participant_nonces(nonces, &self.program_context.key_chain)?;

                        // Send ack to the other party
                        program.send_nonces_ack(&self.program_context)?;
                    }
                    P2PMessageType::PartialSignatures => {
                        info!("{:?}: RECIEVE SIGNATURES", program.my_role);

                        if !Self::should_program_handle_msg(&program.state, &msg_type) {
                            // Just send ack to the other party
                            info!("{:?}: SEND SIGNATURES ACK", program.my_role);
                            program.send_signatures_ack(&self.program_context)?;
                            return Ok(());
                        }

                        let signatures = bytes_to_signatures(data)
                            .map_err(|_| BitVMXError::InvalidMessageFormat)?;

                        program.recieve_participant_partial_signatures(
                            signatures,
                            &self.program_context.key_chain,
                        )?;

                        // Send ack to the other party
                        program.send_signatures_ack(&self.program_context)?;
                    }
                    P2PMessageType::KeysAck => {
                        info!("{:?}: RECIEVE KEYS ACK", program.my_role);

                        if !Self::should_program_handle_msg(&program.state, &msg_type) {
                            return Ok(());
                        }

                        program.move_to_next_state()?;
                    }
                    P2PMessageType::PublicNoncesAck => {
                        info!("{:?}: RECIEVE NONCES ACK", program.my_role);

                        if !Self::should_program_handle_msg(&program.state, &msg_type) {
                            return Ok(());
                        }

                        program.move_to_next_state()?;
                    }
                    P2PMessageType::PartialSignaturesAck => {
                        info!("{:?}: RECIEVE SIGNATURES ACK", program.my_role);

                        if !Self::should_program_handle_msg(&program.state, &msg_type) {
                            return Ok(());
                        }

                        program.move_to_next_state()?;
                    }
                }
            }
            ReceiveHandlerChannel::Error(e) => {
                info!("Error receiving message {}", e);
            } //TODO: handle error
        }

        info!("Chau >>>>>>>>>>>>>>>>>>>>>>>>>");
        Ok(())
    }

    pub fn process_bitcoin_updates(&mut self) -> Result<bool, BitVMXError> {
        let ret = self.orchestrator.tick();
        if ret.is_err() {
            //TODO: Fix why orchestrator is failing
            return Ok(false);
        }

        if !self.orchestrator.is_ready()? {
            return Ok(false);
        }

        let news = self.orchestrator.get_news()?;
        if !news.txs_by_id.is_empty() {
            info!("Processing news: {:?}", news);
        } else {
            return Ok(true);
        }

        let mut ret = vec![];

        for (program_id, txs) in news.txs_by_id {
            let mut ret_tx = vec![];
            for tx in txs {
                ret_tx.push(tx.tx.compute_txid());
            }
            ret.push((program_id, ret_tx));

            let _program = self.load_program(&program_id)?;
            //TODO: Check that the transaction
            // program.deploy();
        }

        //let txids = news.txs_by_id.iter().map(|tx| (tx.0, tx.1)).collect::<Vec<Txid>>();
        let processed_news = ProcessedNews {
            txs_by_id: ret,
            txs_by_address: vec![],
            funds_requests: vec![],
        };

        self.orchestrator.acknowledge_news(processed_news)?;

        Ok(false)
    }

    pub fn process_api_messages(&mut self) -> Result<(), BitVMXError> {
        //TODO: Dedice if we want to process all message in a while or just one per tick
        if let Some((msg, _from)) = self.broker_channel.recv()? {
            let decoded: BitVMXApiMessages = serde_json::from_str(&msg)?;
            // info!("Processing api message {:#?}", decoded);

            match decoded {
                BitVMXApiMessages::SetupProgram(id, role, peer_address, funding) => {
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
        self.advance_programs()?;
        self.process_api_messages()?;
        //self.process_bitcoin_updates()?;
        Ok(())
    }

    pub fn should_program_handle_msg(state: &ProgramState, msg_type: &P2PMessageType) -> bool {
        match (state, msg_type) {
            (ProgramState::WaitingKeys, P2PMessageType::Keys) => true,
            (ProgramState::WaitingNonces, P2PMessageType::PublicNonces) => true,
            (ProgramState::WaitingSignatures, P2PMessageType::PartialSignatures) => true,
            (ProgramState::SendingKeys, P2PMessageType::KeysAck) => true,
            (ProgramState::SendingNonces, P2PMessageType::PublicNoncesAck) => true,
            (ProgramState::SendingSignatures, P2PMessageType::PartialSignaturesAck) => true,
            _ => {
                info!("NO SE HANDLEA: {:?} {:?}", state, msg_type);
                false
            }
        }
    }

    fn advance_programs(&mut self) -> Result<(), BitVMXError> {
        let programs = self.get_active_programs()?;
        for mut program in programs {
            program.tick(&mut self.program_context)?;

            if !program.is_active() {
                info!("INACTIVO!!!! {:?} ", program.program_id);
                self.mark_program_inactive(&program.program_id)?;
            }
        }
        Ok(())
    }

    fn get_programs(&self) -> Result<Vec<ProgramStatus>, BitVMXError> {
        let programs_ids: Option<Vec<ProgramStatus>> = self
            .store
            .get("bitvmx/programs/all")
            .map_err(BitVMXError::StorageError)?;

        if programs_ids.is_none() {
            let empty_programs: Vec<ProgramStatus> = vec![];

            self.store
                .set("bitvmx/programs/all", empty_programs.clone(), None)?;
            return Ok(empty_programs);
        }

        Ok(programs_ids.unwrap())
    }

    fn get_active_programs(&self) -> Result<Vec<Program>, BitVMXError> {
        let programs = self.get_programs()?;

        let mut active_programs = vec![];

        for program_status in programs {
            if program_status.is_active {
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

        self.store.set("bitvmx/programs/all", programs, None)?;

        Ok(())
    }

    fn mark_program_inactive(&mut self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let mut programs = self.get_programs()?;

        if let Some(program) = programs.iter_mut().find(|p| p.program_id == *program_id) {
            program.is_active = false;
        }

        self.store.set("bitvmx/programs/all", programs, None)?;
        Ok(())
    }

    fn program_exists(&self, program_id: &Uuid) -> Result<bool, BitVMXError> {
        let programs = self.get_programs()?;
        Ok(programs.iter().any(|p| p.program_id == *program_id))
    }
}
