use crate::{
    bitcoin::rpc::BitcoinClient,
    config::Config,
    errors::BitVMXError,
    keys::keychain::KeyChain,
    p2p::p2p_parser::{deserialize_msg, P2PMessageType},
    program::{
        dispute::{Funding, SearchParams},
        participant::{P2PAddress, Participant, ParticipantKeys, ParticipantRole},
        program::Program,
        witness,
    },
};
use bitcoin::PublicKey;
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use bitvmx_orchestrator::{
    orchestrator::{Orchestrator, OrchestratorApi},
    types::{BitvmxInstance, OrchestratorType, ProcessedNews, TransactionPartialInfo},
};
use key_manager::winternitz;
use p2p_handler::{LocalAllowList, P2pHandler, ReceiveHandlerChannel};
use std::{collections::HashMap, path::PathBuf, rc::Rc};
use storage_backend::storage::Storage;
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub enum BitVMXApiMessages {
    SetupProgram(Uuid, ParticipantRole, P2PAddress),
}

pub struct BitVMX {
    config: Config,
    bitcoin: BitcoinClient,
    comms: P2pHandler,
    key_chain: KeyChain,
    programs: HashMap<Uuid, Program>,
    _storage: Rc<Storage>,
    orchestrator: OrchestratorType,
    api_messages: Vec<BitVMXApiMessages>,
}

impl BitVMX {
    pub fn new(config: Config) -> Result<Self, BitVMXError> {
        let bitcoin = Self::new_bitcoin_client(&config)?;
        let keys = KeyChain::new(&config)?;
        let communications_key = keys.communications_key();
        let comms = P2pHandler::new::<LocalAllowList>(
            config.p2p_address().to_string(),
            communications_key,
        )?;

        let storage = Rc::new(Storage::new_with_path(&PathBuf::from(&config.storage.db))?);
        let orchestrator = Orchestrator::new_with_paths(
            &config.bitcoin,
            storage.clone(),
            keys.get_key_manager(),
            config.monitor.checkpoint_height,
            config.monitor.confirmation_threshold,
            config.bitcoin.network,
        )?;

        Ok(Self {
            config,
            bitcoin,
            comms,
            key_chain: keys,
            programs: HashMap::new(),
            _storage: storage,
            orchestrator,
            api_messages: vec![],
        })
    }

    pub fn add_funds(&mut self) -> Result<(Txid, u32, PublicKey), BitVMXError> {
        let one_btc = 100_000_000;
        let funding_key = self.key_chain.derive_keypair()?;
        let funding_address = self.bitcoin.get_new_address(funding_key);

        let (tx, vout) = self
            .bitcoin
            .fund_address(&funding_address, Amount::from_sat(one_btc))?;
        Ok((tx.compute_txid(), vout, funding_key))
    }

    pub fn setup_program(
        &mut self,
        id: &Uuid,
        role: ParticipantRole,
        outpoint: OutPoint,
        pre_kickoff: &PublicKey,
        peer_address: &P2PAddress,
    ) -> Result<ParticipantKeys, BitVMXError> {
        // Generate my keys.
        let keys = self.generate_keys(pre_kickoff, &role)?;

        // Create a participant that represents me with the specified role (Prover or Verifier).
        let me = Participant::new(
            //&self.comms.address(),
            &P2PAddress::new(&self.comms.get_address(), self.comms.get_peer_id()),
            Some(keys.clone()),
        );

        // Create a participant that represents the counterparty with the opposite role.
        let other = Participant::new(peer_address, None);

        // Rename the variables to the correct roles
        let (prover, verifier) = match role.clone() {
            ParticipantRole::Prover => (me, other.clone()),
            ParticipantRole::Verifier => (other.clone(), me),
        };

        // Create a program with the funding information, and the dispute resolution search parameters.
        let program = Program::new(
            &self.config,
            *id,
            role.clone(),
            prover,
            verifier,
            self.funding(outpoint),
        )?;

        //TODO: remove
        // if role == ParticipantRole::Prover {
        //     program.tick(&mut self.comms);
        // }

        // Save the program and return the keys to be shared
        self.save_program(program);

        Ok(keys)
    }

    // After contaction  the counterparty to setup the same program, exchange public keys to allow us (and the counterparty)
    // generate the program aggregated signatures.
    pub fn setup_counterparty_keys(
        &mut self,
        id: &Uuid,
        keys: ParticipantKeys,
    ) -> Result<(), BitVMXError> {
        // 1. Send keys and program data (id and config) to counterparty
        // 2. Receive keys from counterparty

        //TODO: Save after modification
        self.program_mut(id)?.setup_counterparty_keys(keys)?;

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

    /*fn _aggregate_keys(&mut self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let program = self.program(program_id)?.clone();

        // Generate the program aggregated keys.
        // self.aggregate_keys(&prover, &verifier)?;

        self.save_program(program.clone());
        Ok(())
    }

    fn _exchange_nonces(&mut self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let program = self.program_mut(program_id)?;

        // Contacts the counterparty to exchange nonces.
        // self.send_nonces(&prover, &verifier)?;

        let program_clone = program.clone();
        self.save_program(program_clone);
        Ok(())
    }
    */

    pub fn partial_sign(&mut self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let mut program = self.program(program_id)?.clone();

        // Generate the program partial signatures.

        self.sign_program(&mut program)?;
        self.save_program(program);
        Ok(())
    }

    /*
    fn _exchange_partial_signatures(&mut self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let _program = self.program_mut(program_id)?;

        // Contacts the counterparty to exchange signatures.
        // self.send_signatures(&prover, &verifier)?;

        Ok(())
    }

    fn _aggregate_partial_signatures(&self, _program_id: &Uuid) -> Result<(), BitVMXError> {
        // Generate the program aggregated signatures.
        // self.aggregate_signatures(&prover, &verifier)?;

        Ok(())
    }*/

    /// Sends the pre-kickoff transaction to the Bitcoin network, the program is now ready for the prover to
    /// claim its funds using the kickoff transaction.
    pub fn deploy_program(&mut self, program_id: &Uuid) -> Result<bool, BitVMXError> {
        let transaction = {
            let program = self.program_mut(program_id)?;
            program.prekickoff_transaction()?
        };

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
        let program = self.program_mut(program_id)?;

        if deployed {
            program.deploy();
        }

        info!("Program deployed: {}", program_id);

        Ok(program.is_ready())*/
        Ok(true)
    }

    pub fn mine_blocks(&self, blocks: u64) -> Result<(), BitVMXError> {
        self.bitcoin.mine(blocks)?;
        Ok(())
    }

    /// Executes the program offchain using the BitVMX CPU to generate the program trace, ending state and
    /// ending step number.
    pub fn run_program(&mut self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let program = self.program_mut(program_id)?;
        if !program.is_ready() {
            return Err(BitVMXError::ProgramNotReady(*program_id));
        }

        // Run program on the CPU and store the execution result (end step, end state and trace) in the program instance
        Ok(())
    }

    /// Sends the kickoff transaction to the Bitcoin network, the program is now ready for the verifier to
    /// challenge its execution.
    pub fn claim_program(&mut self, program_id: &Uuid) -> Result<bool, BitVMXError> {
        let transaction = {
            let program = self.program_mut(program_id)?;
            program.kickoff_transaction()?
        };

        let claimed = self.wait_claim(&transaction)?;
        let program = self.program_mut(program_id)?;

        if claimed {
            program.claim();
        }

        info!("Program claimed: {}", program_id);

        Ok(program.is_claimed())
    }

    pub fn program(&self, program_id: &Uuid) -> Result<&Program, BitVMXError> {
        self.programs
            .get(program_id)
            .ok_or(BitVMXError::ProgramNotFound(*program_id))
    }

    pub fn address(&self) -> String {
        self.comms.get_address()
    }

    pub fn peer_id(&self) -> String {
        self.comms.get_peer_id().to_string()
    }

    fn program_mut(&mut self, program_id: &Uuid) -> Result<&mut Program, BitVMXError> {
        //TODO: Serialize program to db
        self.programs
            .get_mut(program_id)
            .ok_or(BitVMXError::ProgramNotFound(*program_id))
    }

    fn save_program(&mut self, program: Program) -> Uuid {
        //TODO: Serialize program to db
        let id = program.id();
        self.programs.insert(id, program);
        id
    }

    fn new_bitcoin_client(config: &Config) -> Result<BitcoinClient, BitVMXError> {
        let bitcoin = BitcoinClient::new(
            config.bitcoin.network,
            &config.bitcoin,
            &config.bitcoin.wallet,
        )?;
        Ok(bitcoin)
    }

    fn generate_keys(
        &mut self,
        pre_kickoff: &PublicKey,
        _role: &ParticipantRole,
    ) -> Result<ParticipantKeys, BitVMXError> {
        //TODO: define which keys are generated for each role
        let message_size = 2;
        let one_time_keys_count = 10;

        let protocol = self.key_chain.derive_keypair()?;
        let speedup = self.key_chain.derive_keypair()?;
        let timelock = self.key_chain.derive_keypair()?;
        let internal = self.key_chain.unspendable_key()?;
        let program_ending_state = self.key_chain.derive_winternitz_hash160(message_size)?;
        let program_ending_step_number = self.key_chain.derive_winternitz_hash160(message_size)?;
        let dispute_resolution = self
            .key_chain
            .derive_winternitz_hash160_keys(message_size, one_time_keys_count)?;

        let keys = ParticipantKeys::new(
            *pre_kickoff,
            internal,
            protocol,
            speedup,
            timelock,
            program_ending_state,
            program_ending_step_number,
            dispute_resolution,
        );

        Ok(keys)
    }

    fn funding(&self, funding_outpoint: OutPoint) -> Funding {
        Funding::new(
            funding_outpoint.txid,
            funding_outpoint.vout,
            100_000_000,
            2450000,
            95000000,
            2450000,
        )
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

    fn sign_program(&mut self, program: &mut Program) -> Result<(), BitVMXError> {
        self.key_chain.sign_program(program)?;

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
        deployment_transaction: &Transaction,
    ) -> Result<bool, BitVMXError> {
        // 1. Wait for the prekickoff transaction to be confirmed
        // 2. Return true if the transaction is confirmed, false otherwise

        let txid = self
            .bitcoin
            .send_transaction(deployment_transaction.clone())?;
        while self.bitcoin.get_transaction(&txid)?.is_none() {}

        Ok(true)
    }

    fn wait_claim(&mut self, claim_transaction: &Transaction) -> Result<bool, BitVMXError> {
        // 1. Wait for the kickoff transaction to be confirmed
        // 2. Return true if the transaction is confirmed, false otherwise

        let mut txid = self.bitcoin.send_transaction(claim_transaction.clone())?;
        while self.bitcoin.get_transaction(&txid)?.is_none() {
            txid = self.bitcoin.send_transaction(claim_transaction.clone())?;
        }

        Ok(true)
    }

    pub fn process_p2p_messages(&mut self) -> bool {
        let message = self.comms.check_receive();
        let _priority = self.comms.check_priority(); //TODO: handle priority

        if message.is_none() {
            return false;
        }

        let message = message.unwrap();
        match message {
            ReceiveHandlerChannel::Msg(peer_id, msg) => {
                let (_version, msg_type, program_id, msg) = deserialize_msg(msg).unwrap(); //TODO: handle error

                //Process the message
                match msg_type {
                    P2PMessageType::Key => {
                        // Verify keys TODO: else restart fsm?
                        info!("Received key {:?} from {:?}", msg, peer_id);
                    }
                    P2PMessageType::Nonce => {
                        // Verify nonces TODO: else restart fsm?
                        info!("Received nonce {:?} from {:?}", msg, peer_id);
                    }
                    P2PMessageType::Signature => {
                        // Verify signatures TODO: else restart fsm?
                        info!("Received signature {:?} from {:?}", msg, peer_id);
                    }
                }
                let program = self.programs.get_mut(&program_id); // Borrow the program

                if let Some(program) = program {
                    program.tick(&mut self.comms).unwrap();
                } else {
                    //TODO: handle error
                }
            }
            ReceiveHandlerChannel::Error(e) => {
                info!("Error receiving message {}", e);
            } //TODO: handle error
        }

        false
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

            if let Some(p) = self.programs.get_mut(&program_id) {
                //TODO: Chekc that the transaction
                p.deploy();
            }
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
        let api_messages = self.api_messages.clone();
        self.api_messages.clear();
        for message in api_messages {
            match message {
                BitVMXApiMessages::SetupProgram(id, role, peer_address) => {
                    let (txid, vout, key) = self.add_funds()?;
                    let _prover_pub_keys = self.setup_program(
                        &id,
                        role,
                        OutPoint { txid, vout },
                        &key,
                        &peer_address,
                    )?;
                }
            }
        }
        Ok(())
    }

    pub fn api_call(&mut self, message: BitVMXApiMessages) {
        self.api_messages.push(message);
    }

    pub fn tick(&mut self) -> Result<(), BitVMXError> {
        self.process_api_messages()?;
        self.process_p2p_messages();
        self.process_bitcoin_updates()?;
        Ok(())
    }

    pub fn start_sending(&mut self, program_id: Uuid) -> Result<(), BitVMXError> {
        let program = self.programs.get_mut(&program_id); // Borrow the program
        if let Some(program) = program {
            program.tick(&mut self.comms)?;
        } else {
            return Err(BitVMXError::ProgramNotFound(program_id));
        }
        Ok(())
    }
}
