use crate::{
    bitcoin::rpc::BitcoinClient,
    config::Config,
    errors::BitVMXError,
    keys::keychain::KeyChain,
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
use p2p_handler::{LocalAllowList, P2pHandler, PeerId, ReceiveHandlerChannel};
use std::{path::PathBuf, rc::Rc, str::FromStr};
use storage_backend::storage::{KeyValueStore, Storage};

use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub enum BitVMXApiMessages {
    SetupProgram(Uuid, ParticipantRole, P2PAddress),
}

#[derive(Debug)]
pub enum P2PMessageKind {
    Key,
    Nonce,
    Signature,
}

pub struct BitVMX {
    _config: Config,
    bitcoin: BitcoinClient,
    comms: P2pHandler,
    key_chain: KeyChain,
    storage: Rc<Storage>,
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
            _config: config,
            bitcoin,
            comms,
            key_chain: keys,
            storage,
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
            *id,
            role.clone(),
            prover,
            verifier,
            self.funding(outpoint),
            self.storage.clone()
        )?;

        // Only prover can start dialing
        /*if role == ParticipantRole::Prover {
            self.exchange_keys(
                id,
                *peer_address.peer_id(),
                Some(peer_address.address().to_string()),
            )?;
        }*/

        // Save the program and return the keys to be shared
        self.save_program(program)?;

        Ok(keys)
    }

    pub fn exchange_keys(
        &mut self,
        program_id: &Uuid,
        peer_id: PeerId,
        addr: Option<String>,
    ) -> Result<(), BitVMXError> {
        let program = self.load_program(program_id)?;
        let me = match program.my_role {
            ParticipantRole::Prover => program.prover(),
            ParticipantRole::Verifier => program.verifier(),
        };

        let keys = me.keys();
        let keys = match keys {
            Some(keys) => keys.get_keys(),
            None => return Err(BitVMXError::KeysNotFound(*program_id)),
        };

        match addr {
            Some(addr) => {
                self.comms
                    .dial_and_send(peer_id, addr, program_id.to_string(), keys)?;
            }
            None => {
                self.comms.send_msg(program_id.to_string(), peer_id, keys)?;
            }
        }

        //self.save_program(program.clone());
        Ok(())
    }

    fn exchange_nonces(
        &mut self,
        program_id: Uuid,
        peer_id: PeerId,
        addr: Option<String>,
    ) -> Result<(), BitVMXError> {
        //TODO: implement
        //let program = self.program_mut(program_id)?;
        match addr {
            Some(addr) => {
                self.comms.dial_and_send(
                    peer_id,
                    addr,
                    program_id.to_string(),
                    "Hello".as_bytes().to_vec(),
                )?;
            }
            None => {
                self.comms.send_msg(
                    program_id.to_string(),
                    peer_id,
                    "World".as_bytes().to_vec(),
                )?;
            }
        }

        // let program_clone = program.clone();
        // self.save_program(program_clone);
        Ok(())
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
        let mut program = self.load_program(id)?;
        program.setup_counterparty_keys(keys)?;
        self.save_program(program)?;

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
        let mut program = self.load_program(program_id)?.clone();

        // Generate the program partial signatures.

        self.sign_program(&mut program)?;
        self.save_program(program)?;
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
            let program = self.load_program(program_id)?;
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
        let mut program = self.load_program(program_id)?;

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
        let program = self.load_program(program_id)?;
        if !program.is_ready() {
            return Err(BitVMXError::ProgramNotReady(*program_id));
        }

        // Run program on the CPU and store the execution result (end step, end state and trace) in the program instance
        self.save_program(program)?;
        Ok(())
    }

    /// Sends the kickoff transaction to the Bitcoin network, the program is now ready for the verifier to
    /// challenge its execution.
    pub fn claim_program(&mut self, program_id: &Uuid) -> Result<bool, BitVMXError> {
        let transaction = {
            let program = self.load_program(program_id)?;
            let transaction = program.kickoff_transaction()?;
            self.save_program(program)?;
            transaction
        };

        let claimed = self.wait_claim(&transaction)?;
        let mut program = self.load_program(program_id)?; //mut

        if claimed {
            program.claim();
        }

        info!("Program claimed: {}", program_id);

        Ok(program.is_claimed())
    }

    pub fn address(&self) -> String {
        self.comms.get_address()
    }

    pub fn peer_id(&self) -> String {
        self.comms.get_peer_id().to_string()
    }

    pub fn load_program(&self, program_id: &Uuid) -> Result<Program, BitVMXError> {
        let program = Program::load(self.storage.clone(), program_id)?;

        Ok(program)
    }

    fn save_program(&mut self, program: Program) -> Result<Uuid, BitVMXError> {
        let id = program.id();
        let key = format!("program_{}", id);
        self.storage.set(key, program.clone(), None)?;
        Ok(id)
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

        if let Err(_) = message {
            //TODO: handle error
            return false;
        }

        let message = message.unwrap();
        // let priotity = self.comms.check_priority(); //TODO:

        match message {
            ReceiveHandlerChannel::Msg(program_id, peer_id, msg) => {
                let program_id = Uuid::from_str(&program_id).unwrap(); //TODO: how to propagate?

                // If program not found, create and save a new program
                if let Err(BitVMXError::ProgramNotFound(_)) = self.load_program(&program_id) {
                    // TODO: Take out funding here
                    let funding = self.add_funds().unwrap(); //TODO: how to propagate?
                    let funds = funding.0.to_string() + ":" + &funding.1.to_string();
                    let prekickoff = funding.2;

                    //TODO: dont have the others address. Is it necessary? Using my own address as placeholder
                    let peer_address = &P2PAddress::new(&self.comms.get_address(), peer_id);

                    self.setup_program(
                        &program_id,               // TODO: use predefined uuid
                        ParticipantRole::Verifier, // If program was not found, I must be the verifier!
                        OutPoint::from_str(&funds).unwrap(),
                        &prekickoff,
                        peer_address,
                    )
                    .unwrap(); //TODO: how to propagate?
                }

                //process the message
                self.process_message(program_id, peer_id, msg).unwrap(); //TODO: how to propagate?
            }
            ReceiveHandlerChannel::Error(_) => {}
        }

        false
    }

    fn process_message(
        &mut self,
        program_id: Uuid,
        peer_id: PeerId,
        msg: Vec<u8>,
    ) -> Result<(), BitVMXError> {
        let utf_msg = match String::from_utf8(msg.clone()) {
            Ok(valid_string) => valid_string,
            Err(_) => "long message".to_string(),
        };
        info!("Processing message: {:?}", utf_msg);

        match self.identify_message(program_id, msg)? {
            P2PMessageKind::Key => {
                let mut program = self.load_program(&program_id)?;
                program.exchange_keys();
                if program.my_role == ParticipantRole::Verifier {
                    // Verifier
                    self.exchange_keys(&program_id, peer_id, None)?;
                } else {
                    // Prover
                    program.send_nonces();
                    let addr = program.verifier().address().address().to_string();
                    self.exchange_nonces(program_id, peer_id, Some(addr))?;
                }

                self.save_program(program)?;
            }
            P2PMessageKind::Nonce => {
                let mut program = self.load_program(&program_id)?;
                program.exchange_nonces();
                if program.my_role == ParticipantRole::Verifier {
                    // Verifier
                    self.exchange_nonces(program_id, peer_id, None)?;
                } else {
                    // Prover
                }

                self.save_program(program)?;
            }
            P2PMessageKind::Signature => {} //TODO: implement
        }

        Ok(())
    }

    fn identify_message(
        &self,
        program_id: Uuid,
        msg: Vec<u8>,
    ) -> Result<P2PMessageKind, BitVMXError> {
        //TODO: re-do function
        let program = self.load_program(&program_id)?;

        let me = match program.my_role {
            ParticipantRole::Prover => program.prover(),
            ParticipantRole::Verifier => program.verifier(),
        };
        // }; //TODO: Keys should be saved on the other participant

        // Check keys
        let keys = me.keys();
        let keys = match keys {
            Some(keys) => keys,
            None => return Err(BitVMXError::KeysNotFound(program_id)),
        };
        if keys.check_if_keys(msg) == true {
            info!("Received keys!");
            return Ok(P2PMessageKind::Key);
        // TODO: Check nonces
        } else {
            info!("Received nonces!");
            return Ok(P2PMessageKind::Nonce);
        }
        // TODO: Check sig
        // Ok(P2PMessageKind::Signature)
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

            let mut p = self.load_program(&program_id)?;
            //TODO: Check that the transaction
            p.deploy();
            self.save_program(p)?;
            
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
}
