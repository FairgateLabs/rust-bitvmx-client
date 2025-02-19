use crate::{
    bitcoin::rpc::BitcoinClient,
    config::Config,
    errors::BitVMXError,
    helper::{bytes_to_nonces, bytes_to_participant_keys, bytes_to_signatures},
    keys::keychain::KeyChain,
    p2p::p2p_parser::{deserialize_msg, P2PMessageType},
    program::{
        dispute::{Funding, SearchParams},
        participant::{P2PAddress, ParticipantData, ParticipantKeys, ParticipantRole},
        program::Program,
        witness,
    },
};
use bitcoin::PublicKey;
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use bitvmx_broker::{
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
use storage_backend::storage::Storage;

use tracing::info;
use uuid::Uuid;

//TODO: This should be moved to a common place that could be used to share the messages api
#[derive(Clone, Serialize, Deserialize)]
pub enum BitVMXApiMessages {
    SetupProgram(Uuid, ParticipantRole, P2PAddress),
}

pub struct BitVMX {
    _config: Config,
    bitcoin: BitcoinClient,
    comms: P2pHandler,
    key_chain: KeyChain,
    storage: Rc<Storage>,
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
        let bitcoin = Self::new_bitcoin_client(&config)?;
        let storage = Rc::new(Storage::new_with_path(&PathBuf::from(&config.storage.db))?);
        let keys = KeyChain::new(&config, storage.clone())?;
        let communications_key = keys.communications_key();
        let comms = P2pHandler::new::<LocalAllowList>(
            config.p2p_address().to_string(),
            communications_key,
        )?;

        let orchestrator = Orchestrator::new_with_paths(
            &config.bitcoin,
            storage.clone(),
            keys.get_key_manager(),
            config.monitor.checkpoint_height,
            config.monitor.confirmation_threshold,
            config.bitcoin.network,
        )?;

        //TOOD: This could be moved to a simplified helper inside brokerstorage new
        //Also the broker could be run independently if needed
        let broker_backend = Storage::new_with_path(&PathBuf::from(&config.broker_storage))?;
        let broker_storage = Arc::new(Mutex::new(
            bitvmx_broker::broker_storage::BrokerStorage::new(Arc::new(Mutex::new(broker_backend))),
        ));
        let broker_config = BrokerConfig::new(config.broker_port, None);
        let broker = BrokerSync::new(&broker_config, broker_storage);

        //TODO: A channel that talks directly with the broker without going through localhost loopback could be implemented
        let broker_channel = DualChannel::new(&broker_config, 1);

        Ok(Self {
            _config: config,
            bitcoin,
            comms,
            key_chain: keys,
            storage,
            orchestrator,
            broker,
            broker_channel,
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
        my_role: ParticipantRole,
        outpoint: OutPoint,
        pre_kickoff: &PublicKey,
        peer_address: &P2PAddress,
    ) -> Result<ParticipantKeys, BitVMXError> {
        // Generate my keys.
        let keys = self.generate_keys(pre_kickoff, &my_role)?;

        // Create a participant that represents me with the specified role (Prover or Verifier).
        let me = ParticipantData::new(
            //&self.comms.address(),
            &P2PAddress::new(&self.comms.get_address(), self.comms.get_peer_id()),
            Some(keys.clone()),
        );

        // Create a participant that represents the counterparty with the opposite role.
        let other = ParticipantData::new(peer_address, None);

        // Rename the variables to the correct roles
        let (prover, verifier) = match my_role {
            ParticipantRole::Prover => (me, other.clone()),
            ParticipantRole::Verifier => (other.clone(), me),
        };

        // Create a program with the funding information, and the dispute resolution search parameters.
        Program::new(
            *id,
            my_role,
            prover,
            verifier,
            self.funding(outpoint),
            self.storage.clone(),
        )?;

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
        let mut program = self.load_program(id)?;
        program.setup_counterparty_keys(keys)?;

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
        let program = self.load_program(program_id)?.clone();

        // Generate the program partial signatures.

        self.sign_program(&program)?;
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
        Ok(())
    }

    /// Sends the kickoff transaction to the Bitcoin network, the program is now ready for the verifier to
    /// challenge its execution.
    pub fn claim_program(&mut self, program_id: &Uuid) -> Result<bool, BitVMXError> {
        let program = self.load_program(program_id)?;

        let transaction = program.kickoff_transaction()?;
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
        let program_input = self.key_chain.derive_winternitz_hash160(message_size)?;
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
            program_input,
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

    fn sign_program(&mut self, program: &Program) -> Result<(), BitVMXError> {
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

    pub fn process_p2p_messages(&mut self) -> Result<(), BitVMXError> {
        let message = self.comms.check_receive();

        if message.is_none() {
            return Ok(());
        }

        let message = message.unwrap();

        // let _priority = self.comms.check_priority(); //TODO: handle priority

        match message {
            ReceiveHandlerChannel::Msg(_peer_id, msg) => {
                let (_version, msg_type, program_id, data) = deserialize_msg(msg).unwrap();
                let mut program = self.load_program(&program_id).unwrap();

                match msg_type {
                    P2PMessageType::Keys => {
                        let participant_keys = bytes_to_participant_keys(data)
                            .map_err(|_| BitVMXError::InvalidMessageFormat)?;

                        program.setup_counterparty_keys(participant_keys.clone())?;
                    }
                    P2PMessageType::PublicNonces => {
                        let nonces = bytes_to_nonces(data).unwrap();
                        let participant_key =
                            program.counterparty_data.keys.as_ref().unwrap().protocol;

                        let my_pubkey = program.party_data.keys.as_ref().unwrap().protocol;

                        self.key_chain.add_nonces(
                            program_id,
                            nonces,
                            participant_key,
                            my_pubkey,
                        )?;
                    }
                    P2PMessageType::PartialSignatures => {
                        let signatures = bytes_to_signatures(data).unwrap();
                        let my_pubkey = program.counterparty_data.keys.as_ref().unwrap().protocol;

                        self.key_chain
                            .add_signatures(program_id, signatures, my_pubkey.clone())?;
                    }
                }
            }
            ReceiveHandlerChannel::Error(e) => {
                info!("Error receiving message {}", e);
            } //TODO: handle error
        }

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

            let mut p = self.load_program(&program_id)?;
            //TODO: Check that the transaction
            p.deploy();
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
            match decoded {
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

    pub fn tick(&mut self) -> Result<(), BitVMXError> {
        self.process_api_messages()?;
        self.process_p2p_messages()?;
        self.process_bitcoin_updates()?;
        Ok(())
    }

    pub fn start_sending(&mut self, program_id: Uuid) -> Result<(), BitVMXError> {
        let mut program = self.load_program(&program_id).unwrap();
        program.tick(&mut self.comms).unwrap();
        Ok(())
    }
}
