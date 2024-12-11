use std::collections::HashMap;
use bitcoin::{Amount, OutPoint, Transaction, Txid};
use key_manager::winternitz;
use uuid::Uuid;
use crate::{bitcoin::rpc::BitcoinClient, comms::{P2PComms, P2PMessage, P2PMessageKind}, config::Config, errors::BitVMXError, keys::keychain::KeyChain, program::{dispute::{Funding, SearchParams}, participant::{P2PAddress, Participant, ParticipantKeys, ParticipantRole}, program::Program, witness}};

pub struct BitVMX {
    config: Config,
    bitcoin: BitcoinClient,
    comms: P2PComms,
    key_chain: KeyChain,
    programs: HashMap<Uuid, Program>,
}

impl BitVMX {
    pub fn new(config: &Config) -> Result<Self, BitVMXError> {
        let bitcoin = Self::new_bitcoin_client(config)?;
        let keys = KeyChain::new(&config)?;
        let communications_key = keys.communications_key();
        let comms = P2PComms::new(&config, communications_key)?;

        Ok(Self {
            config: (*config).clone(),
            bitcoin,
            comms,
            key_chain: keys,
            programs: HashMap::new(),
        })
    }

    pub fn add_funds(&mut self) -> Result<(Txid, u32), BitVMXError> {
        let one_btc = 100_000_000;
        let current_index = self.key_chain.ecdsa_index();
        let funding_key = self.key_chain.derive_keypair_with_index(current_index)?;
        let funding_address = self.bitcoin.get_new_address(funding_key);

        let (tx, vout) = self.bitcoin.fund_address(&funding_address, Amount::from_sat(one_btc))?;
        Ok((tx.compute_txid(), vout))
    }

    pub fn setup_program(&mut self, role: ParticipantRole, outpoint: OutPoint, peer_address: &P2PAddress) -> Result<Uuid, BitVMXError> {        
        self.comms.connect(peer_address)?;
        // self.comms.send_message(peer_address, "Hello".as_bytes().to_vec())?;
        // let message = self.comms.receive_message();

        // println!("Received message: {:?}", message);

        // Generate my keys.
        let keys = self.generate_keys()?;

        // Create a participant that represents me with the specified role (Prover or Verifier).
        let me = Participant::new(
            &role,
            &self.comms.address(),
            Some(keys.clone()),
        );

        // Create a participant that represents the counterparty with the opposite role.
        let other = Participant::new(
            &role.counterparty_role(),
            peer_address, 
            None,
        );

        // Rename the variables to the correct roles
        let (prover, verifier) = match me.role() {
            ParticipantRole::Prover => (me, other.clone()),
            ParticipantRole::Verifier => (other.clone(), me),
        };

        // Create a program with the funding information, and the dispute resolution search parameters.
        let program = Program::new(&self.comms.address(), &self.config, prover, verifier, self.funding(outpoint))?;
        
        // Contacts the counterparty to setup the same program, exchange public keys to allow us (and the counterparty) 
        // generate the program aggregated signatures.
        self.setup_counterparty_program(&program, other.role(), keys)?;

        // Save the program and return an unique program id.
        let id = self.save_program(program);
        Ok(id)
    }

    pub fn process_message(&mut self) -> Result<(), BitVMXError> {
        match self.comms.receive_message() {
            None => return Ok(()),
            Some(data) => {
                let message = P2PMessage::from_bytes(data);

                match message.kind() {
                    P2PMessageKind::Status => {
        
                    },
                    P2PMessageKind::Keys => {
                        
                    },
                    P2PMessageKind::Nonces => {
        
                    },
                    P2PMessageKind::Signatures => {
        
                    },
                    P2PMessageKind::Setup => {
        
                    }
                }
            }
        }

        Ok(())
    }

    fn aggregate_keys(&mut self, program_id: Uuid) -> Result<(), BitVMXError> {
        let mut program = self.program(program_id)?.clone();

        // Generate the program aggregated keys.
        // self.aggregate_keys(&prover, &verifier)?;

        self.save_program(program.clone());
        Ok(())
    }

    fn exchange_nonces(&mut self, program_id: Uuid) -> Result<(), BitVMXError> {
        let program = self.program_mut(program_id)?;

        // Contacts the counterparty to exchange nonces.
        // self.send_nonces(&prover, &verifier)?;

        let program_clone = program.clone();
        self.save_program(program_clone);
        Ok(())
    }

    fn partial_sign(&mut self, program_id: Uuid) -> Result<(), BitVMXError> {
        let mut program = self.program(program_id)?.clone();

        // Generate the program partial signatures.

        self.sign_program(&mut program)?;
        self.save_program(program);
        Ok(())
    }

    fn exchange_partial_signatures(&mut self, program_id: Uuid) -> Result<(), BitVMXError> {
        let program = self.program_mut(program_id)?;

        // Contacts the counterparty to exchange signatures.
        // self.send_signatures(&prover, &verifier)?;

        Ok(())
    }

    fn aggregate_partial_signatures(&self, program_id: Uuid) -> Result<(), BitVMXError> {
        // Generate the program aggregated signatures.
        // self.aggregate_signatures(&prover, &verifier)?;

        Ok(())
    }

    /// Sends the pre-kickoff transaction to the Bitcoin network, the program is now ready for the prover to
    /// claim its funds using the kickoff transaction.
    pub fn deploy_program(&mut self, program_id: Uuid) -> Result<bool, BitVMXError> {
        let transaction = {
            let program = self.program_mut(program_id)?;
            program.prekickoff_transaction()?
        };

        let deployed = self.wait_deployment(&transaction)?;
        let program = self.program_mut(program_id)?;

        if deployed {
            program.deploy();
        }

        Ok(program.is_ready())
    }

    /// Executes the program offchain using the BitVMX CPU to generate the program trace, ending state and 
    /// ending step number.
    pub fn run_program(&mut self, program_id: Uuid) -> Result<(), BitVMXError> {
        let program = self.program_mut(program_id)?;
        if !program.is_ready() {
            return Err(BitVMXError::ProgramNotReady(program_id));
        }

        // Run program on the CPU and store the execution result (end step, end state and trace) in the program instance
        Ok(())
    }

    /// Sends the kickoff transaction to the Bitcoin network, the program is now ready for the verifier to
    /// challenge its execution.
    pub fn claim_program(&mut self, program_id: Uuid) -> Result<bool, BitVMXError> {
        let transaction = {
            let program = self.program_mut(program_id)?;
            program.kickoff_transaction()?
        };

        let claimed = self.wait_claim(&transaction)?;
        let program = self.program_mut(program_id)?;

        if claimed {
            program.claim();
        }

        Ok(program.is_claimed())
    }

    pub fn program(&self, program_id: Uuid) -> Result<&Program, BitVMXError> {
        self.programs.get(&program_id).ok_or(BitVMXError::ProgramNotFound(program_id))
    }

    pub fn peer_id(&self) -> String {
        self.comms.peer_id_bs58()
    }

    fn program_mut(&mut self, program_id: Uuid) -> Result<&mut Program, BitVMXError> {
        self.programs.get_mut(&program_id).ok_or(BitVMXError::ProgramNotFound(program_id))
    }

    fn save_program(&mut self, program: Program) -> Uuid {
        let id = program.id();
        self.programs.insert(id, program);
        id
    }

    fn new_bitcoin_client(config: &Config) -> Result<BitcoinClient, BitVMXError> {
        let network = config.network()?;
        let url = config.bitcoin_rpc_url();
        let user = config.bitcoin_rpc_username();
        let pass = config.bitcoin_rpc_password();
        let wallet = config.bitcoin_rpc_wallet();
    
        let bitcoin = BitcoinClient::new(network, url, user, pass, wallet)?;
        Ok(bitcoin)
    }

    fn generate_keys(&mut self) -> Result<ParticipantKeys, BitVMXError> {
        let message_size = 2; 
        let one_time_keys_count = 10;

        let pre_kickoff = self.key_chain.derive_keypair()?;
        let protocol = self.key_chain.derive_keypair()?;
        let speedup = self.key_chain.derive_keypair()?;
        let timelock = self.key_chain.derive_keypair()?;
        let internal = self.key_chain.unspendable_key()?;
        let program_ending_state = self.key_chain.derive_winternitz_hash160(message_size)?;
        let program_ending_step_number = self.key_chain.derive_winternitz_hash160(message_size)?;
        let dispute_resolution = self.key_chain.derive_winternitz_hash160_keys(message_size, one_time_keys_count)?;
        
        let keys = ParticipantKeys::new(
            pre_kickoff, 
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

    fn search_params(&self) -> SearchParams {
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

    fn setup_counterparty_program(&self, program: &Program, counterparty_role: ParticipantRole, keys: ParticipantKeys) -> Result<(), BitVMXError> {
        // 1. Send keys and program data (id and config) to counterparty
        // 2. Receive keys from counterparty
        Ok(())
    }

    fn sign_program(&mut self, program: &mut Program) -> Result<(), BitVMXError> {
        self.key_chain.sign_program(program)?;

        // 1. Send signatures to counterparty
        // 2. Receive signatures from counterparty
        // 3. Verify signatures

        Ok(())
    }

    fn decode_witness_data(&self, winternitz_message_sizes: Vec<usize>, winternitz_type: winternitz::WinternitzType, witness: bitcoin::Witness) -> Result<Vec<winternitz::WinternitzSignature>, BitVMXError> {
        witness::decode_witness(winternitz_message_sizes, winternitz_type, witness)
    }

    fn wait_deployment(&mut self, deployment_transaction: &Transaction) -> Result<bool, BitVMXError> {
        // 1. Wait for the prekickoff transaction to be confirmed
        // 2. Return true if the transaction is confirmed, false otherwise

        let mut txid = self.bitcoin.send_transaction(deployment_transaction.clone())?;
        while self.bitcoin.get_transaction(&txid)?.is_none() {
        }

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
}
