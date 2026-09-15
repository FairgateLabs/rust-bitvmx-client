use super::{BitVMX, Context, RejectedInputSource, StoreKey};
use crate::comms_allow_list;
use crate::error_handling::{classify, send_error_report, Severity};
use crate::errors::BitVMXError;
use crate::program::participant::CommsAddress;
use crate::program::program::Program;
use crate::program::protocols::protocol_handler::ProtocolHandler;
use crate::program::variables::VariableTypes;
use crate::spv_proof::get_spv_proof;
use crate::types::{
    ErrorReport, ErrorReportKind, ErrorScope, IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages,
    ProgramStatus, PROGRAM_TYPE_AGGREGATED_KEY, RSK_PEGIN_TAG,
};
use bitcoin::secp256k1::Message;
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TypesToMonitor;
use bitvmx_broker::identification::allow_list::AllowList;
use bitvmx_broker::identification::identifier::Identifier;
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::prover_messages::ProverJobType;
use key_manager::key_type::BitcoinKeyType;
use protocol_builder::graph::graph::GraphOptions;
use storage_backend::storage::KeyValueStore;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

impl BitVMX {
    fn add_new_program(&self, program_id: &Uuid) -> Result<(), BitVMXError> {
        let mut programs = self.get_programs()?;

        if programs.iter().any(|p| p.program_id == *program_id) {
            return Err(BitVMXError::ProgramAlreadyExists(*program_id));
        }

        programs.push(ProgramStatus::new(*program_id));

        self.store
            .set(StoreKey::Programs.get_key(), programs, None)?;

        Ok(())
    }

    fn setup(
        &mut self,
        from: Identifier,
        id: Uuid,
        program_type: String,
        peer_address: Vec<CommsAddress>,
        leader: u16,
    ) -> Result<(), BitVMXError> {
        if self.program_exists(&id)? {
            warn!("Program {id} already exists ");
            self.reply(
                from,
                OutgoingBitVMXApiMessages::ApiError(id, "Program already exists".to_string()),
            )?;
            return Ok(());
        }

        info!("Setting up program: {:?} type {}", id, program_type);

        Program::new(
            id,
            &program_type,
            peer_address,
            leader as usize,
            &mut self.program_context,
            self.store.clone(),
        )?;

        self.add_new_program(&id)?;
        info!(
            "Program Setup Finished {}",
            self.program_context.comms.get_pubk_hash()?,
        );

        Ok(())
    }

    fn program_exists(&self, program_id: &Uuid) -> Result<bool, BitVMXError> {
        let programs = self.get_programs()?;
        Ok(programs.iter().any(|p| p.program_id == *program_id))
    }

    /// Persist an allow-list change, reply, and only then apply it in memory.
    fn mutate_allow_list<F>(&self, id: Uuid, from: Identifier, change: F) -> Result<(), BitVMXError>
    where
        F: Fn(&mut AllowList),
    {
        let allow_list = self.program_context.comms.get_allow_list();
        comms_allow_list::mutate(&self.store, &allow_list, change, |persisted| {
            self.reply(
                from,
                OutgoingBitVMXApiMessages::AllowListUpdated(id, persisted),
            )
        })?;
        Ok(())
    }

    fn ping(&mut self, from: Identifier, uuid: Uuid) -> Result<Uuid, BitVMXError> {
        self.reply(from, OutgoingBitVMXApiMessages::Pong(uuid))?;
        Ok(uuid)
    }

    fn get_var(&mut self, from: Identifier, id: Uuid, key: &str) -> Result<(), BitVMXError> {
        info!("Getting variable {}", key);
        let value = self.program_context.globals.get_var(&id, key)?;

        let response = match value {
            Some(var) => OutgoingBitVMXApiMessages::Variable(id, key.to_string(), var),
            None => OutgoingBitVMXApiMessages::NotFound(id, key.to_string()),
        };

        self.reply(from, response)?;
        Ok(())
    }

    fn get_witness(&mut self, from: Identifier, id: Uuid, key: &str) -> Result<(), BitVMXError> {
        info!("Getting witness {}", key);
        let value = self.program_context.witness.get_witness(&id, key)?;

        // Create response based on whether we found a value
        let response = match value {
            Some(witness) => OutgoingBitVMXApiMessages::Witness(id, key.to_string(), witness),
            None => OutgoingBitVMXApiMessages::NotFound(id, key.to_string()),
        };

        self.reply(from, response)?;
        Ok(())
    }

    fn setup_key(
        &mut self,
        from: Identifier,
        id: Uuid,
        participants: Vec<CommsAddress>,
        participants_keys: Option<Vec<PublicKey>>,
        leader_idx: u16,
    ) -> Result<(), BitVMXError> {
        match self.setup_key_inner(id, participants, participants_keys, leader_idx) {
            Err(e) => Err(e),
            Ok(Some(msg)) => {
                self.reply(from, msg)?;
                Ok(())
            }
            Ok(None) => Ok(()),
        }
    }

    fn setup_key_inner(
        &mut self,
        id: Uuid,
        participants: Vec<CommsAddress>,
        participants_keys: Option<Vec<PublicKey>>,
        leader_idx: u16,
    ) -> Result<Option<OutgoingBitVMXApiMessages>, BitVMXError> {
        info!("Setting up key for program: {:?}", id);

        // Check if program already exists BEFORE storing any data
        if self.program_exists(&id)? {
            return Ok(Some(OutgoingBitVMXApiMessages::ApiError(
                id,
                "Program already exists".to_string(),
            )));
        }

        // Check if participants vector is empty or leader_idx is out of bounds
        if participants.is_empty() {
            return Ok(Some(OutgoingBitVMXApiMessages::ApiError(
                id,
                "Participants list cannot be empty".to_string(),
            )));
        }

        if leader_idx as usize >= participants.len() {
            return Ok(Some(OutgoingBitVMXApiMessages::ApiError(
                id,
                "Leader index is out of bounds".to_string(),
            )));
        }

        let optional_keys = serde_json::to_string(&participants_keys)?;

        self.program_context.globals.set_var(
            &id,
            "optional_keys",
            VariableTypes::String(optional_keys),
        )?;

        // Use Program with AggregatedKeyProtocol for key aggregation
        Program::new(
            id,
            PROGRAM_TYPE_AGGREGATED_KEY,
            participants,
            leader_idx as usize,
            &mut self.program_context,
            self.store.clone(),
        )?;

        // Add the program to the programs list
        self.add_new_program(&id)?;

        info!("Key setup finished for program: {:?}", id);
        Ok(None)
    }

    fn sign_message(
        &mut self,
        from: Identifier,
        id: Uuid,
        payload: Vec<u8>,
        public_key: PublicKey,
    ) -> Result<(), BitVMXError> {
        let response = (|| -> Result<OutgoingBitVMXApiMessages, String> {
            let message = Message::from_digest_slice(&payload).map_err(|error| {
                format!(
                    "Failed to sign message: invalid payload; expected a 32-byte digest: {error}"
                )
            })?;

            let signature = self
                .program_context
                .key_manager
                .sign_ecdsa_recoverable_message(&message, &public_key)
                .map_err(|error| {
                    format!("Failed to sign message with public key {public_key}: {error}")
                })?;

            let (recovery_id, compact) = signature.serialize_compact();
            let (r_bytes, s_bytes) = compact.split_at(32);
            let signature_r = r_bytes
                .try_into()
                .map_err(|error| format!("Failed to serialize signature R value: {error}"))?;
            let signature_s = s_bytes
                .try_into()
                .map_err(|error| format!("Failed to serialize signature S value: {error}"))?;

            Ok(OutgoingBitVMXApiMessages::SignedMessage(
                id,
                signature_r,
                signature_s,
                recovery_id.to_i32() as u8,
            ))
        })()
        .unwrap_or_else(|message| {
            error!("{message}");
            OutgoingBitVMXApiMessages::ApiError(id, message)
        });

        self.reply(from, response)?;
        Ok(())
    }

    fn get_aggregated_pubkey(&mut self, from: Identifier, id: Uuid) -> Result<(), BitVMXError> {
        info!("Getting aggregated pubkey for program: {:?}", id);

        // Read from globals (protocol-based approach via AggregatedKeyProtocol)
        let response = if let Some(key_var) = self
            .program_context
            .globals
            .get_var(&id, "final_aggregated_key")?
        {
            match key_var.pubkey() {
                Ok(aggregated_pubkey) => {
                    info!("Found aggregated pubkey in globals for program: {:?}", id);
                    OutgoingBitVMXApiMessages::AggregatedPubkey(id, aggregated_pubkey)
                }
                Err(e) => {
                    warn!("Failed to read aggregated key from globals: {}", e);
                    OutgoingBitVMXApiMessages::AggregatedPubkeyNotReady(id)
                }
            }
        } else {
            OutgoingBitVMXApiMessages::AggregatedPubkeyNotReady(id)
        };

        self.reply(from, response)?;

        Ok(())
    }

    fn generate_zkp(
        &mut self,
        from: Identifier,
        id: Uuid,
        input: Vec<u8>,
        elf_file_path: String,
    ) -> Result<(), BitVMXError> {
        info!("Generating ZKP for input: {:?}", input);

        // Store the 'from' parameter
        self.store
            .set(StoreKey::ZKPFrom(id).get_key(), from, None)?;

        let msg = serde_json::to_string(&DispatcherJob {
            job_id: id.to_string(),
            job_type: ProverJobType::Prove(input, elf_file_path, format!("./zkp-jobs/{}", id)),
        })?;

        info!("Sending dispatcher job message: {}", msg);
        self.program_context
            .broker_channel
            .send_service(&self.config.components.prover, msg)?;

        Ok(())
    }

    fn get_zkp_execution_result(&mut self, from: Identifier, id: Uuid) -> Result<(), BitVMXError> {
        // Check if the proof is ready
        info!("Checking if {} ZKP job is ready", id);
        let status_key = StoreKey::ZKPStatus(id).get_key();
        let status: Option<String> = self.store.get(&status_key, None)?;

        let response = match status {
            Some(status_str) => {
                if status_str == "OK" {
                    info!("Getting ZKP execution result for job: {}", id);
                    let seal: Vec<u8> =
                        // Retrieve the ZKP proof (seal) from the store
                        // if it's not available, return an error because the ZKP data is inconsistent
                        // as the proof should have been generated successfully if the status is "OK"
                        match self.store.get(&StoreKey::ZKPProof(id).get_key(), None)? {
                            Some(seal) => seal,
                            None => return Err(BitVMXError::InconsistentZKPData(id)),
                        };

                    let journal: Vec<u8> =
                        match self.store.get(&StoreKey::ZKPJournal(id).get_key(), None)? {
                            Some(journal) => journal,
                            None => {
                                return Err(BitVMXError::InconsistentZKPData(id));
                            }
                        };
                    OutgoingBitVMXApiMessages::ZKPResult(id, seal, journal)
                } else {
                    OutgoingBitVMXApiMessages::ProofGenerationError(id, status_str)
                }
            }
            None => OutgoingBitVMXApiMessages::ProofNotReady(id),
        };

        self.reply(from, response)?;

        Ok(())
    }

    fn subscribe_to_tx(
        &mut self,
        from: Identifier,
        id: Uuid,
        txid: Txid,
        confirmation_threshold: Option<u32>,
    ) -> Result<(), BitVMXError> {
        info!(
            "Subscribing to transaction: {:?} from: {} id: {}",
            txid, from, id
        );
        self.program_context
            .bitcoin_coordinator
            .monitor(TypesToMonitor::Transactions(
                vec![txid],
                Context::RequestId(id, from).to_string()?,
                confirmation_threshold,
            ))?;

        Ok(())
    }

    fn subscribe_to_spending_utxo(
        &mut self,
        from: Identifier,
        id: Uuid,
        txid: Txid,
        vout: u32,
        confirmation_threshold: Option<u32>,
    ) -> Result<(), BitVMXError> {
        info!(
            "Subscribing to spending of UTXO: {:?}:{} from: {} id: {}",
            txid, vout, from, id
        );
        self.program_context.bitcoin_coordinator.monitor(
            TypesToMonitor::SpendingUTXOTransaction(
                txid,
                vout,
                Context::RequestId(id, from).to_string()?,
                confirmation_threshold,
            ),
        )?;

        Ok(())
    }

    fn subscribe_to_output_pattern(
        &mut self,
        filter: bitcoin_coordinator::OutputPatternFilter,
        confirmation_threshold: Option<u32>,
    ) -> Result<(), BitVMXError> {
        self.program_context
            .bitcoin_coordinator
            .monitor(TypesToMonitor::OutputPattern(
                filter,
                confirmation_threshold,
            ))?;
        Ok(())
    }

    fn get_transaction(
        &mut self,
        from: Identifier,
        id: Uuid,
        txid: Txid,
    ) -> Result<(), BitVMXError> {
        let response = match self
            .program_context
            .bitcoin_coordinator
            .get_transaction(txid)
        {
            Ok(tx_status) => OutgoingBitVMXApiMessages::Transaction(id, tx_status, None),
            Err(e) => {
                info!("Transaction not found: {:?}. Error: {}", txid, e);
                OutgoingBitVMXApiMessages::NotFound(id, txid.to_string())
            }
        };

        self.reply(from, response)?;
        Ok(())
    }

    fn dispatch_transaction(
        &mut self,
        from: Identifier,
        id: Uuid,
        tx: Transaction,
        confirmation_threshold: Option<u32>,
        stuck_in_mempool_blocks: Option<u32>,
    ) -> Result<(), BitVMXError> {
        info!("Dispatching transaction: {:?} for instance: {:?}", tx, id);

        self.program_context
            .bitcoin_coordinator
            .dispatch_without_speedup(
                tx,
                Context::RequestId(id, from).to_string()?,
                None,
                confirmation_threshold,
                stuck_in_mempool_blocks,
            )?;

        Ok(())
    }

    fn load_program_or_reply(
        &self,
        from: &Identifier,
        id: Uuid,
    ) -> Result<Option<Program>, BitVMXError> {
        let program = self.load_program(&id)?;
        if program.is_none() {
            warn!("Program {} not found", id);
            self.reply(
                from.clone(),
                OutgoingBitVMXApiMessages::NotFound(id, format!("Program not found: {id}")),
            )?;
        }
        Ok(program)
    }

    fn dispatch_transaction_name(
        &mut self,
        from: Identifier,
        id: Uuid,
        name: &str,
    ) -> Result<(), BitVMXError> {
        let Some(mut program) = self.load_program_or_reply(&from, id)? else {
            return Ok(());
        };
        program.dispatch_transaction_name(name, &mut self.program_context)?;
        Ok(())
    }

    fn get_spv_proof(&mut self, from: Identifier, txid: Txid) -> Result<(), BitVMXError> {
        let tx_info = self
            .program_context
            .bitcoin_coordinator
            .get_transaction(txid);

        match tx_info {
            Ok(utx) => match utx.block_info {
                Some(block_info) => {
                    let proof = get_spv_proof(txid, block_info)?;
                    self.reply(from, OutgoingBitVMXApiMessages::SPVProof(txid, Some(proof)))?;
                }
                None => {
                    warn!("Missing block info for txid {}", txid);
                    self.reply(from, OutgoingBitVMXApiMessages::SPVProof(txid, None))?;
                }
            },
            Err(e) => {
                warn!(
                    "Failed to retrieve transaction info for txid {}: {:?}",
                    txid, e
                );
                self.reply(from, OutgoingBitVMXApiMessages::SPVProof(txid, None))?;
            }
        }

        Ok(())
    }

    fn api_request_id(message: &IncomingBitVMXApiMessages) -> Option<Uuid> {
        use IncomingBitVMXApiMessages::*;

        match message {
            Ping(id)
            | SetVar(id, ..)
            | SetWitness(id, ..)
            | GetVar(id, ..)
            | GetWitness(id, ..)
            | GetCommInfo(id)
            | GetTransaction(id, ..)
            | GetTransactionInfoByName(id, ..)
            | GetHashedMessage(id, ..)
            | Setup(id, ..)
            | SubscribeToTransaction(id, ..)
            | SubscribeToSpendingUTXO(id, ..)
            | DispatchTransaction(id, ..)
            | DispatchTransactionName(id, ..)
            | SetupKey(id, ..)
            | GetAggregatedPubkey(id)
            | GetKeyPair(id)
            | GetPubKey(id, ..)
            | GetEvenPubKey(id)
            | SignMessage(id, ..)
            | GenerateZKP(id, ..)
            | ProofReady(id)
            | GetZKPExecutionResult(id)
            | Encrypt(id, ..)
            | Decrypt(id, ..)
            | Backup(id, ..)
            | GetFundingAddress(id)
            | GetFundingBalance(id)
            | SendFunds(id, ..)
            | GetProtocolVisualization(id)
            | ListAllowList(id)
            | AddToAllowList(id, ..)
            | RemoveFromAllowList(id, ..)
            | SetAllowAll(id, ..) => Some(*id),
            SetFundingUtxo(_)
            | SubscribeToOutputPattern(..)
            | SubscribeToRskPegin(..)
            | GetSPVProof(_)
            | Shutdown() => None,
            #[cfg(feature = "testpanic")]
            Test(_) => None,
        }
    }

    pub(super) fn handle_api_message(
        &mut self,
        msg: String,
        from: Identifier,
    ) -> Result<(), BitVMXError> {
        let Some(decoded) = Self::accept_decoded_input(
            &self.store,
            RejectedInputSource::Api,
            &from,
            &msg,
            serde_json::from_str::<IncomingBitVMXApiMessages>(&msg),
        )?
        else {
            return Ok(());
        };
        debug!("< {:?}", decoded);

        let request_id = Self::api_request_id(&decoded);
        let reply_to = from.clone();
        let result = (|| -> Result<(), BitVMXError> {
            match decoded {
                IncomingBitVMXApiMessages::GetHashedMessage(id, name, vout, leaf) => {
                    let Some(mut program) = self.load_program_or_reply(&from, id)? else {
                        return Ok(());
                    };
                    let hashed = program.protocol.get_hashed_message(&name, vout, leaf)?;
                    self.reply(
                        from,
                        OutgoingBitVMXApiMessages::HashedMessage(id, name, vout, leaf, hashed),
                    )?;
                }
                IncomingBitVMXApiMessages::GetCommInfo(uuid) => {
                    let comm_info = OutgoingBitVMXApiMessages::CommInfo(
                        uuid,
                        CommsAddress {
                            address: self.program_context.comms.get_address(),
                            pubkey_hash: self.program_context.comms.get_pubk_hash()?,
                        },
                    );
                    self.reply(from, comm_info)?;
                }
                IncomingBitVMXApiMessages::Ping(uuid) => {
                    self.ping(from, uuid)?;
                }
                IncomingBitVMXApiMessages::SetVar(uuid, key, value) => {
                    debug!("Setting variable {}: {:?}", key, value);
                    self.program_context.globals.set_var(&uuid, &key, value)?;
                }
                IncomingBitVMXApiMessages::SetWitness(uuid, key, value) => {
                    debug!("Setting witness {}: {:?}", key, value);
                    self.program_context
                        .witness
                        .set_witness(&uuid, &key, value)?;
                }
                IncomingBitVMXApiMessages::SetFundingUtxo(utxo) => {
                    info!("Setting funding utxo {:?}", utxo);
                    self.program_context.bitcoin_coordinator.add_funding(utxo)?;
                }
                IncomingBitVMXApiMessages::GetFundingAddress(id) => {
                    debug!("Getting funding address uuid: {:?}", id);
                    let address = match self.wallet.receive_address() {
                        Ok(address) => address,
                        Err(e) => {
                            error!("Error getting funding address uuid: {:?}: {:?}", id, e);
                            self.program_context.broker_channel.send_service(
                                &from,
                                serde_json::to_string(&OutgoingBitVMXApiMessages::WalletError(
                                    id,
                                    e.to_string(),
                                ))?,
                            )?;
                            return Ok(());
                        }
                    };

                    self.program_context.broker_channel.send_service(
                        &from,
                        serde_json::to_string(&OutgoingBitVMXApiMessages::FundingAddress(
                            id,
                            address.into_unchecked(),
                        ))?,
                    )?;
                }
                IncomingBitVMXApiMessages::GetFundingBalance(id) => {
                    debug!("Getting funding balance uuid: {:?}", id);
                    if !self.wallet.is_ready {
                        warn!("Wallet is not ready, to get funding balance uuid: {:?}", id);
                        self.reply(from, OutgoingBitVMXApiMessages::WalletNotReady(id))?;
                        return Ok(());
                    }
                    let balance = self.wallet.balance();
                    self.program_context.broker_channel.send_service(
                        &from,
                        serde_json::to_string(&OutgoingBitVMXApiMessages::FundingBalance(
                            id,
                            balance.trusted_spendable().to_sat(),
                        ))?,
                    )?;
                }
                IncomingBitVMXApiMessages::SendFunds(id, destination, fee_rate) => {
                    info!("Sending funds to {:?}", destination);
                    if !self.wallet.is_ready {
                        warn!("Wallet is not ready, to send funds uuid: {:?}", id);
                        self.reply(from, OutgoingBitVMXApiMessages::WalletNotReady(id))?;
                        return Ok(());
                    }
                    // Use the fee_rate parameter passed in the message
                    let tx = match self.wallet.create_tx(destination.clone(), fee_rate) {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("Failed sending funds to {:?}. Error: {:?}", destination, e);
                            self.program_context.broker_channel.send_service(
                                &from.clone(),
                                serde_json::to_string(&OutgoingBitVMXApiMessages::WalletError(
                                    id,
                                    e.to_string(),
                                ))?,
                            )?;
                            return Ok(());
                        }
                    };

                    let txid = tx.compute_txid();
                    //TODO: Is this confirmation threshold of 1 appropriate here? What about stuck_in_mempool_blocks?
                    self.dispatch_transaction(from.clone(), id, tx.clone(), Some(1), None)?;
                    self.wallet.update_with_tx(&tx)?;

                    self.program_context.broker_channel.send_service(
                        &from,
                        serde_json::to_string(&OutgoingBitVMXApiMessages::FundsSent(id, txid))?,
                    )?;
                }

                IncomingBitVMXApiMessages::GetVar(uuid, key) => {
                    self.get_var(from, uuid, &key)?;
                }
                IncomingBitVMXApiMessages::GetWitness(uuid, key) => {
                    self.get_witness(from, uuid, &key)?;
                }
                IncomingBitVMXApiMessages::GetTransaction(id, txid) => {
                    self.get_transaction(from, id, txid)?
                }
                IncomingBitVMXApiMessages::GetTransactionInfoByName(id, name) => {
                    let Some(program) = self.load_program_or_reply(&from, id)? else {
                        return Ok(());
                    };
                    let response =
                        match program.get_transaction_by_name(&name, &self.program_context) {
                            Ok(tx) => OutgoingBitVMXApiMessages::TransactionInfo(id, name, tx),
                            Err(err) => {
                                error!(
                                    "Transaction not found: {} in program {:?}. Error: {}",
                                    name, id, err
                                );
                                OutgoingBitVMXApiMessages::NotFound(
                                    id,
                                    format!("Transaction not found: {}", name),
                                )
                            }
                        };

                    self.reply(from, response)?;
                }
                IncomingBitVMXApiMessages::Setup(id, program_type, participants, leader) => {
                    self.setup(from, id, program_type, participants, leader)?
                }
                IncomingBitVMXApiMessages::SubscribeToTransaction(
                    uuid,
                    txid,
                    confirmation_threshold,
                ) => self.subscribe_to_tx(from, uuid, txid, confirmation_threshold)?,
                IncomingBitVMXApiMessages::SubscribeToSpendingUTXO(
                    uuid,
                    txid,
                    vout,
                    confirmation_threshold,
                ) => {
                    self.subscribe_to_spending_utxo(from, uuid, txid, vout, confirmation_threshold)?
                }
                IncomingBitVMXApiMessages::SubscribeToOutputPattern(
                    filter,
                    confirmation_threshold,
                ) => self.subscribe_to_output_pattern(filter, confirmation_threshold)?,
                IncomingBitVMXApiMessages::SubscribeToRskPegin(confirmation_threshold) => self
                    .subscribe_to_output_pattern(
                        bitcoin_coordinator::OutputPatternFilter {
                            output_index: 1,
                            tag: RSK_PEGIN_TAG.to_vec(),
                            max_outputs: None,
                        },
                        confirmation_threshold,
                    )?,
                IncomingBitVMXApiMessages::GetSPVProof(txid) => self.get_spv_proof(from, txid)?,

                IncomingBitVMXApiMessages::DispatchTransactionName(id, tx) => {
                    self.dispatch_transaction_name(from, id, &tx)?
                }
                IncomingBitVMXApiMessages::DispatchTransaction(
                    id,
                    tx,
                    confirmation_threshold,
                    stuck_in_mempool_blocks,
                ) => {
                    self.dispatch_transaction(
                        from,
                        id,
                        tx,
                        confirmation_threshold,
                        stuck_in_mempool_blocks,
                    )?;
                }
                IncomingBitVMXApiMessages::SetupKey(
                    id,
                    participants,
                    participants_keys,
                    leader_idx,
                ) => self.setup_key(from, id, participants, participants_keys, leader_idx)?,
                IncomingBitVMXApiMessages::GetKeyPair(id) => {
                    // Get aggregated key from globals (set by AggregatedKeyProtocol)
                    let aggregated = self
                        .program_context
                        .globals
                        .get_var(&id, "final_aggregated_key")?
                        .and_then(|v| v.pubkey().ok())
                        .ok_or(BitVMXError::KeysNotFound(id))?;
                    let pair = self
                        .program_context
                        .key_manager
                        .get_key_pair_for_too_insecure(&aggregated)?;
                    self.reply(from, OutgoingBitVMXApiMessages::KeyPair(id, pair.0, pair.1))?;
                    //RETURN PK
                    //TODO: Revisit this as it might be insecure
                }
                IncomingBitVMXApiMessages::GetPubKey(id, new) => {
                    if new {
                        let public = self
                            .program_context
                            .key_manager
                            .next_keypair(BitcoinKeyType::P2tr)?;
                        self.reply(from, OutgoingBitVMXApiMessages::PubKey(id, public))?;
                    } else {
                        // Get aggregated key from globals (set by AggregatedKeyProtocol)
                        let aggregated = self
                            .program_context
                            .globals
                            .get_var(&id, "final_aggregated_key")?
                            .and_then(|v| v.pubkey().ok())
                            .ok_or(BitVMXError::KeysNotFound(id))?;
                        let pubkey = self
                            .program_context
                            .key_manager
                            .get_my_public_key(&aggregated)?;
                        self.reply(from, OutgoingBitVMXApiMessages::PubKey(id, pubkey))?;
                    }
                }
                IncomingBitVMXApiMessages::GetEvenPubKey(id) => {
                    let public = self
                        .program_context
                        .key_manager
                        .next_keypair_adjusted(BitcoinKeyType::P2tr)?;
                    self.reply(from, OutgoingBitVMXApiMessages::PubKey(id, public))?;
                }
                IncomingBitVMXApiMessages::SignMessage(id, payload, public_key) => {
                    self.sign_message(from, id, payload, public_key)?;
                }
                IncomingBitVMXApiMessages::GetAggregatedPubkey(id) => {
                    self.get_aggregated_pubkey(from, id)?
                }
                IncomingBitVMXApiMessages::GenerateZKP(id, input, elf_file_path) => {
                    self.generate_zkp(from, id, input, elf_file_path)?
                }
                IncomingBitVMXApiMessages::ProofReady(id) => self.proof_ready(from, id)?,
                IncomingBitVMXApiMessages::GetZKPExecutionResult(id) => {
                    self.get_zkp_execution_result(from, id)?
                }
                IncomingBitVMXApiMessages::Encrypt(id, message, pub_key) => {
                    let encrypted = self
                        .program_context
                        .key_manager
                        .encrypt_rsa_message(&message, &pub_key);
                    match encrypted {
                        Ok(e) => {
                            self.reply(from, OutgoingBitVMXApiMessages::Encrypted(id, e))?;
                        }
                        Err(e) => {
                            error!("Error encrypting message: {}", e);
                            let err_str = format!("Error encrypting message: {}", e);
                            self.reply(from, OutgoingBitVMXApiMessages::NotFound(id, err_str))?;
                        }
                    };
                }
                IncomingBitVMXApiMessages::Decrypt(id, message, pub_key) => {
                    let decrypted = self
                        .program_context
                        .key_manager
                        .decrypt_rsa_message(&message, &pub_key);
                    match decrypted {
                        Ok(d) => {
                            self.reply(from, OutgoingBitVMXApiMessages::Decrypted(id, d))?;
                        }
                        Err(e) => {
                            error!("Error decrypting message: {}", e);
                            let err_str = format!("Error decrypting message: {}", e);
                            self.reply(from, OutgoingBitVMXApiMessages::NotFound(id, err_str))?;
                        }
                    };
                }
                IncomingBitVMXApiMessages::Backup(id, backup_path, dek_path, password) => {
                    let message = match self.store.backup(&backup_path, &dek_path, password) {
                        Ok(_) => OutgoingBitVMXApiMessages::BackupResult(
                            id,
                            true,
                            "Backup successful".to_string(),
                        ),
                        Err(e) => OutgoingBitVMXApiMessages::BackupResult(id, false, e.to_string()),
                    };

                    self.reply(from, message)?;
                }
                IncomingBitVMXApiMessages::GetProtocolVisualization(id) => {
                    let Some(program) = self.load_program_or_reply(&from, id)? else {
                        return Ok(());
                    };
                    let protocol_str = program
                        .protocol
                        .load_protocol()
                        .and_then(|op| op.visualize(GraphOptions::EdgeArrows));
                    let reply_msg = match protocol_str {
                        Ok(s) => OutgoingBitVMXApiMessages::ProtocolVisualization(id, s),
                        Err(e) => {
                            error!("Error visualizing protocol: {}", e);
                            let err_str = format!("Error visualizing protocol: {}", e);
                            OutgoingBitVMXApiMessages::NotFound(id, err_str)
                        }
                    };

                    self.reply(from, reply_msg)?;
                }
                IncomingBitVMXApiMessages::ListAllowList(id) => {
                    let allow_list = self.program_context.comms.get_allow_list();
                    let (entries, allow_all) = comms_allow_list::snapshot(&allow_list)?;
                    self.reply(
                        from,
                        OutgoingBitVMXApiMessages::AllowListEntries(id, entries, allow_all),
                    )?;
                }
                IncomingBitVMXApiMessages::AddToAllowList(id, pubk_hash, addr) => {
                    info!("Allowing comms peer {} from {:?}", pubk_hash, addr);
                    self.mutate_allow_list(id, from, |allow_list| {
                        allow_list.add_entry(pubk_hash.clone(), addr)
                    })?;
                }
                IncomingBitVMXApiMessages::RemoveFromAllowList(id, pubk_hash) => {
                    info!("Removing comms peer {}", pubk_hash);
                    self.mutate_allow_list(id, from, |allow_list| allow_list.remove(&pubk_hash))?;
                }
                IncomingBitVMXApiMessages::SetAllowAll(id, allow_all) => {
                    info!("Setting comms allow_all to {}", allow_all);
                    self.mutate_allow_list(id, from, |allow_list| {
                        allow_list.set_allow_all(allow_all)
                    })?;
                }
                IncomingBitVMXApiMessages::Shutdown() => {
                    info!("Shutdown message received. Initiating shutdown...");
                    self.shutdown()?;
                }
                #[cfg(feature = "testpanic")]
                IncomingBitVMXApiMessages::Test(s) => {
                    if s == "panic" {
                        panic!("test-induced panic");
                    }
                    if s == "fatal" {
                        use storage_backend::error::StorageError as KVStorageError;
                        return Err(BitVMXError::from(KVStorageError::WriteError));
                    }
                }
            }
            Ok(())
        })();

        if let Err(error) = result {
            error!(
                "Failed to handle API message from {}: {:?}",
                reply_to, error
            );

            let (kind, fatal) = match classify(&error) {
                Severity::Fatal => (ErrorReportKind::Fatal, true),
                Severity::BitcoinNodeUnreachable => (ErrorReportKind::BitcoinRpcUnavailable, false),
                Severity::Other => (ErrorReportKind::NonFatal, false),
            };
            let scope = request_id.map_or(ErrorScope::Node, ErrorScope::Request);
            send_error_report(
                &self.program_context.broker_channel,
                &reply_to,
                ErrorReport::new(scope, kind, Some(error.to_string())),
            );

            if fatal {
                return Err(error);
            }
        }

        Ok(())
    }
}
