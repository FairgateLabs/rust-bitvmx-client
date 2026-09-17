use super::{BitVMX, Context, RejectedInputSource, StoreKey};
use crate::comms_allow_list;
use crate::error_handling::is_fatal;
use crate::errors::BitVMXError;
use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use crate::program::participant::CommsAddress;
use crate::program::program::Program;
use crate::program::protocols::protocol_handler::ProtocolHandler;
use crate::program::variables::VariableTypes;
use crate::spv_proof::get_spv_proof;
use crate::types::{
    IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ProgramStatus, FINAL_AGGREGATED_KEY,
    PROGRAM_TYPE_AGGREGATED_KEY, RSK_PEGIN_TAG,
};
use bitcoin::secp256k1::Message;
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::{errors::BitcoinCoordinatorError, TypesToMonitor};
use bitvmx_broker::identification::allow_list::AllowList;
use bitvmx_broker::identification::identifier::Identifier;
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::prover_messages::ProverJobType;
use bitvmx_transaction_monitor::errors::MonitorError;
use bitvmx_wallet::wallet::Destination;
use key_manager::{errors::KeyManagerError, key_type::BitcoinKeyType};
use protocol_builder::{
    errors::{GraphError, ProtocolBuilderError},
    graph::graph::GraphOptions,
};
use storage_backend::storage::KeyValueStore;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

impl<BC: BitcoinCoordinatorApi> BitVMX<BC> {
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
        id: Uuid,
        program_type: String,
        peer_address: Vec<CommsAddress>,
        leader: u16,
    ) -> Result<Option<OutgoingBitVMXApiMessages>, BitVMXError> {
        if self.program_exists(&id)? {
            return Ok(Some(Self::api_error(
                id,
                "Program already exists".to_string(),
            )));
        }

        info!("Setting up program: {:?} type {}", id, program_type);

        if let Err(error) = Program::new(
            id,
            &program_type,
            peer_address,
            leader as usize,
            &mut self.program_context,
            self.store.clone(),
        ) {
            if is_fatal(&error) {
                return Err(error);
            }

            return Ok(Some(Self::api_error(
                id,
                format!("Failed to set up program: {error}"),
            )));
        }

        self.add_new_program(&id)?;
        info!(
            "Program Setup Finished {}",
            self.program_context.comms.get_pubk_hash(),
        );

        Ok(None)
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

    fn ping(uuid: Uuid) -> OutgoingBitVMXApiMessages {
        OutgoingBitVMXApiMessages::Pong(uuid)
    }

    fn get_funding_address(&mut self, id: Uuid) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        debug!("Getting funding address uuid: {:?}", id);
        let Some(wallet) = self.wallet.as_mut() else {
            return Ok(OutgoingBitVMXApiMessages::ApiError(
                id,
                "Wallet not available".to_string(),
            ));
        };

        match wallet.receive_address() {
            Ok(address) => Ok(OutgoingBitVMXApiMessages::FundingAddress(
                id,
                address.into_unchecked(),
            )),
            Err(error) => {
                error!("Error getting funding address uuid: {:?}: {:?}", id, error);
                Ok(OutgoingBitVMXApiMessages::WalletError(
                    id,
                    error.to_string(),
                ))
            }
        }
    }

    fn get_funding_balance(&self, id: Uuid) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        debug!("Getting funding balance uuid: {:?}", id);
        let Some(wallet) = self.wallet.as_ref() else {
            return Ok(OutgoingBitVMXApiMessages::ApiError(
                id,
                "Wallet not available".to_string(),
            ));
        };

        if !wallet.is_ready {
            warn!("Wallet is not ready, to get funding balance uuid: {:?}", id);
            return Ok(OutgoingBitVMXApiMessages::WalletNotReady(id));
        }

        let balance = wallet.balance();
        Ok(OutgoingBitVMXApiMessages::FundingBalance(
            id,
            balance.trusted_spendable().to_sat(),
        ))
    }

    fn send_funds(
        &mut self,
        from: Identifier,
        id: Uuid,
        destination: Destination,
        fee_rate: Option<u64>,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        info!("Sending funds to {:?}", destination);
        let transaction = {
            let Some(wallet) = self.wallet.as_mut() else {
                return Ok(OutgoingBitVMXApiMessages::ApiError(
                    id,
                    "Wallet not available".to_string(),
                ));
            };

            if !wallet.is_ready {
                warn!("Wallet is not ready, to send funds uuid: {:?}", id);
                return Ok(OutgoingBitVMXApiMessages::WalletNotReady(id));
            }

            match wallet.create_tx(destination.clone(), fee_rate) {
                Ok(transaction) => transaction,
                Err(error) => {
                    error!(
                        "Failed sending funds to {:?}. Error: {:?}",
                        destination, error
                    );
                    return Ok(OutgoingBitVMXApiMessages::WalletError(
                        id,
                        error.to_string(),
                    ));
                }
            }
        };

        let txid = transaction.compute_txid();
        // TODO: Is this confirmation threshold of 1 appropriate here? What about stuck_in_mempool_blocks?
        self.dispatch_transaction(from, id, transaction.clone(), Some(1), None)?;
        self.wallet
            .as_mut()
            .expect("wallet availability checked above")
            .update_with_tx(&transaction)?;

        Ok(OutgoingBitVMXApiMessages::FundsSent(id, txid))
    }

    fn get_var(&mut self, id: Uuid, key: &str) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        info!("Getting variable {}", key);
        let value = self.program_context.globals.get_var(&id, key)?;

        Ok(match value {
            Some(var) => OutgoingBitVMXApiMessages::Variable(id, key.to_string(), var),
            None => OutgoingBitVMXApiMessages::NotFound(id, key.to_string()),
        })
    }

    fn get_witness(
        &mut self,
        id: Uuid,
        key: &str,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        info!("Getting witness {}", key);
        let value = self.program_context.witness.get_witness(&id, key)?;

        Ok(match value {
            Some(witness) => OutgoingBitVMXApiMessages::Witness(id, key.to_string(), witness),
            None => OutgoingBitVMXApiMessages::NotFound(id, key.to_string()),
        })
    }

    fn setup_key(
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
        if let Err(error) = Program::new(
            id,
            PROGRAM_TYPE_AGGREGATED_KEY,
            participants,
            leader_idx as usize,
            &mut self.program_context,
            self.store.clone(),
        ) {
            if is_fatal(&error) {
                return Err(error);
            }

            return Ok(Some(Self::api_error(
                id,
                format!("Failed to set up program: {error}"),
            )));
        }
        // Add the program to the programs list
        self.add_new_program(&id)?;

        info!("Key setup finished for program: {:?}", id);
        Ok(None)
    }

    fn api_error(id: Uuid, message: String) -> OutgoingBitVMXApiMessages {
        error!("{message}");
        OutgoingBitVMXApiMessages::ApiError(id, message)
    }

    fn key_manager_response<T, F>(
        id: Uuid,
        result: Result<T, KeyManagerError>,
        error_context: &str,
        success: F,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError>
    where
        F: FnOnce(T) -> OutgoingBitVMXApiMessages,
    {
        match result {
            Ok(value) => Ok(success(value)),
            Err(error) if error.is_storage_error() => Err(error.into()),
            Err(error) => Ok(Self::api_error(id, format!("{error_context}: {error}"))),
        }
    }

    fn get_key_pair(&mut self, id: Uuid) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        let Some(aggregated) = self
            .program_context
            .globals
            .get_var(&id, FINAL_AGGREGATED_KEY)?
        else {
            return Ok(Self::api_error(
                id,
                format!("Aggregated key not found for id: {id}"),
            ));
        };

        let aggregated = match aggregated.pubkey() {
            Ok(public_key) => public_key,
            Err(error) => {
                return Ok(Self::api_error(
                    id,
                    format!("Failed to get public key from aggregated key: {error}"),
                ));
            }
        };

        let result = self
            .program_context
            .key_manager
            .get_key_pair_for_too_insecure(&aggregated);
        Self::key_manager_response(
            id,
            result,
            "Failed to get key pair for aggregated key",
            |pair| OutgoingBitVMXApiMessages::KeyPair(id, pair.0, pair.1),
        )
    }

    fn get_pub_key(
        &mut self,
        id: Uuid,
        new: bool,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        let response = if new {
            let result = self
                .program_context
                .key_manager
                .next_keypair(BitcoinKeyType::P2tr);
            Self::key_manager_response(id, result, "Failed to generate public key", |public| {
                OutgoingBitVMXApiMessages::PubKey(id, public)
            })?
        } else {
            let Some(aggregated) = self
                .program_context
                .globals
                .get_var(&id, FINAL_AGGREGATED_KEY)?
            else {
                return Ok(Self::api_error(
                    id,
                    format!("Aggregated key not found for id: {id}"),
                ));
            };

            let aggregated = match aggregated.pubkey() {
                Ok(public_key) => public_key,
                Err(error) => {
                    return Ok(Self::api_error(
                        id,
                        format!("Failed to get public key from aggregated key: {error}"),
                    ));
                }
            };

            let result = self
                .program_context
                .key_manager
                .get_my_public_key(&aggregated);
            Self::key_manager_response(
                id,
                result,
                "Failed to get participant public key",
                |public| OutgoingBitVMXApiMessages::PubKey(id, public),
            )?
        };

        Ok(response)
    }

    fn get_even_pub_key(&mut self, id: Uuid) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        let result = self
            .program_context
            .key_manager
            .next_keypair_adjusted(BitcoinKeyType::P2tr);
        Self::key_manager_response(
            id,
            result,
            "Failed to generate adjusted public key",
            |public| OutgoingBitVMXApiMessages::PubKey(id, public),
        )
    }

    fn sign_message(
        &mut self,
        id: Uuid,
        payload: Vec<u8>,
        public_key: PublicKey,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        let message = match Message::from_digest_slice(&payload) {
            Ok(message) => message,
            Err(error) => {
                return Ok(Self::api_error(
                    id,
                    format!(
                        "Failed to sign message: invalid payload; expected a 32-byte digest: {error}"
                    ),
                ));
            }
        };

        let result = self
            .program_context
            .key_manager
            .sign_ecdsa_recoverable_message(&message, &public_key);
        Self::key_manager_response(
            id,
            result,
            &format!("Failed to sign message with public key {public_key}"),
            |signature| {
                let (recovery_id, compact) = signature.serialize_compact();
                let mut signature_r = [0; 32];
                let mut signature_s = [0; 32];
                signature_r.copy_from_slice(&compact[..32]);
                signature_s.copy_from_slice(&compact[32..]);

                OutgoingBitVMXApiMessages::SignedMessage(
                    id,
                    signature_r,
                    signature_s,
                    recovery_id.to_i32() as u8,
                )
            },
        )
    }

    fn encrypt_message(
        &mut self,
        id: Uuid,
        message: Vec<u8>,
        public_key: String,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        let result = self
            .program_context
            .key_manager
            .encrypt_rsa_message(&message, &public_key);
        Self::key_manager_response(id, result, "Failed to encrypt message", |encrypted| {
            OutgoingBitVMXApiMessages::Encrypted(id, encrypted)
        })
    }

    fn decrypt_message(
        &mut self,
        id: Uuid,
        message: Vec<u8>,
        public_key: String,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        let result = self
            .program_context
            .key_manager
            .decrypt_rsa_message(&message, &public_key);
        Self::key_manager_response(id, result, "Failed to decrypt message", |decrypted| {
            OutgoingBitVMXApiMessages::Decrypted(id, decrypted)
        })
    }

    fn get_aggregated_pubkey(
        &mut self,
        id: Uuid,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        info!("Getting aggregated pubkey for program: {:?}", id);

        // Read from globals (protocol-based approach via AggregatedKeyProtocol)
        Ok(
            if let Some(key_var) = self
                .program_context
                .globals
                .get_var(&id, FINAL_AGGREGATED_KEY)?
            {
                match key_var.pubkey() {
                    Ok(aggregated_pubkey) => {
                        info!("Found aggregated pubkey in globals for program: {:?}", id);
                        OutgoingBitVMXApiMessages::AggregatedPubkey(id, aggregated_pubkey)
                    }
                    Err(error) => Self::api_error(
                        id,
                        format!(
                            "Failed to resolve aggregated public key for program {id}: {error}"
                        ),
                    ),
                }
            } else {
                OutgoingBitVMXApiMessages::AggregatedPubkeyNotReady(id)
            },
        )
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

    fn get_zkp_execution_result(
        &mut self,
        id: Uuid,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        // Check if the proof is ready
        info!("Checking if {} ZKP job is ready", id);
        let status_key = StoreKey::ZKPStatus(id).get_key();
        let status: Option<String> = self.store.get(&status_key, None)?;

        let response = match status {
            Some(status_str) => {
                if status_str == "OK" {
                    info!("Getting ZKP execution result for job: {}", id);
                    let seal: Vec<u8> = match self
                        .store
                        .get(&StoreKey::ZKPProof(id).get_key(), None)?
                    {
                        Some(seal) => seal,
                        None => {
                            return Ok(Self::api_error(
                                    id,
                                    format!(
                                        "Inconsistent ZKP data for job {id}: status is OK but the proof is missing"
                                    ),
                                ));
                        }
                    };

                    let journal: Vec<u8> = match self
                        .store
                        .get(&StoreKey::ZKPJournal(id).get_key(), None)?
                    {
                        Some(journal) => journal,
                        None => {
                            return Ok(Self::api_error(
                                    id,
                                    format!(
                                        "Inconsistent ZKP data for job {id}: status is OK but the journal is missing"
                                    ),
                                ));
                        }
                    };
                    OutgoingBitVMXApiMessages::ZKPResult(id, seal, journal)
                } else {
                    OutgoingBitVMXApiMessages::ProofGenerationError(id, status_str)
                }
            }
            None => OutgoingBitVMXApiMessages::ProofNotReady(id),
        };

        Ok(response)
    }

    fn subscription_response(
        id: Uuid,
        result: Result<(), BitcoinCoordinatorError>,
    ) -> Result<Option<OutgoingBitVMXApiMessages>, BitVMXError> {
        match result {
            Ok(()) => Ok(None),
            Err(BitcoinCoordinatorError::MonitorError(
                error @ MonitorError::InvalidConfirmationTrigger(_, _),
            )) => Ok(Some(Self::api_error(
                id,
                format!("Failed to subscribe: {error}"),
            ))),
            Err(error) => Err(error.into()),
        }
    }

    fn subscribe_to_tx(
        &mut self,
        from: Identifier,
        id: Uuid,
        txid: Txid,
        confirmation_threshold: Option<u32>,
    ) -> Result<Option<OutgoingBitVMXApiMessages>, BitVMXError> {
        info!(
            "Subscribing to transaction: {:?} from: {} id: {}",
            txid, from, id
        );
        let result =
            self.program_context
                .bitcoin_coordinator
                .monitor(TypesToMonitor::Transactions(
                    vec![txid],
                    Context::RequestId(id, from).to_string()?,
                    confirmation_threshold,
                ));

        Self::subscription_response(id, result)
    }

    fn subscribe_to_spending_utxo(
        &mut self,
        from: Identifier,
        id: Uuid,
        txid: Txid,
        vout: u32,
        confirmation_threshold: Option<u32>,
    ) -> Result<Option<OutgoingBitVMXApiMessages>, BitVMXError> {
        info!(
            "Subscribing to spending of UTXO: {:?}:{} from: {} id: {}",
            txid, vout, from, id
        );
        let result = self.program_context.bitcoin_coordinator.monitor(
            TypesToMonitor::SpendingUTXOTransaction(
                txid,
                vout,
                Context::RequestId(id, from).to_string()?,
                confirmation_threshold,
            ),
        );

        Self::subscription_response(id, result)
    }

    fn subscribe_to_output_pattern(
        &mut self,
        id: Uuid,
        filter: bitcoin_coordinator::OutputPatternFilter,
        confirmation_threshold: Option<u32>,
    ) -> Result<Option<OutgoingBitVMXApiMessages>, BitVMXError> {
        let result =
            self.program_context
                .bitcoin_coordinator
                .monitor(TypesToMonitor::OutputPattern(
                    filter,
                    confirmation_threshold,
                ));
        Self::subscription_response(id, result)
    }

    fn get_transaction(
        &mut self,
        id: Uuid,
        txid: Txid,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        let tx_status = self
            .program_context
            .bitcoin_coordinator
            .get_transaction(txid)?;
        Ok(OutgoingBitVMXApiMessages::Transaction(id, tx_status, None))
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

    fn load_program_or_not_found(
        &self,
        id: Uuid,
    ) -> Result<Result<Program, OutgoingBitVMXApiMessages>, BitVMXError> {
        match self.load_program(&id)? {
            Some(program) => Ok(Ok(program)),
            None => {
                warn!("Program {} not found", id);
                Ok(Err(OutgoingBitVMXApiMessages::NotFound(
                    id,
                    format!("Program not found: {id}"),
                )))
            }
        }
    }

    fn get_hashed_message(
        &mut self,
        id: Uuid,
        name: String,
        vout: u32,
        leaf: u32,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        let mut program = match self.load_program_or_not_found(id)? {
            Ok(program) => program,
            Err(response) => return Ok(response),
        };

        match program.protocol.get_hashed_message(&name, vout, leaf) {
            Ok(hashed) => Ok(OutgoingBitVMXApiMessages::HashedMessage(
                id, name, vout, leaf, hashed,
            )),
            Err(error) if is_fatal(&error) => Err(error),
            Err(error) => Ok(Self::api_error(
                id,
                format!("Failed to get hashed message: {error}"),
            )),
        }
    }

    fn get_transaction_info_by_name(
        &self,
        id: Uuid,
        name: String,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        let program = match self.load_program_or_not_found(id)? {
            Ok(program) => program,
            Err(response) => return Ok(response),
        };

        match program.get_transaction_by_name(&name, &self.program_context) {
            Ok(transaction) => Ok(OutgoingBitVMXApiMessages::TransactionInfo(
                id,
                name,
                transaction,
            )),
            Err(error) if is_fatal(&error) => Err(error),
            Err(error) => {
                error!(
                    "Transaction not found: {} in program {:?}. Error: {}",
                    name, id, error
                );
                Ok(OutgoingBitVMXApiMessages::NotFound(
                    id,
                    format!("Transaction not found: {name}"),
                ))
            }
        }
    }

    fn dispatch_response(
        id: Uuid,
        result: Result<(), BitVMXError>,
    ) -> Result<Option<OutgoingBitVMXApiMessages>, BitVMXError> {
        match result {
            Ok(()) => Ok(None),
            Err(
                error @ BitVMXError::BitcoinCoordinatorError(
                    BitcoinCoordinatorError::MonitorError(
                        MonitorError::InvalidConfirmationTrigger(_, _),
                    ),
                ),
            ) => Ok(Some(Self::api_error(
                id,
                format!("Failed to dispatch transaction: {error}"),
            ))),
            Err(BitVMXError::InvalidTransactionName(name)) => Ok(Some(Self::api_error(
                id,
                format!("Failed to dispatch transaction: transaction not found: {name}"),
            ))),
            Err(BitVMXError::ProtocolBuilderError(
                ProtocolBuilderError::MissingTransaction(name, protocol),
            )) => Ok(Some(Self::api_error(
                id,
                format!(
                    "Failed to dispatch transaction: transaction {name} not found in protocol {protocol}"
                ),
            ))),
            Err(BitVMXError::ProtocolBuilderError(
                ProtocolBuilderError::GraphBuildingError(GraphError::MissingTransaction(name)),
            )) => Ok(Some(Self::api_error(
                id,
                format!("Failed to dispatch transaction: transaction not found: {name}"),
            ))),
            Err(error) => Err(error),
        }
    }

    fn dispatch_transaction_name(
        &mut self,
        id: Uuid,
        name: &str,
    ) -> Result<Option<OutgoingBitVMXApiMessages>, BitVMXError> {
        let mut program = match self.load_program_or_not_found(id)? {
            Ok(program) => program,
            Err(response) => return Ok(Some(response)),
        };

        let result = program.dispatch_transaction_name(name, &mut self.program_context);
        Self::dispatch_response(id, result)
    }

    fn get_protocol_visualization(
        &self,
        id: Uuid,
    ) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        let program = match self.load_program_or_not_found(id)? {
            Ok(program) => program,
            Err(response) => return Ok(response),
        };

        match program
            .protocol
            .load_protocol()
            .and_then(|protocol| protocol.visualize(GraphOptions::EdgeArrows))
        {
            Ok(visualization) => Ok(OutgoingBitVMXApiMessages::ProtocolVisualization(
                id,
                visualization,
            )),
            Err(error) => {
                let error = BitVMXError::from(error);
                if is_fatal(&error) {
                    return Err(error);
                }
                Ok(Self::api_error(
                    id,
                    format!("Error visualizing protocol: {error}"),
                ))
            }
        }
    }

    fn get_spv_proof(&mut self, txid: Txid) -> Result<OutgoingBitVMXApiMessages, BitVMXError> {
        let tx_info = self
            .program_context
            .bitcoin_coordinator
            .get_transaction(txid)?;

        match tx_info.block_info {
            Some(block_info) => {
                let proof = match get_spv_proof(txid, block_info) {
                    Ok(proof) => Some(proof),
                    Err(error) => {
                        warn!("Failed to build SPV proof for txid {}: {}", txid, error);
                        None
                    }
                };
                Ok(OutgoingBitVMXApiMessages::SPVProof(txid, proof))
            }
            None => {
                warn!("Missing block info for txid {}", txid);
                Ok(OutgoingBitVMXApiMessages::SPVProof(txid, None))
            }
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

        let reply_to = from.clone();
        let result = (|| -> Result<Option<OutgoingBitVMXApiMessages>, BitVMXError> {
            match decoded {
                IncomingBitVMXApiMessages::GetHashedMessage(id, name, vout, leaf) => {
                    self.get_hashed_message(id, name, vout, leaf).map(Some)
                }
                IncomingBitVMXApiMessages::GetCommInfo(id) => {
                    Ok(Some(OutgoingBitVMXApiMessages::CommInfo(
                        id,
                        CommsAddress {
                            address: self.program_context.comms.get_address(),
                            pubkey_hash: self.program_context.comms.get_pubk_hash(),
                        },
                    )))
                }
                IncomingBitVMXApiMessages::Ping(id) => Ok(Some(Self::ping(id))),
                IncomingBitVMXApiMessages::SetVar(id, key, value) => {
                    debug!("Setting variable {}: {:?}", key, value);
                    self.program_context.globals.set_var(&id, &key, value)?;
                    Ok(None)
                }
                IncomingBitVMXApiMessages::SetWitness(id, key, value) => {
                    debug!("Setting witness {}: {:?}", key, value);
                    self.program_context.witness.set_witness(&id, &key, value)?;
                    Ok(None)
                }
                IncomingBitVMXApiMessages::SetFundingUtxo(_id, utxo) => {
                    info!("Setting funding utxo {:?}", utxo);
                    self.program_context.bitcoin_coordinator.add_funding(utxo)?;
                    Ok(None)
                }
                IncomingBitVMXApiMessages::GetFundingAddress(id) => {
                    self.get_funding_address(id).map(Some)
                }
                IncomingBitVMXApiMessages::GetFundingBalance(id) => {
                    self.get_funding_balance(id).map(Some)
                }
                IncomingBitVMXApiMessages::SendFunds(id, destination, fee_rate) => self
                    .send_funds(from.clone(), id, destination, fee_rate)
                    .map(Some),
                IncomingBitVMXApiMessages::GetVar(id, key) => self.get_var(id, &key).map(Some),
                IncomingBitVMXApiMessages::GetWitness(id, key) => {
                    self.get_witness(id, &key).map(Some)
                }
                IncomingBitVMXApiMessages::GetTransaction(id, txid) => {
                    self.get_transaction(id, txid).map(Some)
                }
                IncomingBitVMXApiMessages::GetTransactionInfoByName(id, name) => {
                    self.get_transaction_info_by_name(id, name).map(Some)
                }
                IncomingBitVMXApiMessages::Setup(id, program_type, participants, leader) => {
                    self.setup(id, program_type, participants, leader)
                }
                IncomingBitVMXApiMessages::SubscribeToTransaction(
                    id,
                    txid,
                    confirmation_threshold,
                ) => self.subscribe_to_tx(from, id, txid, confirmation_threshold),
                IncomingBitVMXApiMessages::SubscribeToSpendingUTXO(
                    id,
                    txid,
                    vout,
                    confirmation_threshold,
                ) => self.subscribe_to_spending_utxo(from, id, txid, vout, confirmation_threshold),
                IncomingBitVMXApiMessages::SubscribeToOutputPattern(
                    id,
                    filter,
                    confirmation_threshold,
                ) => self.subscribe_to_output_pattern(id, filter, confirmation_threshold),
                IncomingBitVMXApiMessages::SubscribeToRskPegin(id, confirmation_threshold) => self
                    .subscribe_to_output_pattern(
                        id,
                        bitcoin_coordinator::OutputPatternFilter {
                            output_index: 1,
                            tag: RSK_PEGIN_TAG.to_vec(),
                            max_outputs: None,
                        },
                        confirmation_threshold,
                    ),
                IncomingBitVMXApiMessages::GetSPVProof(_id, txid) => {
                    self.get_spv_proof(txid).map(Some)
                }
                IncomingBitVMXApiMessages::DispatchTransactionName(id, name) => {
                    self.dispatch_transaction_name(id, &name)
                }
                IncomingBitVMXApiMessages::DispatchTransaction(
                    id,
                    tx,
                    confirmation_threshold,
                    stuck_in_mempool_blocks,
                ) => {
                    let result = self.dispatch_transaction(
                        from,
                        id,
                        tx,
                        confirmation_threshold,
                        stuck_in_mempool_blocks,
                    );
                    Self::dispatch_response(id, result)
                }
                IncomingBitVMXApiMessages::SetupKey(
                    id,
                    participants,
                    participants_keys,
                    leader_idx,
                ) => self.setup_key(id, participants, participants_keys, leader_idx),
                IncomingBitVMXApiMessages::GetKeyPair(id) => self.get_key_pair(id).map(Some),
                IncomingBitVMXApiMessages::GetPubKey(id, new) => {
                    self.get_pub_key(id, new).map(Some)
                }
                IncomingBitVMXApiMessages::GetEvenPubKey(id) => self.get_even_pub_key(id).map(Some),
                IncomingBitVMXApiMessages::SignMessage(id, payload, public_key) => {
                    self.sign_message(id, payload, public_key).map(Some)
                }
                IncomingBitVMXApiMessages::GetAggregatedPubkey(id) => {
                    self.get_aggregated_pubkey(id).map(Some)
                }
                IncomingBitVMXApiMessages::GenerateZKP(id, input, elf_file_path) => {
                    self.generate_zkp(from, id, input, elf_file_path)?;
                    Ok(None)
                }
                IncomingBitVMXApiMessages::ProofReady(id) => self.proof_ready(id).map(Some),
                IncomingBitVMXApiMessages::GetZKPExecutionResult(id) => {
                    self.get_zkp_execution_result(id).map(Some)
                }
                IncomingBitVMXApiMessages::Encrypt(id, message, public_key) => {
                    self.encrypt_message(id, message, public_key).map(Some)
                }
                IncomingBitVMXApiMessages::Decrypt(id, message, public_key) => {
                    self.decrypt_message(id, message, public_key).map(Some)
                }
                IncomingBitVMXApiMessages::Backup(id, backup_path, dek_path, password) => {
                    let response = match self.store.backup(&backup_path, &dek_path, password) {
                        Ok(_) => OutgoingBitVMXApiMessages::BackupResult(
                            id,
                            true,
                            "Backup successful".to_string(),
                        ),
                        Err(error) => {
                            OutgoingBitVMXApiMessages::BackupResult(id, false, error.to_string())
                        }
                    };
                    Ok(Some(response))
                }
                IncomingBitVMXApiMessages::GetProtocolVisualization(id) => {
                    self.get_protocol_visualization(id).map(Some)
                }
                IncomingBitVMXApiMessages::ListAllowList(id) => {
                    let allow_list = self.program_context.comms.get_allow_list();
                    let (entries, allow_all) = comms_allow_list::snapshot(&allow_list)?;
                    Ok(Some(OutgoingBitVMXApiMessages::AllowListEntries(
                        id, entries, allow_all,
                    )))
                }
                IncomingBitVMXApiMessages::AddToAllowList(id, pubk_hash, addr) => {
                    info!("Allowing comms peer {} from {:?}", pubk_hash, addr);
                    self.mutate_allow_list(id, from, |allow_list| {
                        allow_list.add_entry(pubk_hash.clone(), addr)
                    })?;
                    Ok(None)
                }
                IncomingBitVMXApiMessages::RemoveFromAllowList(id, pubk_hash) => {
                    info!("Removing comms peer {}", pubk_hash);
                    self.mutate_allow_list(id, from, |allow_list| allow_list.remove(&pubk_hash))?;
                    Ok(None)
                }
                IncomingBitVMXApiMessages::SetAllowAll(id, allow_all) => {
                    info!("Setting comms allow_all to {}", allow_all);
                    self.mutate_allow_list(id, from, |allow_list| {
                        allow_list.set_allow_all(allow_all)
                    })?;
                    Ok(None)
                }
                IncomingBitVMXApiMessages::Shutdown(_id) => {
                    info!("Shutdown message received. Initiating shutdown...");
                    self.shutdown()?;
                    Ok(None)
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
                    Ok(None)
                }
            }
        })();

        match result {
            Ok(Some(response)) => self.reply(reply_to, response),
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::variables::WitnessTypes;
    use crate::test_utils::{BitcoinCoordinatorMock, TestBitVMXEnv};
    use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, TxOut};
    use bitcoin_coordinator::coordinator::BitcoinCoordinator;

    type BitVMX = super::BitVMX<BitcoinCoordinator>;
    type MockBitVMX = super::BitVMX<BitcoinCoordinatorMock>;

    fn dummy_transaction() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn send_api(
        bitvmx: &mut MockBitVMX,
        request: IncomingBitVMXApiMessages,
    ) -> Result<(), BitVMXError> {
        let sender = bitvmx.config.components.l2.clone();
        bitvmx.handle_api_message(request.to_string()?, sender)
    }

    fn api_replies(bitvmx: &mut MockBitVMX) -> Vec<OutgoingBitVMXApiMessages> {
        bitvmx.program_context.broker_channel.tick().unwrap();
        let channel = bitvmx
            .program_context
            .broker_channel
            .create_local_channel(bitvmx.config.components.l2.clone())
            .unwrap();
        channel
            .get_all()
            .unwrap()
            .into_iter()
            .map(|message| OutgoingBitVMXApiMessages::from_string(&message.msg).unwrap())
            .collect()
    }

    #[test]
    fn invalid_subscription_confirmation_threshold_is_an_api_error() {
        let id = Uuid::new_v4();
        let error =
            BitcoinCoordinatorError::MonitorError(MonitorError::InvalidConfirmationTrigger(10, 10));

        let response = BitVMX::subscription_response(id, Err(error))
            .unwrap()
            .expect("terminal API response");

        match response {
            OutgoingBitVMXApiMessages::ApiError(response_id, message) => {
                assert_eq!(response_id, id);
                assert_eq!(
                    message,
                    "Failed to subscribe: Invalid confirmation trigger: requested 10, max allowed 10"
                );
            }
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[test]
    fn subscription_infrastructure_errors_propagate() {
        let id = Uuid::new_v4();
        let error = BitcoinCoordinatorError::Internal("coordinator unavailable".to_string());

        assert!(matches!(
            BitVMX::subscription_response(id, Err(error)),
            Err(BitVMXError::BitcoinCoordinatorError(
                BitcoinCoordinatorError::Internal(message)
            )) if message == "coordinator unavailable"
        ));
    }

    #[test]
    fn successful_subscription_has_no_immediate_response() {
        assert!(BitVMX::subscription_response(Uuid::new_v4(), Ok(()))
            .unwrap()
            .is_none());
    }

    fn expect_dispatch_api_error(error: BitVMXError) -> String {
        let response = BitVMX::dispatch_response(Uuid::new_v4(), Err(error))
            .unwrap()
            .expect("terminal API response");
        match response {
            OutgoingBitVMXApiMessages::ApiError(_, message) => message,
            other => panic!("expected ApiError, got {other:?}"),
        }
    }

    #[test]
    fn invalid_dispatch_confirmation_threshold_is_an_api_error() {
        let error = BitVMXError::BitcoinCoordinatorError(BitcoinCoordinatorError::MonitorError(
            MonitorError::InvalidConfirmationTrigger(10, 10),
        ));

        assert_eq!(
            expect_dispatch_api_error(error),
            "Failed to dispatch transaction: Failed to use Bitcoin Coordinator: Monitor Error: Invalid confirmation trigger: requested 10, max allowed 10"
        );
    }

    #[test]
    fn invalid_dispatch_transaction_name_is_an_api_error() {
        let message =
            expect_dispatch_api_error(BitVMXError::InvalidTransactionName("unknown".to_string()));
        assert_eq!(
            message,
            "Failed to dispatch transaction: transaction not found: unknown"
        );
    }

    #[test]
    fn missing_protocol_transaction_is_an_api_error() {
        let error = BitVMXError::ProtocolBuilderError(ProtocolBuilderError::GraphBuildingError(
            GraphError::MissingTransaction("unknown".to_string()),
        ));

        assert_eq!(
            expect_dispatch_api_error(error),
            "Failed to dispatch transaction: transaction not found: unknown"
        );
    }

    #[test]
    fn dispatch_infrastructure_errors_propagate() {
        let error = BitVMXError::BitcoinCoordinatorError(BitcoinCoordinatorError::Internal(
            "coordinator unavailable".to_string(),
        ));

        assert!(matches!(
            BitVMX::dispatch_response(Uuid::new_v4(), Err(error)),
            Err(BitVMXError::BitcoinCoordinatorError(
                BitcoinCoordinatorError::Internal(message)
            )) if message == "coordinator unavailable"
        ));
    }

    #[test]
    fn basic_dispatcher_requests_round_trip_state_and_replies() {
        let mut env = TestBitVMXEnv::new("api-basic-requests").unwrap();
        let id = Uuid::new_v4();
        let variable = VariableTypes::String("value".to_string());
        let witness = WitnessTypes::Secret(vec![1, 2, 3]);

        send_api(
            &mut env.bitvmx,
            IncomingBitVMXApiMessages::SetVar(id, "var".to_string(), variable),
        )
        .unwrap();
        send_api(
            &mut env.bitvmx,
            IncomingBitVMXApiMessages::SetWitness(id, "witness".to_string(), witness),
        )
        .unwrap();
        send_api(
            &mut env.bitvmx,
            IncomingBitVMXApiMessages::GetVar(id, "var".to_string()),
        )
        .unwrap();
        send_api(
            &mut env.bitvmx,
            IncomingBitVMXApiMessages::GetWitness(id, "witness".to_string()),
        )
        .unwrap();
        let ping_id = Uuid::new_v4();
        send_api(&mut env.bitvmx, IncomingBitVMXApiMessages::Ping(ping_id)).unwrap();
        let comm_id = Uuid::new_v4();
        send_api(
            &mut env.bitvmx,
            IncomingBitVMXApiMessages::GetCommInfo(comm_id),
        )
        .unwrap();

        let replies = api_replies(&mut env.bitvmx);
        assert_eq!(replies.len(), 4);
        assert!(
            matches!(&replies[0], OutgoingBitVMXApiMessages::Variable(response_id, key, VariableTypes::String(value)) if *response_id == id && key == "var" && value == "value")
        );
        assert!(
            matches!(&replies[1], OutgoingBitVMXApiMessages::Witness(response_id, key, WitnessTypes::Secret(value)) if *response_id == id && key == "witness" && value == &vec![1, 2, 3])
        );
        assert!(
            matches!(&replies[2], OutgoingBitVMXApiMessages::Pong(response_id) if *response_id == ping_id)
        );
        assert!(
            matches!(&replies[3], OutgoingBitVMXApiMessages::CommInfo(response_id, _) if *response_id == comm_id)
        );
    }

    #[test]
    fn missing_values_and_wallet_return_terminal_responses() {
        let mut env = TestBitVMXEnv::new("api-missing-values").unwrap();
        let id = Uuid::new_v4();

        for request in [
            IncomingBitVMXApiMessages::GetVar(id, "missing-var".to_string()),
            IncomingBitVMXApiMessages::GetWitness(id, "missing-witness".to_string()),
            IncomingBitVMXApiMessages::GetFundingAddress(id),
            IncomingBitVMXApiMessages::GetFundingBalance(id),
        ] {
            send_api(&mut env.bitvmx, request).unwrap();
        }

        let replies = api_replies(&mut env.bitvmx);
        assert!(
            matches!(&replies[0], OutgoingBitVMXApiMessages::NotFound(_, key) if key == "missing-var")
        );
        assert!(
            matches!(&replies[1], OutgoingBitVMXApiMessages::NotFound(_, key) if key == "missing-witness")
        );
        assert!(
            matches!(&replies[2], OutgoingBitVMXApiMessages::ApiError(_, message) if message == "Wallet not available")
        );
        assert!(
            matches!(&replies[3], OutgoingBitVMXApiMessages::ApiError(_, message) if message == "Wallet not available")
        );
    }

    #[test]
    fn setup_key_validation_and_duplicate_program_are_terminal() {
        let mut env = TestBitVMXEnv::new("api-setup-validation").unwrap();
        let empty_id = Uuid::new_v4();
        let leader_id = Uuid::new_v4();
        let duplicate_id = Uuid::new_v4();
        let participant = CommsAddress {
            address: env.bitvmx.program_context.comms.get_address(),
            pubkey_hash: env.bitvmx.program_context.comms.get_pubk_hash(),
        };

        send_api(
            &mut env.bitvmx,
            IncomingBitVMXApiMessages::SetupKey(empty_id, vec![], None, 0),
        )
        .unwrap();
        send_api(
            &mut env.bitvmx,
            IncomingBitVMXApiMessages::SetupKey(leader_id, vec![participant.clone()], None, 1),
        )
        .unwrap();
        env.bitvmx.add_new_program(&duplicate_id).unwrap();
        assert!(env.bitvmx.program_exists(&duplicate_id).unwrap());
        send_api(
            &mut env.bitvmx,
            IncomingBitVMXApiMessages::SetupKey(duplicate_id, vec![participant], None, 0),
        )
        .unwrap();
        assert!(matches!(
            env.bitvmx.add_new_program(&duplicate_id),
            Err(BitVMXError::ProgramAlreadyExists(id)) if id == duplicate_id
        ));

        let messages: Vec<_> = api_replies(&mut env.bitvmx)
            .into_iter()
            .map(|response| match response {
                OutgoingBitVMXApiMessages::ApiError(_, message) => message,
                other => panic!("expected ApiError, got {other:?}"),
            })
            .collect();
        assert_eq!(
            messages,
            [
                "Participants list cannot be empty",
                "Leader index is out of bounds",
                "Program already exists",
            ]
        );
    }

    #[test]
    fn zkp_result_reports_each_persisted_state() {
        let mut env = TestBitVMXEnv::new("api-zkp-results").unwrap();
        let id = Uuid::new_v4();

        assert!(matches!(
            env.bitvmx.get_zkp_execution_result(id).unwrap(),
            OutgoingBitVMXApiMessages::ProofNotReady(response_id) if response_id == id
        ));
        env.bitvmx
            .store
            .set(StoreKey::ZKPStatus(id).get_key(), "FAILED", None)
            .unwrap();
        assert!(matches!(
            env.bitvmx.get_zkp_execution_result(id).unwrap(),
            OutgoingBitVMXApiMessages::ProofGenerationError(response_id, message)
                if response_id == id && message == "FAILED"
        ));
        env.bitvmx
            .store
            .set(StoreKey::ZKPStatus(id).get_key(), "OK", None)
            .unwrap();
        assert!(
            matches!(env.bitvmx.get_zkp_execution_result(id).unwrap(), OutgoingBitVMXApiMessages::ApiError(_, message) if message.contains("proof is missing"))
        );
        env.bitvmx
            .store
            .set(StoreKey::ZKPProof(id).get_key(), vec![1_u8], None)
            .unwrap();
        assert!(
            matches!(env.bitvmx.get_zkp_execution_result(id).unwrap(), OutgoingBitVMXApiMessages::ApiError(_, message) if message.contains("journal is missing"))
        );
        env.bitvmx
            .store
            .set(StoreKey::ZKPJournal(id).get_key(), vec![2_u8], None)
            .unwrap();
        assert!(matches!(
            env.bitvmx.get_zkp_execution_result(id).unwrap(),
            OutgoingBitVMXApiMessages::ZKPResult(response_id, seal, journal)
                if response_id == id && seal == vec![1] && journal == vec![2]
        ));
    }

    #[test]
    fn key_crypto_and_aggregated_key_responses_cover_success_and_validation() {
        let mut env = TestBitVMXEnv::new("api-key-operations").unwrap();
        let id = Uuid::new_v4();

        assert!(matches!(
            env.bitvmx.get_aggregated_pubkey(id).unwrap(),
            OutgoingBitVMXApiMessages::AggregatedPubkeyNotReady(response_id) if response_id == id
        ));
        env.bitvmx
            .program_context
            .globals
            .set_var(&id, FINAL_AGGREGATED_KEY, VariableTypes::Number(1))
            .unwrap();
        assert!(
            matches!(env.bitvmx.get_aggregated_pubkey(id).unwrap(), OutgoingBitVMXApiMessages::ApiError(_, message) if message.contains("Failed to resolve"))
        );

        let public_key = match env.bitvmx.get_pub_key(id, true).unwrap() {
            OutgoingBitVMXApiMessages::PubKey(_, key) => key,
            other => panic!("expected PubKey, got {other:?}"),
        };
        env.bitvmx
            .program_context
            .globals
            .set_var(&id, FINAL_AGGREGATED_KEY, VariableTypes::PubKey(public_key))
            .unwrap();
        assert!(matches!(
            env.bitvmx.get_aggregated_pubkey(id).unwrap(),
            OutgoingBitVMXApiMessages::AggregatedPubkey(response_id, key)
                if response_id == id && key == public_key
        ));
        assert!(
            matches!(env.bitvmx.sign_message(id, vec![1], public_key).unwrap(), OutgoingBitVMXApiMessages::ApiError(_, message) if message.contains("expected a 32-byte digest"))
        );

        let rsa_key = env.bitvmx.program_context.rsa_public_key.clone();
        let encrypted = match env
            .bitvmx
            .encrypt_message(id, b"secret".to_vec(), rsa_key.clone())
            .unwrap()
        {
            OutgoingBitVMXApiMessages::Encrypted(_, encrypted) => encrypted,
            other => panic!("expected Encrypted, got {other:?}"),
        };
        assert!(matches!(
            env.bitvmx.decrypt_message(id, encrypted, rsa_key).unwrap(),
            OutgoingBitVMXApiMessages::Decrypted(response_id, plaintext)
                if response_id == id && plaintext == b"secret"
        ));
    }

    #[test]
    fn missing_program_queries_return_not_found() {
        let mut env = TestBitVMXEnv::new("api-missing-program").unwrap();
        let id = Uuid::new_v4();

        for request in [
            IncomingBitVMXApiMessages::GetHashedMessage(id, "tx".to_string(), 0, 0),
            IncomingBitVMXApiMessages::GetTransactionInfoByName(id, "tx".to_string()),
            IncomingBitVMXApiMessages::GetProtocolVisualization(id),
            IncomingBitVMXApiMessages::DispatchTransactionName(id, "tx".to_string()),
        ] {
            send_api(&mut env.bitvmx, request).unwrap();
        }

        assert!(api_replies(&mut env.bitvmx).iter().all(
            |response| matches!(response, OutgoingBitVMXApiMessages::NotFound(response_id, _) if *response_id == id)
        ));
    }

    #[test]
    fn subscription_variants_are_forwarded_to_the_mock_without_replies() {
        let mut env = TestBitVMXEnv::new("api-subscription-variants").unwrap();
        let id = Uuid::new_v4();
        let txid = dummy_transaction().compute_txid();
        let filter = bitcoin_coordinator::OutputPatternFilter {
            output_index: 2,
            tag: vec![1, 2],
            max_outputs: Some(3),
        };

        for request in [
            IncomingBitVMXApiMessages::SubscribeToSpendingUTXO(id, txid, 4, Some(2)),
            IncomingBitVMXApiMessages::SubscribeToOutputPattern(id, filter.clone(), Some(3)),
            IncomingBitVMXApiMessages::SubscribeToRskPegin(id, Some(4)),
        ] {
            send_api(&mut env.bitvmx, request).unwrap();
        }

        let monitored = env.coordinator_mock().monitored();
        assert_eq!(monitored.len(), 4); // NewBlock is registered during construction.
        assert!(matches!(
            &monitored[1],
            TypesToMonitor::SpendingUTXOTransaction(monitored_txid, 4, _, Some(2))
                if *monitored_txid == txid
        ));
        assert!(matches!(
            &monitored[2],
            TypesToMonitor::OutputPattern(monitored_filter, Some(3))
                if monitored_filter == &filter
        ));
        assert!(matches!(
            &monitored[3],
            TypesToMonitor::OutputPattern(monitored_filter, Some(4))
                if monitored_filter.output_index == 1 && monitored_filter.tag == RSK_PEGIN_TAG
        ));
        assert!(api_replies(&mut env.bitvmx).is_empty());
    }

    #[test]
    fn transaction_and_spv_queries_use_the_staged_coordinator_status() {
        let mut env = TestBitVMXEnv::new("api-transaction-status").unwrap();
        let id = Uuid::new_v4();
        let txid = dummy_transaction().compute_txid();
        let status: bitcoin_coordinator::TransactionStatus =
            serde_json::from_value(serde_json::json!({
                "tx": null,
                "block_info": null,
                "confirmations": 0,
                "status": "NotFound",
            }))
            .unwrap();
        env.coordinator_mock()
            .set_transaction_status(txid, status.clone());

        send_api(
            &mut env.bitvmx,
            IncomingBitVMXApiMessages::GetTransaction(id, txid),
        )
        .unwrap();
        send_api(
            &mut env.bitvmx,
            IncomingBitVMXApiMessages::GetSPVProof(id, txid),
        )
        .unwrap();

        let replies = api_replies(&mut env.bitvmx);
        assert!(matches!(
            &replies[0],
            OutgoingBitVMXApiMessages::Transaction(response_id, response_status, None)
                if *response_id == id && response_status == &status
        ));
        assert!(matches!(
            &replies[1],
            OutgoingBitVMXApiMessages::SPVProof(response_txid, None)
                if *response_txid == txid
        ));
    }

    #[test]
    fn dispatcher_turns_mocked_invalid_subscription_into_a_reply() {
        let mut env = TestBitVMXEnv::new("api-invalid-subscription").unwrap();
        let id = Uuid::new_v4();
        let txid = dummy_transaction().compute_txid();
        env.coordinator_mock()
            .fail_next_monitor(BitcoinCoordinatorError::MonitorError(
                MonitorError::InvalidConfirmationTrigger(5, 3),
            ));
        let sender = env.bitvmx.config.components.l2.clone();
        let request = IncomingBitVMXApiMessages::SubscribeToTransaction(id, txid, Some(5));

        env.bitvmx
            .handle_api_message(request.to_string().unwrap(), sender)
            .unwrap();

        assert!(matches!(
            api_replies(&mut env.bitvmx).as_slice(),
            [OutgoingBitVMXApiMessages::ApiError(response_id, message)]
                if *response_id == id && message.contains("Failed to subscribe")
        ));
    }

    #[test]
    fn mocked_subscription_infrastructure_failure_propagates_without_a_reply() {
        let mut env = TestBitVMXEnv::new("api-subscription-outage").unwrap();
        let id = Uuid::new_v4();
        env.coordinator_mock()
            .fail_next_monitor(BitcoinCoordinatorError::Internal(
                "coordinator unavailable".to_string(),
            ));
        let sender = env.bitvmx.config.components.l2.clone();
        let request = IncomingBitVMXApiMessages::SubscribeToTransaction(
            id,
            dummy_transaction().compute_txid(),
            Some(1),
        );

        assert!(matches!(
            env.bitvmx
                .handle_api_message(request.to_string().unwrap(), sender),
            Err(BitVMXError::BitcoinCoordinatorError(
                BitcoinCoordinatorError::Internal(message)
            )) if message == "coordinator unavailable"
        ));
        assert!(api_replies(&mut env.bitvmx).is_empty());
    }

    #[test]
    fn dispatcher_turns_mocked_invalid_dispatch_into_a_reply() {
        let mut env = TestBitVMXEnv::new("api-invalid-dispatch").unwrap();
        let id = Uuid::new_v4();
        env.coordinator_mock()
            .fail_next_dispatch(BitcoinCoordinatorError::MonitorError(
                MonitorError::InvalidConfirmationTrigger(5, 3),
            ));
        let sender = env.bitvmx.config.components.l2.clone();
        let request =
            IncomingBitVMXApiMessages::DispatchTransaction(id, dummy_transaction(), Some(5), None);

        env.bitvmx
            .handle_api_message(request.to_string().unwrap(), sender)
            .unwrap();

        assert!(matches!(
            api_replies(&mut env.bitvmx).as_slice(),
            [OutgoingBitVMXApiMessages::ApiError(response_id, message)]
                if *response_id == id && message.contains("Failed to dispatch transaction")
        ));
        assert!(env.coordinator_mock().dispatched().is_empty());
    }

    #[test]
    fn successful_dispatch_is_forwarded_to_the_mock_without_a_reply() {
        let mut env = TestBitVMXEnv::new("api-dispatch-success").unwrap();
        let id = Uuid::new_v4();
        let transaction = dummy_transaction();
        let sender = env.bitvmx.config.components.l2.clone();
        let request = IncomingBitVMXApiMessages::DispatchTransaction(
            id,
            transaction.clone(),
            Some(2),
            Some(7),
        );

        env.bitvmx
            .handle_api_message(request.to_string().unwrap(), sender)
            .unwrap();

        let dispatched = env.coordinator_mock().dispatched();
        assert_eq!(dispatched.len(), 1);
        assert_eq!(dispatched[0].tx, transaction);
        assert_eq!(dispatched[0].confirmation_trigger, Some(2));
        assert_eq!(dispatched[0].stuck_in_mempool_blocks, Some(7));
        assert!(api_replies(&mut env.bitvmx).is_empty());
    }

    #[test]
    fn mocked_transaction_query_failure_propagates() {
        let mut env = TestBitVMXEnv::new("api-transaction-outage").unwrap();
        env.coordinator_mock()
            .fail_next_get_transaction(BitcoinCoordinatorError::Internal(
                "bitcoin RPC unavailable".to_string(),
            ));
        let sender = env.bitvmx.config.components.l2.clone();
        let request = IncomingBitVMXApiMessages::GetTransaction(
            Uuid::new_v4(),
            dummy_transaction().compute_txid(),
        );

        assert!(matches!(
            env.bitvmx
                .handle_api_message(request.to_string().unwrap(), sender),
            Err(BitVMXError::BitcoinCoordinatorError(
                BitcoinCoordinatorError::Internal(message)
            )) if message == "bitcoin RPC unavailable"
        ));
        assert!(api_replies(&mut env.bitvmx).is_empty());
    }
}
