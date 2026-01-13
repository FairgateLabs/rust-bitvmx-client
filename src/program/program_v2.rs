/// ProgramV2 - New Program implementation using SetupEngine
///
/// This is the next generation Program implementation that:
/// - Uses SetupEngine for orchestrating setup steps
/// - Delegates aggregation responsibility to protocols
/// - Provides cleaner separation of concerns
/// - Allows protocols to opt-in gradually via UsesSetupSteps trait
///
/// Key differences from Program:
/// - No prepare_aggregated_keys() - protocols do their own aggregation
/// - Uses SetupEngine to orchestrate setup steps
/// - Cleaner state machine
/// - Protocol-specific setup logic in the protocol itself

use crate::{
    bitvmx::Context,
    comms_helper::{request, CommsMessageType},
    config::ClientConfig,
    errors::{BitVMXError, ProgramError},
    program::{
        participant::ParticipantData,
        protocols::protocol_handler::{new_protocol_type, ProtocolHandler, ProtocolType},
        setup::{SetupEngine, UsesSetupSteps},
        state::ProgramState,
    },
    signature_verifier::OperatorVerificationStore,
    types::ProgramContext,
};
use bitcoin::{Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus, TypesToMonitor};
use bitvmx_operator_comms::operator_comms::PubKeyHash;
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use storage_backend::storage::{KeyValueStore, Storage};
use tracing::{debug, error, info};
use uuid::Uuid;

use super::participant::{CommsAddress, ParticipantKeys};

#[derive(Debug, Clone)]
pub enum StoreKeyV2 {
    Program(Uuid),
}

#[derive(Serialize, Deserialize)]
pub struct ProgramV2 {
    pub program_id: Uuid,
    pub my_idx: usize,
    pub participants: Vec<ParticipantData>,
    pub leader: usize,
    pub protocol: ProtocolType,
    #[serde(skip)]
    pub state: ProgramState,
    #[serde(skip)]
    pub setup_engine: Option<SetupEngine>,
    #[serde(skip)]
    storage: Option<Rc<Storage>>,
    config: ClientConfig,
}

impl ProgramV2 {
    /// Returns the storage key for this program
    fn storage_key(&self) -> String {
        format!("program_v2_{}", self.program_id)
    }

    /// Tries to create a SetupEngine for the protocol if it supports it
    fn try_create_setup_engine(protocol: &ProtocolType) -> Option<SetupEngine> {
        if let Some(steps) = protocol.setup_steps() {
            info!("Protocol supports SetupEngine with {} steps", steps.len());
            Some(SetupEngine::new(steps))
        } else {
            info!("Protocol does not use SetupEngine");
            None
        }
    }

    /// Creates and initializes a new ProgramV2 instance
    pub fn setup(
        program_id: Uuid,
        program_type: &str,
        peers: Vec<CommsAddress>,
        leader: usize,
        context: &mut ProgramContext,
        storage: Rc<Storage>,
        config: &ClientConfig,
    ) -> Result<(), BitVMXError> {
        info!(
            "ProgramV2: Setting up program {} with type {}",
            program_id, program_type
        );

        // Validate leader index
        if leader >= peers.len() {
            return Err(BitVMXError::InvalidMessageFormat);
        }

        let my_pubkey_hash = context.comms.get_pubk_hash()?;

        let my_idx = peers
            .iter()
            .position(|peer| peer.pubkey_hash == my_pubkey_hash)
            .ok_or_else(|| BitVMXError::InvalidMessage("Peer not found in the list".to_string()))?;

        info!("ProgramV2: my_pos: {}", my_idx);
        info!("ProgramV2: Leader pos: {}", leader);

        // Request verification keys from other participants for message authentication
        // This is critical for security - allows us to verify message authenticity
        OperatorVerificationStore::request_missing_verification_keys(
            &context.globals,
            &context.comms,
            &context.key_chain,
            &program_id,
            &peers,
        )?;

        let participants: Vec<ParticipantData> = peers
            .into_iter()
            .map(|addr| ParticipantData {
                comms_address: addr,
                keys: None,
                nonces: None,
                partial: None,
            })
            .collect();

        // Create protocol
        let mut protocol = new_protocol_type(program_id, program_type, my_idx, storage.clone())?;
        protocol.set_storage(storage.clone());

        // Try to create SetupEngine if protocol supports it
        let setup_engine = Self::try_create_setup_engine(&protocol);

        let mut program = ProgramV2 {
            program_id,
            my_idx,
            participants,
            leader,
            protocol,
            state: ProgramState::New,
            setup_engine,
            storage: Some(storage.clone()),
            config: config.clone(),
        };

        // Handle single-participant protocols
        // For protocols with only one participant, we can skip setup and go straight to building
        if program.participants.len() == 1 {
            info!("ProgramV2: Single participant protocol - building immediately");

            // Generate keys for the protocol (normally done by SetupEngine's KeysStep)
            let my_keys = program.protocol.generate_keys(context)?;

            // Store keys in the format expected by build_protocol
            let all_keys = vec![my_keys];
            let all_keys_json = serde_json::to_string(&all_keys)
                .map_err(|e| BitVMXError::InvalidMessage(format!("Failed to serialize keys: {}", e)))?;

            context.globals.set_var(
                &program.protocol.context().id,
                "all_participant_keys",
                crate::program::variables::VariableTypes::String(all_keys_json),
            )?;

            // Now build and sign
            program.build_protocol(context)?;
            program.protocol.sign(&context.key_chain)?;
            program.state = ProgramState::Monitoring;
        }

        // Save initial program (includes state)
        program.save()?;

        info!("ProgramV2: Setup complete for program {}", program_id);
        Ok(())
    }

    /// Loads a ProgramV2 from storage
    pub fn load(storage: Rc<Storage>, program_id: &Uuid) -> Result<Self, ProgramError> {
        let key = format!("program_v2_{}", program_id);
        let mut program: ProgramV2 = storage
            .get(&key)?
            .ok_or(ProgramError::ProgramNotFound(*program_id))?;

        program.storage = Some(storage.clone());
        program.protocol.set_storage(storage.clone());

        // State is already loaded as part of the program struct
        // Recreate SetupEngine if protocol supports it
        program.setup_engine = Self::try_create_setup_engine(&program.protocol);

        Ok(program)
    }

    /// Saves the program to storage
    ///
    /// Following Program legacy pattern, this saves the complete program struct
    /// which includes the state as a field
    pub fn save(&self) -> Result<(), ProgramError> {
        let storage = self
            .storage
            .as_ref()
            .ok_or_else(|| {
                ProgramError::ProgramNotFound(self.program_id)
            })?;

        storage.set(&self.storage_key(), self, None)?;
        Ok(())
    }

    /// Main tick function - drives the program forward
    pub fn tick(&mut self, program_context: &mut ProgramContext) -> Result<(), BitVMXError> {
        match &self.state {
            ProgramState::New => {
                info!("ProgramV2: State is New, transitioning to SettingUpV2");
                // Use SettingUpV2 - SetupEngine manages the actual setup flow
                // No SettingUpState needed - SetupEngine tracks its own state
                self.state = ProgramState::SettingUpV2;
            }
            ProgramState::SettingUpV2 => {
                // SetupEngine drives the entire setup flow
                if let Some(engine) = &mut self.setup_engine {
                    // Use SetupEngine to drive setup
                    let data_to_send = engine.tick(&mut self.protocol, &self.participants, program_context)?;
                    let is_complete = engine.is_complete();

                    // Send data if generated
                    if let Some(data) = data_to_send {
                        // Send the data to other participants
                        self.broadcast_setup_data(data, program_context)?;

                        // Mark as sent
                        if let Some(engine) = &mut self.setup_engine {
                            engine.mark_current_step_sent()?;
                        }
                    }

                    // Check if setup is complete
                    if is_complete {
                        info!("ProgramV2: SetupEngine completed all steps, building protocol");
                        self.build_protocol(&program_context)?;
                        self.state = ProgramState::Monitoring;
                        info!("ProgramV2: Protocol built, transitioning to Monitoring state");
                    }
                } else {
                    error!("ProgramV2: Protocol doesn't use SetupEngine - this shouldn't happen");
                    return Err(BitVMXError::InvalidMessage(
                        "Protocol must implement UsesSetupSteps for ProgramV2".to_string(),
                    ));
                }
            }
            ProgramState::Monitoring => {
                // After the protocol is ready, we need to monitor the transactions on blockchain
                info!("ProgramV2: Setting up blockchain monitoring");

                // Get transactions and UTXOs to monitor from the protocol
                let (txns_to_monitor, vouts_to_monitor) =
                    self.protocol.get_transactions_to_monitor(program_context)?;

                // Create context for monitoring
                let context = Context::ProgramId(self.program_id);
                let context_str = context.to_string()?;

                // Register transactions to monitor
                if !txns_to_monitor.is_empty() {
                    info!(
                        "ProgramV2: Monitoring {} transactions for program {}",
                        txns_to_monitor.len(),
                        self.program_id
                    );
                    let txs_to_monitor = TypesToMonitor::Transactions(txns_to_monitor, context_str.clone());
                    program_context.bitcoin_coordinator.monitor(txs_to_monitor)?;
                }

                // Register specific UTXOs (vouts) to monitor for spending
                for (txid, vout) in vouts_to_monitor {
                    info!(
                        "ProgramV2: Monitoring vout {} of txid {} for program {}",
                        vout, txid, self.program_id
                    );
                    let vout_to_monitor = TypesToMonitor::SpendingUTXOTransaction(txid, vout, context_str.clone());
                    program_context.bitcoin_coordinator.monitor(vout_to_monitor)?;
                }

                // Transition to Ready state - monitoring is now active
                self.state = ProgramState::Ready;
                info!("ProgramV2: Monitoring setup complete, transitioning to Ready state");
            }
            ProgramState::Ready => {
                // Protocol is ready and monitoring is active
                // Just waiting for blockchain events via notify_news()
                debug!("ProgramV2: In Ready state - monitoring active, waiting for events");
            }
            ProgramState::SettingUp(_) => {
                // This should never happen for ProgramV2 - we use SettingUpV2
                // But handle it gracefully for forward compatibility
                error!("ProgramV2: Unexpected SettingUp state - should be SettingUpV2");
                return Err(BitVMXError::InvalidMessage(
                    "ProgramV2 should use SettingUpV2, not SettingUp".to_string(),
                ));
            }
        }

        // Save program (includes state) at the end of every tick
        self.save()?;
        Ok(())
    }

    /// Broadcasts setup data to all participants
    ///
    /// Uses `CommsMessageType::SetupStepData` which is a generic message type for
    /// any SetupEngine step data. The actual step type (keys, nonces, signatures, etc.)
    /// is determined by the SetupEngine's current step, not by the message type.
    ///
    /// This is different from Program (legacy) which uses specific message types
    /// (Keys, PublicNonces, PartialSignatures) for each step.
    fn broadcast_setup_data(
        &self,
        data: Vec<u8>,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let my_pubkey_hash = program_context.comms.get_pubk_hash()?;

        for participant in &self.participants {
            if participant.comms_address.pubkey_hash != my_pubkey_hash {
                debug!(
                    "ProgramV2: Sending setup data to {}",
                    participant.comms_address.pubkey_hash
                );

                // Use SetupStepData message type for generic SetupEngine data
                // The actual step type (keys, nonces, etc.) is determined by SetupEngine
                request(
                    &program_context.comms,
                    &program_context.key_chain,
                    &self.program_id,
                    participant.comms_address.clone(),
                    CommsMessageType::SetupStepData,
                    data.clone(),
                )?;
            }
        }

        Ok(())
    }

    /// Receives setup data from another participant
    ///
    /// This handles messages with type `CommsMessageType::SetupStepData`.
    /// The data is passed to the current SetupStep for verification and processing.
    pub fn receive_setup_data(
        &mut self,
        data: &[u8],
        from: &PubKeyHash,
        program_context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        // Find the participant
        let from_participant = self
            .participants
            .iter()
            .find(|p| &p.comms_address.pubkey_hash == from)
            .ok_or_else(|| {
                BitVMXError::InvalidMessage(format!("Unknown participant: {}", from))
            })?
            .clone();

        if let Some(engine) = &mut self.setup_engine {
            engine.receive_current_step_data(
                data,
                &from_participant,
                &self.protocol,
                &self.participants,
                program_context,
            )?;

            // Try to advance after receiving data
            engine.try_advance_current_step(&self.protocol, &self.participants, program_context)?;
        }

        self.save()?;
        Ok(())
    }

    /// Builds the protocol after all setup steps are complete
    ///
    /// This method:
    /// 1. Collects all participant keys from globals
    /// 2. Passes them to protocol.build()
    /// 3. The protocol is responsible for its own MuSig2 aggregation
    ///
    /// NOTE: Unlike Program::build_protocol(), this does NOT compute aggregated keys.
    /// Each protocol must handle its own aggregation in its build() method.
    fn build_protocol(&mut self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        use std::collections::HashMap;

        info!("ProgramV2: Building protocol {}", self.program_id);

        // Collect all participant keys from globals
        // These were stored by KeysStep during setup
        let all_keys_var = program_context
            .globals
            .get_var(&self.protocol.context().id, "all_participant_keys")?
            .ok_or_else(|| BitVMXError::InvalidMessage("all_participant_keys not found in globals".to_string()))?;

        let all_keys_json = all_keys_var.string()?;

        let all_keys: Vec<ParticipantKeys> = serde_json::from_str(&all_keys_json)
            .map_err(|e| BitVMXError::InvalidMessage(format!("Failed to parse keys: {}", e)))?;

        info!(
            "ProgramV2: Collected {} participant keys for protocol build",
            all_keys.len()
        );

        // Call protocol.build() with empty computed_aggregated
        // Protocols using ProgramV2 should ignore this parameter and do their own aggregation
        let empty_aggregated = HashMap::new();
        self.protocol.build(all_keys, empty_aggregated, program_context)?;

        info!("ProgramV2: Protocol build complete");
        Ok(())
    }

    /// Returns the protocol ID
    pub fn protocol_id(&self) -> Uuid {
        self.protocol.context().id
    }

    /// Returns the program state
    pub fn state(&self) -> &ProgramState {
        &self.state
    }

    /// Returns whether the program is complete
    pub fn is_complete(&self) -> bool {
        matches!(
            self.state,
            ProgramState::Monitoring | ProgramState::Ready
        )
    }

    /// Finds a participant's address by their pubkey hash
    pub fn get_address_from_pubkey_hash(
        &self,
        pubkey_hash: &PubKeyHash,
    ) -> Result<CommsAddress, BitVMXError> {
        for p in &self.participants {
            if &p.comms_address.pubkey_hash == pubkey_hash {
                return Ok(p.comms_address.clone());
            }
        }
        Err(BitVMXError::CommsCommunicationError)
    }

    /// Main entry point for processing incoming communication messages
    ///
    /// Routes SetupStepData messages to receive_setup_data()
    pub fn process_comms_message(
        &mut self,
        comms_address: &PubKeyHash,
        msg_type: &CommsMessageType,
        data: Vec<u8>,
        program_context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        debug!("ProgramV2: Message received: {:?}", msg_type);

        match msg_type {
            CommsMessageType::SetupStepData => {
                self.receive_setup_data(&data, comms_address, program_context)?;
            }
            CommsMessageType::VerificationKey | CommsMessageType::VerificationKeyRequest => {
                debug!("ProgramV2: Verification key message handled upstream, ignoring");
            }
            CommsMessageType::Broadcasted => {
                debug!("ProgramV2: Broadcasted message should be handled upstream");
            }
            _ => {
                // Other message types are for Program legacy
                debug!(
                    "ProgramV2: Ignoring message type {:?} - not supported by ProgramV2",
                    msg_type
                );
            }
        }

        Ok(())
    }

    /// Gets a transaction by name from the protocol
    pub fn get_transaction_by_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        let (tx, _speedup) = self.protocol.get_transaction_by_name(name, context)?;
        Ok(tx)
    }

    /// Gets a transaction by ID
    pub fn get_tx_by_id(&self, txid: Txid) -> Result<Transaction, BitVMXError> {
        self.protocol
            .get_transaction_by_id(&txid)
            .map_err(|e| BitVMXError::InvalidMessage(format!("Transaction not found: {}", e)))
    }

    /// Dispatches (broadcasts) a transaction by name
    pub fn dispatch_transaction_name(
        &mut self,
        name: &str,
        program_context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        let (tx, speedup) = self.protocol.get_transaction_by_name(name, program_context)?;
        let context = Context::ProgramId(self.program_id);

        info!(
            "ProgramV2: Dispatching transaction: {} with speedup: {:?}",
            tx.compute_txid(),
            speedup.is_some()
        );

        program_context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            context.to_string()?,
            None,
        )?;

        Ok(())
    }

    /// Notifies the protocol about blockchain events (transaction confirmations, etc.)
    pub fn notify_news(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let participant_keys: Vec<&ParticipantKeys> = self
            .participants
            .iter()
            .filter_map(|p| p.keys.as_ref())
            .collect();

        self.protocol.notify_news(
            tx_id,
            vout,
            tx_status,
            context,
            program_context,
            participant_keys,
        )?;
        Ok(())
    }
}
