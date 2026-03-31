use crate::{
    config::ComponentsConfig,
    errors::BitVMXError,
    program::{
        participant::{get_index_by_pubkey_hash, CommsAddress},
        protocols::protocol_handler::{ProtocolHandler, ProtocolType},
        setup::SetupStep,
        variables::VariableTypes,
    },
    types::ProgramContext,
};
use bitvmx_broker::identification::identifier::Identifier;
use enum_dispatch::enum_dispatch;
use tracing::{debug, info};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// AsyncStepHandler trait
// ---------------------------------------------------------------------------

/// Trait for handling async dispatcher interactions in setup steps.
///
/// Implementations define how to create jobs for a specific dispatcher,
/// parse its results, and validate data received from peers.
///
/// ## Adding a new async dispatcher type
///
/// 1. Implement this trait for your handler
/// 2. Add a variant to `AsyncStepHandlerEnum` and `SetupStepName`
/// 3. Map the step name to `AsyncDispatcher(AsyncDispatcherStep::new("..."))` in `create_setup_step`
/// 4. Register the handler on `ProgramContext` before running the protocol:
#[enum_dispatch]
pub trait AsyncStepHandler {
    /// Create a serialized job message to send to the dispatcher.
    ///
    /// Returns the serialized JSON string ready to send via broker.
    fn create_job(
        &self,
        protocol_id: &Uuid,
        protocol: &mut ProtocolType,
    ) -> Result<String, BitVMXError>;

    /// Parse the raw dispatcher result and return a JSON string to broadcast to peers.
    ///
    /// The returned string is stored in globals and sent to other participants.
    fn parse_result(&self, result: &[u8]) -> Result<String, BitVMXError>;

    /// Validate data received from a peer before storing.
    fn validate_received(&self, data: &str) -> Result<(), BitVMXError>;

    /// Return the dispatcher Identifier from the components config.
    fn dispatcher_id(&self, config: &ComponentsConfig) -> Option<Identifier>;

    /// Create a serialized verification job from all participants' data.
    ///
    /// Called after all participants' data has been received, before the step completes.
    /// The dispatcher verifies that the collected data is consistent/valid.
    fn create_verify_job(
        &self,
        protocol_id: &Uuid,
        all_data: &[String],
    ) -> Result<String, BitVMXError>;

    /// Parse the verification result from the dispatcher.
    ///
    /// Should return `Ok(())` if verification passed, or an error if it failed.
    fn parse_verify_result(&self, result: &[u8]) -> Result<(), BitVMXError>;
}

// ---------------------------------------------------------------------------
// AsyncDispatcherStep
// ---------------------------------------------------------------------------

/// Generic async setup step that delegates to an [`AsyncStepHandler`].
///
/// This step sends a job to an external dispatcher, waits for the result,
/// then exchanges it with all participants. The specific job format and
/// result parsing are determined by the handler registered in `ProgramContext`.
///
/// ## Flow
/// 1. `generate_data()` → handler creates job → sends to dispatcher → returns `None`
/// 2. Engine waits in `WaitingGeneration` state
/// 3. Dispatcher result arrives → `receive_generation_result()` → handler parses result
/// 4. Engine transitions to `WaitingForParticipants` and broadcasts data
/// 5. All participants exchange and verify data via handler
#[derive(Debug, Clone)]
pub struct AsyncDispatcherStep {
    name: String,
}

impl AsyncDispatcherStep {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl SetupStep for AsyncDispatcherStep {
    fn step_name(&self) -> &str {
        &self.name
    }

    fn is_async(&self) -> bool {
        true
    }

    fn generate_data(
        &self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        let protocol_id = protocol.context().id;

        info!(
            "AsyncDispatcherStep[{}]: Sending job for protocol {}",
            self.name, protocol_id
        );

        // Extract what we need from the handler, then drop the borrow on context
        let (msg, dispatcher_id) = {
            let handler = context.async_step_handlers.get(&self.name).ok_or_else(|| {
                BitVMXError::InvalidMessage(format!(
                    "No AsyncStepHandler registered for step '{}'",
                    self.name
                ))
            })?;

            let msg = handler.create_job(&protocol_id, protocol)?;
            let id = handler
                .dispatcher_id(&context.components_config)
                .ok_or_else(|| {
                    BitVMXError::InvalidMessage(format!(
                        "Dispatcher not configured for async step '{}'",
                        self.name
                    ))
                })?;
            (msg, id)
        };

        context.broker_channel.send(&dispatcher_id, msg)?;
        info!("AsyncDispatcherStep[{}]: Job sent to dispatcher", self.name);

        Ok(None)
    }

    fn receive_generation_result(
        &self,
        result: &[u8],
        protocol: &mut ProtocolType,
        context: &mut ProgramContext,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        let protocol_id = protocol.context().id;

        info!(
            "AsyncDispatcherStep[{}]: Received async result ({} bytes) for protocol {}",
            self.name,
            result.len(),
            protocol_id
        );

        let data_string = {
            let handler = context.async_step_handlers.get(&self.name).ok_or_else(|| {
                BitVMXError::InvalidMessage(format!(
                    "No AsyncStepHandler registered for step '{}'",
                    self.name
                ))
            })?;
            handler.parse_result(result)?
        };

        debug!(
            "AsyncDispatcherStep[{}]: Parsed result ({} chars)",
            self.name,
            data_string.len()
        );

        // Store in globals
        context.globals.set_var(
            &protocol_id,
            &format!("my_{}", self.name),
            VariableTypes::String(data_string.clone()),
        )?;

        // Convert to bytes for broadcast
        Ok(Some(data_string.into_bytes()))
    }

    fn verify_received(
        &self,
        data: &[u8],
        from_participant: &CommsAddress,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        let protocol_id = protocol.context().id;

        debug!(
            "AsyncDispatcherStep[{}]: Verifying data from participant {}",
            self.name, from_participant.pubkey_hash
        );

        let data_str = std::str::from_utf8(data).map_err(|e| {
            BitVMXError::InvalidMessage(format!("Invalid UTF-8 in async step data: {}", e))
        })?;

        // Validate via handler
        {
            let handler = context.async_step_handlers.get(&self.name).ok_or_else(|| {
                BitVMXError::InvalidMessage(format!(
                    "No AsyncStepHandler registered for step '{}'",
                    self.name
                ))
            })?;
            handler.validate_received(data_str)?;
        }

        // Find participant index and store
        let idx = get_index_by_pubkey_hash(participants, &from_participant.pubkey_hash)?;

        context.globals.set_var(
            &protocol_id,
            &format!("participant_{}_{}", idx, self.name),
            VariableTypes::String(data_str.to_string()),
        )?;

        debug!(
            "AsyncDispatcherStep[{}]: Stored data from participant {} at index {}",
            self.name, from_participant.pubkey_hash, idx
        );

        Ok(())
    }

    fn can_advance(
        &self,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &ProgramContext,
    ) -> Result<bool, BitVMXError> {
        let protocol_id = protocol.context().id;

        for (idx, participant) in participants.iter().enumerate() {
            if context
                .globals
                .get_var(&protocol_id, &format!("participant_{}_{}", idx, self.name))?
                .is_none()
            {
                debug!(
                    "AsyncDispatcherStep[{}]: Waiting for data from participant {} (index {})",
                    self.name, participant.pubkey_hash, idx
                );
                return Ok(false);
            }
        }

        debug!(
            "AsyncDispatcherStep[{}]: All {} participants have sent their data",
            self.name,
            participants.len()
        );
        Ok(true)
    }

    fn send_verification_job(
        &self,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        let protocol_id = protocol.context().id;

        info!(
            "AsyncDispatcherStep[{}]: Collecting data for verification job",
            self.name
        );

        // Collect all participants' data from globals
        let all_data: Vec<String> = participants
            .iter()
            .enumerate()
            .map(|(idx, _)| {
                context
                    .globals
                    .get_var(&protocol_id, &format!("participant_{}_{}", idx, self.name))?
                    .ok_or_else(|| {
                        BitVMXError::InvalidMessage(format!(
                            "Missing data for participant {} in step '{}'",
                            idx, self.name
                        ))
                    })?
                    .string()
            })
            .collect::<Result<_, _>>()?;

        // Create verification job via handler, then drop the borrow
        let (msg, dispatcher_id) = {
            let handler = context.async_step_handlers.get(&self.name).ok_or_else(|| {
                BitVMXError::InvalidMessage(format!(
                    "No AsyncStepHandler registered for step '{}'",
                    self.name
                ))
            })?;

            let msg = handler.create_verify_job(&protocol_id, &all_data)?;
            let id = handler
                .dispatcher_id(&context.components_config)
                .ok_or_else(|| {
                    BitVMXError::InvalidMessage(format!(
                        "Dispatcher not configured for async step '{}'",
                        self.name
                    ))
                })?;
            (msg, id)
        };

        context.broker_channel.send(&dispatcher_id, msg)?;
        info!(
            "AsyncDispatcherStep[{}]: Verification job sent to dispatcher",
            self.name
        );

        Ok(())
    }

    fn receive_verification_result(
        &self,
        result: &[u8],
        _protocol: &ProtocolType,
        context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        info!(
            "AsyncDispatcherStep[{}]: Received verification result ({} bytes)",
            self.name,
            result.len()
        );

        let handler = context.async_step_handlers.get(&self.name).ok_or_else(|| {
            BitVMXError::InvalidMessage(format!(
                "No AsyncStepHandler registered for step '{}'",
                self.name
            ))
        })?;

        handler.parse_verify_result(result)?;

        info!(
            "AsyncDispatcherStep[{}]: Verification passed",
            self.name
        );

        Ok(())
    }

    fn on_step_complete(
        &self,
        protocol: &ProtocolType,
        participants: &[CommsAddress],
        context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        let protocol_id = protocol.context().id;

        debug!(
            "AsyncDispatcherStep[{}]: Collecting all participant data",
            self.name
        );

        // Collect all participant data as JSON values
        let mut all_data: Vec<serde_json::Value> = Vec::new();
        for (idx, _) in participants.iter().enumerate() {
            let data_json = context
                .globals
                .get_var(&protocol_id, &format!("participant_{}_{}", idx, self.name))?
                .ok_or_else(|| {
                    BitVMXError::InvalidMessage(format!(
                        "Missing data for participant {} in step '{}'",
                        idx, self.name
                    ))
                })?
                .string()?;

            let value: serde_json::Value = serde_json::from_str(&data_json)?;
            all_data.push(value);
        }

        // Store the complete collection
        context.globals.set_var(
            &protocol_id,
            &format!("all_{}", self.name),
            VariableTypes::String(serde_json::to_string(&all_data)?),
        )?;

        info!(
            "AsyncDispatcherStep[{}]: Completed with {} participants' data",
            self.name,
            all_data.len()
        );

        Ok(())
    }
}
