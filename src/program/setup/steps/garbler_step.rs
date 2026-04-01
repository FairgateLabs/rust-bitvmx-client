use crate::{
    errors::BitVMXError,
    program::{
        participant::CommsAddress,
        protocols::protocol_handler::{ProtocolHandler, ProtocolType},
        setup::SetupStep,
    },
    types::ProgramContext,
};

/// Template step for exchanging public keys in MuSig2 protocols.
///
/// This step orchestrates the key generation and exchange process by:
/// 1. Calling the protocol's `generate_keys()` method to create protocol-specific keys
/// 2. Serializing and exchanging the keys with other participants
/// 3. Verifying and storing received keys from all participants
/// 4. Aggregating all keys when the step completes
///
/// The generated keys are stored in globals with the following conventions:
/// - Own keys: "my_keys"
/// - Participant i keys: "participant_{i}_keys"
/// - All keys aggregated: "all_participant_keys"
#[derive(Debug, Clone, Default)]
pub struct GarblerStep;

impl GarblerStep {
    pub fn new() -> Self {
        Self
    }
}

impl SetupStep for GarblerStep {
    fn step_name(&self) -> &str {
        "garbler"
    }

    fn generate_data(
        &self,
        protocol: &mut ProtocolType,
        _context: &mut ProgramContext,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        let _protocol_id = protocol.context().id;

        Ok(None)
    }

    fn verify_received(
        &self,
        _data: &[u8],
        _from_participant: &CommsAddress,
        protocol: &ProtocolType,
        _participants: &[CommsAddress],
        _context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        let _protocol_id = protocol.context().id;

        Ok(())
    }

    fn can_advance(
        &self,
        protocol: &ProtocolType,
        _participants: &[CommsAddress],
        _context: &ProgramContext,
    ) -> Result<bool, BitVMXError> {
        let _protocol_id = protocol.context().id;

        Ok(false)
    }

    fn on_step_complete(
        &self,
        protocol: &ProtocolType,
        _participants: &[CommsAddress],
        _context: &mut ProgramContext,
    ) -> Result<(), BitVMXError> {
        let _protocol_id = protocol.context().id;
        Ok(())
    }

    fn generate_async(&self) -> bool {
        true
    }

    fn verify_async(&self) -> bool {
        true
    }
}
