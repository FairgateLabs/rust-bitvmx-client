use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::garbled_messages::GarbledJobType;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::{CommsAddress, ParticipantRole},
        protocols::protocol_handler::{ProtocolHandler, ProtocolType},
        setup::SetupStep,
        variables::{Globals, VariableTypes},
    },
    types::ProgramContext,
};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GCConfiguration {
    pub id: Uuid,
    pub role: ParticipantRole,
    pub circuit: String,
}

impl GCConfiguration {
    pub const NAME: &'static str = "gc_configuration";

    pub fn new(id: Uuid, role: ParticipantRole, circuit: String) -> Self {
        Self { id, role, circuit }
    }

    pub fn load(id: &Uuid, globals: &Globals) -> Result<Self, BitVMXError> {
        let gc_dispute_configuration = globals.get_var_or_err(id, Self::NAME)?.string()?;
        Ok(serde_json::from_str(&gc_dispute_configuration)?)
    }

    pub fn get_setup_message(&self) -> Result<String, BitVMXError> {
        Ok(VariableTypes::String(serde_json::to_string(&self)?).set_msg(self.id, Self::NAME)?)
    }
}

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
        context: &mut ProgramContext,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        let protocol_id = protocol.context().id;

        let config = GCConfiguration::load(&protocol_id, &context.globals)?;

        if config.role != ParticipantRole::Prover {
            return Ok(None);
        }

        let output_dir = format!("runs/gc/{}/{}", config.role, protocol_id);
        std::fs::create_dir_all(&output_dir)?;

        //TODO: Input bytes will be removed
        const INPUT_BYTES: &[u8] = &[0, 0, 1];
        let prove_job = DispatcherJob {
            job_id: format!("prove_job_{}", protocol_id),
            job_type: GarbledJobType::Prove(
                INPUT_BYTES.to_vec(),
                config.circuit.clone(),
                output_dir.clone(),
            ),
        };

        let msg = serde_json::to_string(&prove_job)?;
        context
            .broker_channel
            .send(&context.components_config.garbler, msg)?;

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
