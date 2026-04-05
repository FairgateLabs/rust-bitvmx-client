use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::garbled_messages::GarbledJobType;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;
use uuid::Uuid;

use crate::{
    bitvmx::Context,
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
            return Ok(Some(Vec::new()));
        }

        let output_dir = format!("runs/gc/{}/{}", config.role, protocol_id);
        std::fs::create_dir_all(&output_dir)?;

        //TODO: Input bytes will be removed
        const INPUT_BYTES: &[u8] = &[0, 0, 1];
        let prove_job = DispatcherJob {
            job_id: Context::SetupStep(
                protocol_id,
                self.step_name().to_string(),
                "generate".to_string(),
            )
            .to_string()?,
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

    fn receive_dispatcher_result(
        &self,
        result: Value,
        sub_step: &str,
        _program_context: &mut ProgramContext,
    ) -> Result<Vec<u8>, BitVMXError> {
        if sub_step == "generate" {
            let gc_proof_path = result["proof_path"].as_str().unwrap().to_string();
            info!("[prover] Proof generated at path: {}", gc_proof_path);
            info!("[prover] Proofs generated");
            info!("  digest_io: {}", result["digest_io"]);
            info!("  digest_labels: {}", result["digest_labels"]);
            info!("  digest_lamport: {}", result["digest_lamport"]);
        }

        //covnert result into vec<u8>
        let result_bytes = serde_json::to_vec(&result)?;

        Ok(result_bytes)
    }

    fn verify_received(
        &self,
        data: &[u8],
        _from_participant: &CommsAddress,
        protocol: &ProtocolType,
        _participants: &[CommsAddress],
        context: &mut ProgramContext,
        your_data: bool,
    ) -> Result<(), BitVMXError> {
        let protocol_id = protocol.context().id;

        if your_data {
            return Ok(());
        }

        let config = GCConfiguration::load(&protocol_id, &context.globals)?;
        if config.role == ParticipantRole::Prover {
            if data.len() != 0 {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Expected empty data for non-prover role, but got: {:?}",
                    data
                )));
            }
            info!( "Received expected empty message from Garbler step for non-prover role. Protocol ID: {}", protocol_id);
            return Ok(());
        }

        info!(
            "Received data for Garbler step. Protocol ID: {}",
            protocol_id
        );
        let value: Value = serde_json::from_slice(data).map_err(|e| {
            BitVMXError::InvalidMessage(format!("Failed to deserialize garbler data: {}", e))
        })?;

        info!("Data content (hex): {:?}", value);

        Ok(())
    }

    fn can_advance(
        &self,
        protocol: &ProtocolType,
        _participants: &[CommsAddress],
        context: &ProgramContext,
    ) -> Result<bool, BitVMXError> {
        let protocol_id = protocol.context().id;

        let config = GCConfiguration::load(&protocol_id, &context.globals)?;
        if config.role == ParticipantRole::Prover {
            // Prover can advance immediately after generating the proof
            return Ok(true);
        }

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
