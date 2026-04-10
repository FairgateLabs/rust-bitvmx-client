use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::garbled_messages::{
    GCJobProveResult, GarbledJobType, ProofBlob, Sha256CommitmentHex,
};
use bitvmx_settings::settings::decrypt_or_read_file_bytes;
use key_manager::lamport::{ExtraData, HashFunction, LamportPublicKey, LamportType};
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

pub const GC_INPUT_PK: &str = "GC_INPUT_PK";
pub const GC_OUTPUT_PK: &str = "GC_OUTPUT_PK";
pub const GC_PUBLIC_DATA: &str = "GC_PUBLIC_DATA";
pub const GC_CAN_CONTINUE: &str = "GC_CAN_CONTINUE";

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
        context: &mut ProgramContext,
        protocol_id: &Uuid,
    ) -> Result<Option<Vec<u8>>, BitVMXError> {
        if sub_step == "generate" {
            let prove_result: GCJobProveResult =
                serde_json::from_value(result.clone()).map_err(|e| {
                    BitVMXError::InvalidMessage(format!(
                        "Failed to deserialize garbler data: {}",
                        e
                    ))
                })?;

            let gc_proof_path = &prove_result.proof_path;
            let lamport_proof_path = &prove_result.lamport_proof_path;

            let io_inputs_path = &prove_result.io_inputs_path;
            let io_inputs = decrypt_or_read_file_bytes(&io_inputs_path)?;
            let hash_type = LamportType::SHA256;
            let chunks = io_inputs.chunks(hash_type.hash_size());
            let message_bit_length = chunks.len() / 2;

            let mut bytes_0s: Vec<u8> = Vec::new();
            let mut bytes_1s: Vec<u8> = Vec::new();

            for (i, chunk) in chunks.enumerate() {
                if i % 2 == 0 {
                    bytes_0s.extend_from_slice(chunk);
                } else {
                    bytes_1s.extend_from_slice(chunk);
                }
            }

            context.key_manager.import_lamport_private_key(
                &bytes_0s,
                &bytes_1s,
                message_bit_length,
                hash_type,
            )?;

            info!("[Prover] Imported Garbled Circuit Input Private Key");

            let mut commitments = prove_result.sha256_commitments.clone();
            commitments.dedup_by(|a, b| a.h0 == b.h0 && a.h1 == b.h1);
            let num_inputs = prove_result.num_inputs;

            import_public_lamport(
                &commitments[..num_inputs],
                GC_INPUT_PK,
                &context,
                protocol_id,
            )?;
            import_public_lamport(
                &commitments[num_inputs..],
                GC_OUTPUT_PK,
                &context,
                protocol_id,
            )?;

            info!("[prover] Proof generated at path: {}", gc_proof_path);
            info!("[prover] Lamport proof generated at path: {}", lamport_proof_path);
            info!("[prover] Proofs generated");
            info!("  digest_io: {}", &prove_result.digest_io);
            info!("  digest_labels: {}", &prove_result.digest_labels);
            info!("  digest_lamport: {}", &prove_result.digest_lamport);

            let gc_proof = std::fs::read(gc_proof_path)?;
            let lamport_proof = std::fs::read(lamport_proof_path)?;

            let proof_blob = ProofBlob {
                prove_result,
                gc_proof,
                lamport_proof,
            };

            let result_bytes = serde_json::to_vec(&proof_blob)?;

            return Ok(Some(result_bytes));
        }

        if sub_step == "verify" {
            info!(" result[\"status\"]: {}", result["status"]);
            info!(" result[\"type\"]: {}", result["type"]);
            info!(" result[\"valid\"]: {}", result["valid"]);
            info!(" result[\"proofs_linked\"]: {}", result["proofs_linked"]);

            if !result["valid"].as_bool().unwrap_or(false) {
                return Err(BitVMXError::InvalidMessage(format!(
                    "The provided proof is invalid: {result}"
                )));
            }

            context
                .globals
                .set_var(protocol_id, GC_CAN_CONTINUE, VariableTypes::Bool(true))?;
            return Ok(Some(Vec::new()));
        }

        return Err(BitVMXError::InvalidState(format!(
            "Unknown sub_step for GarblerStep result: {}",
            sub_step
        )));
    }

    fn verify_received(
        &self,
        data: &[u8],
        _from_participant: &CommsAddress,
        protocol: &ProtocolType,
        _participants: &[CommsAddress],
        context: &mut ProgramContext,
        your_data: bool,
    ) -> Result<bool, BitVMXError> {
        let protocol_id = protocol.context().id;
        let config = GCConfiguration::load(&protocol_id, &context.globals)?;
        let is_prover_data = (config.role == ParticipantRole::Prover && your_data)
            || (!your_data && config.role == ParticipantRole::Verifier);

        info!(
            "role: {:?}, your_data: {your_data}, is_prover_data: {is_prover_data}",
            config.role
        );

        if !is_prover_data {
            if data.len() != 0 {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Expected empty data for non-prover role, but got: {:?}",
                    data
                )));
            }
            info!("Received expected empty message from Garbler step for non-prover role. Protocol ID: {}", protocol_id);

            if config.role == ParticipantRole::Prover {
                context.globals.set_var(
                    &protocol_id,
                    GC_CAN_CONTINUE,
                    VariableTypes::Bool(true),
                )?;
            }

            return Ok(true);
        }

        let proof_blob: ProofBlob = serde_json::from_slice(data).map_err(|e| {
            BitVMXError::InvalidMessage(format!(
                "Failed to deserialize garbler data: {} \n {:?}",
                e,
                serde_json::to_value(data)
            ))
        })?;

        let mut commitments = proof_blob.prove_result.sha256_commitments.clone();
        commitments.dedup_by(|a, b| a.h0 == b.h0 && a.h1 == b.h1);
        let num_inputs = proof_blob.prove_result.num_inputs;

        import_public_lamport(
            &commitments[..num_inputs],
            GC_INPUT_PK,
            &context,
            &protocol_id,
        )?;
        import_public_lamport(
            &commitments[num_inputs..],
            GC_OUTPUT_PK,
            &context,
            &protocol_id,
        )?;

        if config.role == ParticipantRole::Prover {
            Ok(false)
        } else {
            // role == Verifier

            context.globals.set_var(
                &protocol_id,
                GC_PUBLIC_DATA,
                VariableTypes::String(serde_json::to_string(&proof_blob.prove_result)?),
            )?;

            let output_dir = format!("runs/gc/{}/{}", config.role, protocol_id);

            info!("[verifier] Verifying GC + Lamport proofs...");
            let verify_job =
                GarbledJobType::Verify(proof_blob, config.circuit.clone(), output_dir.clone());

            let prove_job = DispatcherJob {
                job_id: Context::SetupStep(
                    protocol_id,
                    self.step_name().to_string(),
                    "verify".to_string(),
                )
                .to_string()?,
                job_type: verify_job,
            };

            let msg = serde_json::to_string(&prove_job)?;
            context
                .broker_channel
                .send(&context.components_config.garbler, msg)?;

            Ok(true)
        }
    }

    fn can_advance(
        &self,
        protocol: &ProtocolType,
        _participants: &[CommsAddress],
        context: &ProgramContext,
    ) -> Result<bool, BitVMXError> {
        let protocol_id = protocol.context().id;

        let can_continue = context
            .globals
            .get_var(&protocol_id, GC_CAN_CONTINUE)?
            .and_then(|v| v.bool().ok())
            .unwrap_or(false);

        Ok(can_continue)
    }

    fn generate_async(&self) -> bool {
        true
    }

    fn verify_async(&self) -> bool {
        true
    }
}

fn import_public_lamport(
    commitments: &[Sha256CommitmentHex],
    name: &str,
    context: &ProgramContext,
    protocol_id: &Uuid,
) -> Result<(), BitVMXError> {
    let h0s = commitments
        .into_iter()
        .map(|c| {
            hex::decode(&c.h0).map_err(|_| {
                BitVMXError::InvalidMessage(
                    "Could not parse commitment, invalid hex value".to_string(),
                )
            })
        })
        .collect::<Result<Vec<Vec<u8>>, BitVMXError>>()?
        .concat();

    let h1s = commitments
        .into_iter()
        .map(|c| {
            hex::decode(&c.h1).map_err(|_| {
                BitVMXError::InvalidMessage(
                    "Could not parse commitment, invalid hex value".to_string(),
                )
            })
        })
        .collect::<Result<Vec<Vec<u8>>, BitVMXError>>()?
        .concat();

    // FIXME: it's invalid to have a derivation index for an imported key, but the current
    // implementation of the ProtocolScript needs the ScriptKey to have one, even if it's not used.
    let extra_data = ExtraData::new(commitments.len(), Some(0));
    let public_key = LamportPublicKey::from_bytes_splitted(
        &h0s,
        &h1s,
        commitments.len(),
        LamportType::SHA256,
        true,
        Some(extra_data),
    )?;

    context
        .globals
        .set_var(&protocol_id, name, VariableTypes::LamportPubKey(public_key))?;

    info!("Lamport imported successfully ({:?})", name);

    Ok(())
}
