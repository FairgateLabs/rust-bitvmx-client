use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::garbled_messages::{
    GCJobProveResult, GarbledJobType, ProofBlob, Sha256CommitmentHex,
};
use bitvmx_settings::settings::decrypt_or_read_file_bytes;
use key_manager::lamport::{
    ExtraData, HashFunction, Lamport, LamportPublicKey, LamportSignature, LamportType,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;
use uuid::Uuid;

use crate::{
    bitvmx::Context,
    comms_helper::CommsMessageType,
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
pub const GC_PUBLIC_INPUT_PK: &str = "GC_PUBLIC_INPUT_PK";
pub const GC_PUBLIC_INPUT_SIGNATURE: &str = "GC_PUBLIC_INPUT_SIGNATURE";

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GCConfiguration {
    pub id: Uuid,
    pub role: ParticipantRole,
    pub circuit: String,
    pub circuit_public_input: Vec<bool>,
}

impl GCConfiguration {
    pub const NAME: &'static str = "gc_configuration";

    pub fn new(
        id: Uuid,
        role: ParticipantRole,
        circuit: String,
        circuit_public_input: Vec<bool>,
    ) -> Self {
        Self {
            id,
            role,
            circuit,
            circuit_public_input,
        }
    }

    pub fn load(id: &Uuid, globals: &Globals) -> Result<Self, BitVMXError> {
        let gc_dispute_configuration = globals.get_var_or_err(id, Self::NAME)?.string()?;
        Ok(serde_json::from_str(&gc_dispute_configuration)?)
    }

    pub fn get_setup_message(&self) -> Result<String, BitVMXError> {
        Ok(VariableTypes::String(serde_json::to_string(&self)?).set_msg(self.id, Self::NAME)?)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProverGarblerData {
    pub proof_blob: ProofBlob,
    pub public_input_signature: Vec<u8>,
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
    ) -> Result<Option<(serde_json::Value, CommsMessageType)>, BitVMXError> {
        let protocol_id = protocol.context().id;

        let config = GCConfiguration::load(&protocol_id, &context.globals)?;

        if config.role != ParticipantRole::Prover {
            return Ok(None);
        }

        let output_dir = format!("runs/gc/{}/{}", config.role, protocol_id);
        std::fs::create_dir_all(&output_dir)?;

        let prove_job = DispatcherJob {
            job_id: Context::SetupStep(
                protocol_id,
                self.step_name().to_string(),
                "generate".to_string(),
                CommsMessageType::GarbledCircuit,
            )
            .to_string()?,
            job_type: GarbledJobType::Prove(config.circuit.clone(), output_dir.clone()),
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
        _msg_type: CommsMessageType,
        sub_step: &str,
        context: &mut ProgramContext,
        protocol_id: &Uuid,
    ) -> Result<Option<Value>, BitVMXError> {
        if sub_step == "generate" {
            let prove_result: GCJobProveResult =
                serde_json::from_value(result.clone()).map_err(|e| {
                    BitVMXError::InvalidMessage(format!(
                        "Failed to deserialize garbler data: {}",
                        e
                    ))
                })?;

            let config = GCConfiguration::load(protocol_id, &context.globals)?;
            import_input_private_keys(&prove_result, &config, context)?;

            info!("[Prover] Imported Garbled Circuit Input Private Key");

            let [public_input_pk, _, _] =
                import_public_keys(&prove_result, &config, context, protocol_id)?;

            info!("[Prover] Imported Garbled Circuit Public Keys");

            let gc_proof_path = &prove_result.proof_path;
            let lamport_proof_path = &prove_result.lamport_proof_path;
            info!("[Prover] Proof generated at path: {}", gc_proof_path);
            info!(
                "[Prover] Lamport proof generated at path: {}",
                lamport_proof_path
            );
            info!("[Prover] Proofs generated");
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

            let public_input_signature = context
                .key_manager
                .sign_lamport_message_by_pubkey(&config.circuit_public_input, &public_input_pk)?;

            let result_bytes = serde_json::to_value(&ProverGarblerData {
                proof_blob,
                public_input_signature: public_input_signature.to_bytes(),
            })?;

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
            return Ok(Some(Value::Null));
        }

        return Err(BitVMXError::InvalidState(format!(
            "Unknown sub_step for GarblerStep result: {}",
            sub_step
        )));
    }

    fn verify_received(
        &self,
        data: Value,
        msg_type: CommsMessageType,
        _from_participant: &CommsAddress,
        protocol: &ProtocolType,
        _participants: &[CommsAddress],
        context: &mut ProgramContext,
        your_data: bool,
    ) -> Result<bool, BitVMXError> {
        if !matches!(msg_type, CommsMessageType::GarbledCircuit) {
            info!(
                "Received message with type {msg_type:?} in GarblerStep, ignoring. Expected type: GarbledCircuit"
            );
            return Ok(false);
        }

        let protocol_id = protocol.context().id;
        let config = GCConfiguration::load(&protocol_id, &context.globals)?;
        let is_prover_data = (config.role == ParticipantRole::Prover && your_data)
            || (!your_data && config.role == ParticipantRole::Verifier);

        info!(
            "role: {:?}, your_data: {your_data}, is_prover_data: {is_prover_data}",
            config.role
        );

        if !is_prover_data {
            if !&data.is_null() {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Expected empty data for non-prover role, but got: {:?}",
                    data
                )));
            }
            info!("Received expected empty message from Garbler step for non-prover role. Protocol ID: {}", protocol_id);

            // The prover MUST NOT continue until the verifier has finished verifying the proof.
            // The verifier MUST signal completion by returning an empty successful result from receive_dispatcher_result.
            // The verifier MUST NOT produce any data in generate_data, it MUST only generate data after successful verification.
            if config.role == ParticipantRole::Prover {
                context.globals.set_var(
                    &protocol_id,
                    GC_CAN_CONTINUE,
                    VariableTypes::Bool(true),
                )?;
            }

            return Ok(true);
        }

        let ProverGarblerData {
            proof_blob,
            public_input_signature,
        } = serde_json::from_value(data).map_err(|e| {
            BitVMXError::InvalidMessage(format!("Failed to deserialize garbler data: {} ", e))
        })?;

        let [public_input_pk, _, _] =
            import_public_keys(&proof_blob.prove_result, &config, context, &protocol_id)?;

        info!("[Verifier] Imported Garbled Circuit Public Keys");

        import_public_input_signature(
            &public_input_signature,
            &config,
            public_input_pk,
            context,
            &protocol_id,
        )?;

        info!("[Verifier] Imported Garbled Circuit Public Input Signature");

        dispatch_proof_verification(proof_blob, context, &config, protocol_id, self.step_name())?;

        Ok(true)
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

fn import_public_input_signature(
    public_input_signature: &Vec<u8>,
    config: &GCConfiguration,
    public_input_pk: LamportPublicKey,
    context: &ProgramContext,
    protocol_id: &Uuid,
) -> Result<(), BitVMXError> {
    let circuit_public_input = &config.circuit_public_input;
    let signature = LamportSignature::from_bytes(
        public_input_signature,
        circuit_public_input.len(),
        LamportType::SHA256,
    )?;

    let (valid_signature, _) = Lamport::new().verify_signature(
        Some(circuit_public_input),
        &signature,
        &public_input_pk,
    )?;

    if !valid_signature {
        return Err(BitVMXError::InvalidInput(
            "Prover provided invalid public input for circuit during garbler setup step"
                .to_string(),
        ));
    }

    context.globals.set_var(
        &protocol_id,
        GC_PUBLIC_INPUT_SIGNATURE,
        VariableTypes::Input(public_input_signature.clone()),
    )?;

    Ok(())
}

fn import_public_keys(
    prove_result: &GCJobProveResult,
    config: &GCConfiguration,
    context: &mut ProgramContext,
    protocol_id: &Uuid,
) -> Result<[LamportPublicKey; 3], BitVMXError> {
    let indices = &prove_result.input_commitment_indices;
    let unordered_commitments = prove_result.sha256_commitments.clone();
    let commitments: Vec<Sha256CommitmentHex> =
        indices.iter().map(|&i| unordered_commitments[i].clone()).collect();

    info!("Total deduped commitments: {}", commitments.len());

    let num_inputs = prove_result.num_inputs;
    let public_input_size = config.circuit_public_input.len();
    let num_outputs = 1; // we assume only one output

    let expected = num_inputs + num_outputs;
    if commitments.len() != expected {
        return Err(BitVMXError::InvalidMessage(format!(
            "Not enough commitments: expected at least {}, got {}",
            expected,
            commitments.len()
        )));
    }

    let public_input_pk = import_public_lamport(
        &commitments[..public_input_size],
        GC_PUBLIC_INPUT_PK,
        &context,
        protocol_id,
    )?;

    let input_pk = import_public_lamport(
        &commitments[public_input_size..num_inputs],
        GC_INPUT_PK,
        &context,
        protocol_id,
    )?;

    let output_pk = import_public_lamport(
        &commitments[num_inputs..],
        GC_OUTPUT_PK,
        &context,
        protocol_id,
    )?;

    Ok([public_input_pk, input_pk, output_pk])
}

fn import_input_private_keys(
    prove_result: &GCJobProveResult,
    config: &GCConfiguration,
    context: &ProgramContext,
) -> Result<(), BitVMXError> {
    let io_inputs_path = &prove_result.io_inputs_path;
    let io_inputs = decrypt_or_read_file_bytes(&io_inputs_path)?;
    let hash_type = LamportType::SHA256;
    let chunks = io_inputs.chunks(hash_type.hash_size());

    let mut bytes_0s: Vec<&[u8]> = Vec::new();
    let mut bytes_1s: Vec<&[u8]> = Vec::new();

    for (i, chunk) in chunks.enumerate() {
        if i % 2 == 0 {
            bytes_0s.push(chunk);
        } else {
            bytes_1s.push(chunk);
        }
    }

    let public_input_size = config.circuit_public_input.len();
    let num_inputs = prove_result.num_inputs;

    context.key_manager.import_lamport_private_key(
        &bytes_0s[..public_input_size].concat(),
        &bytes_1s[..public_input_size].concat(),
        public_input_size,
        hash_type,
    )?;

    context.key_manager.import_lamport_private_key(
        &bytes_0s[public_input_size..num_inputs].concat(),
        &bytes_1s[public_input_size..num_inputs].concat(),
        num_inputs - public_input_size,
        hash_type,
    )?;

    Ok(())
}

fn dispatch_proof_verification(
    proof_blob: ProofBlob,
    context: &ProgramContext,
    config: &GCConfiguration,
    protocol_id: Uuid,
    step_name: &str,
) -> Result<(), BitVMXError> {
    context.globals.set_var(
        &protocol_id,
        GC_PUBLIC_DATA,
        VariableTypes::String(serde_json::to_string(&proof_blob.prove_result)?),
    )?;

    let output_dir = format!("runs/gc/{}/{}", config.role, protocol_id);

    info!("[Verifier] Verifying GC + Lamport proofs...");
    let verify_job = GarbledJobType::Verify(proof_blob, config.circuit.clone(), output_dir.clone());

    let prove_job = DispatcherJob {
        job_id: Context::SetupStep(
            protocol_id,
            step_name.to_string(),
            "verify".to_string(),
            CommsMessageType::GarbledCircuit,
        )
        .to_string()?,
        job_type: verify_job,
    };

    let msg = serde_json::to_string(&prove_job)?;
    context
        .broker_channel
        .send(&context.components_config.garbler, msg)?;

    Ok(())
}

fn import_public_lamport(
    commitments: &[Sha256CommitmentHex],
    name: &str,
    context: &ProgramContext,
    protocol_id: &Uuid,
) -> Result<LamportPublicKey, BitVMXError> {
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

    context.globals.set_var(
        &protocol_id,
        name,
        VariableTypes::LamportPubKey(public_key.clone()),
    )?;

    info!("Lamport imported successfully ({:?})", name);

    Ok(public_key)
}
