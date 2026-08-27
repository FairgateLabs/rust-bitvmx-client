use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use bitvmx_job_dispatcher::dispatcher_job::DispatcherJob;
use bitvmx_job_dispatcher_types::garbled_messages::{
    GCCommitmentsFile, GCJobProveResult, GCJobVerifyResult, GarbledJobType, ProofBlob,
    Sha256CommitmentHex,
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
pub const GC_COMMITMENTS: &str = "GC_COMMITMENTS";
pub const GC_CAN_CONTINUE: &str = "GC_CAN_CONTINUE";
pub const GC_PUBLIC_INPUT_PK: &str = "GC_PUBLIC_INPUT_PK";
pub const GC_PUBLIC_INPUT_SIGNATURE: &str = "GC_PUBLIC_INPUT_SIGNATURE";
const GC_JOB_GENERATE_STEP: &str = "generate";
const GC_JOB_VERIFY_STEP: &str = "verify";

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GCConfiguration {
    pub id: Uuid,
    pub role: ParticipantRole,
    pub circuit: String,
    pub circuit_public_input: Vec<bool>,
    pub import_proof_path: Option<String>,
}

impl GCConfiguration {
    pub const NAME: &'static str = "gc_configuration";

    pub fn new(
        id: Uuid,
        role: ParticipantRole,
        circuit: String,
        circuit_public_input: Vec<bool>,
        import_proof_path: Option<String>,
    ) -> Self {
        Self {
            id,
            role,
            circuit,
            circuit_public_input,
            import_proof_path,
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

    fn generate_data<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &mut ProtocolType,
        context: &mut ProgramContext<BC>,
    ) -> Result<Option<(serde_json::Value, CommsMessageType)>, BitVMXError> {
        let protocol_id = protocol.context().id;

        let config = GCConfiguration::load(&protocol_id, &context.globals)?;

        if config.role != ParticipantRole::Prover {
            return Ok(None);
        }

        let output_dir = format!("runs/gc/{}/{}", config.role, protocol_id);

        let job_type = if let Some(from_path) = config.import_proof_path {
            GarbledJobType::ImportProof(from_path, output_dir)
        } else {
            GarbledJobType::Prove(config.circuit.clone(), output_dir.clone())
        };

        let prove_job = DispatcherJob {
            job_id: Context::SetupStep(
                protocol_id,
                self.step_name().to_string(),
                GC_JOB_GENERATE_STEP.to_string(),
                CommsMessageType::GarbledCircuit,
            )
            .to_string()?,
            job_type,
        };

        let msg = serde_json::to_string(&prove_job)?;
        context
            .broker_channel
            .send_service(&context.components_config.garbler, msg)?;

        Ok(None)
    }

    fn receive_dispatcher_result<BC: BitcoinCoordinatorApi>(
        &self,
        result: Value,
        msg_type: CommsMessageType,
        sub_step: &str,
        context: &mut ProgramContext<BC>,
        protocol_id: &Uuid,
    ) -> Result<Value, BitVMXError> {
        if msg_type != CommsMessageType::GarbledCircuit {
            return Err(BitVMXError::InvalidMessage(format!(
                "Expected message type GarbledCircuit, but got: {:?}",
                msg_type
            )));
        }

        let expected_role = match sub_step {
            GC_JOB_GENERATE_STEP => ParticipantRole::Prover,
            GC_JOB_VERIFY_STEP => ParticipantRole::Verifier,
            _ => {
                return Err(BitVMXError::InvalidState(format!(
                    "Unknown sub_step for GarblerStep result: {}",
                    sub_step
                )));
            }
        };
        let config = GCConfiguration::load(protocol_id, &context.globals)?;
        if config.role != expected_role {
            return Err(BitVMXError::InvalidState(format!(
                "Garbler sub-step '{}' requires role {:?}, but local role is {:?}",
                sub_step, expected_role, config.role
            )));
        }

        if sub_step == GC_JOB_GENERATE_STEP {
            let prove_result: GCJobProveResult =
                serde_json::from_value(result.clone()).map_err(|e| {
                    BitVMXError::InvalidMessage(format!(
                        "Failed to deserialize garbler data: {}",
                        e
                    ))
                })?;

            import_input_private_keys(&prove_result, &config, context)?;

            info!("[Prover] Imported Garbled Circuit Input Private Key");

            let commitments_path = &prove_result.commitments_path;
            let encoded_commitments = std::fs::read(commitments_path)?;

            let commitments: GCCommitmentsFile = serde_json::from_slice(&encoded_commitments)
                .map_err(|e| {
                    BitVMXError::InvalidMessage(format!(
                        "Failed to deserialize commitments data: {} ",
                        e
                    ))
                })?;

            let [public_input_pk, _, _] = import_public_keys(
                &commitments.input_commitment_indices,
                &commitments.sha256_commitments,
                prove_result.num_inputs,
                &config,
                context,
                &protocol_id,
            )?;

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
                commitments: encoded_commitments,
            };

            let public_input_signature = context
                .key_manager
                .sign_lamport_message_by_pubkey(&config.circuit_public_input, &public_input_pk)?;

            let result_bytes = serde_json::to_value(&ProverGarblerData {
                proof_blob,
                public_input_signature: public_input_signature.to_bytes(),
            })?;

            return Ok(result_bytes);
        }

        if sub_step == GC_JOB_VERIFY_STEP {
            let verify_result: GCJobVerifyResult =
                serde_json::from_value(result.clone()).map_err(|e| {
                    BitVMXError::InvalidMessage(format!(
                        "Failed to deserialize verification data: {}",
                        e
                    ))
                })?;

            info!(" result[\"status\"]: {}", verify_result.status);
            info!(" result[\"type\"]: {}", verify_result.r#type);
            info!(" result[\"valid\"]: {}", verify_result.valid);
            info!(
                " result[\"proofs_linked\"]: {}",
                verify_result.proofs_linked
            );

            if !verify_result.valid {
                return Err(BitVMXError::InvalidMessage(format!(
                    "The provided proof is invalid: {:?}",
                    verify_result
                )));
            }

            context
                .globals
                .set_var(protocol_id, GC_CAN_CONTINUE, VariableTypes::Bool(true))?;
            return Ok(Value::Null);
        }

        unreachable!("sub-step was validated before processing")
    }

    fn verify_received<BC: BitcoinCoordinatorApi>(
        &self,
        data: Value,
        msg_type: CommsMessageType,
        _from_participant: &CommsAddress,
        protocol: &ProtocolType,
        _participants: &[CommsAddress],
        context: &mut ProgramContext<BC>,
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

        let encoded_commitments = &proof_blob.commitments;
        let commitments: GCCommitmentsFile =
            serde_json::from_slice(encoded_commitments).map_err(|e| {
                BitVMXError::InvalidMessage(format!(
                    "Failed to deserialize commitments data: {} ",
                    e
                ))
            })?;

        let [public_input_pk, _, _] = import_public_keys(
            &commitments.input_commitment_indices,
            &commitments.sha256_commitments,
            proof_blob.prove_result.num_inputs,
            &config,
            context,
            &protocol_id,
        )?;

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

    fn can_advance<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &ProtocolType,
        _participants: &[CommsAddress],
        context: &ProgramContext<BC>,
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

fn import_public_input_signature<BC: BitcoinCoordinatorApi>(
    public_input_signature: &Vec<u8>,
    config: &GCConfiguration,
    public_input_pk: LamportPublicKey,
    context: &ProgramContext<BC>,
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

fn import_public_keys<BC: BitcoinCoordinatorApi>(
    indices: &[usize],
    unordered_commitments: &[Sha256CommitmentHex],
    num_inputs: usize,
    config: &GCConfiguration,
    context: &mut ProgramContext<BC>,
    protocol_id: &Uuid,
) -> Result<[LamportPublicKey; 3], BitVMXError> {
    let public_input_size = config.circuit_public_input.len();
    let num_outputs = 1usize; // we assume only one output

    if public_input_size > num_inputs {
        return Err(BitVMXError::InvalidMessage(format!(
            "Public input size {} exceeds total input count {}",
            public_input_size, num_inputs
        )));
    }

    let expected = num_inputs.checked_add(num_outputs).ok_or_else(|| {
        BitVMXError::InvalidMessage("Garbler commitment count overflow".to_string())
    })?;
    if indices.len() != expected {
        return Err(BitVMXError::InvalidMessage(format!(
            "Invalid commitment index count: expected {}, got {}",
            expected,
            indices.len()
        )));
    }

    let commitments: Vec<Sha256CommitmentHex> = indices
        .iter()
        .enumerate()
        .map(|(position, &index)| {
            unordered_commitments.get(index).cloned().ok_or_else(|| {
                BitVMXError::InvalidMessage(format!(
                    "Commitment index {} at position {} is out of range for {} commitments",
                    index,
                    position,
                    unordered_commitments.len()
                ))
            })
        })
        .collect::<Result<_, _>>()?;

    info!("Total deduped commitments: {}", commitments.len());

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

fn import_input_private_keys<BC: BitcoinCoordinatorApi>(
    prove_result: &GCJobProveResult,
    config: &GCConfiguration,
    context: &ProgramContext<BC>,
) -> Result<(), BitVMXError> {
    let io_inputs_path = &prove_result.io_inputs_path;
    let io_inputs = decrypt_or_read_file_bytes(&io_inputs_path)?;
    let hash_type = LamportType::SHA256;
    let hash_size = hash_type.hash_size();
    let public_input_size = config.circuit_public_input.len();
    let num_inputs = prove_result.num_inputs;

    if public_input_size > num_inputs {
        return Err(BitVMXError::InvalidMessage(format!(
            "Public input size {} exceeds total input count {}",
            public_input_size, num_inputs
        )));
    }

    let expected_chunks = num_inputs.checked_mul(2).ok_or_else(|| {
        BitVMXError::InvalidMessage("Garbler private-key chunk count overflow".to_string())
    })?;
    let expected_bytes = expected_chunks.checked_mul(hash_size).ok_or_else(|| {
        BitVMXError::InvalidMessage("Garbler private-key byte count overflow".to_string())
    })?;
    if io_inputs.len() != expected_bytes {
        return Err(BitVMXError::InvalidMessage(format!(
            "Invalid garbler private-key data length: expected {} bytes for {} inputs, got {}",
            expected_bytes,
            num_inputs,
            io_inputs.len()
        )));
    }

    let mut bytes_0s: Vec<&[u8]> = Vec::with_capacity(num_inputs);
    let mut bytes_1s: Vec<&[u8]> = Vec::with_capacity(num_inputs);
    for (i, chunk) in io_inputs.chunks_exact(hash_size).enumerate() {
        if i % 2 == 0 {
            bytes_0s.push(chunk);
        } else {
            bytes_1s.push(chunk);
        }
    }

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

fn dispatch_proof_verification<BC: BitcoinCoordinatorApi>(
    proof_blob: ProofBlob,
    context: &ProgramContext<BC>,
    config: &GCConfiguration,
    protocol_id: Uuid,
    step_name: &str,
) -> Result<(), BitVMXError> {
    context.globals.set_var(
        &protocol_id,
        GC_COMMITMENTS,
        VariableTypes::VecNumber(proof_blob.commitments.iter().map(|&n| n as u32).collect()),
    )?;

    let output_dir = format!("runs/gc/{}/{}", config.role, protocol_id);

    info!("[Verifier] Verifying GC + Lamport proofs...");
    let verify_job = GarbledJobType::Verify(proof_blob, config.circuit.clone(), output_dir.clone());

    let prove_job = DispatcherJob {
        job_id: Context::SetupStep(
            protocol_id,
            step_name.to_string(),
            GC_JOB_VERIFY_STEP.to_string(),
            CommsMessageType::GarbledCircuit,
        )
        .to_string()?,
        job_type: verify_job,
    };

    let msg = serde_json::to_string(&prove_job)?;
    context
        .broker_channel
        .send_service(&context.components_config.garbler, msg)?;

    Ok(())
}

fn import_public_lamport<BC: BitcoinCoordinatorApi>(
    commitments: &[Sha256CommitmentHex],
    name: &str,
    context: &ProgramContext<BC>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::protocols::protocol_handler::new_protocol_type;
    use crate::test_utils::{TestProgramContextEnv, TestStorageDir};
    use crate::types::PROGRAM_TYPE_GC_GENERATION;
    use bitcoin::hashes::{sha256, Hash};
    use serde_json::json;

    fn protocol(id: Uuid, dir: &TestStorageDir) -> ProtocolType {
        new_protocol_type(id, PROGRAM_TYPE_GC_GENERATION, 0, dir.storage()).unwrap()
    }

    fn commitment(byte0: u8, byte1: u8) -> Sha256CommitmentHex {
        serde_json::from_value(json!({
            "h0": sha256::Hash::hash(&[byte0; 32]).to_string(),
            "h1": sha256::Hash::hash(&[byte1; 32]).to_string(),
        }))
        .unwrap()
    }

    fn prove_result(num_inputs: usize, input_commitment_indices: Vec<usize>) -> GCJobProveResult {
        serde_json::from_value(json!({
            "status": "ok",
            "type": "prove",
            "circuit_file": "test",
            "num_gates": 0,
            "num_inputs": num_inputs,
            "proof_path": "",
            "lamport_proof_path": "",
            "io_inputs_path": "",
            "commitments_path": "",
            "digest_circ": "",
            "digest_ct": "",
            "digest_io": "",
            "digest_labels": "",
            "digest_lamport": "",
            "garbling_public": { "gates": [] },
            "sha256_commitments": [],
            "input_commitment_indices": input_commitment_indices,
        }))
        .unwrap()
    }

    fn verify_result(valid: bool) -> Value {
        json!({
            "status": "ok",
            "type": "verify",
            "valid": valid,
            "digest_circ": "",
            "digest_ct": "",
            "digest_io": "",
            "digest_labels": "",
            "digest_lamport": "",
            "gc_proof_valid": valid,
            "lamport_proof_valid": valid,
            "proofs_linked": valid,
            "digest_circ_matches": valid,
            "digest_ct_matches": valid,
            "digest_lamport_matches": valid,
            "valid_indices": valid,
            "valid_num_inputs": valid,
        })
    }

    fn store_config(
        context: &ProgramContext<impl BitcoinCoordinatorApi>,
        id: &Uuid,
        role: ParticipantRole,
    ) {
        let config = GCConfiguration::new(*id, role, "test".to_string(), Vec::new(), None);
        context
            .globals
            .set_var(
                id,
                GCConfiguration::NAME,
                VariableTypes::String(serde_json::to_string(&config).unwrap()),
            )
            .unwrap();
    }

    #[test]
    fn configuration_round_trips_and_step_reports_async_behavior() {
        let env = TestProgramContextEnv::new("garbler-configuration").unwrap();
        let id = Uuid::new_v4();
        let config = GCConfiguration::new(
            id,
            ParticipantRole::Verifier,
            "circuit".to_string(),
            vec![true, false],
            Some("proof.bin".to_string()),
        );
        env.context
            .globals
            .set_var(
                &id,
                GCConfiguration::NAME,
                VariableTypes::String(serde_json::to_string(&config).unwrap()),
            )
            .unwrap();

        let loaded = GCConfiguration::load(&id, &env.context.globals).unwrap();
        assert_eq!(loaded.id, id);
        assert_eq!(loaded.role, ParticipantRole::Verifier);
        assert!(config
            .get_setup_message()
            .unwrap()
            .contains(GCConfiguration::NAME));

        let step = GarblerStep::new();
        assert_eq!(step.step_name(), "garbler");
        assert!(step.generate_async());
        assert!(step.verify_async());
    }

    #[test]
    fn generation_dispatches_only_for_prover() {
        let mut env = TestProgramContextEnv::new("garbler-generation").unwrap();
        let dir = TestStorageDir::new("garbler-generation-protocol");
        let id = Uuid::new_v4();
        let mut protocol = protocol(id, &dir);
        let step = GarblerStep::new();

        store_config(&env.context, &id, ParticipantRole::Verifier);
        assert!(step
            .generate_data(&mut protocol, &mut env.context)
            .unwrap()
            .is_none());

        for import_path in [None, Some("existing-proof".to_string())] {
            let config = GCConfiguration::new(
                id,
                ParticipantRole::Prover,
                "test".to_string(),
                Vec::new(),
                import_path,
            );
            env.context
                .globals
                .set_var(
                    &id,
                    GCConfiguration::NAME,
                    VariableTypes::String(serde_json::to_string(&config).unwrap()),
                )
                .unwrap();
            assert!(step
                .generate_data(&mut protocol, &mut env.context)
                .unwrap()
                .is_none());
        }
    }

    #[test]
    fn malformed_public_key_data_returns_errors() {
        let mut env = TestProgramContextEnv::new("garbler-malformed-public-keys").unwrap();
        let id = Uuid::new_v4();

        let too_many_public_inputs = GCConfiguration::new(
            id,
            ParticipantRole::Prover,
            "test".to_string(),
            vec![true],
            None,
        );
        let result =
            import_public_keys(&[0], &[], 0, &too_many_public_inputs, &mut env.context, &id);
        assert!(matches!(result, Err(BitVMXError::InvalidMessage(_))));

        let no_public_inputs = GCConfiguration::new(
            id,
            ParticipantRole::Prover,
            "test".to_string(),
            Vec::new(),
            None,
        );
        let result = import_public_keys(&[0], &[], 0, &no_public_inputs, &mut env.context, &id);
        assert!(matches!(result, Err(BitVMXError::InvalidMessage(_))));
    }

    #[test]
    fn public_and_private_lamport_material_can_be_imported() {
        let mut env = TestProgramContextEnv::new("garbler-valid-key-import").unwrap();
        let files = TestStorageDir::new("garbler-key-files");
        std::fs::create_dir_all(files.path()).unwrap();
        let id = Uuid::new_v4();
        let config = GCConfiguration::new(
            id,
            ParticipantRole::Prover,
            "test".to_string(),
            vec![true],
            None,
        );
        let commitments = vec![commitment(1, 2), commitment(3, 4), commitment(5, 6)];
        let mut result = prove_result(2, vec![0, 1, 2]);
        result.io_inputs_path = format!("{}/inputs.bin", files.path());
        let private_bytes = [vec![1; 32], vec![2; 32], vec![3; 32], vec![4; 32]].concat();
        std::fs::write(&result.io_inputs_path, private_bytes).unwrap();

        import_input_private_keys(&result, &config, &env.context).unwrap();
        let [public_input, _, _] =
            import_public_keys(&[0, 1, 2], &commitments, 2, &config, &mut env.context, &id)
                .unwrap();

        let signature = env
            .context
            .key_manager
            .sign_lamport_message_by_pubkey(&config.circuit_public_input, &public_input)
            .unwrap()
            .to_bytes();
        import_public_input_signature(&signature, &config, public_input, &env.context, &id)
            .unwrap();
        assert!(env
            .context
            .globals
            .get_var(&id, GC_PUBLIC_INPUT_SIGNATURE)
            .unwrap()
            .is_some());
    }

    #[test]
    fn malformed_lamport_material_returns_errors() {
        let env = TestProgramContextEnv::new("garbler-malformed-material").unwrap();
        let files = TestStorageDir::new("garbler-malformed-files");
        std::fs::create_dir_all(files.path()).unwrap();
        let id = Uuid::new_v4();
        let config = GCConfiguration::new(
            id,
            ParticipantRole::Prover,
            "test".to_string(),
            vec![true],
            None,
        );
        let mut result = prove_result(1, vec![0, 1]);
        result.io_inputs_path = format!("{}/short.bin", files.path());
        std::fs::write(&result.io_inputs_path, [0u8; 3]).unwrap();
        assert!(matches!(
            import_input_private_keys(&result, &config, &env.context),
            Err(BitVMXError::InvalidMessage(_))
        ));

        let invalid: Sha256CommitmentHex =
            serde_json::from_value(json!({"h0": "not-hex", "h1": "00"})).unwrap();
        assert!(matches!(
            import_public_lamport(&[invalid], "bad", &env.context, &id),
            Err(BitVMXError::InvalidMessage(_))
        ));
    }

    #[test]
    fn verifier_result_and_empty_messages_control_advancement() {
        let mut env = TestProgramContextEnv::new("garbler-verifier-result").unwrap();
        let dir = TestStorageDir::new("garbler-verifier-protocol");
        let id = Uuid::new_v4();
        let protocol = protocol(id, &dir);
        let step = GarblerStep::new();
        let participant = env.self_address().unwrap();

        store_config(&env.context, &id, ParticipantRole::Verifier);
        assert!(!step
            .verify_received(
                Value::Null,
                CommsMessageType::Keys,
                &participant,
                &protocol,
                &[],
                &mut env.context,
                true,
            )
            .unwrap());
        assert!(step
            .verify_received(
                Value::Null,
                CommsMessageType::GarbledCircuit,
                &participant,
                &protocol,
                &[],
                &mut env.context,
                true,
            )
            .unwrap());
        assert!(!step.can_advance(&protocol, &[], &env.context).unwrap());
        assert!(matches!(
            step.verify_received(
                json!({"unexpected": true}),
                CommsMessageType::GarbledCircuit,
                &participant,
                &protocol,
                &[],
                &mut env.context,
                true,
            ),
            Err(BitVMXError::InvalidMessage(_))
        ));

        assert!(matches!(
            step.receive_dispatcher_result(
                verify_result(false),
                CommsMessageType::GarbledCircuit,
                GC_JOB_VERIFY_STEP,
                &mut env.context,
                &id,
            ),
            Err(BitVMXError::InvalidMessage(_))
        ));
        assert_eq!(
            step.receive_dispatcher_result(
                verify_result(true),
                CommsMessageType::GarbledCircuit,
                GC_JOB_VERIFY_STEP,
                &mut env.context,
                &id,
            )
            .unwrap(),
            Value::Null
        );
        assert!(step.can_advance(&protocol, &[], &env.context).unwrap());

        store_config(&env.context, &id, ParticipantRole::Prover);
        assert!(step
            .verify_received(
                Value::Null,
                CommsMessageType::GarbledCircuit,
                &participant,
                &protocol,
                &[],
                &mut env.context,
                false,
            )
            .unwrap());
    }

    #[test]
    fn dispatcher_rejects_wrong_type_unknown_step_and_bad_payload() {
        let mut env = TestProgramContextEnv::new("garbler-dispatcher-errors").unwrap();
        let id = Uuid::new_v4();
        let step = GarblerStep::new();
        store_config(&env.context, &id, ParticipantRole::Prover);

        assert!(matches!(
            step.receive_dispatcher_result(
                Value::Null,
                CommsMessageType::Keys,
                GC_JOB_GENERATE_STEP,
                &mut env.context,
                &id,
            ),
            Err(BitVMXError::InvalidMessage(_))
        ));
        assert!(matches!(
            step.receive_dispatcher_result(
                Value::Null,
                CommsMessageType::GarbledCircuit,
                "unknown",
                &mut env.context,
                &id,
            ),
            Err(BitVMXError::InvalidState(_))
        ));
        assert!(matches!(
            step.receive_dispatcher_result(
                Value::Null,
                CommsMessageType::GarbledCircuit,
                GC_JOB_GENERATE_STEP,
                &mut env.context,
                &id,
            ),
            Err(BitVMXError::InvalidMessage(_))
        ));
    }

    #[test]
    fn dispatcher_sub_steps_require_the_corresponding_role() {
        let mut env = TestProgramContextEnv::new("garbler-dispatcher-role").unwrap();
        let id = Uuid::new_v4();
        let step = GarblerStep::new();

        store_config(&env.context, &id, ParticipantRole::Verifier);
        let result = step.receive_dispatcher_result(
            Value::Null,
            CommsMessageType::GarbledCircuit,
            GC_JOB_GENERATE_STEP,
            &mut env.context,
            &id,
        );
        assert!(matches!(result, Err(BitVMXError::InvalidState(_))));

        store_config(&env.context, &id, ParticipantRole::Prover);
        let result = step.receive_dispatcher_result(
            Value::Null,
            CommsMessageType::GarbledCircuit,
            GC_JOB_VERIFY_STEP,
            &mut env.context,
            &id,
        );
        assert!(matches!(result, Err(BitVMXError::InvalidState(_))));
    }
}
