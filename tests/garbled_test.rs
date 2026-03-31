#![cfg(test)]

use anyhow::Result;
use bitvmx_broker::{
    channel::channel::DualChannel,
    identification::{allow_list::AllowList, identifier::Identifier},
    rpc::{tls_helper::Cert, BrokerConfig},
};
use bitvmx_client::{
    config::Config,
    program::{setup::steps::GarbledHandler, variables::VariableTypes},
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel},
};
use bitvmx_job_dispatcher::{dispatcher_job::ResultMessage, helper::PingMessage};
use bitvmx_settings::settings;
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

mod common;
use common::{config_trace, get_all, init_bitvmx, prepare_bitcoin_guarded, send_all, tick};

/// Mirrors the MockGarbledJob struct from the client's async_dispatcher_step.rs
#[derive(Debug, Deserialize)]
struct MockGarbledJob {
    job_id: String,
    job_type: MockGarbledJobType,
}

#[derive(Debug, Deserialize)]
enum MockGarbledJobType {
    Prove(#[allow(dead_code)] Vec<u8>, String, String),
    Verify(#[allow(dead_code)] Vec<serde_json::Value>),
}

/// Mock result matching the garbled-dispatcher's ProveResult format
#[derive(Debug, Serialize)]
struct MockProveResult {
    r#type: String,
    status: String,
    circuit_type: String,
    num_gates: u32,
    num_inputs: u32,
    digest_circ: String,
    digest_ct: String,
    digest_io: String,
    proof_path: String,
}

/// Mock result for verification jobs
#[derive(Debug, Serialize)]
struct MockVerifyResult {
    r#type: String,
    status: String,
}

/// Creates a DualChannel that acts as the mock garbled dispatcher.
///
/// Reuses the prover key with a distinct ID (99) so it has a unique identity
/// on the broker, separate from any real dispatchers.
fn create_mock_garbled_channel(config: &Config) -> Result<(DualChannel, Identifier)> {
    let allow_list = AllowList::from_file(&config.broker.allow_list)?;
    let broker_config = BrokerConfig::new(config.broker.port, None, config.broker.get_pubk_hash()?);

    let priv_key = settings::decrypt_or_read_file(&config.testing.prover.priv_key)?;
    let cert = Cert::new_with_privk(&priv_key)?;
    let pubkey_hash = cert.get_pubk_hash()?;

    let garbled_id: u8 = 99; // distinct ID for the mock garbled dispatcher
    let channel = DualChannel::new(&broker_config, cert, Some(garbled_id), allow_list)?;

    let identifier = Identifier {
        pubkey_hash,
        id: garbled_id,
    };

    Ok((channel, identifier))
}

/// What kind of job the mock dispatcher processed.
#[derive(Debug, Clone, Copy, PartialEq)]
enum MockJobProcessed {
    None,
    Prove,
    Verify,
}

/// Processes one pending message from the mock garbled dispatcher channel.
///
/// If there's a garbled job request, creates and sends back a mock result.
fn process_mock_garbled_dispatcher(channel: &DualChannel) -> Result<MockJobProcessed> {
    match channel.recv()? {
        Some((msg, from)) => {
            // Handle ping
            if let Ok(PingMessage::Ping) = serde_json::from_str::<PingMessage>(&msg) {
                let pong = serde_json::to_string(&PingMessage::Pong)?;
                channel.send(&from, pong)?;
                return Ok(MockJobProcessed::None);
            }

            // Handle garbled job
            let job: MockGarbledJob = serde_json::from_str(&msg)?;
            info!(
                "Mock garbled dispatcher: received job {} ({:?})",
                job.job_id, job.job_type
            );

            let (job_kind, result_json) = match &job.job_type {
                MockGarbledJobType::Prove(_, circuit, out) => {
                    let result = MockProveResult {
                        r#type: "ProveResult".to_string(),
                        status: "OK".to_string(),
                        circuit_type: circuit.clone(),
                        num_gates: 42,
                        num_inputs: 3,
                        digest_circ: "test_digest_circ_001".to_string(),
                        digest_ct: "test_digest_ct_002".to_string(),
                        digest_io: "test_digest_io_003".to_string(),
                        proof_path: format!("{}/proof.bin", out),
                    };
                    (MockJobProcessed::Prove, serde_json::to_string(&result)?)
                }
                MockGarbledJobType::Verify(_data) => {
                    info!("Mock garbled dispatcher: verifying garbled data");
                    let result = MockVerifyResult {
                        r#type: "VerifyResult".to_string(),
                        status: "OK".to_string(),
                    };
                    (MockJobProcessed::Verify, serde_json::to_string(&result)?)
                }
            };

            let result_message = ResultMessage {
                job_id: job.job_id,
                result: result_json,
            };

            channel.send(&from, serde_json::to_string(&result_message)?)?;
            info!("Mock garbled dispatcher: sent result");
            Ok(job_kind)
        }
        None => Ok(MockJobProcessed::None),
    }
}

/// Test the garbled protocol with async garbled circuit setup step.
///
/// This test exercises the complete async setup flow:
/// 1. Keys step: participants exchange keys (synchronous)
/// 2. GarbledCircuits step: each participant sends a job to the mock garbled dispatcher
///    and waits for the result (asynchronous)
/// 3. After both steps complete, the setup is finalized
#[ignore]
#[test]
pub fn test_garbled_setup() -> Result<()> {
    config_trace();

    let (_bitcoin_client, _bitcoind_guard, _wallet) = prepare_bitcoin_guarded()?;

    // Initialize 2 BitVMX instances
    let config_op1 = Config::new(Some("config/op_1.yaml".to_string()))?;
    let config_op2 = Config::new(Some("config/op_2.yaml".to_string()))?;
    let (mut bitvmx_op1, _addr1, bridge_op1, _) = init_bitvmx("op_1", false)?;
    let (mut bitvmx_op2, _addr2, bridge_op2, _) = init_bitvmx("op_2", false)?;

    // Each operator has its own broker, so we need a mock garbled channel per broker
    let (mock_garbled_channel_op1, garbled_identifier) =
        create_mock_garbled_channel(&config_op1)?;
    let (mock_garbled_channel_op2, _) = create_mock_garbled_channel(&config_op2)?;

    // Inject the garbled dispatcher identifier and handler into both instances
    bitvmx_op1.set_garbled_identifier(garbled_identifier.clone());
    bitvmx_op1.register_async_step_handler("garbled_circuits", GarbledHandler.into());
    bitvmx_op2.set_garbled_identifier(garbled_identifier.clone());
    bitvmx_op2.register_async_step_handler("garbled_circuits", GarbledHandler.into());

    let mut instances = vec![bitvmx_op1, bitvmx_op2];
    let channels = vec![bridge_op1.clone(), bridge_op2.clone()];

    let identifiers = [
        instances[0].get_components_config().bitvmx.clone(),
        instances[1].get_components_config().bitvmx.clone(),
    ];

    let id_channel_pairs: Vec<ParticipantChannel> = identifiers
        .into_iter()
        .zip(channels.clone().into_iter())
        .map(|(id, channel)| ParticipantChannel { id, channel })
        .collect();

    info!("================================================");
    info!("Syncing Bitcoin blockchain");
    info!("================================================");

    for _ in 0..101 {
        for instance in instances.iter_mut() {
            instance.process_bitcoin_updates()?;
        }
    }

    info!("================================================");
    info!("Getting participant addresses");
    info!("================================================");

    let command = IncomingBitVMXApiMessages::GetCommInfo(Uuid::new_v4()).to_string()?;
    send_all(&id_channel_pairs, &command)?;
    let comm_info: Vec<OutgoingBitVMXApiMessages> = get_all(&channels, &mut instances, false)?;
    let addresses = comm_info
        .iter()
        .map(|msg| msg.comm_info().unwrap().1)
        .collect::<Vec<_>>();

    info!("Op1 (Leader) address: {:?}", addresses[0]);
    info!("Op2 (Non-leader) address: {:?}", addresses[1]);

    info!("================================================");
    info!("Setting up garbled protocol");
    info!("================================================");

    let program_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::Setup(
        program_id,
        "garbled".to_string(),
        addresses.clone(),
        0, // Op1 is leader
    )
    .to_string()?;
    send_all(&id_channel_pairs, &command)?;

    info!("================================================");
    info!("Running setup loop (Keys + GarbledCircuits steps)");
    info!("================================================");

    // Drive the setup loop: tick all instances and process mock garbled dispatcher
    // The flow is:
    //   1. Keys step completes synchronously via tick + comms
    //   2. GarbledCircuits step sends job → WaitingGeneration
    //   3. Mock dispatcher receives job → sends result
    //   4. Client receives result → WaitingForParticipants → Completed
    let mut setup_completed_count = 0;
    let mut prove_jobs_count = 0;
    let mut verify_jobs_count = 0;
    let max_iterations = 5000;

    for i in 0..max_iterations {
        // Process mock garbled dispatchers (one per broker)
        for channel in [&mock_garbled_channel_op1, &mock_garbled_channel_op2] {
            match process_mock_garbled_dispatcher(channel)? {
                MockJobProcessed::Prove => prove_jobs_count += 1,
                MockJobProcessed::Verify => verify_jobs_count += 1,
                MockJobProcessed::None => {}
            }
        }

        // Tick all instances
        for instance in instances.iter_mut() {
            tick(instance)?;
        }

        // Check for SetupCompleted messages
        for channel in &channels {
            if let Some((msg, _from)) = channel.recv()? {
                let decoded = OutgoingBitVMXApiMessages::from_string(&msg)?;
                if let OutgoingBitVMXApiMessages::SetupCompleted(id) = &decoded {
                    info!("Received SetupCompleted for program {}", id);
                    setup_completed_count += 1;
                }
            }
        }

        if setup_completed_count >= 2 {
            info!("Both participants completed setup at iteration {}", i);
            break;
        }

        if i % 500 == 0 && i > 0 {
            info!(
                "Setup loop iteration {} (completed: {})",
                i, setup_completed_count
            );
        }

        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    assert!(
        setup_completed_count >= 2,
        "Expected both participants to complete setup, got {}",
        setup_completed_count
    );

    // Verify the mock dispatcher processed the expected job types:
    // - 2 Prove jobs (one per participant for generation)
    // - 2 Verify jobs (one per participant for verification)
    assert_eq!(
        prove_jobs_count, 2,
        "Expected 2 Prove jobs (one per participant), got {}",
        prove_jobs_count
    );
    assert_eq!(
        verify_jobs_count, 2,
        "Expected 2 Verify jobs (one per participant), got {}",
        verify_jobs_count
    );

    info!("================================================");
    info!("Verifying garbled circuit data in globals");
    info!("================================================");

    // Query the garbled circuit data from all participants
    let get_garbled_command =
        IncomingBitVMXApiMessages::GetVar(program_id, "all_garbled_circuits".to_string())
            .to_string()?;

    send_all(&id_channel_pairs, &get_garbled_command)?;
    let garbled_responses = get_all(&channels, &mut instances, false)?;

    for (i, response) in garbled_responses.iter().enumerate() {
        if let Some((_, key_name, key_value)) = response.variable() {
            info!(
                "Participant {} garbled data: {} = {:?}",
                i, key_name, key_value
            );
            assert_eq!(key_name, "all_garbled_circuits");

            if let VariableTypes::String(data_json) = key_value {
                // Parse and verify the garbled data
                let data: Vec<serde_json::Value> = serde_json::from_str(&data_json)?;
                assert_eq!(
                    data.len(),
                    2,
                    "Should have garbled data from both participants"
                );

                // Verify each participant's data has the expected mock digests
                for participant_data in &data {
                    assert_eq!(
                        participant_data["digest_circ"].as_str().unwrap(),
                        "test_digest_circ_001"
                    );
                    assert_eq!(
                        participant_data["digest_ct"].as_str().unwrap(),
                        "test_digest_ct_002"
                    );
                    assert_eq!(
                        participant_data["digest_io"].as_str().unwrap(),
                        "test_digest_io_003"
                    );
                }

                info!(
                    "Participant {} has valid garbled circuit data from {} participants",
                    i,
                    data.len()
                );
            } else {
                panic!(
                    "Expected String variable for garbled data, got {:?}",
                    key_value
                );
            }
        } else {
            panic!("Participant {} did not return the garbled data variable", i);
        }
    }

    // Also verify the aggregated key from the Keys step
    let get_key_command =
        IncomingBitVMXApiMessages::GetVar(program_id, "garbled_aggregated_key".to_string())
            .to_string()?;
    send_all(&id_channel_pairs, &get_key_command)?;
    let key_responses = get_all(&channels, &mut instances, false)?;

    let mut keys = Vec::new();
    for (i, response) in key_responses.iter().enumerate() {
        if let Some((_, _, key_value)) = response.variable() {
            if let VariableTypes::PubKey(key) = key_value {
                info!("Participant {} aggregated key: {}", i, key);
                keys.push(key.to_string());
            }
        }
    }
    assert_eq!(
        keys.len(),
        2,
        "Both participants should have the aggregated key"
    );
    assert_eq!(
        keys[0], keys[1],
        "Both participants should have the same aggregated key"
    );

    info!("================================================");
    info!("Test completed successfully!");
    info!("  - Keys step: completed (aggregated key matches)");
    info!("  - GarbledCircuits step: generation ({} Prove jobs) + verification ({} Verify jobs)", prove_jobs_count, verify_jobs_count);
    info!("  - All garbled data verified across participants");
    info!("================================================");

    Ok(())
}
