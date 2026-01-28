#![cfg(test)]

use anyhow::Result;
use bitvmx_client::program::variables::VariableTypes;
use bitvmx_client::types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel};
use common::{
    config_trace, get_all, init_bitvmx, prepare_bitcoin, send_all,
};
use tracing::info;
use uuid::Uuid;

mod common;

/// Test aggregated key protocol (implemented with ProgramV2 and SetupEngine)
#[ignore]
#[test]
pub fn test_aggregated_key() -> Result<()> {
    config_trace();

    let (_bitcoin_client, bitcoind, _wallet) = prepare_bitcoin()?;

    // Initialize 3 BitVMX instances (1 leader + 2 non-leaders)
    let (bitvmx_op1, _address_op1, bridge_op1, _) = init_bitvmx("op_1", false)?;
    let (bitvmx_op2, _address_op2, bridge_op2, _) = init_bitvmx("op_2", false)?;
    let (bitvmx_op3, _address_op3, bridge_op3, _) = init_bitvmx("op_3", false)?;

    let mut instances = vec![bitvmx_op1, bitvmx_op2, bitvmx_op3];
    let channels = vec![bridge_op1.clone(), bridge_op2.clone(), bridge_op3.clone()];

    let identifiers = [
        instances[0].get_components_config().bitvmx.clone(),
        instances[1].get_components_config().bitvmx.clone(),
        instances[2].get_components_config().bitvmx.clone(),
    ];

    let id_channel_pairs: Vec<ParticipantChannel> = identifiers
        .clone()
        .into_iter()
        .zip(channels.clone().into_iter())
        .map(|(identifier, channel)| ParticipantChannel { id: identifier, channel })
        .collect();

    info!("================================================");
    info!("Syncing Bitcoin blockchain");
    info!("================================================");

    // Sync Bitcoin blockchain
    for _ in 0..101 {
        for instance in instances.iter_mut() {
            instance.process_bitcoin_updates()?;
        }
    }

    info!("================================================");
    info!("Getting participant addresses");
    info!("================================================");

    // Get communication addresses from all participants
    let command = IncomingBitVMXApiMessages::GetCommInfo(Uuid::new_v4()).to_string()?;
    send_all(&id_channel_pairs, &command)?;
    let comm_info: Vec<OutgoingBitVMXApiMessages> = get_all(&channels, &mut instances, false)?;
    let addresses = comm_info
        .iter()
        .map(|msg| msg.comm_info().unwrap().1)
        .collect::<Vec<_>>();

    info!("Op1 (Leader) address: {:?}", addresses[0]);
    info!("Op2 (Non-leader) address: {:?}", addresses[1]);
    info!("Op3 (Non-leader) address: {:?}", addresses[2]);

    info!("================================================");
    info!("Setting up aggregated public key");
    info!("================================================");

    // Setup aggregated public key for the aggregated key protocol
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(
        aggregation_id,
        addresses.clone(),
        None,
        0, // Op1 is leader (index 0)
    )
    .to_string()?;
    send_all(&id_channel_pairs, &command)?;

    let msgs = get_all(&channels, &mut instances, false)?;
    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    info!("Aggregated public key: {}", aggregated_pub_key);

    // AggregatedKeyProtocol suppresses SetupCompleted (send_setup_completed() returns false)
    // because SetupKey callers only expect the AggregatedPubkey response.
    // No need to drain any extra messages here.

    info!("================================================");
    info!("Verifying Aggregated Key Result - Aggregated MuSig2 Key");
    info!("================================================");

    // The AggregatedKeyProtocol stores the final aggregated key in globals
    // under the variable name "final_aggregated_key"
    // IMPORTANT: Use aggregation_id so GetVar knows which program's globals to query
    let get_key_command = IncomingBitVMXApiMessages::GetVar(
        aggregation_id,
        "final_aggregated_key".to_string(),
    )
    .to_string()?;

    // Query the aggregated key from all participants
    send_all(&id_channel_pairs, &get_key_command)?;
    let key_responses = get_all(&channels, &mut instances, false)?;

    // All participants should return the same aggregated key
    let mut aggregated_keys = Vec::new();
    for (i, response) in key_responses.iter().enumerate() {
        if let Some((_, key_name, key_value)) = response.variable() {
            info!("Participant {} aggregated key variable: {} = {:?}", i, key_name, key_value);

            assert_eq!(key_name, "final_aggregated_key",
                "Variable name should be 'final_aggregated_key'");

            if let VariableTypes::String(key_str) = key_value {
                info!("Participant {} final aggregated MuSig2 key: {}", i, key_str);
                aggregated_keys.push(key_str.clone());
            } else {
                panic!("Expected String variable type for aggregated key");
            }
        } else {
            panic!("Participant {} did not return the aggregated key variable", i);
        }
    }

    // Verify all three participants have the same aggregated key
    assert_eq!(aggregated_keys.len(), 3, "Should have 3 aggregated keys");
    assert_eq!(aggregated_keys[0], aggregated_keys[1],
        "All participants should compute the same aggregated MuSig2 key");
    assert_eq!(aggregated_keys[0], aggregated_keys[2],
        "All participants should compute the same aggregated MuSig2 key");

    info!("Aggregated key protocol successful! All three participants computed the same aggregated key");
    info!("   Aggregated MuSig2 Key: {}", aggregated_keys[0]);

    info!("================================================");
    info!("Test completed successfully!");
    info!("================================================");

    info!("Stopping bitcoind");
    if let Some(bitcoind) = bitcoind {
        bitcoind.stop()?;
    }

    Ok(())
}

/// Test single-participant aggregated key protocol
/// Verifies that SetupEngine handles a single participant naturally
/// without any special-case bypass in ProgramV2::setup()
#[ignore]
#[test]
pub fn test_aggregated_key_single_participant() -> Result<()> {
    config_trace();

    let (_bitcoin_client, bitcoind, _wallet) = prepare_bitcoin()?;

    // Initialize just 1 BitVMX instance
    let (bitvmx_op1, _address_op1, bridge_op1, _) = init_bitvmx("op_1", false)?;

    let mut instances = vec![bitvmx_op1];
    let channels = vec![bridge_op1.clone()];

    let identifiers = [
        instances[0].get_components_config().bitvmx.clone(),
    ];

    let id_channel_pairs: Vec<ParticipantChannel> = identifiers
        .clone()
        .into_iter()
        .zip(channels.clone().into_iter())
        .map(|(identifier, channel)| ParticipantChannel { id: identifier, channel })
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
    info!("Getting participant address");
    info!("================================================");

    let command = IncomingBitVMXApiMessages::GetCommInfo(Uuid::new_v4()).to_string()?;
    send_all(&id_channel_pairs, &command)?;
    let comm_info: Vec<OutgoingBitVMXApiMessages> = get_all(&channels, &mut instances, false)?;
    let addresses = comm_info
        .iter()
        .map(|msg| msg.comm_info().unwrap().1)
        .collect::<Vec<_>>();

    info!("Op1 (sole participant) address: {:?}", addresses[0]);

    info!("================================================");
    info!("Setting up single-participant AggregatedKeyProtocol via SetupV2");
    info!("================================================");

    let program_id = Uuid::new_v4();
    info!("Program ID: {}", program_id);

    let aggregated_key_config = AggregatedKeyConfig::new(program_id);
    aggregated_key_config.setup(&id_channel_pairs, addresses.clone(), 0)?;

    info!("================================================");
    info!("Waiting for setup completion (single participant)");
    info!("================================================");

    // SetupEngine should handle single participant naturally:
    // Tick 1: Generate keys, store own data, broadcast to 0 others, mark self complete
    // Tick 2: can_advance() -> true, on_step_complete(), build_protocol()
    // Tick 3: Monitoring -> Ready, sends SetupCompleted
    let setup_responses = get_all(&channels, &mut instances, false)?;

    for (i, response) in setup_responses.iter().enumerate() {
        info!("Setup response from participant {}: {:?}", i, response);
        assert!(
            matches!(response, OutgoingBitVMXApiMessages::SetupCompleted(_)),
            "Setup should complete successfully for single participant"
        );
    }

    info!("================================================");
    info!("Verifying Aggregated Key Result");
    info!("================================================");

    // Tick a few times to ensure Ready state
    for _ in 0..10 {
        for instance in instances.iter_mut() {
            instance.tick()?;
        }
        std::thread::sleep(std::time::Duration::from_millis(LOCAL_SLEEP_MS));
    }

    let get_key_command = IncomingBitVMXApiMessages::GetVar(
        program_id,
        "final_aggregated_key".to_string(),
    )
    .to_string()?;

    send_all(&id_channel_pairs, &get_key_command)?;
    let key_responses = get_all(&channels, &mut instances, false)?;

    for (i, response) in key_responses.iter().enumerate() {
        if let Some((_, key_name, key_value)) = response.variable() {
            assert_eq!(key_name, "final_aggregated_key",
                "Variable name should be 'final_aggregated_key'");

            if let VariableTypes::String(key_str) = key_value {
                info!("Single participant aggregated key: {}", key_str);
                assert!(!key_str.is_empty(), "Key should not be empty");
            } else {
                panic!("Expected String variable type for aggregated key");
            }
        } else {
            panic!("Participant {} did not return the aggregated key variable", i);
        }
    }

    info!("================================================");
    info!("Single-participant test completed successfully!");
    info!("================================================");

    if let Some(bitcoind) = bitcoind {
        bitcoind.stop()?;
    }

    Ok(())
}

