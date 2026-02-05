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

            if let VariableTypes::PubKey(key) = key_value {
                let key_str = key.to_string();
                info!("Participant {} final aggregated MuSig2 key: {}", i, key_str);
                aggregated_keys.push(key_str);
            } else {
                panic!("Expected PubKey variable type for aggregated key, got {:?}", key_value);
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

/// Test that single-participant aggregated key protocol returns an error
/// MuSig2 requires at least 2 participants, so a single participant should fail
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
    info!("Setting up single-participant AggregatedKeyProtocol via SetupKey");
    info!("================================================");

    let aggregation_id = Uuid::new_v4();
    info!("Aggregation ID: {}", aggregation_id);

    // Use SetupKey API (same as multi-participant test)
    let command = IncomingBitVMXApiMessages::SetupKey(
        aggregation_id,
        addresses.clone(),
        None,
        0, // Op1 is leader (and only participant)
    )
    .to_string()?;
    send_all(&id_channel_pairs, &command)?;

    info!("================================================");
    info!("Expecting error: Aggregated key requires at least 2 participants");
    info!("================================================");

    // The protocol should fail because MuSig2 requires at least 2 participants
    // The error occurs during build_protocol(), so we won't receive AggregatedPubkey
    // Instead, the error will propagate and the test should fail with the expected error
    let result = get_all(&channels, &mut instances, false);
    
    // The error should occur during protocol build, so get_all might timeout
    // or we might not receive AggregatedPubkey. Either way, we verify the error
    // by checking that we don't get a successful AggregatedPubkey response
    match result {
        Ok(msgs) => {
            // If we get messages, verify none of them are AggregatedPubkey
            let has_aggregated_pubkey = msgs.iter().any(|msg| msg.aggregated_pub_key().is_some());
            assert!(!has_aggregated_pubkey, 
                "Should not receive AggregatedPubkey with only 1 participant");
        }
        Err(e) => {
            // If we get an error, verify it's the expected one
            let error_msg = format!("{}", e);
            assert!(error_msg.contains("requires at least 2 participants") || 
                    error_msg.contains("not enough participants"),
                "Expected error about requiring at least 2 participants, got: {}", error_msg);
        }
    }

    info!("================================================");
    info!("Single-participant test correctly returned error!");
    info!("================================================");

    if let Some(bitcoind) = bitcoind {
        bitcoind.stop()?;
    }

    Ok(())
}

