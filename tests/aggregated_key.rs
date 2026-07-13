#![cfg(test)]

use anyhow::Result;
use bitvmx_client::program::variables::VariableTypes;
use bitvmx_client::types::{
    IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel,
};
use common::{config_trace, get_all, init_bitvmx, prepare_bitcoin_guarded, send_all};
use tracing::info;
use uuid::Uuid;

mod common;

/// Test aggregated key protocol (implemented with Program and SetupEngine)
#[ignore = "integration: requires bitcoind"]
#[test]
pub fn test_aggregated_key() -> Result<()> {
    config_trace();

    let number_of_operators = 3;

    let (_bitcoin_client, _bitcoind_guard, _wallet) = prepare_bitcoin_guarded()?;

    // Initialize BitVMX instances dynamically (1 leader + remaining as non-leaders)
    let mut instances = Vec::new();
    let mut channels = Vec::new();

    for i in 1..=number_of_operators {
        let operator_name = format!("op_{}", i);
        let (bitvmx, _address, bridge, _) = init_bitvmx(&operator_name, false)?;
        instances.push(bitvmx);
        channels.push(bridge.clone());
    }

    let identifiers: Vec<_> = instances
        .iter()
        .map(|instance| instance.get_components_config().bitvmx.clone())
        .collect();

    let id_channel_pairs: Vec<ParticipantChannel> = identifiers
        .clone()
        .into_iter()
        .zip(channels.clone().into_iter())
        .map(|(identifier, channel)| ParticipantChannel {
            id: identifier,
            channel,
        })
        .collect();

    info!("================================================");
    info!("Syncing Bitcoin blockchain");
    info!("================================================");

    // Sync Bitcoin blockchain
    for _ in 0..101 {
        for instance in instances.iter_mut() {
            instance.process_bitcoin_updates_with_throttle()?;
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

    for (i, address) in addresses.iter().enumerate() {
        let role = if i == 0 { "Leader" } else { "Non-leader" };
        info!("Op{} ({}) address: {:?}", i + 1, role, address);
    }

    info!("================================================");
    info!("Setting up aggregated public key");
    info!("================================================");

    // Setup aggregated public key for the aggregated key protocol
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(
        aggregation_id,
        addresses.clone(),
        None,
        0, // First operator is leader (index 0)
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
    let get_key_command =
        IncomingBitVMXApiMessages::GetVar(aggregation_id, "final_aggregated_key".to_string())
            .to_string()?;

    // Query the aggregated key from all participants
    send_all(&id_channel_pairs, &get_key_command)?;
    let key_responses = get_all(&channels, &mut instances, false)?;

    // All participants should return the same aggregated key
    let mut aggregated_keys = Vec::new();
    for (i, response) in key_responses.iter().enumerate() {
        if let Some((_, key_name, key_value)) = response.variable() {
            info!(
                "Participant {} aggregated key variable: {} = {:?}",
                i, key_name, key_value
            );

            assert_eq!(
                key_name, "final_aggregated_key",
                "Variable name should be 'final_aggregated_key'"
            );

            if let VariableTypes::PubKey(key) = key_value {
                let key_str = key.to_string();
                info!("Participant {} final aggregated MuSig2 key: {}", i, key_str);
                aggregated_keys.push(key_str);
            } else {
                panic!(
                    "Expected PubKey variable type for aggregated key, got {:?}",
                    key_value
                );
            }
        } else {
            panic!(
                "Participant {} did not return the aggregated key variable",
                i
            );
        }
    }

    // Verify all participants have the same aggregated key
    assert_eq!(
        aggregated_keys.len(),
        number_of_operators,
        "Should have {} aggregated keys",
        number_of_operators
    );
    for i in 1..number_of_operators {
        assert_eq!(
            aggregated_keys[0], aggregated_keys[i],
            "All participants should compute the same aggregated MuSig2 key"
        );
    }

    // Verify the key from the response matches the stored key from GetVar
    assert_eq!(
        aggregated_pub_key.to_string(),
        aggregated_keys[0],
        "AggregatedPubkey response should match the stored final_aggregated_key"
    );

    info!(
        "Aggregated key protocol successful! All {} participants computed the same aggregated key",
        number_of_operators
    );
    info!("   Aggregated MuSig2 Key: {}", aggregated_keys[0]);

    info!("================================================");
    info!("Test completed successfully!");
    info!("================================================");

    // BitcoindGuard handles cleanup automatically on drop
    Ok(())
}

/// Test that single-participant aggregated key protocol works correctly.
/// With a single participant, the "aggregated" key is just that participant's own key.
#[ignore = "integration: requires bitcoind"]
#[test]
pub fn test_aggregated_single_participant() -> Result<()> {
    config_trace();

    let (_bitcoin_client, _bitcoind_guard, _wallet) = prepare_bitcoin_guarded()?;

    // Initialize just 1 BitVMX instance
    let (bitvmx_op1, _address_op1, bridge_op1, _) = init_bitvmx("op_1", false)?;

    let mut instances = vec![bitvmx_op1];
    let channels = vec![bridge_op1.clone()];

    let identifiers = [instances[0].get_components_config().bitvmx.clone()];

    let id_channel_pairs: Vec<ParticipantChannel> = identifiers
        .clone()
        .into_iter()
        .zip(channels.clone().into_iter())
        .map(|(identifier, channel)| ParticipantChannel {
            id: identifier,
            channel,
        })
        .collect();

    info!("================================================");
    info!("Syncing Bitcoin blockchain");
    info!("================================================");

    for _ in 0..101 {
        for instance in instances.iter_mut() {
            instance.process_bitcoin_updates_with_throttle()?;
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

    let msgs = get_all(&channels, &mut instances, false)?;
    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    info!("Single-participant aggregated key: {}", aggregated_pub_key);

    info!("================================================");
    info!("Verifying stored key matches response");
    info!("================================================");

    // Query the stored key from globals
    let get_key_command =
        IncomingBitVMXApiMessages::GetVar(aggregation_id, "final_aggregated_key".to_string())
            .to_string()?;

    send_all(&id_channel_pairs, &get_key_command)?;
    let key_responses = get_all(&channels, &mut instances, false)?;

    if let Some((_, key_name, key_value)) = key_responses[0].variable() {
        assert_eq!(key_name, "final_aggregated_key");
        if let VariableTypes::PubKey(key) = key_value {
            assert_eq!(
                aggregated_pub_key.to_string(),
                key.to_string(),
                "Response key should match stored key"
            );
            info!("Verified: stored key matches response");
        } else {
            panic!("Expected PubKey variable type, got {:?}", key_value);
        }
    } else {
        panic!("Did not receive key variable");
    }

    info!("================================================");
    info!("Single-participant test completed successfully!");
    info!("================================================");

    // BitcoindGuard handles cleanup automatically on drop
    Ok(())
}
