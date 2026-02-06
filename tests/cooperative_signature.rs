#![cfg(test)]

use anyhow::Result;
use bitvmx_client::program::variables::VariableTypes;
use bitvmx_client::types::{
    IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel,
    PROGRAM_TYPE_COOPERATIVE_SIGNATURE,
};
use common::{config_trace, get_all, init_bitvmx, prepare_bitcoin_guarded, send_all, LOCAL_SLEEP_MS};
use tracing::info;
use uuid::Uuid;

mod common;

/// Test cooperative signature protocol with all 3 steps: Keys, Nonces, Signatures
#[ignore]
#[test]
pub fn test_cooperative_signature() -> Result<()> {
    config_trace();

    let (_bitcoin_client, _bitcoind_guard, _wallet) = prepare_bitcoin_guarded()?;

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
    info!("Setting up Cooperative Signature Protocol with ProgramV2");
    info!("This will test all 3 setup steps:");
    info!("  1. KeysStep - Exchange keys and compute aggregated key");
    info!("  2. NoncesStep - Exchange nonces for MuSig2 signing");
    info!("  3. SignaturesStep - Exchange partial signatures");
    info!("================================================");

    // Create program ID
    let program_id = Uuid::new_v4();
    info!("Program ID: {}", program_id);

    // Setup cooperative signature protocol (uses ProgramV2 with SetupEngine)
    let setup_msg = IncomingBitVMXApiMessages::SetupV2(
        program_id,
        PROGRAM_TYPE_COOPERATIVE_SIGNATURE.to_string(),
        addresses.clone(),
        0, // Op1 is leader (index 0)
    );
    let command = setup_msg.to_string()?;
    send_all(&id_channel_pairs, &command)?;

    info!("================================================");
    info!("Waiting for setup completion (all 3 steps)");
    info!("================================================");

    // Wait for setup to complete - all participants should respond with ProgramSetupComplete
    let setup_responses = get_all(&channels, &mut instances, false)?;

    for (i, response) in setup_responses.iter().enumerate() {
        info!("Setup response from participant {}: {:?}", i, response);
        // Verify setup completed successfully
        assert!(
            matches!(response, OutgoingBitVMXApiMessages::SetupCompleted(_)),
            "Setup should complete successfully"
        );
    }

    info!("================================================");
    info!("Setup completed! SetupEngine successfully executed all 3 steps:");
    info!("  [OK] KeysStep - Keys exchanged");
    info!("  [OK] NoncesStep - Nonces exchanged");
    info!("  [OK] SignaturesStep - Partial signatures exchanged");
    info!("================================================");

    info!("================================================");
    info!("Processing final tick to reach Ready state");
    info!("================================================");

    // CooperativeSignatureProtocol has no transactions to monitor, so we just need
    // to tick the instances a few times to let them transition to Ready state
    for _ in 0..10 {
        for instance in instances.iter_mut() {
            instance.tick()?;
        }
        std::thread::sleep(std::time::Duration::from_millis(LOCAL_SLEEP_MS));
    }

    info!("================================================");
    info!("Verifying Protocol Results");
    info!("================================================");

    // The CooperativeSignatureProtocol stores the final aggregated key in globals
    // under the variable name "final_aggregated_key"
    let get_key_command =
        IncomingBitVMXApiMessages::GetVar(program_id, "final_aggregated_key".to_string())
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
                panic!("Expected PubKey variable type for aggregated key, got {:?}", key_value);
            }
        } else {
            panic!(
                "Participant {} did not return the aggregated key variable",
                i
            );
        }
    }

    // Verify all three participants have the same aggregated key
    assert_eq!(aggregated_keys.len(), 3, "Should have 3 aggregated keys");
    assert_eq!(
        aggregated_keys[0], aggregated_keys[1],
        "All participants should compute the same aggregated MuSig2 key"
    );
    assert_eq!(
        aggregated_keys[0], aggregated_keys[2],
        "All participants should compute the same aggregated MuSig2 key"
    );

    info!("================================================");
    info!("[OK] Keys exchanged successfully - same aggregated key");
    info!("  Aggregated MuSig2 Key: {}", aggregated_keys[0]);
    info!("================================================");

    // Verify nonces were exchanged by checking globals
    info!("================================================");
    info!("Verifying Nonces Step Completion");
    info!("================================================");

    // Check that nonces were stored for all participants
    let get_nonces_command =
        IncomingBitVMXApiMessages::GetVar(program_id, "my_nonces".to_string()).to_string()?;

    send_all(&id_channel_pairs, &get_nonces_command)?;
    let nonces_responses = get_all(&channels, &mut instances, false)?;

    let mut nonces_count = 0;
    for (i, response) in nonces_responses.iter().enumerate() {
        if let Some((_, var_name, var_value)) = response.variable() {
            assert_eq!(var_name, "my_nonces", "Should have stored nonces");
            if let VariableTypes::String(nonces_str) = var_value {
                info!(
                    "Participant {} has stored nonces ({} bytes)",
                    i,
                    nonces_str.len()
                );
                nonces_count += 1;
            } else {
                panic!("Participant {} nonces should be String type, got {:?}", i, var_value);
            }
        } else {
            panic!("Participant {} did not return nonces variable, got {:?}", i, response);
        }
    }
    assert_eq!(nonces_count, 3, "All 3 participants should have nonces");

    info!("[OK] Nonces exchanged successfully");

    // Verify signatures were exchanged by checking globals
    info!("================================================");
    info!("Verifying Signatures Step Completion");
    info!("================================================");

    let get_sigs_command =
        IncomingBitVMXApiMessages::GetVar(program_id, "my_signatures".to_string()).to_string()?;

    send_all(&id_channel_pairs, &get_sigs_command)?;
    let sigs_responses = get_all(&channels, &mut instances, false)?;

    let mut sigs_count = 0;
    for (i, response) in sigs_responses.iter().enumerate() {
        if let Some((_, var_name, var_value)) = response.variable() {
            assert_eq!(var_name, "my_signatures", "Should have stored signatures");
            if let VariableTypes::String(sigs_str) = var_value {
                info!(
                    "Participant {} has stored signatures ({} bytes)",
                    i,
                    sigs_str.len()
                );
                sigs_count += 1;
            } else {
                panic!("Participant {} signatures should be String type, got {:?}", i, var_value);
            }
        } else {
            panic!("Participant {} did not return signatures variable, got {:?}", i, response);
        }
    }
    assert_eq!(sigs_count, 3, "All 3 participants should have signatures");

    info!("[OK] Partial signatures exchanged successfully");

    info!("================================================");
    info!("Test completed successfully!");
    info!("All 3 setup steps verified:");
    info!("  [OK] KeysStep");
    info!("  [OK] NoncesStep");
    info!("  [OK] SignaturesStep");
    info!("Leader broadcast pattern working correctly!");
    info!("================================================");

    // BitcoindGuard handles cleanup automatically on drop
    Ok(())
}
