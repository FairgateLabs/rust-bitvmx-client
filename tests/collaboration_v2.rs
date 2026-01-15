#![cfg(test)]

use anyhow::Result;
use bitcoin::Amount;
use bitcoind::bitcoind::{Bitcoind, BitcoindFlags};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_client::program::variables::VariableTypes;
use bitvmx_client::types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel, PROGRAM_TYPE_COLLABORATION};
use bitvmx_wallet::wallet::{RegtestWallet, Wallet};
use common::{
    clear_db, config_trace, ensure_docker_available, get_all, init_bitvmx, init_utxo, send_all, INITIAL_BLOCK_COUNT, LOCAL_SLEEP_MS,
};
use tracing::info;
use uuid::Uuid;

mod common;

const MIN_TX_FEE: f64 = 2.0;

/// Helper struct to configure and setup a collaboration protocol test
pub struct CollaborationConfig {
    pub id: Uuid,
}

impl CollaborationConfig {
    pub fn new(id: Uuid) -> Self {
        Self { id }
    }

    /// Send setup messages to all participants
    pub fn setup(
        &self,
        id_channel_pairs: &Vec<ParticipantChannel>,
        addresses: Vec<bitvmx_client::program::participant::CommsAddress>,
        leader: u16,
    ) -> Result<()> {
        // Send setup message once - it will be processed by all participants
        // Each participant receives the same setup message through the broker
        let setup_msg = IncomingBitVMXApiMessages::SetupV2(
            self.id,
            PROGRAM_TYPE_COLLABORATION.to_string(),
            addresses,
            leader,
        );

        let msg_str = setup_msg.to_string()
            .map_err(|e| anyhow::anyhow!("Failed to serialize setup message: {}", e))?;

        send_all(id_channel_pairs, &msg_str)?;
        Ok(())
    }
}

/// Test collaboration protocol (implemented with ProgramV2 and SetupEngine)
#[ignore]
#[test]
pub fn test_collaboration() -> Result<()> {
    config_trace();

    info!("================================================");
    info!("Starting Collaboration Protocol Test");
    info!("================================================");

    // Load wallet configuration
    let wallet_config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::wallet::config::Config,
    >(Some("config/wallet_regtest.yaml".to_string()))?;

    // Clear all databases for fresh start
    clear_db(&wallet_config.storage.path);
    clear_db(&wallet_config.key_storage.path);
    Wallet::clear_db(&wallet_config.wallet)?;

    // Check Docker availability before starting bitcoind
    info!("Checking Docker availability...");
    ensure_docker_available()?;
    info!("Docker is available");

    // Start local bitcoind
    info!("Starting local bitcoind...");
    let _bitcoind = Bitcoind::new_with_flags(
        "bitcoin-regtest",
        "bitcoin/bitcoin:29.1",
        wallet_config.bitcoin.clone(),
        BitcoindFlags {
            min_relay_tx_fee: 0.00001,
            block_min_tx_fee: 0.00001 * MIN_TX_FEE,
            debug: 1,
            fallback_fee: 0.0002,
        },
    );
    _bitcoind.start()?;
    info!("Bitcoind started successfully");

    // Initialize wallet
    let bitcoin_client = BitcoinClient::new(
        &wallet_config.bitcoin.url,
        &wallet_config.bitcoin.username,
        &wallet_config.bitcoin.password,
    )?;

    let address = bitcoin_client.init_wallet(&wallet_config.bitcoin.wallet)?;
    info!("Mining initial {} blocks...", INITIAL_BLOCK_COUNT);
    bitcoin_client.mine_blocks_to_address(INITIAL_BLOCK_COUNT, &address)?;

    let mut wallet = Wallet::from_config(
        wallet_config.bitcoin.clone(),
        wallet_config.wallet.clone(),
    )?;

    bitcoin_client.fund_address(&wallet.receive_address()?, Amount::from_int_btc(10))?;
    wallet.sync_wallet()?;
    info!("Wallet ready with {} BTC", 10);

    // Initialize 2 BitVMX instances (prover and verifier)
    let (bitvmx_prover, _address_prover, bridge_prover, _) = init_bitvmx("op_1", false)?;
    let (bitvmx_verifier, _address_verifier, bridge_verifier, _) = init_bitvmx("op_2", false)?;

    let mut instances = vec![bitvmx_prover, bitvmx_verifier];
    let channels = vec![bridge_prover.clone(), bridge_verifier.clone()];

    let identifiers = [
        instances[0].get_components_config().bitvmx.clone(),
        instances[1].get_components_config().bitvmx.clone(),
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

    info!("Prover address: {:?}", addresses[0]);
    info!("Verifier address: {:?}", addresses[1]);

    info!("================================================");
    info!("Setting up aggregated public key");
    info!("================================================");

    // Setup aggregated public key for the collaboration
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(
        aggregation_id,
        addresses.clone(),
        None,
        0, // Prover is leader (index 0)
    )
    .to_string()?;
    send_all(&id_channel_pairs, &command)?;

    let msgs = get_all(&channels, &mut instances, false)?;
    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    info!("Aggregated public key: {}", aggregated_pub_key);

    info!("================================================");
    info!("Funding collaboration protocol UTXO");
    info!("================================================");

    // Create a UTXO that can be spent by the aggregated key
    let amount = 100_000u64; // 100k sats
    let utxo = init_utxo(&mut wallet, aggregated_pub_key, None, amount)?;

    info!("Funded UTXO: {:?}", utxo);

    info!("================================================");
    info!("Setting up Collaboration Protocol with ProgramV2");
    info!("================================================");

    // Create program ID
    let program_id = Uuid::new_v4();
    info!("Program ID: {}", program_id);

    // Create CollaborationConfig (uses ProgramV2 with SetupEngine)
    let collaboration_config = CollaborationConfig::new(program_id);

    // Call setup_v2 through the API (prover is leader, index 0)
    collaboration_config.setup(&id_channel_pairs, addresses.clone(), 0)?;

    info!("================================================");
    info!("Waiting for setup completion");
    info!("================================================");

    // Wait for setup to complete - both participants should respond with ProgramSetupComplete
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
    info!("Setup completed! SetupEngine successfully exchanged keys");
    info!("================================================");

    info!("================================================");
    info!("Processing final tick to reach Ready state");
    info!("================================================");

    // CollaborationProtocol has no transactions to monitor, so we just need
    // to tick the instances a few times to let them transition to Ready state
    for _ in 0..10 {
        for instance in instances.iter_mut() {
            instance.tick()?;
        }
        std::thread::sleep(std::time::Duration::from_millis(LOCAL_SLEEP_MS));
    }

    info!("================================================");
    info!("Verifying Collaboration Result - Aggregated MuSig2 Key");
    info!("================================================");

    // The CollaborationProtocol stores the final aggregated key in globals
    // under the variable name "final_aggregated_key"
    // IMPORTANT: Use program_id so GetVar knows which program's globals to query
    let get_key_command = IncomingBitVMXApiMessages::GetVar(
        program_id,
        "final_aggregated_key".to_string(),
    )
    .to_string()?;

    // Query the aggregated key from both participants
    send_all(&id_channel_pairs, &get_key_command)?;
    let key_responses = get_all(&channels, &mut instances, false)?;

    // Both participants should return the same aggregated key
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

    // Verify both participants have the same aggregated key
    assert_eq!(aggregated_keys.len(), 2, "Should have 2 aggregated keys");
    assert_eq!(aggregated_keys[0], aggregated_keys[1],
        "Both participants should compute the same aggregated MuSig2 key");

    info!("✅ Collaboration successful! Both participants computed the same aggregated key");
    info!("   Aggregated MuSig2 Key: {}", aggregated_keys[0]);

    info!("================================================");
    info!("Test completed successfully!");
    info!("================================================");

    Ok(())
}

