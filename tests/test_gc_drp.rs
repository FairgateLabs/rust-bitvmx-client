#![cfg(test)]
use anyhow::Result;
use bitvmx_bitcoin_rpc::rpc_config::NetworkFlavor;
use bitvmx_broker::rpc::errors::BrokerError;
use bitvmx_client::{
    program::{
        participant::{CommsAddress, ParticipantRole},
        protocols::{
            gc_drp::{GCDisputeConfiguration, START_CH},
            protocol_handler::action_wins,
        },
        setup::steps::garbler_step::GCConfiguration,
        variables::VariableTypes,
    },
    types::IncomingBitVMXApiMessages,
};
use bitvmx_wallet::Destination;
use protocol_builder::{
    scripts::{self, SignMode},
    types::{OutputType, Utxo},
};
use sha2::{Digest, Sha512};
use tracing::info;
use uuid::Uuid;

use crate::common::{check_gnova_built, config_trace, helper::TestHelper, init_utxo_new};

mod common;

fn test_aux(
    prover_public_circuit_input: Vec<bool>,
    verifier_public_circuit_input: Vec<bool>,
    circuit_input: Vec<bool>,
    winner_role: ParticipantRole,
    independent: Option<bool>,
    network_flavor: Option<NetworkFlavor>,
    circuit_path: String,
    import_proof_path: Option<String>,
) -> Result<()> {
    let independent = independent.unwrap_or(false);
    let network_flavor = network_flavor.unwrap_or_else(NetworkFlavor::from_env);

    check_gnova_built()?;

    config_trace();

    let mut helper = TestHelper::new(network_flavor, independent, Some(1000))?;
    helper.wallet.sync_wallet()?;

    // Obtain communication addresses from all participants
    let command = IncomingBitVMXApiMessages::GetCommInfo(Uuid::new_v4());
    helper.send_all(command)?;

    let addresses: Vec<CommsAddress> = helper
        .wait_all_msg()?
        .iter()
        .map(|msg| msg.comm_info().unwrap().1)
        .collect::<Vec<_>>();

    //one time per bitvmx instance, we need to get the public key for the speedup funding utxo
    let funding_public_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::GetPubKey(funding_public_id, true);
    helper.send_all(command)?;
    let msgs = helper.wait_all_msg()?;
    let funding_key_0 = msgs[0].public_key().unwrap().1;
    let funding_key_1 = msgs[1].public_key().unwrap().1;

    info!("Creating speedup funds");
    let speedup_amount_0 = 41_000;
    let speedup_amount_1 = 11_000;

    // Get funds for the operator 0
    let fund_txid_0 = helper
        .wallet
        .fund_destination(Destination::P2WPKH(funding_key_0, speedup_amount_0))?
        .compute_txid();

    // Get funds for the operator 1
    let fund_txid_1 = helper
        .wallet
        .fund_destination(Destination::P2WPKH(funding_key_1, speedup_amount_1))?
        .compute_txid();
    helper.wallet.mine(1)?;

    // Set funding UTXOs for both participants
    info!("Setting funding UTXOs");
    let funds_utxo_0 = Utxo::new(fund_txid_0, 0, speedup_amount_0, &funding_key_0);
    let command = IncomingBitVMXApiMessages::SetFundingUtxo(funds_utxo_0).to_string()?;
    helper.id_channel_pairs[0]
        .channel
        .send(&helper.id_channel_pairs[0].id, command)?;
    let funds_utxo_1 = Utxo::new(fund_txid_1, 0, speedup_amount_1, &funding_key_1);
    let command = IncomingBitVMXApiMessages::SetFundingUtxo(funds_utxo_1).to_string()?;
    helper.id_channel_pairs[1]
        .channel
        .send(&helper.id_channel_pairs[1].id, command)?;

    // Generate aggregated public key for pair 0 and 1 (order matters)
    info!("Generate Aggregated from pair");
    let pair_0_1 = vec![addresses[0].clone(), addresses[1].clone()];
    let pair_0_1_agg_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(pair_0_1_agg_id, pair_0_1.clone(), None, 0);
    helper.id_channel_pairs[0]
        .channel
        .send(&helper.id_channel_pairs[0].id, command.to_string()?)?;
    helper.id_channel_pairs[1]
        .channel
        .send(&helper.id_channel_pairs[1].id, command.to_string()?)?;
    let _msg = helper.wait_msg(0)?;
    let msg = helper.wait_msg(1)?;
    let pair_0_1_agg_pub_key = msg.aggregated_pub_key().unwrap();

    // Prepare the UTXO that will be consumed if the Prover Wins ( peg-in or ClaimGate to obtain the pegin )
    info!("Initializing UTXO as pegin input");
    let spending_condition = vec![scripts::check_aggregated_signature(
        &pair_0_1_agg_pub_key,
        SignMode::Aggregate,
    )];

    let pegin_amount = 10_000;
    let (utxo_pegin, pegin_output_type) = init_utxo_new(
        &mut helper.wallet,
        &pair_0_1_agg_pub_key,
        spending_condition.clone(),
        pegin_amount,
    )?;

    // Prepare the UTXO that will be used to cover the cost of the protocol
    info!("Initializing UTXO to cover protocol cost");
    let spending_condition = vec![scripts::check_aggregated_signature(
        &pair_0_1_agg_pub_key,
        SignMode::Aggregate,
    )];

    let protocol_cost = 26_000;
    let (utxo, initial_out_type) = init_utxo_new(
        &mut helper.wallet,
        &pair_0_1_agg_pub_key,
        spending_condition.clone(),
        protocol_cost,
    )?;

    // Now configure the protocol itself

    let pair_0_1_channels = vec![
        helper.id_channel_pairs[0].clone(),
        helper.id_channel_pairs[1].clone(),
    ];

    let prog_id = Uuid::new_v4();

    let test_enabler = OutputType::segwit_key(540, &pair_0_1_agg_pub_key).unwrap();

    let gc_drp_config = GCDisputeConfiguration::new(
        prog_id,
        (
            utxo.txid,
            utxo.vout,
            Some(utxo.amount),
            Some(initial_out_type),
        ),
        pair_0_1_agg_pub_key,
        15,
        vec![(
            (
                utxo_pegin.txid,
                utxo_pegin.vout,
                Some(utxo_pegin.amount),
                Some(pegin_output_type.clone()),
            ),
            vec![0],
        )],
        vec![test_enabler.clone()],
        vec![(
            (
                utxo_pegin.txid,
                utxo_pegin.vout,
                Some(utxo_pegin.amount),
                Some(pegin_output_type.clone()),
            ),
            vec![0],
        )],
        vec![test_enabler.clone(), test_enabler],
        vec![],
    );

    let gc_config_prover = GCConfiguration::new(
        prog_id,
        ParticipantRole::Prover,
        circuit_path.clone(),
        prover_public_circuit_input.clone(),
        import_proof_path.clone(),
    );
    let gc_config_verifier = GCConfiguration::new(
        prog_id,
        ParticipantRole::Verifier,
        circuit_path,
        verifier_public_circuit_input,
        import_proof_path,
    );

    pair_0_1_channels[0].channel.send(
        &pair_0_1_channels[0].id,
        gc_config_prover.get_setup_message()?,
    )?;
    pair_0_1_channels[1].channel.send(
        &pair_0_1_channels[1].id,
        gc_config_verifier.get_setup_message()?,
    )?;

    info!("Setup start");
    gc_drp_config.setup(&pair_0_1_channels, pair_0_1, 1)?;

    let msg = helper.wait_msg(0)?;
    info!("Setup dispute done: {:?}", msg);
    let msg = helper.wait_msg(1)?;
    info!("Setup dispute done: {:?}", msg);

    let set_input = VariableTypes::GcInput(circuit_input).set_msg(prog_id, "prover_input")?;

    pair_0_1_channels[0]
        .channel
        .send(&pair_0_1_channels[0].id, set_input)?;

    helper.id_channel_pairs[1].channel.send(
        &helper.id_channel_pairs[1].id,
        IncomingBitVMXApiMessages::DispatchTransactionName(prog_id, START_CH.to_string())
            .to_string()?,
    )?;

    info!("Waiting for start");
    helper.wait_tx_name(1, &action_wins(&winner_role, 1))?;
    helper.stop()?;

    Ok(())
}

#[test]
#[ignore]
pub fn test_wrong_public_input() {
    let prover_public_circuit_input = vec![true, false];
    let verifier_public_circuit_input = vec![true, true];
    let circuit_input = vec![false];
    let winner_role = ParticipantRole::Verifier; // No one wins in this case since it fails at setup
    let result = test_aux(
        prover_public_circuit_input,
        verifier_public_circuit_input,
        circuit_input,
        winner_role,
        None,
        None,
        "../rust-bitvmx-gc/test-circuits/simple.circuit".to_string(),
        None,
    );

    assert!(matches!(
        result.unwrap_err().downcast_ref::<BrokerError>(),
        Some(BrokerError::Disconnected)
    ));
}

#[test]
#[ignore]
pub fn test_wrong_input() -> Result<()> {
    // current circuit computes (a & b) ^ c  = (true & false) ^ false = (false) ^ false = false -> input is incorrect
    let public_circuit_input = vec![true, false];
    let circuit_input = vec![false];
    let winner_role = ParticipantRole::Verifier;
    test_aux(
        public_circuit_input.clone(),
        public_circuit_input,
        circuit_input,
        winner_role,
        None,
        None,
        "../rust-bitvmx-gc/test-circuits/simple.circuit".to_string(),
        None,
    )
}

#[test]
#[ignore]
pub fn test_correct_input() -> Result<()> {
    // current circuit computes (a & b) ^ c  = (true & false) ^ true = (false) ^ true = true -> input is correct
    let public_circuit_input = vec![true, false];
    let circuit_input = vec![true];
    let winner_role = ParticipantRole::Prover;
    test_aux(
        public_circuit_input.clone(),
        public_circuit_input,
        circuit_input,
        winner_role,
        None,
        None,
        "../rust-bitvmx-gc/test-circuits/simple.circuit".to_string(),
        None,
    )
}

const SHA512_IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

fn sha512_iv_bits_le() -> Vec<bool> {
    SHA512_IV
        .iter()
        .rev()
        .flat_map(|&w| u64_to_bits_le(w))
        .collect()
}

fn u64_to_bits_le(x: u64) -> Vec<bool> {
    (0..64)
        .map(|i| if ((x >> i) & 1) == 1 { true } else { false })
        .collect()
}

fn u8_to_bits_le(x: u8) -> Vec<bool> {
    (0..8)
        .map(|i| if ((x >> i) & 1) == 1 { true } else { false })
        .collect()
}

fn sha512_block_bits(block: &[u8; 128]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(1024);

    for chunk in block.chunks(8).rev() {
        let word = u64::from_be_bytes(chunk.try_into().unwrap());
        bits.extend(u64_to_bits_le(word));
    }

    bits
}

fn sha512_single_block(message: &[u8]) -> [u8; 128] {
    assert!(
        message.len() <= 111,
        "single-block SHA-512 only works for messages up to 111 bytes"
    );

    let bit_len = (message.len() as u128) * 8;
    let mut block = [0u8; 128];

    block[..message.len()].copy_from_slice(message);
    block[message.len()] = 0x80;

    // Last 16 bytes are the 128-bit big-endian length
    block[112..].copy_from_slice(&bit_len.to_be_bytes());

    block
}

// The circuit full-sha512.json is generated by test_full_sha512_circuit in rust-bitvmx-gc
#[test]
#[ignore]
pub fn test_sha512_correct_input() -> Result<()> {
    // The preimage is chosen to occupy the first 512 bits of the SHA-512 block.
    // This ensures that the circuit's public input fully commits to the actual message bytes.
    //
    // If the preimage were shorter, some of the bytes after the message (including SHA-512 padding)
    // would lie in the prover-controlled private witness. In that case, the prover could provide a
    // block that does not correspond to the canonical SHA-512 padding of the intended preimage.
    let preimage = b"my_super_secret_string_that_noone_knowsAAAAAAAAAAAAAAAAAAAAAAAAA";

    let mut hasher = Sha512::new();
    hasher.update(preimage);
    let hash = hasher.finalize();

    let expected_bits = hash
        .into_iter()
        .rev()
        .flat_map(u8_to_bits_le)
        .collect::<Vec<_>>();
    let iv_bits = sha512_iv_bits_le();

    let block = sha512_single_block(preimage);

    let circuit_input = sha512_block_bits(&block);
    let public_circuit_input = vec![iv_bits, expected_bits, circuit_input[..512].to_vec()]
        .concat()
        .into_iter()
        .collect::<Vec<_>>();

    let winner_role = ParticipantRole::Prover;
    test_aux(
        public_circuit_input.clone(),
        public_circuit_input,
        circuit_input[512..].to_vec(),
        winner_role,
        None,
        None,
        "../rust-bitvmx-gc/test-circuits/full-sha512.json".to_string(),
        None,
    )
}

#[test]
#[ignore]
fn test_sha512_wrong_input() -> Result<()> {
    let preimage = b"my_super_secret_string_that_noone_knowsAAAAAAAAAAAAAAAAAAAAAAAAA";
    let wrong_preimage = b"my_wrong_secret_string_that_noone_knowsAAAAAAAAAAAAAAAAAAAAAAAAA";

    let mut hasher = Sha512::new();
    hasher.update(preimage);
    let hash = hasher.finalize();

    let expected_bits = hash
        .into_iter()
        .rev()
        .flat_map(u8_to_bits_le)
        .collect::<Vec<_>>();
    let iv_bits = sha512_iv_bits_le();

    let block = sha512_single_block(wrong_preimage);
    let circuit_input = sha512_block_bits(&block);
    let public_circuit_input = vec![iv_bits, expected_bits, circuit_input[..512].to_vec()]
        .concat()
        .into_iter()
        .collect::<Vec<_>>();

    let winner_role = ParticipantRole::Verifier;
    test_aux(
        public_circuit_input.clone(),
        public_circuit_input,
        circuit_input[512..].to_vec(),
        winner_role,
        Some(true),
        Some(NetworkFlavor::Testnet4),
        "../rust-bitvmx-gc/test-circuits/full-sha512.json".to_string(),
        Some("../rust-bitvmx-gc/test-proof".to_string()),
    )
}
