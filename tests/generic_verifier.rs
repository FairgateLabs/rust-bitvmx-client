#![cfg(test)]
use anyhow::Result;
use bitcoin::Network;
use bitvmx_client::program;
use bitvmx_client::program::participant::{
    CommsAddress,
    ParticipantRole::{self, Verifier},
};
use bitvmx_client::program::protocols::dispute::{
    action_wins, program_input, program_input_prev_prefix, program_input_prev_protocol,
    protocol_cost,
};
use bitvmx_client::program::variables::{VariableTypes, WitnessTypes};
use bitvmx_client::types::IncomingBitVMXApiMessages;
use bitvmx_wallet::wallet::{Destination, RegtestWallet};
use common::dispute::{prepare_dispute, ForcedChallenges};
use common::helper::TestHelper;
use common::init_utxo_new;
use common::{config_trace, send_all};
use key_manager::winternitz::{
    self, checksum_length, to_checksummed_message, WinternitzPublicKey, WinternitzSignature,
    WinternitzType,
};
use protocol_builder::scripts::{self, SignMode};
use protocol_builder::types::Utxo;
use std::vec;
use tracing::info;
use uuid::Uuid;

use crate::common::check_bitvmx_cpu_built;

mod common;

const MIN_TX_FEE: f64 = 2.0;

pub enum InputType {
    Const(String, u32, String, u32),
    Participant(String, ParticipantRole),
}
impl From<(&str, u32, &str, u32)> for InputType {
    fn from(t: (&str, u32, &str, u32)) -> Self {
        InputType::Const(t.0.to_string(), t.1, t.2.to_string(), t.3)
    }
}

pub fn test_all_aux(
    independent: bool,
    network: Network,
    program: Option<String>,
    force_challenge: Option<ForcedChallenges>,
    force_winner: Option<ParticipantRole>,
) -> Result<()> {
    // Check if BitVMX-CPU is built before running the test
    check_bitvmx_cpu_built()?;

    config_trace();

    let mut helper = TestHelper::new(network, independent, Some(3000))?;

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
    let speedup_amount = 200_000 * MIN_TX_FEE as u64;

    let fund_tx_0 = helper
        .wallet
        .fund_destination(Destination::P2WPKH(funding_key_0, speedup_amount))?;
    let fund_txid_0 = fund_tx_0.compute_txid();

    helper.wallet.mine(1)?;
    info!("Wait for the fund for operator 0 speedups");

    wait_enter(independent);
    let fund_tx_1 = helper
        .wallet
        .fund_destination(Destination::P2WPKH(funding_key_1, speedup_amount))?;
    let fund_txid_1 = fund_tx_1.compute_txid();
    helper.wallet.mine(1)?;
    info!("Wait for the first funding ready");
    info!("Wait for the fund for operator 1 speedups");
    wait_enter(independent);

    let funds_utxo_0 = Utxo::new(fund_txid_0, 0, speedup_amount, &funding_key_0);
    let command = IncomingBitVMXApiMessages::SetFundingUtxo(funds_utxo_0).to_string()?;
    helper.id_channel_pairs[0]
        .channel
        .send(&helper.id_channel_pairs[0].id, command)?;
    let funds_utxo_1 = Utxo::new(fund_txid_1, 0, speedup_amount, &funding_key_1);
    let command = IncomingBitVMXApiMessages::SetFundingUtxo(funds_utxo_1).to_string()?;
    helper.id_channel_pairs[1]
        .channel
        .send(&helper.id_channel_pairs[1].id, command)?;

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

    // prepare a second fund available so we don't need 2 blocks to get the UTXO

    info!("Initializing UTXO for program");
    let spending_condition = vec![
        scripts::check_aggregated_signature(&pair_0_1_agg_pub_key, SignMode::Aggregate),
        scripts::check_aggregated_signature(&pair_0_1_agg_pub_key, SignMode::Aggregate),
    ];
    let (utxo, initial_out_type) = init_utxo_new(
        &mut helper.wallet,
        &pair_0_1_agg_pub_key,
        spending_condition.clone(),
        protocol_cost(),
    )?;

    info!("Wait for the first funding ready");
    wait_enter(independent);

    info!("Initializing UTXO for the prover action");
    let (prover_win_utxo, prover_win_out_type) = init_utxo_new(
        &mut helper.wallet,
        &pair_0_1_agg_pub_key,
        spending_condition.clone(),
        11_000,
    )?;
    info!("Wait for the action utxo ready");
    wait_enter(independent);

    let pair_0_1_channels = vec![
        helper.id_channel_pairs[0].clone(),
        helper.id_channel_pairs[1].clone(),
    ];
    let prog_id = Uuid::new_v4();

    // simulate a protocol with a prover previous input
    // usualy the public inputs are set in previous protocols
    // in the sample guest the journal is just a word in zero
    let previous_protocol = Uuid::new_v4();

    let pub_key = derive_winternitz(4, 0);
    let signature = sign_winternitz_message(&hex::decode("00000000").unwrap(), 0);

    // name the variables in a way that can be indexed by word
    let set_pub_key =
        VariableTypes::WinternitzPubKey(pub_key).set_msg(previous_protocol, "previous_input_0")?;
    let set_witness =
        WitnessTypes::Winternitz(signature).set_msg(previous_protocol, "previous_input_0")?;
    send_all(&pair_0_1_channels, &set_pub_key)?;

    //configure the dispute so is able to retrive the data from previous protocols
    let prev_protocol =
        VariableTypes::Uuid(previous_protocol).set_msg(prog_id, &program_input_prev_protocol(3))?;
    let prev_prefix = VariableTypes::String("previous_input_".to_string())
        .set_msg(prog_id, &program_input_prev_prefix(3))?;
    send_all(&pair_0_1_channels, &prev_protocol)?;
    send_all(&pair_0_1_channels, &prev_prefix)?;

    // Set the const input with the size in words of the journal
    let const_input = VariableTypes::Input(hex::decode("01000000").unwrap())
        .set_msg(prog_id, &program_input(0, None))?;
    let _ = send_all(&pair_0_1_channels, &const_input);

    // Set the const input with the elf id of the risc0 verifier function
    let const_input = VariableTypes::Input(
        hex::decode("311021d9b7a1a876e7fa25caabaa0ebc9c944782d530521059113caefa0b81d1").unwrap(),
    )
    .set_msg(prog_id, &program_input(1, None))?;
    let _ = send_all(&pair_0_1_channels, &const_input);

    let forced_challenge = force_challenge.unwrap_or(ForcedChallenges::Execution);
    prepare_dispute(
        prog_id,
        pair_0_1,
        pair_0_1_channels.clone(),
        &pair_0_1_agg_pub_key,
        utxo,
        initial_out_type,
        prover_win_utxo,
        prover_win_out_type,
        forced_challenge.clone(),
        program,
        None,
    )?;

    let msg = helper.wait_msg(0)?;
    info!("Setup dispute done: {:?}", msg);
    let msg = helper.wait_msg(1)?;
    info!("Setup dispute done: {:?}", msg);

    // wait input from command line
    info!("Waiting for funding ready");
    wait_enter(independent);

    //the witness is observed and then the challenge is sent
    send_all(&pair_0_1_channels, &set_witness)?;

    let _ = helper.id_channel_pairs[1].channel.send(
        &helper.id_channel_pairs[1].id,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            prog_id,
            program::protocols::dispute::START_CH.to_string(),
        )
        .to_string()?,
    );

    helper.wait_tx_name(1, program::protocols::dispute::START_CH)?;

    // Proover set the groth16 proof as input
    let proof = "bb95aed6bc21f863c163de106478ccd0cfb4d5ac8867babcad8d9a1c628c2085f2e8d8e72d80f6c5af2368fd771b91de1cd7599db1f4aa86cbf7a71c3eb8a20181dfa283ea17881478abf468135bb88f234d19a93468524661a60889a3c409027e46211e6c5ec8c4e3eb3b17ccaa12db5123a116f9e1bcf1358c078141a71fad";
    helper.set_input_and_send(hex::decode(proof).unwrap(), 2, 0, prog_id)?;

    let role = match force_winner {
        Some(role) => role,
        None => forced_challenge.get_role().unwrap_or(Verifier).opposite(),
    };

    helper.wait_tx_name(1, &action_wins(&role, 1))?;

    helper.stop()?;

    Ok(())
}

fn wait_enter(independent: bool) {
    if !independent {
        return;
    }
    info!("Waiting for user input to continue...");
    info!("Press Enter to continue...");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
}

pub fn derive_winternitz(message_size_in_bytes: usize, index: u32) -> WinternitzPublicKey {
    let message_digits_length = winternitz::message_digits_length(message_size_in_bytes);
    let checksum_size = checksum_length(message_digits_length);

    let winternitz = winternitz::Winternitz::new();
    let master_secret = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    let public_key = winternitz
        .generate_public_key(
            &master_secret,
            WinternitzType::HASH160,
            message_digits_length,
            checksum_size,
            index,
        )
        .unwrap();

    public_key
}

pub fn sign_winternitz_message(message_bytes: &[u8], index: u32) -> WinternitzSignature {
    let message_digits_length = winternitz::message_digits_length(message_bytes.len());
    let checksummed_message = to_checksummed_message(message_bytes);
    let checksum_size = checksum_length(message_digits_length);
    let message_size = checksummed_message.len() - checksum_size;

    assert!(message_size == message_digits_length);

    let master_secret = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let winternitz = winternitz::Winternitz::new();
    let private_key = winternitz
        .generate_private_key(
            &master_secret,
            WinternitzType::HASH160,
            message_size,
            checksum_size,
            index,
        )
        .unwrap();

    let signature =
        winternitz.sign_message(message_digits_length, &checksummed_message, &private_key);

    signature
}

#[ignore]
#[test]
fn test_generic_verifier() -> Result<()> {
    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/generic-verifier.yaml".to_string()),
        None,
        None,
    )?;
    Ok(())
}
