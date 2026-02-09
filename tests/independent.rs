#![cfg(test)]
use anyhow::Result;
use bitcoin::Network;
use bitcoin_coordinator::coordinator::{BitcoinCoordinator, BitcoinCoordinatorApi};
use bitcoin_coordinator::types::CoordinatorNews;
use bitcoind::{bitcoind::Bitcoind, config::BitcoindConfig};
use bitvmx_client::config::Config;
use bitvmx_client::program;
use bitvmx_client::program::participant::{
    CommsAddress,
    ParticipantRole::{self, Prover, Verifier},
};
use bitvmx_client::program::protocols::dispute::config::{ConfigResult, ForceFailConfiguration};
use bitvmx_client::program::protocols::dispute::{
    action_wins, input_tx_name, program_input, program_input_prev_prefix,
    program_input_prev_protocol, protocol_cost, COMMITMENT, POST_COMMITMENT, PRE_COMMITMENT,
};
use bitvmx_client::program::variables::{VariableTypes, WitnessTypes};
use bitvmx_client::types::IncomingBitVMXApiMessages;
use bitvmx_wallet::wallet::{Destination, RegtestWallet, Wallet};
use common::dispute::{prepare_dispute, ForcedChallenges};
use common::helper::TestHelper;
use common::{clear_db, init_utxo_new};
use common::{config_trace, send_all};
use emulator::decision::challenge::{ForceChallenge, ForceCondition};
use emulator::executor::utils::{FailConfiguration, FailReads};
use key_manager::config::KeyManagerConfig;
use key_manager::create_key_manager_from_config;
use key_manager::winternitz::{
    self, checksum_length, to_checksummed_message, WinternitzPublicKey, WinternitzSignature,
    WinternitzType,
};
use protocol_builder::scripts::{self, SignMode};
use protocol_builder::types::Utxo;
use std::rc::Rc;
use std::vec;
use storage_backend::storage::Storage;
use storage_backend::storage_config::StorageConfig;
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
    inputs: Option<InputType>,
    force_challenge: Option<ForcedChallenges>,
    force_winner: Option<ParticipantRole>,
) -> Result<()> {
    // Check if BitVMX-CPU is built before running the test
    check_bitvmx_cpu_built()?;

    config_trace();

    let mut helper = TestHelper::new(network, independent, Some(1000))?;

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
    let _funding_key_2 = msgs[2].public_key().unwrap().1;

    info!("Creating speedup funds");
    let speedup_amount = 100_000 * MIN_TX_FEE as u64;

    // let fund_txid_0 = helper.wallet.fund_address(
    //     WALLET_NAME,
    //     FUNDING_ID,
    //     funding_key_0,
    //     &vec![speedup_amount],
    //     1000,
    //     false,
    //     true,
    //     None,
    // )?;
    let fund_tx_0 = helper
        .wallet
        .fund_destination(Destination::P2WPKH(funding_key_0, speedup_amount))?;
    let fund_txid_0 = fund_tx_0.compute_txid();

    helper.wallet.mine(1)?;
    info!("Wait for the fund for operator 0 speedups");

    wait_enter(independent);
    // let fund_txid_1 = helper.wallet.fund_address(
    //     WALLET_NAME,
    //     FUNDING_ID,
    //     funding_key_1,
    //     &vec![speedup_amount],
    //     1000,
    //     false,
    //     true,
    //     None,
    // )?;

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

    //simulate a protocol with a prover previous input
    let previous_protocol = Uuid::new_v4();
    let pub_key = derive_winternitz(4, 0);
    let signature = sign_winternitz_message(&hex::decode("00000001").unwrap(), 0);
    let set_pub_key =
        VariableTypes::WinternitzPubKey(pub_key).set_msg(previous_protocol, "previous_input_0")?;
    let set_witness =
        WitnessTypes::Winternitz(signature).set_msg(previous_protocol, "previous_input_0")?;
    send_all(&pair_0_1_channels, &set_pub_key)?;

    //configure the dispute so is able to retrive the data
    let prev_protocol =
        VariableTypes::Uuid(previous_protocol).set_msg(prog_id, &program_input_prev_protocol(0))?;
    let prev_prefix = VariableTypes::String("previous_input_".to_string())
        .set_msg(prog_id, &program_input_prev_prefix(0))?;
    send_all(&pair_0_1_channels, &prev_protocol)?;
    send_all(&pair_0_1_channels, &prev_prefix)?;

    if let Some(InputType::Const(input, index, _, _)) = &inputs {
        let const_input = VariableTypes::Input(hex::decode(input).unwrap())
            .set_msg(prog_id, &program_input(*index, None))?;
        let _ = send_all(&pair_0_1_channels, &const_input);
    }

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

    // Get input
    let (role, msg, idx) = match &inputs {
        Some(InputType::Const(_, _, input, idx)) => (ParticipantRole::Prover, input.as_str(), *idx),
        Some(InputType::Participant(msg, role)) => (role.clone(), msg.as_str(), 0),
        None => (ParticipantRole::Prover, "11111111", 0),
    };
    let participant_id = match role {
        ParticipantRole::Prover => 0,
        ParticipantRole::Verifier => 1,
    };
    helper.set_input_and_send(hex::decode(msg).unwrap(), idx, participant_id, prog_id)?;

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

/*
#[ignore]
#[test]
fn test_independent_testnet() -> Result<()> {
    test_all_aux(true, Network::Testnet, None, None, None, None)?;
    Ok(())
}*/
/*
#[ignore]
#[test]
fn test_independent_regtest() -> Result<()> {
    test_all_aux(true, Network::Regtest, None, None, None, None)?;
    Ok(())
}*/
#[ignore]
#[test]
fn test_all() -> Result<()> {
    test_all_aux(false, Network::Regtest, None, None, None, None)?;
    Ok(())
}

#[ignore]
#[test]
fn test_const() -> Result<()> {
    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-const-pre.yaml".to_string()),
        Some(("0000000100000002", 0, "00000003", 1).into()),
        None,
        None,
    )?;

    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-const-post.yaml".to_string()),
        Some(("0000000200000003", 1, "00000001", 0).into()),
        None,
        None,
    )?;

    Ok(())
}

#[ignore]
#[test]
fn test_const_fail_input() -> Result<()> {
    let main_config = ConfigResult {
        fail_config_prover: Some(FailConfiguration::new_fail_reads(FailReads::new(
            None,
            Some(&vec![
                "16".to_string(),
                "0xaa000000".to_string(),
                "0x00000002".to_string(),
                "0xaa000000".to_string(),
                "0xffffffffffffffff".to_string(),
            ]),
        ))),
        fail_config_verifier: None,
        force_challenge: ForceChallenge::No,
        force_condition: ForceCondition::ValidInputWrongStepOrHash,
    };

    let fail_config = ForceFailConfiguration {
        prover_force_second_nary: false,
        fail_input_tx: None,
        main: main_config,
        read: ConfigResult::default(),
    };

    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-previous-wots.yaml".to_string()),
        Some(("00000002", 1, "00000003", 2).into()),
        Some(ForcedChallenges::Personalized(fail_config.clone())),
        Some(Verifier),
    )?;
    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-const-post.yaml".to_string()),
        Some(("0000000200000004", 1, "00000001", 0).into()),
        Some(ForcedChallenges::Personalized(fail_config.clone())),
        Some(Verifier),
    )?;
    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-const-pre.yaml".to_string()),
        Some(("0000000100000002", 0, "00000004", 1).into()),
        Some(ForcedChallenges::Personalized(fail_config)),
        Some(Verifier),
    )?;

    Ok(())
}

#[ignore]
#[test]
fn test_previous_input() -> Result<()> {
    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-previous-wots.yaml".to_string()),
        Some(("00000002", 1, "00000003", 2).into()),
        None,
        None,
    )?;

    Ok(())
}

/// TESTNET test: test for retry mechanism of failed transactions in the Bitcoin coordinator.
///
/// This test verifies that the Bitcoin coordinator properly handles and reports
/// transaction dispatch errors when transactions fail to be processed. The test
/// creates two transactions chained together (causing the second one to fail because the first one was not in the mempool).
/// This failure occurs because QuikNode takes time to update or propagate transactions.
/*/
#[ignore]
#[test]
fn retry_failed_txs_test() -> Result<()> {
    config_trace();

    let config_path = "config/wallet_testnet.yaml";

    let wallet_config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::wallet::config::Config,
    >(Some(config_path.to_string()))?;

    info!("Wallet settings loaded");

    clear_db(&wallet_config.storage.path);
    clear_db(&wallet_config.key_storage.path);
    Wallet::clear_db(&wallet_config.wallet)?;

    let bitcoind = Bitcoind::new(
        BitcoindConfig::default(),
        wallet_config.bitcoin.clone(),
        None,
    );

    bitcoind.start()?;

    let mut wallet =
        Wallet::from_config(wallet_config.bitcoin.clone(), wallet_config.wallet.clone())?;

    wallet.sync_wallet()?;

    info!("Wallet ready");

    let amount = 20_000;
    let amount2 = 10_000;
    let destination_tx1 = Destination::P2WPKH(wallet.public_key, amount);
    let destination_tx2 = Destination::P2WPKH(wallet.public_key, amount2);
    let fee_rate = 2000;
    let tx1 = wallet.create_tx(destination_tx1, Some(fee_rate))?;
    wallet.update_with_tx(&tx1)?;
    let tx2 = wallet.create_tx(destination_tx2, Some(fee_rate))?;

    // Create storage and key manager
    let network = Network::Regtest;
    let storage_config = StorageConfig::new(wallet_config.storage.path.clone(), None);
    let storage = Rc::new(Storage::new(&storage_config).unwrap());
    let keymanger_config = KeyManagerConfig::new(network.to_string(), None, None);
    let key_manager =
        Rc::new(create_key_manager_from_config(&keymanger_config, &storage_config).unwrap());

    let config = Config::new(Some("config/development.yaml".to_string()))?;
    let settings = config.coordinator_settings.clone().unwrap();
    let coordinator = Rc::new(BitcoinCoordinator::new_with_paths(
        &wallet_config.bitcoin,
        storage.clone(),
        key_manager.clone(),
        Some(settings.clone()),
    )?);

    coordinator.dispatch(tx1, None, "test_1".to_string(), None, Some(1))?;
    coordinator.dispatch(tx2, None, "test_2".to_string(), None, Some(1))?;

    for _ in 0..10 {
        coordinator.tick()?;
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    let news = coordinator.get_news()?;
    let mut has_dispatch_error = false;

    for news_item in news.coordinator_news.iter() {
        if let CoordinatorNews::DispatchTransactionError(_, _, _) = news_item {
            has_dispatch_error = true;
            break;
        }
    }

    assert!(
        has_dispatch_error,
        "Expected at least one DispatchTransactionError"
    );

    Ok(())
}*/

#[ignore]
#[test]
fn test_verifier_input() -> Result<()> {
    test_all_aux(
        false,
        Network::Regtest,
        Some("../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world-verifier.yaml".to_string()),
        Some(InputType::Participant("11111111".to_string(), Verifier)),
        None,
        None,
    )?;

    // test_all_aux(
    //     false,
    //     Network::Regtest,
    //     Some("../BitVMX-CPU/docker-riscv32/riscv32/build/add-test-verifier.yaml".to_string()),
    //     Some(InputType::Participant(
    //         "000000010000000200000003".to_string(),
    //         Verifier,
    //     )),
    //     None,
    //     None,
    // )?;

    Ok(())
}

#[cfg(target_os = "linux")]
#[ignore]
#[test]
fn test_zkp() -> Result<()> {
    config_trace();
    let mut helper = TestHelper::new(Network::Regtest, false, Some(1000))?;

    let id = Uuid::new_v4();

    let _ = helper.id_channel_pairs[0].channel.send(
        &helper.id_channel_pairs[0].id,
        IncomingBitVMXApiMessages::GenerateZKP(
            id,
            vec![1, 2, 3, 4],
            "../rust-bitvmx-zk-proof/target/riscv-guest/methods/bitvmx/riscv32im-risc0-zkvm-elf/release/bitvmx.bin".to_string()
        ).to_string()?,
    );

    let msg = helper.wait_msg(0)?;
    info!("ZKP generated: {:?}", msg);

    let _ = helper.id_channel_pairs[0].channel.send(
        &helper.id_channel_pairs[0].id,
        IncomingBitVMXApiMessages::GetZKPExecutionResult(id).to_string()?,
    );

    let msg = helper.wait_msg(0)?;
    info!("ZKP result: {:?}", msg);

    helper.stop()?;
    Ok(())
}

fn test_challenge(challenge: ForcedChallenges) -> Result<()> {
    test_all_aux(false, Network::Regtest, None, None, Some(challenge), None)?;
    Ok(())
}

#[ignore]
#[test]
fn challenge_trace_hash_prover() -> Result<()> {
    test_challenge(ForcedChallenges::TraceHash(Prover))
}

#[ignore]
#[test]
fn challenge_trace_hash_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::TraceHash(Verifier))
}

#[ignore]
#[test]
fn challenge_trace_hash_zero_prover() -> Result<()> {
    test_challenge(ForcedChallenges::TraceHashZero(Prover))
}

#[ignore]
#[test]
fn challenge_trace_hash_zero_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::TraceHashZero(Verifier))
}

#[ignore]
#[test]
fn challenge_entry_point_prover() -> Result<()> {
    test_challenge(ForcedChallenges::EntryPoint(Prover))
}

#[ignore]
#[test]
fn challenge_entry_point_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::EntryPoint(Verifier))
}

#[ignore]
#[test]
fn challenge_program_counter_prover() -> Result<()> {
    test_challenge(ForcedChallenges::ProgramCounter(Prover))
}

#[ignore]
#[test]
fn challenge_program_counter_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::ProgramCounter(Verifier))
}

#[ignore]
#[test]
fn challenge_input_prover() -> Result<()> {
    test_challenge(ForcedChallenges::Input(Prover))
}

#[ignore]
#[test]
fn challenge_input_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::Input(Verifier))
}

#[ignore]
#[test]
fn challenge_opcode_prover() -> Result<()> {
    test_challenge(ForcedChallenges::Opcode(Prover))
}

#[ignore]
#[test]
fn challenge_opcode_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::Opcode(Verifier))
}

#[ignore]
#[test]
fn challenge_read_section_prover() -> Result<()> {
    test_challenge(ForcedChallenges::ReadSection(Prover))
}

#[ignore]
#[test]
fn challenge_read_section_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::ReadSection(Verifier))
}

#[ignore]
#[test]
fn challenge_write_section_prover() -> Result<()> {
    test_challenge(ForcedChallenges::WriteSection(Prover))
}

#[ignore]
#[test]
fn challenge_write_section_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::WriteSection(Verifier))
}

#[ignore]
#[test]
fn challenge_program_counter_section_prover() -> Result<()> {
    test_challenge(ForcedChallenges::ProgramCounterSection(Prover))
}

#[ignore]
#[test]
fn challenge_program_counter_section_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::ProgramCounterSection(Verifier))
}

#[ignore]
#[test]
fn challenge_initialized_prover() -> Result<()> {
    test_challenge(ForcedChallenges::Initialized(Prover))
}

#[ignore]
#[test]
fn challenge_initialized_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::Initialized(Verifier))
}

#[ignore]
#[test]
fn challenge_uninitialized_prover() -> Result<()> {
    test_challenge(ForcedChallenges::Uninitialized(Prover))
}

#[ignore]
#[test]
fn challenge_uninitialized_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::Uninitialized(Verifier))
}

#[ignore]
#[test]
fn challenge_witness_prover() -> Result<()> {
    test_challenge(ForcedChallenges::WitnessDiv(Prover))
}

#[ignore]
#[test]
fn challenge_witness_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::WitnessDiv(Verifier))
}

#[ignore]
#[test]
fn challenge_future_read_prover() -> Result<()> {
    test_challenge(ForcedChallenges::FutureRead(Prover))
}

#[ignore]
#[test]
fn challenge_future_read_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::FutureRead(Verifier))
}

#[ignore]
#[test]
fn challenge_halt_prover() -> Result<()> {
    test_challenge(ForcedChallenges::Halt(Prover))
}

#[ignore]
#[test]
fn challenge_halt_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::Halt(Verifier))
}

#[ignore]
#[test]
fn challenge_read_value_prover() -> Result<()> {
    test_challenge(ForcedChallenges::ReadValue(Prover))
}

#[ignore]
#[test]
fn challenge_read_value_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::ReadValue(Verifier))
}

#[ignore]
#[test]
fn challenge_correct_hash_prover() -> Result<()> {
    test_challenge(ForcedChallenges::CorrectHash(Prover))
}

#[ignore]
#[test]
fn challenge_correct_hash_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::CorrectHash(Verifier))
}

#[ignore]
#[test]
fn challenge_equivocation_hash_prover() -> Result<()> {
    test_challenge(ForcedChallenges::EquivocationHash(Prover))
}

#[ignore]
#[test]
fn challenge_equivocation_hash_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::EquivocationHash(Verifier))
}

#[ignore]
#[test]
fn challenge_equivocation_resign_step_prover() -> Result<()> {
    test_challenge(ForcedChallenges::EquivocationResignStep(Prover))
}

#[ignore]
#[test]
fn challenge_equivocation_resign_step_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::EquivocationResignStep(Verifier))
}

#[ignore]
#[test]
fn challenge_equivocation_resign_next_prover() -> Result<()> {
    test_challenge(ForcedChallenges::EquivocationResignNext(Prover))
}

#[ignore]
#[test]
fn challenge_equivocation_resign_next_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::EquivocationResignNext(Verifier))
}

#[ignore]
#[test]
fn challenge_equivocation_resign_step2_prover() -> Result<()> {
    test_challenge(ForcedChallenges::EquivocationResignStep2(Prover))
}

#[ignore]
#[test]
fn challenge_equivocation_resign_step2_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::EquivocationResignStep2(Verifier))
}

#[ignore]
#[test]
fn challenge_equivocation_resign_next2_prover() -> Result<()> {
    test_challenge(ForcedChallenges::EquivocationResignNext2(Prover))
}

#[ignore]
#[test]
fn challenge_equivocation_resign_next2_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::EquivocationResignNext2(Verifier))
}

#[ignore]
#[test]
fn challenge_prover_challenge_step_prover() -> Result<()> {
    test_challenge(ForcedChallenges::ProverChallengeStep(Prover))
}

#[ignore]
#[test]
fn challenge_prover_challenge_step_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::ProverChallengeStep(Verifier))
}

#[ignore]
#[test]
fn challenge_prover_challenge_step2_prover() -> Result<()> {
    test_challenge(ForcedChallenges::ProverChallengeStep2(Prover))
}

#[ignore]
#[test]
fn challenge_prover_challenge_step2_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::ProverChallengeStep2(Verifier))
}

#[ignore]
#[test]
fn challenge_prover_force_second_nary() -> Result<()> {
    test_challenge(ForcedChallenges::ProverForceSecondNary)
}

#[ignore]
#[test]
fn challenge_verifier_out_of_bounds_bits() -> Result<()> {
    test_challenge(ForcedChallenges::VerifierOutOfBoundsBits)
}

#[ignore]
#[test]
fn challenge_verifier_out_of_bounds_bits_in_challenge() -> Result<()> {
    test_challenge(ForcedChallenges::VerifierOutOfBoundsBitsInChallenge)
}

#[ignore]
#[test]
fn test_input_timeout_hashes_prover() -> Result<()> {
    test_challenge(ForcedChallenges::InputTimeOut(
        "NARY_PROVER_1".to_string(),
        ParticipantRole::Prover,
    ))
}

#[ignore]
#[test]
fn test_input_timeout_pre_commitment_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::InputTimeOut(
        PRE_COMMITMENT.to_string(),
        ParticipantRole::Verifier,
    ))
}

#[ignore]
#[test]
fn test_input_timeout_commitment_prover() -> Result<()> {
    test_challenge(ForcedChallenges::InputTimeOut(
        COMMITMENT.to_string(),
        ParticipantRole::Prover,
    ))
}

#[ignore]
#[test]
fn test_input_timeout_post_commitment_verifier() -> Result<()> {
    test_challenge(ForcedChallenges::InputTimeOut(
        POST_COMMITMENT.to_string(),
        ParticipantRole::Verifier,
    ))
}

#[ignore]
#[test]
fn test_input_timeout_input_prover() -> Result<()> {
    test_challenge(ForcedChallenges::InputTimeOut(
        input_tx_name(0),
        ParticipantRole::Prover,
    ))
}

#[ignore]
#[test]
fn test_input_timeout_input_prover_with_previous() -> Result<()> {
    test_all_aux(
        false,
        Network::Regtest,
        Some("./verifiers/add-test-with-previous-wots.yaml".to_string()),
        Some(("00000002", 1, "00000003", 2).into()),
        Some(ForcedChallenges::InputTimeOut(
            input_tx_name(2),
            ParticipantRole::Prover,
        )),
        None,
    )?;
    Ok(())
}

#[ignore]
#[test]
fn test_input_timeout_input_verifier() -> Result<()> {
    test_all_aux(
        false,
        Network::Regtest,
        Some("../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world-verifier.yaml".to_string()),
        Some(InputType::Participant("11111111".to_string(), Verifier)),
        Some(ForcedChallenges::InputTimeOut(
            input_tx_name(0),
            ParticipantRole::Verifier,
        )),
        None,
    )?;
    Ok(())
}

#[ignore]
#[test]
fn test_input_timeout_input_prover_cosign() -> Result<()> {
    test_all_aux(
        false,
        Network::Regtest,
        Some("../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world-verifier.yaml".to_string()),
        Some(InputType::Participant("11111111".to_string(), Verifier)),
        Some(ForcedChallenges::InputTimeOut(
            input_tx_name(1),
            ParticipantRole::Prover,
        )),
        None,
    )?;
    Ok(())
}

// The forced Execution is required for testing because without it, the prover or verifier will not execute directly
// #[ignore]
// #[test]
// fn challenge_no() -> Result<()> {
//     test_challenge(ForcedChallenges::No)
// }

#[ignore]
#[test]
fn challenge_execution() -> Result<()> {
    test_challenge(ForcedChallenges::Execution)
}
