#![cfg(test)]
//! Calibration of the dispute cost constants.
//!
//! dispute::protocol_cost derives the funding of a dispute from the program definition, as
//! COST_BASE + COST_PER_ROUND * rounds + COST_PER_INPUT_TX * input_txs. Those three constants are measured,
//! not reasoned about, and this test is what measures them. It sets up the dispute for three programs chosen
//! so their round and input counts give three independent equations, reads what each built graph needs, and
//! solves. Then it compares the result against the constants currently in the source and prints them ready to
//! paste. Any change to the transaction graph moves the numbers and this test is what reports the new ones.
//!
//! cargo test --release -- --ignored test_protocol_cost_calibration
use anyhow::Result;
use bitvmx_client::program::participant::CommsAddress;
use bitvmx_client::program::protocols::dispute::{
    input_tx_count, protocol_cost, COST_BASE, COST_PER_INPUT_TX, COST_PER_ROUND, START_CH,
};
use bitvmx_client::types::IncomingBitVMXApiMessages;
use bitvmx_wallet::wallet::Destination;
use common::dispute::{prepare_dispute, ForcedChallenges};
use common::helper::{Mode, TestHelper};
use common::{config_trace, init_utxo_new};
use emulator::loader::program_definition::ProgramDefinition;
use protocol_builder::scripts::{self, SignMode};
use protocol_builder::types::Utxo;
use tracing::info;
use uuid::Uuid;

mod common;

const CALIBRATION_FUNDING: u64 = 200_000; // Only has to be larger than every requirement measured here. The measurement does not depend on it.
const ACTION_FUNDING: u64 = 11_000; // Funds the action utxo of the claim gate. Not part of what is measured here.

/// The three programs to calibrate on, as (program definition, nary rounds, input transactions). Picked so the three equations are independent.
const CONFIGS: [(&str, u8, u64); 3] = [
    ("./verifiers/add-test.yaml", 2, 1),
    ("./verifiers/add-test-with-verifier.yaml", 2, 3),
    ("./verifiers/test_input_count.yaml", 4, 3),
];

#[ignore]
#[test]
pub fn test_protocol_cost_calibration() -> Result<()> {
    config_trace();

    let mut helper = TestHelper::new(Mode::Regtest, Some(1000))?;
    helper.wallet.sync_wallet()?;

    helper.send_all(IncomingBitVMXApiMessages::GetCommInfo(Uuid::new_v4()))?;
    let addresses: Vec<CommsAddress> = helper
        .wait_all_msg()?
        .iter()
        .map(|msg| msg.comm_info().unwrap().1)
        .collect::<Vec<_>>();

    // One speedup funding utxo per participant, as every dispute setup expects one.
    helper.send_all(IncomingBitVMXApiMessages::GetPubKey(Uuid::new_v4(), true))?;
    let msgs = helper.wait_all_msg()?;
    for participant in 0..2 {
        let funding_key = msgs[participant].public_key().unwrap().1;
        let tx = helper
            .wallet
            .fund_destination(Destination::P2WPKH(funding_key, CALIBRATION_FUNDING))?;
        helper.wallet.mine(1)?;
        let utxo = Utxo::new(tx.compute_txid(), 0, CALIBRATION_FUNDING, &funding_key);
        helper.id_channel_pairs[participant].channel.send(
            &helper.id_channel_pairs[participant].id,
            IncomingBitVMXApiMessages::SetFundingUtxo(Uuid::new_v4(), utxo).to_string()?,
        )?;
    }

    let pair = vec![addresses[0].clone(), addresses[1].clone()];
    let pair_channels = vec![
        helper.id_channel_pairs[0].clone(),
        helper.id_channel_pairs[1].clone(),
    ];
    let command = IncomingBitVMXApiMessages::SetupKey(Uuid::new_v4(), pair.clone(), None, 0, None)
        .to_string()?;
    for channel_pair in pair_channels.iter() {
        channel_pair
            .channel
            .send(&channel_pair.id, command.clone())?;
    }
    let _ = helper.wait_msg(0)?;
    let aggregated_pub_key = helper.wait_msg(1)?.aggregated_pub_key().unwrap();

    let spending_condition = vec![
        scripts::check_aggregated_signature(&aggregated_pub_key, SignMode::Aggregate),
        scripts::check_aggregated_signature(&aggregated_pub_key, SignMode::Aggregate),
    ];

    let mut measured = vec![];
    for (program_definition, rounds, input_txs) in CONFIGS.iter() {
        // The program has to hold the shape this calibration assumes, otherwise the three equations below are
        // not the ones being solved.
        let program_def = ProgramDefinition::from_config(program_definition)?;
        assert_eq!(
            program_def.nary_def().total_rounds(),
            *rounds,
            "{} does not have {} rounds anymore",
            program_definition,
            rounds
        );
        assert_eq!(
            input_tx_count(&program_def)?,
            *input_txs,
            "{} does not have {} input transactions anymore",
            program_definition,
            input_txs
        );

        let (utxo, output_type) = init_utxo_new(
            &mut helper.wallet,
            &aggregated_pub_key,
            spending_condition.clone(),
            CALIBRATION_FUNDING,
        )?;
        let (action_utxo, action_output_type) = init_utxo_new(
            &mut helper.wallet,
            &aggregated_pub_key,
            spending_condition.clone(),
            ACTION_FUNDING,
        )?;

        let program_id = Uuid::new_v4();
        prepare_dispute(
            program_id,
            pair.clone(),
            pair_channels.clone(),
            &aggregated_pub_key,
            utxo,
            output_type,
            action_utxo,
            action_output_type,
            ForcedChallenges::Execution,
            Some(program_definition.to_string()),
            None,
        )?;
        helper.wait_specific_msg(0, "SetupCompleted")?;
        helper.wait_specific_msg(1, "SetupCompleted")?;

        // Everything the graph needs is held by the outputs of its first transaction, so the requirement is
        // their sum. The fee START_CHALLENGE itself pays cannot be read here, because it is whatever is left
        // of CALIBRATION_FUNDING. COST_MARGIN covers it.
        helper.id_channel_pairs[0].channel.send(
            &helper.id_channel_pairs[0].id,
            IncomingBitVMXApiMessages::GetTransactionInfoByName(program_id, START_CH.to_string())
                .to_string()?,
        )?;
        let (_, _, start_challenge) = helper
            .wait_specific_msg(0, "TransactionInfo")?
            .transaction_info()
            .unwrap();
        let required: u64 = start_challenge
            .output
            .iter()
            .map(|output| output.value.to_sat())
            .sum();

        info!(
            "calibration {} rounds={} input_txs={} required={}",
            program_definition, rounds, input_txs, required
        );
        assert!(
            required < CALIBRATION_FUNDING,
            "{} needs {} and the calibration only funded {}, so the measurement is not the real requirement",
            program_definition,
            required,
            CALIBRATION_FUNDING
        );
        measured.push(required as i64);
    }

    helper.stop()?;

    // The three measurements, with r for rounds and i for input transactions:
    //   measured[0] = base + 2r + 1i
    //   measured[1] = base + 2r + 3i
    //   measured[2] = base + 4r + 3i
    // so the first pair isolates the input cost and the second pair the round cost.
    let input_diff = measured[1] - measured[0];
    let round_diff = measured[2] - measured[1];
    assert_eq!(
        input_diff % 2,
        0,
        "the two input transactions between the first two programs cost {}, which is not divisible, so the cost is not linear in the input count",
        input_diff
    );
    assert_eq!(
        round_diff % 2,
        0,
        "the two rounds between the last two programs cost {}, which is not divisible, so the cost is not linear in the round count",
        round_diff
    );

    let per_input_tx = input_diff / 2;
    let per_round = round_diff / 2;
    let base = measured[0] - 2 * per_round - per_input_tx;

    info!(
        "calibration result, paste into dispute/mod.rs:\n\
         pub const COST_BASE: u64 = {}_{:03};\n\
         pub const COST_PER_ROUND: u64 = {}_{:03};\n\
         pub const COST_PER_INPUT_TX: u64 = {};",
        base / 1000,
        base % 1000,
        per_round / 1000,
        per_round % 1000,
        per_input_tx
    );

    // Every measured program has to be covered by what protocol_cost derives for it.
    for ((program_definition, _, _), required) in CONFIGS.iter().zip(measured.iter()) {
        let derived = protocol_cost(&ProgramDefinition::from_config(program_definition)?)?;
        assert!(
            derived >= *required as u64,
            "protocol_cost derives {} for {} but its graph needs {}",
            derived,
            program_definition,
            required
        );
    }

    assert_eq!(
        (base, per_round, per_input_tx),
        (
            COST_BASE as i64,
            COST_PER_ROUND as i64,
            COST_PER_INPUT_TX as i64
        ),
        "the graph changed, so the constants in dispute/mod.rs are stale. Replace them with the values logged above"
    );

    Ok(())
}
