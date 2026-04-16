#![cfg(test)]
use anyhow::Result;
use bitcoin::Network;
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
use bitvmx_wallet::{Destination, RegtestWallet};
use protocol_builder::{
    scripts::{self, SignMode},
    types::{OutputType, Utxo},
};
use tracing::info;
use uuid::Uuid;

use crate::common::{check_gnova_built, config_trace, helper::TestHelper, init_utxo_new};

mod common;

#[ignore]
#[test]
pub fn test_protocol() -> Result<()> {
    let independent = false;
    let network = Network::Regtest;

    check_gnova_built()?;

    config_trace();

    let mut helper = TestHelper::new(network, independent, Some(1000))?;

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
    let speedup_amount = 100_000;

    // Get funds for the operator 0
    let fund_txid_0 = helper
        .wallet
        .fund_destination(Destination::P2WPKH(funding_key_0, speedup_amount))?
        .compute_txid();

    helper.wallet.mine(1)?;

    // Get funds for the operator 1
    let fund_txid_1 = helper
        .wallet
        .fund_destination(Destination::P2WPKH(funding_key_1, speedup_amount))?
        .compute_txid();
    helper.wallet.mine(1)?;

    // Set funding UTXOs for both participants
    info!("Setting funding UTXOs");
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

    let pegin_amount = 100_000;
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

    let protocol_cost = 15_000;
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

    const TEST_CIRCUIT_PATH: &str = "../rust-bitvmx-gc/test-circuits/simple.circuit";
    let gc_config_prover = GCConfiguration::new(
        prog_id,
        ParticipantRole::Prover,
        TEST_CIRCUIT_PATH.to_string(),
    );
    let gc_config_verifier = GCConfiguration::new(
        prog_id,
        ParticipantRole::Verifier,
        TEST_CIRCUIT_PATH.to_string(),
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

    let set_input = VariableTypes::GcInput(vec![false, true, false]).set_msg(prog_id, "prover_input")?;

    pair_0_1_channels[0]
        .channel
        .send(&pair_0_1_channels[0].id, set_input)?;

    helper.id_channel_pairs[1].channel.send(
        &helper.id_channel_pairs[1].id,
        IncomingBitVMXApiMessages::DispatchTransactionName(prog_id, START_CH.to_string())
            .to_string()?,
    )?;

    info!("Waiting for start");
    helper.wait_tx_name(1, &action_wins(&ParticipantRole::Verifier, 1))?;
    helper.stop()?;

    Ok(())
}
