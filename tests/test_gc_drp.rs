#![cfg(test)]
use anyhow::Result;
use bitcoin::Network;
use bitvmx_client::{program::participant::CommsAddress, types::IncomingBitVMXApiMessages};
use bitvmx_wallet::{Destination, RegtestWallet};
use protocol_builder::{
    scripts::{self, SignMode},
    types::Utxo,
};
use tracing::info;
use uuid::Uuid;

use crate::common::{check_bitvmx_cpu_built, config_trace, helper::TestHelper, init_utxo_new};

mod common;

#[ignore]
#[test]
pub fn test_protocol() -> Result<()> {
    let independent = false;
    let network = Network::Regtest;

    // Check if BitVMX-CPU is built before running the test
    check_bitvmx_cpu_built()?;

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
    let (_utxo_pegin, _pegin_output_type) = init_utxo_new(
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

    let protocol_cost = 50_000;
    let (_utxo, _initial_out_type) = init_utxo_new(
        &mut helper.wallet,
        &pair_0_1_agg_pub_key,
        spending_condition.clone(),
        protocol_cost,
    )?;

    // Now configure the protocol itself

    Ok(())
}
