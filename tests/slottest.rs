#![cfg(feature = "cardinal")]

use anyhow::Result;
use bitcoin::Amount;
use bitvmx_client::{
    program::{
        self,
        participant::ParticipantRole,
        protocols::{
            cardinal::{
                slot::{certificate_hash, group_id},
                EOL_TIMELOCK_DURATION, FEE, FUND_UTXO, GID_MAX, OPERATORS_AGGREGATED_PUB,
                PAIR_0_1_AGGREGATED, PROTOCOL_COST, SPEEDUP_DUST, UNSPENDABLE,
            },
            dispute::{TIMELOCK_BLOCKS, TIMELOCK_BLOCKS_KEY},
            protocol_handler::external_fund_tx,
        },
        variables::VariableTypes,
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, PROGRAM_TYPE_SLOT},
};
use common::{
    config_trace,
    dispute::{execute_dispute, prepare_dispute, ForcedChallenges},
    get_all, init_bitvmx, init_utxo, mine_and_wait, prepare_bitcoin, send_all,
    wait_message_from_channel,
};
use protocol_builder::{
    scripts::{self, SignMode},
    types::Utxo,
};
use tracing::info;
use uuid::Uuid;

use crate::common::set_speedup_funding;

mod common;
mod fixtures;
//mod integration;

#[ignore]
#[test]
pub fn test_slot_and_drp() -> Result<()> {
    test_slot(true)
}

#[ignore]
#[test]
pub fn test_slot_only() -> Result<()> {
    test_slot(false)
}

pub fn test_slot(and_drp: bool) -> Result<()> {
    config_trace();

    let fake_drp = false;
    let fake_instruction = false;

    //const NETWORK: Network = Network::Regtest;

    let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;

    let (bitvmx_1, address_1, bridge_1, emulator_1) = init_bitvmx("op_1", true)?;
    let (bitvmx_2, address_2, bridge_2, emulator_2) = init_bitvmx("op_2", true)?;
    let (bitvmx_3, _addres_3, bridge_3, _) = init_bitvmx("op_3", false)?;
    //let (bitvmx_4, _addres_4, bridge_4, _) = init_bitvmx("op_4", false)?;
    let mut instances = vec![bitvmx_1, bitvmx_2, bitvmx_3]; //, bitvmx_4];
    let channels = vec![bridge_1, bridge_2, bridge_3]; // , bridge_4];

    //get to the top of the blockchain
    for _ in 0..101 {
        for instance in instances.iter_mut() {
            instance.process_bitcoin_updates()?;
        }
    }

    //get addresses
    let command = IncomingBitVMXApiMessages::GetCommInfo().to_string()?;
    send_all(&channels, &command)?;
    let comm_info: Vec<OutgoingBitVMXApiMessages> = get_all(&channels, &mut instances, false)?;
    let addresses = comm_info
        .iter()
        .map(|msg| msg.comm_info().unwrap())
        .collect::<Vec<_>>();

    //==================================================
    //       SETUP FUNDING ADDRESS FOR SPEEDUP
    //==================================================
    //one time per bitvmx instance, we need to get the public key for the speedup funding utxo
    let funding_public_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::GetPubKey(funding_public_id, true).to_string()?;
    send_all(&channels, &command)?;
    let msgs = get_all(&channels, &mut instances, false)?;
    let funding_key_0 = msgs[0].public_key().unwrap().1;
    let funding_key_1 = msgs[1].public_key().unwrap().1;
    let funding_key_2 = msgs[2].public_key().unwrap().1;
    set_speedup_funding(10_000_000, &funding_key_0, &channels[0], &wallet)?;
    set_speedup_funding(10_000_000, &funding_key_1, &channels[1], &wallet)?;
    set_speedup_funding(10_000_000, &funding_key_2, &channels[2], &wallet)?;

    //==================================================
    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), None, 0)
        .to_string()?;
    send_all(&channels, &command)?;
    let msgs = get_all(&channels, &mut instances, false)?;
    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    //ask the peers to generate the aggregated public key
    let participants = vec![address_1, address_2];
    let sub_channel = vec![channels[0].clone(), channels[1].clone()];
    let aggregation_id = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SetupKey(aggregation_id, participants.clone(), None, 0)
            .to_string()?;
    send_all(&sub_channel, &command)?;
    let msgs = get_all(&sub_channel, &mut instances, false)?;
    let pair_aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    // Protocol fees funding
    let fund_value = Amount::from_sat(300_000);
    let utxo = init_utxo(&wallet, aggregated_pub_key, None, fund_value.to_sat())?;

    // SETUP SLOT BEGIN
    let slot_fee_tx = 1000;
    let slot_speedup_dust = 500;

    let program_id = Uuid::new_v4();
    let set_fee = VariableTypes::Number(slot_fee_tx).set_msg(program_id, FEE)?;
    send_all(&channels, &set_fee)?;

    let set_fund_utxo =
        VariableTypes::Utxo((utxo.txid, utxo.vout, Some(fund_value.to_sat()), None))
            .set_msg(program_id, FUND_UTXO)?;
    send_all(&channels, &set_fund_utxo)?;

    let set_ops_aggregated =
        VariableTypes::PubKey(aggregated_pub_key).set_msg(program_id, OPERATORS_AGGREGATED_PUB)?;
    send_all(&channels, &set_ops_aggregated)?;

    let set_ops_aggregated =
        VariableTypes::PubKey(pair_aggregated_pub_key).set_msg(program_id, PAIR_0_1_AGGREGATED)?;
    send_all(&channels, &set_ops_aggregated)?;

    let set_unspendable = VariableTypes::PubKey(fixtures::hardcoded_unspendable().into())
        .set_msg(program_id, UNSPENDABLE)?;
    send_all(&channels, &set_unspendable)?;

    let eol_timelock_duration =
        VariableTypes::Number(100).set_msg(program_id, EOL_TIMELOCK_DURATION)?;
    send_all(&channels, &eol_timelock_duration)?;

    let protocol_cost = VariableTypes::Number(20_000).set_msg(program_id, PROTOCOL_COST)?;
    send_all(&channels, &protocol_cost)?;

    let speedup_dust =
        VariableTypes::Number(slot_speedup_dust).set_msg(program_id, SPEEDUP_DUST)?;
    send_all(&channels, &speedup_dust)?;

    let gid_max = VariableTypes::Number(8).set_msg(program_id, GID_MAX)?;
    send_all(&channels, &gid_max)?;

    let timelock_blocks =
        VariableTypes::Number(TIMELOCK_BLOCKS.into()).set_msg(program_id, TIMELOCK_BLOCKS_KEY)?;
    send_all(&channels, &timelock_blocks)?;

    let setup_msg =
        IncomingBitVMXApiMessages::Setup(program_id, PROGRAM_TYPE_SLOT.to_string(), addresses, 0)
            .to_string()?;
    send_all(&channels, &setup_msg)?;

    //wait setup complete
    let _msg = get_all(&channels, &mut instances, false)?;

    info!("{:?}", _msg[0]);

    // this should be done for all operators, but for now just setup one dispute
    let _ = channels[0].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::GetTransactionInfoByName(
            program_id,
            format!(
                "unsigned_{}",
                program::protocols::cardinal::slot::cert_hash_tx_op(0)
            ),
        )
        .to_string()?,
    );
    info!("Waiting for transaction info...");
    let mut mutinstances = instances.iter_mut().collect::<Vec<_>>();
    let msg = wait_message_from_channel(&channels[0], &mut mutinstances, false)?;
    let (_uuid, _name, tx) = OutgoingBitVMXApiMessages::from_string(&msg.0)?
        .transaction_info()
        .unwrap();
    let output = &tx.output;
    let txid = tx.compute_txid();
    info!("Output: {:?}", output);

    //=====================================

    let (emulator_channels, dispute_id) = if and_drp {
        let initial_utxo = Utxo::new(txid, 4, 20_000, &pair_aggregated_pub_key);
        let prover_win_utxo_value = (slot_fee_tx + slot_speedup_dust) as u64;
        let prover_win_utxo = Utxo::new(txid, 2, prover_win_utxo_value, &pair_aggregated_pub_key);
        let emulator_channels = vec![emulator_1.unwrap(), emulator_2.unwrap()];

        let initial_spending_condition = vec![
            scripts::timelock(TIMELOCK_BLOCKS, &aggregated_pub_key, SignMode::Aggregate), //convert to timelock
            scripts::check_aggregated_signature(&pair_aggregated_pub_key, SignMode::Aggregate),
        ];
        let initial_output_type =
            external_fund_tx(&aggregated_pub_key, initial_spending_condition, 20_000)?;

        let prover_win_spending_condition = vec![
            scripts::check_aggregated_signature(&aggregated_pub_key, SignMode::Aggregate), //convert to timelock
            scripts::check_aggregated_signature(&pair_aggregated_pub_key, SignMode::Aggregate),
        ];
        let prover_win_output_type = external_fund_tx(
            &aggregated_pub_key,
            prover_win_spending_condition,
            prover_win_utxo_value,
        )?;

        info!("Dispute setup");

        let dispute_id = Uuid::new_v4();
        prepare_dispute(
            dispute_id,
            participants,
            sub_channel.clone(),
            &pair_aggregated_pub_key,
            initial_utxo,
            initial_output_type,
            prover_win_utxo,
            prover_win_output_type,
            500,
            fake_drp,
            fake_instruction,
            ForcedChallenges::TraceHash(ParticipantRole::Prover),
            None,
        )?;
        let _msgs = get_all(&sub_channel.clone(), &mut instances, false)?;
        info!("Dispute setup done");
        (emulator_channels, dispute_id)
    } else {
        info!("Skipping DRP execution");
        (vec![], Uuid::nil())
    };

    // ==========================

    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::cardinal::slot::SETUP_TX.to_string(),
        )
        .to_string()?,
    );

    //observe the setup tx
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    // one operator decide to put a certificate hash to start the transfer
    let cert_hash = "33".repeat(20);
    let set_cert_hash = VariableTypes::Input(hex::decode(cert_hash).unwrap())
        .set_msg(program_id, &certificate_hash(0))?;
    let _ = channels[0].send(BITVMX_ID, set_cert_hash)?;

    let selected_gid: u32 = 4;
    let set_gid = VariableTypes::Input(selected_gid.to_be_bytes().to_vec())
        .set_msg(program_id, &group_id(0))?;
    let _ = channels[0].send(BITVMX_ID, set_gid)?;

    // send the tx
    let _ = channels[0].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::cardinal::slot::cert_hash_tx_op(0),
        )
        .to_string()?,
    );

    //observes the cert hash tx
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //observes the gid tx
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    // one operator disagrees with the gid and challenges
    if and_drp {
        execute_dispute(
            sub_channel,
            &mut instances,
            emulator_channels,
            &bitcoin_client,
            &wallet,
            dispute_id,
            fake_drp,
        )?;

        //Consume other stops through timeout
        let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
        info!("Observerd: {:?}", msgs[0].transaction().unwrap().2);
        //Win start
        let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
        info!("Observerd: {:?}", msgs[0].transaction().unwrap().2);
        //success wait
        wallet.mine(10)?;
        let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
        info!("Observerd: {:?}", msgs[0].transaction().unwrap().2);
    }

    bitcoind.stop()?;
    Ok(())
}
