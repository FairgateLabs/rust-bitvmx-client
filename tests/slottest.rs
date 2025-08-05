#![cfg(feature = "cardinal")]

use anyhow::Result;
use bitcoin::Amount;
use bitvmx_client::{
    program::{
        self,
        //participant::ParticipantRole,
        protocols::{
            cardinal::{
                slot::{certificate_hash, group_id, slot_protocol_dust_cost},
                slot_config::SlotProtocolConfiguration,
            },
            dispute::TIMELOCK_BLOCKS,
        },
        variables::VariableTypes,
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID},
};
use common::{
    config_trace,
    dispute::{execute_dispute, prepare_dispute, ForcedChallenges},
    get_all, init_bitvmx, init_utxo, mine_and_wait, prepare_bitcoin, send_all,
    wait_message_from_channel,
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
    let fund_value = Amount::from_sat(slot_protocol_dust_cost(3));
    let utxo = init_utxo(&wallet, aggregated_pub_key, None, fund_value.to_sat())?;

    let program_id = Uuid::new_v4();
    let slot_protocol_configuration = SlotProtocolConfiguration::new(
        program_id,
        3, //operators
        aggregated_pub_key,
        vec![pair_aggregated_pub_key],
        (utxo.txid, utxo.vout, Some(fund_value.to_sat()), None),
        TIMELOCK_BLOCKS as u16,
    );

    for channel in channels.iter() {
        slot_protocol_configuration.setup(channel, addresses.clone(), 0)?;
    }

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
        let emulator_channels = vec![emulator_1.unwrap(), emulator_2.unwrap()];

        let (
            initial_utxo,
            initial_output_type,
            prover_win_utxo,
            prover_win_output_type,
            pair_aggregated_pub_key,
        ) = slot_protocol_configuration.dispute_connection(txid, 0, 1)?;

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
            ForcedChallenges::No,
            None,
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
