#![cfg(feature = "cardinal")]

use anyhow::Result;
use bitvmx_client::{
    program::{
        self,
        protocols::cardinal::{
            transfer::{op_gid, op_won, pub_too_group},
            EOL_TIMELOCK_DURATION, GID_MAX, OPERATORS_AGGREGATED_PUB, PROTOCOL_COST, SPEEDUP_DUST,
            UNSPENDABLE,
        },
        variables::VariableTypes,
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, PROGRAM_TYPE_TRANSFER},
};
use common::{
    config_trace, get_all, init_bitvmx, init_utxo_new, mine_and_wait, prepare_bitcoin, send_all,
    ParticipantChannel,
};
use protocol_builder::scripts::{self, SignMode};
use tracing::info;
use uuid::Uuid;

mod common;
mod fixtures;
//mod integration;

#[ignore]
#[test]
pub fn test_transfer() -> Result<()> {
    config_trace();

    //const NETWORK: Network = Network::Regtest;

    let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;

    let (bitvmx_1, _address_1, bridge_1, _) = init_bitvmx("op_1", true)?;
    let (bitvmx_2, _address_2, bridge_2, _) = init_bitvmx("op_2", true)?;
    let (bitvmx_3, _addres_3, bridge_3, _) = init_bitvmx("op_3", false)?;
    //let (bitvmx_4, _addres_4, bridge_4, _) = init_bitvmx("op_4", false)?;
    let mut instances = vec![bitvmx_1, bitvmx_2, bitvmx_3]; //, bitvmx_4];
    let channels = vec![bridge_1, bridge_2, bridge_3]; // , bridge_4];
    let identifiers = [
        instances[0]
            .get_components_config()
            .get_bitvmx_identifier()?,
        instances[1]
            .get_components_config()
            .get_bitvmx_identifier()?,
        instances[2]
            .get_components_config()
            .get_bitvmx_identifier()?,
        //instances[3].get_components_config().get_bitvmx_identifier()?,
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

    //get to the top of the blockchain
    for _ in 0..101 {
        for instance in instances.iter_mut() {
            instance.process_bitcoin_updates()?;
        }
    }

    //get addresses
    let command = IncomingBitVMXApiMessages::GetCommInfo().to_string()?;
    send_all(&id_channel_pairs, &command)?;
    let comm_info: Vec<OutgoingBitVMXApiMessages> = get_all(&channels, &mut instances, false)?;
    let addresses = comm_info
        .iter()
        .map(|msg| msg.comm_info().unwrap())
        .collect::<Vec<_>>();

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), None, 0)
        .to_string()?;
    send_all(&id_channel_pairs, &command)?;
    let msgs = get_all(&channels, &mut instances, false)?;
    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    //emulate asset
    let asset_spending_condition = vec![
        scripts::timelock(
            100,
            &fixtures::hardcoded_unspendable().into(),
            SignMode::Skip,
        ),
        scripts::check_aggregated_signature(&aggregated_pub_key, SignMode::Aggregate),
    ];
    let asset_utxo = init_utxo_new(
        &wallet,
        &aggregated_pub_key,
        asset_spending_condition.clone(),
        10_000,
        None,
    )?;

    let spending_condition = vec![scripts::check_aggregated_signature(
        &aggregated_pub_key,
        SignMode::Aggregate,
    )];
    //emulate op_n_gid_i
    let op_gid_utxo = init_utxo_new(
        &wallet,
        &aggregated_pub_key,
        spending_condition.clone(),
        1000,
        None,
    )?;
    //emulate op_won
    let op_won_utxo = init_utxo_new(
        &wallet,
        &aggregated_pub_key,
        spending_condition.clone(),
        500,
        None,
    )?;

    // SETUP TRANSFER BEGIN
    let program_id = Uuid::new_v4();

    let set_unspendable = VariableTypes::PubKey(fixtures::hardcoded_unspendable().into())
        .set_msg(program_id, UNSPENDABLE)?;
    send_all(&id_channel_pairs, &set_unspendable)?;

    let set_ops_aggregated =
        VariableTypes::PubKey(aggregated_pub_key).set_msg(program_id, OPERATORS_AGGREGATED_PUB)?;
    send_all(&id_channel_pairs, &set_ops_aggregated)?;

    let set_operators_count = VariableTypes::Number(3).set_msg(program_id, "operator_count")?;
    send_all(&id_channel_pairs, &set_operators_count)?;

    let eol_timelock_duration =
        VariableTypes::Number(100).set_msg(program_id, EOL_TIMELOCK_DURATION)?;
    send_all(&id_channel_pairs, &eol_timelock_duration)?;

    let protocol_cost = VariableTypes::Number(20_000).set_msg(program_id, PROTOCOL_COST)?;
    send_all(&id_channel_pairs, &protocol_cost)?;

    let speedup_dust = VariableTypes::Number(500).set_msg(program_id, SPEEDUP_DUST)?;
    send_all(&id_channel_pairs, &speedup_dust)?;

    let gid_max = VariableTypes::Number(8).set_msg(program_id, GID_MAX)?;
    send_all(&id_channel_pairs, &gid_max)?;

    for gid in 1..=7 {
        let set_pub_too = VariableTypes::PubKey(fixtures::hardcoded_unspendable().into())
            .set_msg(program_id, &pub_too_group(gid))?;
        send_all(&id_channel_pairs, &set_pub_too)?;
    }

    let set_asset_utxo = VariableTypes::Utxo((
        asset_utxo.0.txid,
        asset_utxo.0.vout,
        Some(asset_utxo.0.amount),
        Some(asset_utxo.1),
    ))
    .set_msg(program_id, "locked_asset_utxo")?;
    send_all(&id_channel_pairs, &set_asset_utxo)?;

    for op in 0..3 {
        let set_op_won = VariableTypes::Utxo((
            op_won_utxo.0.txid,
            op_won_utxo.0.vout,
            Some(op_won_utxo.0.amount),
            Some(op_won_utxo.1.clone()),
        ))
        .set_msg(program_id, &op_won(op))?;
        send_all(&id_channel_pairs, &set_op_won)?;

        for gid in 1..=7 {
            let set_op_gid = VariableTypes::Utxo((
                op_gid_utxo.0.txid,
                op_gid_utxo.0.vout,
                Some(op_gid_utxo.0.amount),
                Some(op_gid_utxo.1.clone()),
            ))
            .set_msg(program_id, &op_gid(op, gid))?;
            send_all(&id_channel_pairs, &set_op_gid)?;
        }
    }

    let setup_msg = IncomingBitVMXApiMessages::Setup(
        program_id,
        PROGRAM_TYPE_TRANSFER.to_string(),
        addresses,
        0,
    )
    .to_string()?;
    send_all(&id_channel_pairs, &setup_msg)?;

    //wait setup complete
    let _msg = get_all(&channels, &mut instances, false)?;

    info!("{:?}", _msg[0]);

    let _ = channels[1].send(
        id_channel_pairs[1].id.clone(),
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::cardinal::transfer::too_tx(0, 1),
        )
        .to_string()?,
    );

    //observe the setup tx
    let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
    info!("Observerd: {:?}", msgs[0].transaction().unwrap().2);

    bitcoind.stop()?;
    Ok(())
}
