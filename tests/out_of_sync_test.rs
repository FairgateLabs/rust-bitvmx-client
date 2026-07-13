#![cfg(all(feature = "cardinal", test))]
use anyhow::Result;
use bitcoin::PublicKey;
use bitvmx_client::{
    program::protocols::cardinal::transfer_config::TransferConfig,
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel},
};
use common::{config_trace, get_all, init_bitvmx, send_all};
use protocol_builder::scripts::{self, SignMode};
use uuid::Uuid;

use crate::common::{fake_utxo, scripted_advance};

mod common;
mod fixtures;
//mod integration;

#[ignore = "integration: requires bitcoind"]
#[test]
pub fn test_out_of_sync() -> Result<()> {
    config_trace();

    let (bitvmx_1, _address_1, bridge_1, _) = init_bitvmx("op_1", false)?;
    let (bitvmx_2, _address_2, bridge_2, _) = init_bitvmx("op_2", false)?;
    let (bitvmx_3, _addres_3, bridge_3, _) = init_bitvmx("op_3", false)?;
    //let (bitvmx_4, _addres_4, bridge_4, _) = init_bitvmx("op_4", false)?;
    let mut instances = vec![bitvmx_1, bitvmx_2, bitvmx_3]; //, bitvmx_4];
    let channels = vec![bridge_1, bridge_2, bridge_3]; // , bridge_4];
    let identifiers = [
        instances[0].get_components_config().bitvmx.clone(),
        instances[1].get_components_config().bitvmx.clone(),
        instances[2].get_components_config().bitvmx.clone(),
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

    //get addresses
    let command = IncomingBitVMXApiMessages::GetCommInfo(Uuid::new_v4()).to_string()?;
    send_all(&id_channel_pairs, &command)?;
    let comm_info: Vec<OutgoingBitVMXApiMessages> = get_all(&channels, &mut instances, false)?;
    let addresses = comm_info
        .iter()
        .map(|msg| msg.comm_info().unwrap().1)
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
    let asset_utxo = fake_utxo(
        &aggregated_pub_key,
        asset_spending_condition.clone(),
        10_000,
    )?;

    let spending_condition = vec![scripts::check_aggregated_signature(
        &aggregated_pub_key,
        SignMode::Aggregate,
    )];
    //emulate op_n_gid_i
    let op_gid_utxo = fake_utxo(&aggregated_pub_key, spending_condition.clone(), 1000)?;
    //emulate op_won
    let op_won_utxo = fake_utxo(&aggregated_pub_key, spending_condition.clone(), 540)?;

    // SETUP TRANSFER BEGIN
    let program_id = Uuid::new_v4();

    let groups_pub_keys: Vec<PublicKey> = (1..=7)
        .map(|_gid| fixtures::hardcoded_unspendable().into())
        .collect();
    let transfer_config = TransferConfig::new(
        program_id,
        fixtures::hardcoded_unspendable().into(),
        aggregated_pub_key.clone(),
        3, // operator count
        (
            asset_utxo.0.txid,
            asset_utxo.0.vout,
            Some(asset_utxo.0.amount),
            Some(asset_utxo.1),
        ),
        groups_pub_keys,
        Some((
            (
                op_won_utxo.0.txid,
                op_won_utxo.0.vout,
                Some(op_won_utxo.0.amount),
                Some(op_won_utxo.1),
            ),
            (
                op_gid_utxo.0.txid,
                op_gid_utxo.0.vout,
                Some(op_gid_utxo.0.amount),
                Some(op_gid_utxo.1),
            ),
        )),
        None,
    );

    transfer_config.setup(&id_channel_pairs, addresses.clone(), 0)?;

    //interactive_advance(&mut instances, &channels, &wallet)?;
    //let seq = generate_sequence_from_log("repro.txt").unwrap();
    //info!("Generated sequence with\n{}", seq);

    let seq = "2323111qq232323232q33221123233222223333333qqqq1q111232323";
    scripted_advance(&seq, 500, &mut instances, &channels, None).unwrap();

    Ok(())
}
