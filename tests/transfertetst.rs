#![cfg(feature = "cardinal")]

use anyhow::Result;
use bitcoin::PublicKey;
use bitvmx_client::{
    program::{self, protocols::cardinal::transfer_config::TransferConfig},
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID},
};
use common::{
    config_trace, get_all, init_bitvmx, init_utxo_new, mine_and_wait, prepare_bitcoin, send_all,
};
use protocol_builder::scripts::{self, SignMode};
use tracing::info;
use uuid::Uuid;

use crate::common::set_speedup_funding;

mod common;
mod fixtures;
//mod integration;

#[cfg(feature = "regtest")]
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

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), None, 0)
        .to_string()?;
    send_all(&channels, &command)?;
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

    for channel in channels.iter() {
        transfer_config.setup(channel, addresses.clone(), 0)?;
    }

    //wait setup complete
    let _msg = get_all(&channels, &mut instances, false)?;

    info!("{:?}", _msg[0]);

    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::cardinal::transfer::too_tx(1, 1),
        )
        .to_string()?,
    );

    //observe the setup tx
    let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
    info!("Observerd: {:?}", msgs[0].transaction().unwrap().2);

    info!("Stopping bitcoind");
    if let Some(ref bitcoind_instance) = bitcoind {
        bitcoind_instance.stop()?;
    }
    Ok(())
}
