use anyhow::Result;
use bitcoin::Amount;
use bitvmx_client::{
    program::{self, protocols::slot::group_id, variables::VariableTypes},
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, PROGRAM_TYPE_SLOT},
};
use common::{
    config_trace, get_all, init_bitvmx, init_utxo, mine_and_wait, prepare_bitcoin, send_all,
    wait_message_from_channel,
};
use tracing::info;
use uuid::Uuid;

mod common;
mod fixtures;

#[ignore]
#[test]
pub fn test_slot() -> Result<()> {
    config_trace();

    //const NETWORK: Network = Network::Regtest;

    let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;

    let (bitvmx_1, _addres_1, bridge_1, _) = init_bitvmx("op_1", false)?;
    let (bitvmx_2, _addres_2, bridge_2, _) = init_bitvmx("op_2", false)?;
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

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), 0).to_string()?;
    send_all(&channels, &command)?;
    let msgs = get_all(&channels, &mut instances, false)?;
    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    // Protocol fees funding
    const ONE_BTC: Amount = Amount::from_sat(100_000_000);
    let fund_value = ONE_BTC;
    let utxo = init_utxo(
        &bitcoin_client,
        aggregated_pub_key,
        None,
        Some(fund_value.to_sat()),
    )?;

    // SETUP SLOT BEGIN
    let program_id = Uuid::new_v4();
    let set_fee = VariableTypes::Number(10_000).set_msg(program_id, "FEE")?;
    send_all(&channels, &set_fee)?;

    let set_fund_utxo = VariableTypes::Utxo((utxo.txid, utxo.vout, Some(fund_value.to_sat())))
        .set_msg(program_id, "fund_utxo")?;
    send_all(&channels, &set_fund_utxo)?;

    let set_ops_aggregated = VariableTypes::PubKey(aggregated_pub_key)
        .set_msg(program_id, "operators_aggregated_pub")?;
    send_all(&channels, &set_ops_aggregated)?;

    let set_unspendable = VariableTypes::PubKey(fixtures::hardcoded_unspendable().into())
        .set_msg(program_id, "unspendable")?;
    send_all(&channels, &set_unspendable)?;

    let setup_msg =
        IncomingBitVMXApiMessages::Setup(program_id, PROGRAM_TYPE_SLOT.to_string(), addresses, 0)
            .to_string()?;
    send_all(&channels, &setup_msg)?;

    //wait setup complete
    let _msg = get_all(&channels, &mut instances, false)?;

    info!("{:?}", _msg[0]);

    // this should be done for all operators, but for now just setup one dispute
    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::GetTransactionInofByName(
            program_id,
            format!("unsigned_{}", program::protocols::slot::cert_hash_tx_op(1)),
        )
        .to_string()?,
    );
    info!("Waiting for transaction info...");
    let mut mutinstances = instances.iter_mut().collect::<Vec<_>>();
    let msg = wait_message_from_channel(&channels[1], &mut mutinstances, false)?;
    let (_uuid, _name, tx) = OutgoingBitVMXApiMessages::from_string(&msg.0)?
        .transaction_info()
        .unwrap();
    let output = tx.output;
    info!("Outputs: {:?}", output);

    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::slot::SETUP_TX.to_string(),
        )
        .to_string()?,
    );

    //observe the setup tx
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    // one operator decide to put a certificate hash to start the transfer
    let cert_hash = "33".repeat(20);
    let set_cert_hash = VariableTypes::Input(hex::decode(cert_hash).unwrap())
        .set_msg(program_id, "certificate_hash_2")?;
    let _ = channels[2].send(BITVMX_ID, set_cert_hash)?;

    let selected_gid = 4;
    let set_gid = VariableTypes::Input(vec![selected_gid]).set_msg(program_id, &group_id(2))?;
    let _ = channels[2].send(BITVMX_ID, set_gid)?;

    // send the tx
    let _ = channels[2].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::slot::cert_hash_tx_op(2),
        )
        .to_string()?,
    );

    //observes the cert hash tx
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //observes the gid tx
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    bitcoind.stop()?;
    Ok(())
}
