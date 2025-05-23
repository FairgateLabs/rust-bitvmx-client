use anyhow::Result;
use bitcoin::Amount;
use bitvmx_client::{
    program::{
        self,
        protocols::{dispute::TIMELOCK_BLOCKS, protocol_handler::external_fund_tx, slot::group_id},
        variables::VariableTypes,
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, PROGRAM_TYPE_SLOT},
};
use common::{
    config_trace,
    dispute::{execute_dispute, prepare_dispute},
    get_all, init_bitvmx, init_utxo, mine_and_wait, prepare_bitcoin, send_all,
    wait_message_from_channel,
};
use protocol_builder::{
    scripts::{self, SignMode},
    types::Utxo,
};
use tracing::info;
use uuid::Uuid;

mod common;
mod fixtures;
//mod integration;

#[ignore]
#[test]
pub fn test_slot() -> Result<()> {
    config_trace();

    let fake_drp = true;

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

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), 0).to_string()?;
    send_all(&channels, &command)?;
    let msgs = get_all(&channels, &mut instances, false)?;
    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    //ask the peers to generate the aggregated public key
    let participants = vec![address_1, address_2];
    let sub_channel = vec![channels[0].clone(), channels[1].clone()];
    let aggregation_id = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SetupKey(aggregation_id, participants.clone(), 0).to_string()?;
    send_all(&sub_channel, &command)?;
    let msgs = get_all(&sub_channel, &mut instances, false)?;
    let pair_aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    // Protocol fees funding
    const ONE_BTC: Amount = Amount::from_sat(10_000_000);
    let fund_value = ONE_BTC;
    let utxo = init_utxo(&wallet, aggregated_pub_key, None, fund_value.to_sat())?;

    // SETUP SLOT BEGIN
    let program_id = Uuid::new_v4();
    let set_fee = VariableTypes::Number(10_000).set_msg(program_id, "FEE")?;
    send_all(&channels, &set_fee)?;

    let set_fund_utxo =
        VariableTypes::Utxo((utxo.txid, utxo.vout, Some(fund_value.to_sat()), None))
            .set_msg(program_id, "fund_utxo")?;
    send_all(&channels, &set_fund_utxo)?;

    let set_ops_aggregated = VariableTypes::PubKey(aggregated_pub_key)
        .set_msg(program_id, "operators_aggregated_pub")?;
    send_all(&channels, &set_ops_aggregated)?;

    let set_ops_aggregated = VariableTypes::PubKey(pair_aggregated_pub_key)
        .set_msg(program_id, "pair_0_1_aggregated")?;
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
    let _ = channels[0].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::GetTransactionInofByName(
            program_id,
            format!("unsigned_{}", program::protocols::slot::cert_hash_tx_op(0)),
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

    let tx_fee = 10_000;
    let initial_utxo = Utxo::new(txid, 4, 200_000, &pair_aggregated_pub_key);
    let prover_win_utxo = Utxo::new(txid, 2, 10_500, &pair_aggregated_pub_key);
    let emulator_channels = vec![emulator_1.unwrap(), emulator_2.unwrap()];

    let initial_spending_condition = vec![
        scripts::timelock(TIMELOCK_BLOCKS, &aggregated_pub_key, SignMode::Aggregate), //convert to timelock
        scripts::check_aggregated_signature(&pair_aggregated_pub_key, SignMode::Aggregate),
    ];
    let initial_output_type =
        external_fund_tx(&aggregated_pub_key, initial_spending_condition, 200_000)?;

    let prover_win_spending_condition = vec![
        scripts::check_aggregated_signature(&aggregated_pub_key, SignMode::Aggregate), //convert to timelock
        scripts::check_aggregated_signature(&pair_aggregated_pub_key, SignMode::Aggregate),
    ];
    let prover_win_output_type =
        external_fund_tx(&aggregated_pub_key, prover_win_spending_condition, 10_500)?;

    info!("Dispute setup");
    let dispute_id = prepare_dispute(
        participants,
        sub_channel.clone(),
        &mut instances,
        &pair_aggregated_pub_key,
        initial_utxo,
        initial_output_type,
        prover_win_utxo,
        prover_win_output_type,
        tx_fee as u32,
        fake_drp,
    )?;
    info!("Dispute setup done");

    // ==========================

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
        .set_msg(program_id, "certificate_hash_0")?;
    let _ = channels[0].send(BITVMX_ID, set_cert_hash)?;

    let selected_gid = 4;
    let set_gid = VariableTypes::Input(vec![selected_gid]).set_msg(program_id, &group_id(0))?;
    let _ = channels[0].send(BITVMX_ID, set_gid)?;

    // send the tx
    let _ = channels[0].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            program_id,
            program::protocols::slot::cert_hash_tx_op(0),
        )
        .to_string()?,
    );

    //observes the cert hash tx
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //observes the gid tx
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    // one operator disagrees with the gid and challenges
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

    bitcoind.stop()?;
    Ok(())
}
