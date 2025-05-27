use anyhow::Result;
use bitcoin::{
    key::rand::rngs::OsRng,
    secp256k1::{self, SecretKey},
    Network, PublicKey as BitcoinPubKey,
};
use bitvmx_client::{
    program::{
        self,
        protocols::{
            dispute::TIMELOCK_BLOCKS, protocol_handler::external_fund_tx, slot::group_id,
            transfer::pub_too_group,
        },
        variables::{VariableTypes, WitnessTypes},
    },
    types::{
        IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, PROGRAM_TYPE_LOCK,
        PROGRAM_TYPE_SLOT, PROGRAM_TYPE_TRANSFER,
    },
};
use common::{
    config_trace,
    dispute::{execute_dispute, prepare_dispute},
    get_all, init_bitvmx, init_utxo, mine_and_wait, prepare_bitcoin, send_all,
    wait_message_from_channel,
};
use key_manager::verifier::SignatureVerifier;
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
pub fn test_full() -> Result<()> {
    config_trace();

    const NETWORK: Network = Network::Regtest;
    let fake_drp = true;
    let fake_instruction = true;

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
    //       SETUP AGGREGATED PUBLIC KEY
    //==================================================
    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), 0).to_string()?;
    send_all(&channels, &command)?;
    let msgs = get_all(&channels, &mut instances, false)?;
    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    //======================================================
    //       SETUP AGGREGATED PAIRS FOR DISPUTE CHALLENGES
    //====================================================
    //ask the peers to generate the aggregated public key
    let participants = vec![address_1, address_2];
    let sub_channel = vec![channels[0].clone(), channels[1].clone()];
    let aggregation_id = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SetupKey(aggregation_id, participants.clone(), 0).to_string()?;
    send_all(&sub_channel, &command)?;
    let msgs = get_all(&sub_channel, &mut instances, false)?;
    let pair_aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    //======================================================
    //       INITIALIZE UTXO TO PAY THE SLOT AND DISPUTE CHANNEL
    //====================================================
    // Protocol fees funding
    let fund_value = 10_000_000;
    let utxo = init_utxo(&wallet, aggregated_pub_key, None, fund_value)?;

    //======================================================
    // SETUP SLOT BEGIN
    //======================================================
    let slot_program_id = Uuid::new_v4();
    let set_fee = VariableTypes::Number(10_000).set_msg(slot_program_id, "FEE")?;
    send_all(&channels, &set_fee)?;

    let set_fund_utxo = VariableTypes::Utxo((utxo.txid, utxo.vout, Some(fund_value), None))
        .set_msg(slot_program_id, "fund_utxo")?;
    send_all(&channels, &set_fund_utxo)?;

    let set_ops_aggregated = VariableTypes::PubKey(aggregated_pub_key)
        .set_msg(slot_program_id, "operators_aggregated_pub")?;
    send_all(&channels, &set_ops_aggregated)?;

    let set_ops_aggregated = VariableTypes::PubKey(pair_aggregated_pub_key)
        .set_msg(slot_program_id, "pair_0_1_aggregated")?;
    send_all(&channels, &set_ops_aggregated)?;

    let set_unspendable = VariableTypes::PubKey(fixtures::hardcoded_unspendable().into())
        .set_msg(slot_program_id, "unspendable")?;
    send_all(&channels, &set_unspendable)?;

    let setup_msg = IncomingBitVMXApiMessages::Setup(
        slot_program_id,
        PROGRAM_TYPE_SLOT.to_string(),
        addresses.clone(),
        0,
    )
    .to_string()?;
    send_all(&channels, &setup_msg)?;

    //wait setup complete
    let _msg = get_all(&channels, &mut instances, false)?;

    info!("{:?}", _msg[0]);

    // this should be done for all operators, but for now just setup one dispute
    let _ = channels[0].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::GetTransactionInofByName(
            slot_program_id,
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

    //======================================================
    // SETUP DISPUTE CHANNEL 0-1
    //======================================================

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
        &pair_aggregated_pub_key,
        initial_utxo,
        initial_output_type,
        prover_win_utxo,
        prover_win_output_type,
        tx_fee as u32,
        fake_drp,
        fake_instruction,
    )?;

    //WAIT SETUP READY
    let _msgs = get_all(&channels, &mut instances, false)?;
    info!("Dispute setup done");

    //======================================================
    //  CREATE AGGREGATED HAPPY PATH
    //======================================================
    // THE AGGREGATED_HAPPY_PATH NEEDS TO BE USED FOR THE HAPPY PATH
    // THE OPTION FOR FAKE ONE IS UNTIL THE AGGREGATED SECRET IS IMPLEMENTED
    // TO SIGN THE HAPPY PATH TX
    let (aggregated_happy_path, _fake_secret) = if true {
        // emulate the user keypair
        let secp = secp256k1::Secp256k1::new();
        let mut rng = OsRng;
        let too_sk = SecretKey::new(&mut rng);
        let too_pk = secp256k1::PublicKey::from_secret_key(&secp, &too_sk);
        let (too_pk, too_sk) = fixtures::adjust_parity(&secp, too_pk, too_sk);
        let aggregated_happy_path = BitcoinPubKey {
            compressed: true,
            inner: too_pk,
        };
        (
            aggregated_happy_path,
            format!("{}", too_sk.display_secret()),
        )
    } else {
        //aggregated for happy path
        let aggregation_id = Uuid::new_v4();
        let command = IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), 0)
            .to_string()?;
        send_all(&channels, &command)?;
        let msgs = get_all(&channels, &mut instances, false)?;
        info!("Received AggregatedPubkey message from all channels");
        let aggregated_happy_path = msgs[0].aggregated_pub_key().unwrap();

        // get keypair to share with the user for happy path too
        let command = IncomingBitVMXApiMessages::GetKeyPair(aggregation_id).to_string()?;
        send_all(&channels, &command)?;
        let _msgs = get_all(&channels, &mut instances, false)?;
        (aggregated_happy_path, "".to_string())
    };

    // USER CREATES LOCKREQ TX
    let preimage = "top_secret".to_string();
    let hash = fixtures::sha256(preimage.as_bytes().to_vec());

    let (txid, pubuser, ordinal_fee, protocol_fee) =
        fixtures::create_lockreq_ready(aggregated_pub_key, hash.clone(), NETWORK, &bitcoin_client)?;

    // OPERATORS WAITS FOR LOCKREQ TX
    let lockreqtx_on_chain = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SubscribeToTransaction(lockreqtx_on_chain, txid).to_string()?;
    send_all(&channels, &command)?;
    mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    // SETUP LOCK BEGIN

    let lock_program_id = Uuid::new_v4();
    let set_fee = VariableTypes::Number(3000).set_msg(lock_program_id, "FEE")?;
    send_all(&channels, &set_fee)?;

    let set_ops_aggregated = VariableTypes::PubKey(aggregated_pub_key)
        .set_msg(lock_program_id, "operators_aggregated_pub")?;
    send_all(&channels, &set_ops_aggregated)?;

    let set_ops_aggregated_hp = VariableTypes::PubKey(aggregated_happy_path)
        .set_msg(lock_program_id, "operators_aggregated_happy_path")?;
    send_all(&channels, &set_ops_aggregated_hp)?;

    let set_unspendable = VariableTypes::PubKey(fixtures::hardcoded_unspendable().into())
        .set_msg(lock_program_id, "unspendable")?;
    send_all(&channels, &set_unspendable)?;

    let set_secret = VariableTypes::Secret(hash).set_msg(lock_program_id, "secret")?;
    send_all(&channels, &set_secret)?;

    let set_ordinal_utxo = VariableTypes::Utxo((txid, 0, Some(ordinal_fee.to_sat()), None))
        .set_msg(lock_program_id, "ordinal_utxo")?;
    send_all(&channels, &set_ordinal_utxo)?;

    let set_protocol_fee = VariableTypes::Utxo((txid, 1, Some(protocol_fee.to_sat()), None))
        .set_msg(lock_program_id, "protocol_utxo")?;
    send_all(&channels, &set_protocol_fee)?;

    let set_user_pubkey = VariableTypes::PubKey(bitcoin::PublicKey::from(pubuser))
        .set_msg(lock_program_id, "user_pubkey")?;
    send_all(&channels, &set_user_pubkey)?;

    let setup_msg = IncomingBitVMXApiMessages::Setup(
        lock_program_id,
        PROGRAM_TYPE_LOCK.to_string(),
        addresses.clone(),
        0,
    )
    .to_string()?;
    send_all(&channels, &setup_msg)?;

    get_all(&channels, &mut instances, false)?;

    //Bridge send signal to send the kickoff message
    let witness_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetWitness(
        lock_program_id,
        "secret".to_string(),
        WitnessTypes::Secret(preimage.as_bytes().to_vec()),
    ))?;
    channels[1].send(BITVMX_ID, witness_msg.clone())?;

    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::GetTransactionInofByName(
            lock_program_id,
            program::protocols::lock::LOCK_TX.to_string(),
        )
        .to_string()?,
    );

    let mut mutinstances = instances.iter_mut().collect::<Vec<_>>();
    let msg = wait_message_from_channel(&channels[1], &mut mutinstances, false)?;
    let (_id, name, tx) = OutgoingBitVMXApiMessages::from_string(&msg.0)?
        .transaction_info()
        .unwrap();
    info!("Transaction name: {} details: {:?} ", name, tx);
    info!(
        "SIGNATURE: ====> {:?}",
        hex::encode(tx.input[0].witness[0].to_vec())
    );
    let locktx_id = tx.compute_txid();

    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::GetHashedMessage(
            lock_program_id,
            program::protocols::lock::LOCK_TX.to_string(),
            0,
            1,
        )
        .to_string()?,
    );

    let msg = wait_message_from_channel(&channels[1], &mut mutinstances, false)?;
    let (_uuid, _name, _vout, _leaf, hashed) = OutgoingBitVMXApiMessages::from_string(&msg.0)?
        .hashed_message()
        .unwrap();
    info!("HASHED MESSAGE: ====> {:?}", hashed);
    info!("AGGREGATED PUB: ====> {}", aggregated_pub_key);

    let verifier = SignatureVerifier::new();
    let mut signature = tx.input[0].witness[0].to_vec();
    signature.pop();
    let hashed = hex::decode(hashed).unwrap();
    let hashed_array: [u8; 32] = hashed.try_into().expect("Hash must be 32 bytes");
    let message = secp256k1::Message::from_digest(hashed_array);
    let signature = secp256k1::schnorr::Signature::from_slice(&signature.as_slice())?;
    assert!(verifier.verify_schnorr_signature(&signature, &message, aggregated_pub_key));

    drop(mutinstances);

    //======================================================
    //  START TRANSFER OF OWNERSHIP SETUP
    //======================================================

    //====================
    // DESCRIVE THE LOCK TX    TODO: This should be done in the lock program
    //====================

    let eol_timelock_duration = 100; // TODO: get this from config
    let taproot_script_eol_timelock_expired_tx_lock = scripts::timelock(
        eol_timelock_duration,
        &bitcoin::PublicKey::from(pubuser),
        SignMode::Skip,
    );

    //this should be another aggregated to be signed later
    let taproot_script_all_sign_tx_lock =
        scripts::check_aggregated_signature(&aggregated_pub_key, SignMode::Aggregate);

    let asset_spending_condition = vec![
        taproot_script_eol_timelock_expired_tx_lock.clone(),
        taproot_script_all_sign_tx_lock.clone(),
    ];

    let asset_output_type = external_fund_tx(
        &fixtures::hardcoded_unspendable().into(),
        asset_spending_condition,
        10_000,
    )?;

    //emulate asset
    /*let asset_utxo = init_utxo_new(
        &bitcoin_client,
        &fixtures::hardcoded_unspendable().into(),
        asset_spending_condition.clone(),
        10_000,
    )?;*/

    // SETUP TRANSFER BEGIN
    let transfer_program_id = Uuid::new_v4();

    let set_unspendable = VariableTypes::PubKey(fixtures::hardcoded_unspendable().into())
        .set_msg(transfer_program_id, "unspendable")?;
    send_all(&channels, &set_unspendable)?;

    let set_ops_aggregated = VariableTypes::PubKey(aggregated_pub_key)
        .set_msg(transfer_program_id, "operators_aggregated_pub")?;
    send_all(&channels, &set_ops_aggregated)?;

    let set_operators_count =
        VariableTypes::Number(3).set_msg(transfer_program_id, "operator_count")?;
    send_all(&channels, &set_operators_count)?;

    for gid in 1..=7 {
        let set_pub_too = VariableTypes::PubKey(fixtures::hardcoded_unspendable().into())
            .set_msg(transfer_program_id, &pub_too_group(gid))?;
        send_all(&channels, &set_pub_too)?;
    }

    let set_asset_utxo = VariableTypes::Utxo((locktx_id, 0, Some(10_000), Some(asset_output_type)))
        .set_msg(transfer_program_id, "locked_asset_utxo")?;
    send_all(&channels, &set_asset_utxo)?;

    let set_slot_program_id = VariableTypes::String(slot_program_id.to_string())
        .set_msg(transfer_program_id, "slot_program_id")?;
    send_all(&channels, &set_slot_program_id)?;

    let setup_msg = IncomingBitVMXApiMessages::Setup(
        transfer_program_id,
        PROGRAM_TYPE_TRANSFER.to_string(),
        addresses.clone(),
        0,
    )
    .to_string()?;
    send_all(&channels, &setup_msg)?;

    //wait setup complete
    let msg = get_all(&channels, &mut instances, false)?;
    info!("{:?}", msg[0]);

    //======================================================
    //  SEND LOCK TX
    //======================================================

    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            lock_program_id,
            program::protocols::lock::LOCK_TX.to_string(),
        )
        .to_string()?,
    );

    mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //======================================================
    //  SEND SETUP TX OF SLOT
    //======================================================
    let _ = channels[1].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            slot_program_id,
            program::protocols::slot::SETUP_TX.to_string(),
        )
        .to_string()?,
    );

    //observe the setup tx
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //======================================================
    //  OPERATOR 0 SENDS CERTIFICATE HASH and GID "4"
    //======================================================
    // one operator decide to put a certificate hash to start the transfer
    let cert_hash = "33".repeat(20);
    let set_cert_hash = VariableTypes::Input(hex::decode(cert_hash).unwrap())
        .set_msg(slot_program_id, "certificate_hash_0")?;
    let _ = channels[0].send(BITVMX_ID, set_cert_hash)?;

    let selected_gid = 4;
    let set_gid =
        VariableTypes::Input(vec![selected_gid]).set_msg(slot_program_id, &group_id(0))?;
    let _ = channels[0].send(BITVMX_ID, set_gid)?;

    // send the tx
    let _ = channels[0].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            slot_program_id,
            program::protocols::slot::cert_hash_tx_op(0),
        )
        .to_string()?,
    );

    //observes the cert hash tx
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //observes the gid tx
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //======================================================
    // one operator disagrees with the gid and challenges
    //======================================================
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

    //======================================================
    // ones the challenge is completed the transfer can be completed
    //======================================================
    let _ = channels[0].send(
        BITVMX_ID,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            transfer_program_id,
            program::protocols::transfer::too_tx(0, 4),
        )
        .to_string()?,
    );

    //observe the transfer tx
    let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
    info!("Observerd: {:?}", msgs[0].transaction().unwrap().2);

    bitcoind.stop()?;
    Ok(())
}
