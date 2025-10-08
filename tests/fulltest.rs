#![cfg(all(feature = "cardinal", test))]
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
            cardinal::{
                lock::lock_protocol_dust_cost,
                lock_config::LockProtocolConfiguration,
                slot::{certificate_hash, group_id, slot_protocol_dust_cost},
                slot_config::SlotProtocolConfiguration,
                transfer_config::TransferConfig,
            },
            dispute::TIMELOCK_BLOCKS,
        },
        variables::{VariableTypes, WitnessTypes},
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel},
};
use bitvmx_wallet::wallet::RegtestWallet;
use common::{
    config_trace,
    dispute::{execute_dispute, prepare_dispute, ForcedChallenges},
    get_all, init_bitvmx, init_utxo, mine_and_wait, prepare_bitcoin, send_all,
    wait_message_from_channel,
};
use key_manager::verifier::SignatureVerifier;
use tracing::info;
use uuid::Uuid;

use crate::common::set_speedup_funding;

mod common;
mod fixtures;
//mod integration;

#[ignore]
#[test]
pub fn test_full() -> Result<()> {
    config_trace();

    const NETWORK: Network = Network::Regtest;

    let (bitcoin_client, bitcoind, mut wallet) = prepare_bitcoin()?;

    let (bitvmx_1, address_1, bridge_1, emulator_1) = init_bitvmx("op_1", true)?;
    let (bitvmx_2, address_2, bridge_2, emulator_2) = init_bitvmx("op_2", true)?;
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

    //==================================================
    //       SETUP FUNDING ADDRESS FOR SPEEDUP
    //==================================================
    //one time per bitvmx instance, we need to get the public key for the speedup funding utxo
    info!("================================================");
    info!("Setting up speedup funding addresses");
    info!("================================================");
    let funding_public_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::GetPubKey(funding_public_id, true).to_string()?;
    send_all(&id_channel_pairs, &command)?;
    let msgs = get_all(&channels, &mut instances, false)?;
    let funding_key_0 = msgs[0].public_key().unwrap().1;
    let funding_key_1 = msgs[1].public_key().unwrap().1;
    let funding_key_2 = msgs[2].public_key().unwrap().1;
    set_speedup_funding(
        10_000_000,
        &funding_key_0,
        &channels[0],
        &mut wallet,
        &instances[0].get_components_config().bitvmx,
    )?;
    set_speedup_funding(
        10_000_000,
        &funding_key_1,
        &channels[1],
        &mut wallet,
        &instances[1].get_components_config().bitvmx,
    )?;
    set_speedup_funding(
        10_000_000,
        &funding_key_2,
        &channels[2],
        &mut wallet,
        &instances[2].get_components_config().bitvmx,
    )?;

    //==================================================
    //       SETUP AGGREGATED PUBLIC KEY
    //==================================================
    //ask the peers to generate the aggregated public key
    info!("================================================");
    info!("Setting up aggregated addresses");
    info!("================================================");
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), None, 0)
        .to_string()?;
    send_all(&id_channel_pairs, &command)?;
    let msgs = get_all(&channels, &mut instances, false)?;
    let aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    //======================================================
    //       SETUP AGGREGATED PAIRS FOR DISPUTE CHALLENGES
    //====================================================
    //ask the peers to generate the aggregated public key
    info!("================================================");
    info!("Setting up pair for disputes");
    info!("================================================");
    let participants = vec![address_1, address_2];
    let sub_channel = vec![channels[0].clone(), channels[1].clone()];
    let sub_id_channel_pairs = vec![id_channel_pairs[0].clone(), id_channel_pairs[1].clone()];
    let aggregation_id = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SetupKey(aggregation_id, participants.clone(), None, 0)
            .to_string()?;
    send_all(&sub_id_channel_pairs, &command)?;
    let msgs = get_all(&sub_channel, &mut instances, false)?;
    let pair_aggregated_pub_key = msgs[0].aggregated_pub_key().unwrap();

    //======================================================
    //       INITIALIZE UTXO TO PAY THE SLOT AND DISPUTE CHANNEL
    //====================================================
    // Protocol fees funding
    info!("================================================");
    info!("Setting SLOT");
    info!("================================================");
    let fund_value = slot_protocol_dust_cost(3);
    let utxo = init_utxo(&mut wallet, aggregated_pub_key, None, fund_value)?;

    //======================================================
    // SETUP SLOT BEGIN
    //======================================================
    let slot_program_id = Uuid::new_v4();
    let slot_protocol_configuration = SlotProtocolConfiguration::new(
        slot_program_id,
        3, //operators
        aggregated_pub_key,
        vec![pair_aggregated_pub_key],
        (utxo.txid, utxo.vout, Some(fund_value), None),
        TIMELOCK_BLOCKS as u16,
    );

    slot_protocol_configuration.setup(&id_channel_pairs, addresses.clone(), 0)?;

    //wait setup complete
    let _msg = get_all(&channels, &mut instances, false)?;

    info!("{:?}", _msg[0]);

    // this should be done for all operators, but for now just setup one dispute
    let _ = channels[0].send(
        &identifiers[0].clone(),
        IncomingBitVMXApiMessages::GetTransactionInfoByName(
            slot_program_id,
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

    //======================================================
    // SETUP DISPUTE CHANNEL 0-1
    //======================================================

    info!("================================================");
    info!("Setting Dispute");
    info!("================================================");
    let emulator_channels = vec![emulator_1.unwrap(), emulator_2.unwrap()];

    let (
        initial_utxo,
        initial_output_type,
        prover_win_utxo,
        prover_win_output_type,
        pair_aggregated_pub_key,
    ) = slot_protocol_configuration.dispute_connection(txid, 0, 1)?;

    info!("Dispute setup");

    let forced_challenge = ForcedChallenges::No;
    let dispute_id = Uuid::new_v4();
    prepare_dispute(
        dispute_id,
        participants,
        sub_id_channel_pairs.clone(),
        &pair_aggregated_pub_key,
        initial_utxo,
        initial_output_type,
        prover_win_utxo,
        prover_win_output_type,
        forced_challenge.clone(),
        None,
        None,
    )?;

    //WAIT SETUP READY
    let _msgs = get_all(&sub_channel, &mut instances, false)?;
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
        let command =
            IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), None, 0)
                .to_string()?;
        send_all(&id_channel_pairs, &command)?;
        let msgs = get_all(&channels, &mut instances, false)?;
        info!("Received AggregatedPubkey message from all channels");
        let aggregated_happy_path = msgs[0].aggregated_pub_key().unwrap();

        // get keypair to share with the user for happy path too
        let command = IncomingBitVMXApiMessages::GetKeyPair(aggregation_id).to_string()?;
        send_all(&id_channel_pairs, &command)?;
        let _msgs = get_all(&channels, &mut instances, false)?;
        (aggregated_happy_path, "".to_string())
    };

    // USER CREATES LOCKREQ TX
    let preimage = "top_secret".to_string();
    let hash = fixtures::sha256(preimage.as_bytes().to_vec());

    let (txid, pubuser, ordinal_fee) = fixtures::create_lockreq_ready(
        aggregated_pub_key,
        hash.clone(),
        NETWORK,
        lock_protocol_dust_cost(3),
        &bitcoin_client,
        2000,
    )?;

    // OPERATORS WAITS FOR LOCKREQ TX
    let lockreqtx_on_chain = Uuid::new_v4();
    let command =
        IncomingBitVMXApiMessages::SubscribeToTransaction(lockreqtx_on_chain, txid).to_string()?;
    send_all(&id_channel_pairs, &command)?;
    mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    // SETUP LOCK BEGIN
    info!("================================================");
    info!("Setting LOCK");
    info!("================================================");

    let lock_program_id = Uuid::new_v4();
    let lock_protocol_configuration = LockProtocolConfiguration::new(
        lock_program_id,
        aggregated_pub_key,
        aggregated_happy_path,
        fixtures::hardcoded_unspendable().into(),
        pubuser.into(),
        hash,
        (txid, 0, Some(ordinal_fee.to_sat()), None),
        (txid, 1, Some(lock_protocol_dust_cost(3)), None),
        10,
        100,
    );

    lock_protocol_configuration.setup(&id_channel_pairs, addresses.clone(), 0)?;

    get_all(&channels, &mut instances, false)?;

    //Bridge send signal to send the kickoff message
    let witness_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetWitness(
        lock_program_id,
        "secret".to_string(),
        WitnessTypes::Secret(preimage.as_bytes().to_vec()),
    ))?;
    channels[1].send(&identifiers[1], witness_msg.clone())?;

    let _ = channels[1].send(
        &identifiers[1],
        IncomingBitVMXApiMessages::GetTransactionInfoByName(
            lock_program_id,
            program::protocols::cardinal::lock::LOCK_TX.to_string(),
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
        &identifiers[1],
        IncomingBitVMXApiMessages::GetHashedMessage(
            lock_program_id,
            program::protocols::cardinal::lock::LOCK_TX.to_string(),
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

    info!("================================================");
    info!("Setting TRANSFER OF OWNERSHIP");
    info!("================================================");

    // SETUP TRANSFER BEGIN
    let transfer_program_id = Uuid::new_v4();

    let asset_utxo = lock_protocol_configuration.get_asset_utxo(&locktx_id)?;

    let groups_pub_keys: Vec<BitcoinPubKey> = (1..=7)
        .map(|_gid| fixtures::hardcoded_unspendable().into())
        .collect();
    let transfer_config = TransferConfig::new(
        transfer_program_id,
        fixtures::hardcoded_unspendable().into(),
        aggregated_pub_key.clone(),
        3, // operator count
        asset_utxo,
        groups_pub_keys,
        None,
        Some(slot_program_id),
    );

    transfer_config.setup(&id_channel_pairs, addresses.clone(), 0)?;

    //wait setup complete
    let msg = get_all(&channels, &mut instances, false)?;
    info!("{:?}", msg[0]);

    //======================================================
    //  SEND LOCK TX
    //======================================================

    info!("================================================");
    info!("Going to dispatch LOCK TX");
    info!("================================================");
    let _ = channels[1].send(
        &identifiers[1],
        IncomingBitVMXApiMessages::DispatchTransactionName(
            lock_program_id,
            program::protocols::cardinal::lock::LOCK_TX.to_string(),
        )
        .to_string()?,
    );

    mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //======================================================
    //  SEND SETUP TX OF SLOT
    //======================================================
    info!("================================================");
    info!("Going to dispatch SLOT SETUP TX");
    info!("================================================");
    let _ = channels[1].send(
        &identifiers[1],
        IncomingBitVMXApiMessages::DispatchTransactionName(
            slot_program_id,
            program::protocols::cardinal::slot::SETUP_TX.to_string(),
        )
        .to_string()?,
    );

    //observe the setup tx
    let _msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;

    //======================================================
    //  OPERATOR 0 SENDS CERTIFICATE HASH and GID "4"
    //======================================================
    info!("================================================");
    info!("Going to send CERTIFICATE HASH and GID");
    info!("================================================");
    // one operator decide to put a certificate hash to start the transfer
    let cert_hash = "966c3c1b3b93d12206202b8c685df7554d3df6c72b5cee973de94c45e3f37a0a";
    let set_cert_hash = VariableTypes::Input(hex::decode(cert_hash).unwrap())
        .set_msg(slot_program_id, &certificate_hash(0))?;
    let _ = channels[0].send(&identifiers[0].clone(), set_cert_hash)?;

    let selected_gid: u32 = 7;
    let set_gid = VariableTypes::Input(selected_gid.to_le_bytes().to_vec())
        .set_msg(slot_program_id, &group_id(0))?;
    let _ = channels[0].send(&identifiers[0].clone(), set_gid)?;

    // send the tx
    let _ = channels[0].send(
        &identifiers[0],
        IncomingBitVMXApiMessages::DispatchTransactionName(
            slot_program_id,
            program::protocols::cardinal::slot::cert_hash_tx_op(0),
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
    info!("================================================");
    info!("Going to DISPUTE");
    info!("================================================");
    execute_dispute(
        sub_id_channel_pairs,
        &mut instances,
        emulator_channels,
        &bitcoin_client,
        &wallet,
        dispute_id,
        None,
        forced_challenge,
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
    info!("================================================");
    info!("Going to complete TOO");
    info!("================================================");
    let _ = channels[0].send(
        &id_channel_pairs[0].id,
        IncomingBitVMXApiMessages::DispatchTransactionName(
            transfer_program_id,
            program::protocols::cardinal::transfer::too_tx(0, 7),
        )
        .to_string()?,
    );

    //observe the transfer tx
    let msgs = mine_and_wait(&bitcoin_client, &channels, &mut instances, &wallet)?;
    info!("Observerd: {:?}", msgs[0].transaction().unwrap().2);

    bitcoind.stop()?;
    Ok(())
}
