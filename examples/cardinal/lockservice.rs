use anyhow::Result;
use bitcoin::{
    key::{rand::rngs::OsRng, Parity, Secp256k1},
    secp256k1::{self, All, PublicKey as SecpPublicKey, SecretKey},
    Address, Amount, PublicKey as BitcoinPubKey, Txid,
};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::{
    broker_storage::BrokerStorage,
    channel::channel::{DualChannel, LocalChannel},
    rpc::{sync_server::BrokerSync, BrokerConfig},
};
use bitvmx_client::{
    config::Config,
    program::{
        self,
        protocols::cardinal::{
            EOL_TIMELOCK_DURATION, FEE, GID_MAX, OPERATORS_AGGREGATED_PUB, PROTOCOL_COST,
            SPEEDUP_DUST, UNSPENDABLE,
        },
        variables::{VariableTypes, WitnessTypes},
    },
    types::{
        IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, L2_ID, PROGRAM_TYPE_LOCK,
    },
};

use storage_backend::{storage::Storage, storage_config::StorageConfig};
use tracing::info;
use uuid::Uuid;

use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

pub fn wait_message_from_channel(channel: &DualChannel) -> Result<(String, u32)> {
    //loop to timeout
    let mut i = 0;
    loop {
        i += 1;
        if i % 10 == 0 {
            let msg = channel.recv()?;
            if msg.is_some() {
                //info!("Received message from channel: {:?}", msg);
                return Ok(msg.unwrap());
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        if i > 100000 {
            break;
        }
    }
    panic!("Timeout waiting for message from channel");
}
pub fn prepare_bitcoin_running() -> Result<(BitcoinClient, Address)> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    let wallet = bitcoin_client.init_wallet("test_wallet").unwrap();

    info!("Mine 1 blocks to address {:?}", wallet);
    bitcoin_client.mine_blocks_to_address(1, &wallet).unwrap();

    Ok((bitcoin_client, wallet))
}

pub fn send_all(channels: &Vec<DualChannel>, msg: &str) -> Result<()> {
    for channel in channels {
        channel.send(BITVMX_ID, msg.to_string())?;
    }
    Ok(())
}

pub fn get_all(channels: &Vec<DualChannel>) -> Result<Vec<(String, u32)>> {
    let mut ret = vec![];
    for channel in channels {
        let msg = wait_message_from_channel(&channel)?;
        ret.push(msg);
    }
    Ok(ret)
}

pub fn init_broker(role: &str) -> Result<DualChannel> {
    let config = Config::new(Some(format!("config/{}.yaml", role)))?;
    let broker_config = BrokerConfig::new(config.broker_port, None);
    let bridge_client = DualChannel::new(&broker_config, L2_ID);
    Ok(bridge_client)
}

pub fn main() -> Result<()> {
    // This will act as rpc with to allow the wallets to talk with the L2
    let config = StorageConfig::new("/tmp/lockservice_broker".to_string(), None);
    let broker_backend = Storage::new(&config)?;
    let broker_backend = Arc::new(Mutex::new(broker_backend));
    let broker_storage = Arc::new(Mutex::new(BrokerStorage::new(broker_backend)));
    let broker_config = BrokerConfig::new(54321, None);
    let mut broker = BrokerSync::new(&broker_config, broker_storage.clone());

    let broker_channel = LocalChannel::new(1, broker_storage.clone());

    lockservice(broker_channel)?;

    broker.close();

    Ok(())
}

pub fn lockservice(channel: LocalChannel<BrokerStorage>) -> Result<()> {
    let (bitcoin_client, wallet) = prepare_bitcoin_running()?;

    //TODO: A channel that talks directly with the broker without going through localhost loopback could be implemented

    let bridge_1 = init_broker("op_1")?;
    let bridge_2 = init_broker("op_2")?;
    let bridge_3 = init_broker("op_3")?;
    let bridge_4 = init_broker("op_4")?;

    let channels = vec![bridge_1, bridge_2, bridge_3, bridge_4];

    let command = IncomingBitVMXApiMessages::GetCommInfo().to_string()?;
    send_all(&channels, &command)?;
    let msgs = get_all(&channels)?;
    let addresses = msgs
        .iter()
        .map(|msg| {
            let msg = OutgoingBitVMXApiMessages::from_string(&msg.0).unwrap();
            match msg {
                OutgoingBitVMXApiMessages::CommInfo(comm_info) => comm_info,
                _ => panic!("Expected CommInfo message"),
            }
        })
        .collect::<Vec<_>>();

    //ask the peers to generate the aggregated public key
    let aggregation_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), None, 0)
        .to_string()?;

    info!("Command to all: {:?}", command);
    send_all(&channels, &command)?;
    info!("Waiting for AggregatedPubkey message from all channels");
    let msgs = get_all(&channels)?;
    info!("Received AggregatedPubkey message from all channels");

    let msg = OutgoingBitVMXApiMessages::from_string(&msgs[0].0)?;
    let aggregated_pub_key = match msg {
        OutgoingBitVMXApiMessages::AggregatedPubkey(_uuid, aggregated_pub_key) => {
            aggregated_pub_key
        }
        _ => panic!("Expected AggregatedPubkey message"),
    };

    info!("Aggregated pubkey: {:?}", aggregated_pub_key);
    info!("Waiting for command from channel");

    loop {
        let txid: Txid;
        let pubuser: bitcoin::PublicKey;
        let ordinal_fee: Amount;
        let protocol_fee: Amount;
        let preimage: String;
        let hash: Vec<u8>;

        let fake_hapy_path = true;
        let (aggregated_happy_path, fake_secret) = if fake_hapy_path {
            // emulate the user keypair
            let secp = secp256k1::Secp256k1::new();
            let mut rng = OsRng;
            let too_sk = SecretKey::new(&mut rng);
            let too_pk = SecpPublicKey::from_secret_key(&secp, &too_sk);
            let (too_pk, too_sk) = adjust_parity(&secp, too_pk, too_sk);
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
            send_all(&channels, &command)?;
            let msgs = get_all(&channels)?;
            info!("Received AggregatedPubkey message from all channels");
            let msg = OutgoingBitVMXApiMessages::from_string(&msgs[0].0)?;
            let aggregated_happy_path = match msg {
                OutgoingBitVMXApiMessages::AggregatedPubkey(_uuid, aggregated_pub_key) => {
                    aggregated_pub_key
                }
                _ => panic!("Expected AggregatedPubkey message"),
            };

            // get keypair to share with the user for happy path too
            let command = IncomingBitVMXApiMessages::GetKeyPair(aggregation_id).to_string()?;
            send_all(&channels, &command)?;
            let msgs = get_all(&channels)?;
            info!("Received keypair message from all channels");
            let msg = OutgoingBitVMXApiMessages::from_string(&msgs[0].0)?;
            match msg {
                OutgoingBitVMXApiMessages::KeyPair(uuid, private_key, public_key) => {
                    info!("Keypair: {} {:?} {:?}", uuid, private_key, public_key);
                }
                _ => panic!("Expected keypair message"),
            };
            (aggregated_happy_path, "".to_string())
        };

        loop {
            let msg = channel.recv()?;
            if let Some(msg) = msg {
                if msg.0 == "get_aggregated" {
                    info!("Ask for aggregated. Sending.");
                    channel.send(2, aggregated_pub_key.to_string())?;
                } else {
                    info!("Received message from channel: {:?}", msg);
                    (txid, pubuser, ordinal_fee, protocol_fee, preimage, hash) =
                        serde_json::from_str(&msg.0)?;
                    break;
                }
            } else {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }

        let program_id = Uuid::new_v4();

        //need lockreq txid to subscribe to it

        let lockreqtx_on_chain = Uuid::new_v4();
        let command = IncomingBitVMXApiMessages::SubscribeToTransaction(lockreqtx_on_chain, txid)
            .to_string()?;
        send_all(&channels, &command)?;

        bitcoin_client.mine_blocks_to_address(10, &wallet)?;
        std::thread::sleep(std::time::Duration::from_millis(1000));
        get_all(&channels)?;

        let set_fee = VariableTypes::Number(3000).set_msg(program_id, FEE)?;
        send_all(&channels, &set_fee)?;

        let set_fee_zkp = VariableTypes::Number(10000).set_msg(program_id, "FEE_ZKP")?;
        send_all(&channels, &set_fee_zkp)?;

        let set_ops_aggregated = VariableTypes::PubKey(aggregated_pub_key)
            .set_msg(program_id, OPERATORS_AGGREGATED_PUB)?;
        send_all(&channels, &set_ops_aggregated)?;

        let set_ops_aggregated_hp = VariableTypes::PubKey(aggregated_happy_path)
            .set_msg(program_id, "operators_aggregated_happy_path")?;
        send_all(&channels, &set_ops_aggregated_hp)?;

        let set_unspendable = VariableTypes::PubKey(hardcoded_unspendable().into())
            .set_msg(program_id, UNSPENDABLE)?;
        send_all(&channels, &set_unspendable)?;

        let set_secret = VariableTypes::Secret(hash).set_msg(program_id, "secret")?;
        send_all(&channels, &set_secret)?;

        let set_ordinal_utxo = VariableTypes::Utxo((txid, 0, Some(ordinal_fee.to_sat()), None))
            .set_msg(program_id, "ordinal_utxo")?;
        send_all(&channels, &set_ordinal_utxo)?;

        let set_protocol_fee = VariableTypes::Utxo((txid, 1, Some(protocol_fee.to_sat()), None))
            .set_msg(program_id, "protocol_utxo")?;
        send_all(&channels, &set_protocol_fee)?;

        let set_user_pubkey = VariableTypes::PubKey(bitcoin::PublicKey::from(pubuser))
            .set_msg(program_id, "user_pubkey")?;
        send_all(&channels, &set_user_pubkey)?;

        let eol_timelock_duration =
            VariableTypes::Number(100).set_msg(program_id, EOL_TIMELOCK_DURATION)?;
        send_all(&channels, &eol_timelock_duration)?;

        let protocol_cost = VariableTypes::Number(20_000).set_msg(program_id, PROTOCOL_COST)?;
        send_all(&channels, &protocol_cost)?;

        let speedup_dust = VariableTypes::Number(500).set_msg(program_id, SPEEDUP_DUST)?;
        send_all(&channels, &speedup_dust)?;

        let gid_max = VariableTypes::Number(8).set_msg(program_id, GID_MAX)?;
        send_all(&channels, &gid_max)?;

        let setup_msg = IncomingBitVMXApiMessages::Setup(
            program_id,
            PROGRAM_TYPE_LOCK.to_string(),
            addresses.clone(),
            0,
        )
        .to_string()?;
        send_all(&channels, &setup_msg)?;

        get_all(&channels)?;

        //Bridge send signal to send the kickoff message
        let witness_msg = serde_json::to_string(&IncomingBitVMXApiMessages::SetWitness(
            program_id,
            "secret".to_string(),
            WitnessTypes::Secret(preimage.as_bytes().to_vec()),
        ))?;
        channels[1].send(BITVMX_ID, witness_msg.clone())?;

        let _ = channels[1].send(
            BITVMX_ID,
            IncomingBitVMXApiMessages::GetTransactionInfoByName(
                program_id,
                program::protocols::cardinal::lock::LOCK_TX.to_string(),
            )
            .to_string()?,
        );

        let msg = wait_message_from_channel(&channels[1])?;
        let msg = OutgoingBitVMXApiMessages::from_string(&msg.0)?;
        let (_id, name, tx) = match msg {
            OutgoingBitVMXApiMessages::TransactionInfo(uuid, name, tx) => (uuid, name, tx),
            _ => panic!("Expected transaction message"),
        };
        info!("Transaction name: {} details: {:?} ", name, tx);

        info!(
            "SIGNATURE: ====> {:?}",
            hex::encode(tx.input[0].witness[0].to_vec())
        );

        let _ = channels[1].send(
            BITVMX_ID,
            IncomingBitVMXApiMessages::GetHashedMessage(
                program_id,
                program::protocols::cardinal::lock::LOCK_TX.to_string(),
                0,
                1,
            )
            .to_string()?,
        );

        let msg = wait_message_from_channel(&channels[1])?;
        let msg = OutgoingBitVMXApiMessages::from_string(&msg.0)?;
        let hashed = match msg {
            OutgoingBitVMXApiMessages::HashedMessage(_uuid, _name, _vout, _leaf, hashed) => hashed,
            _ => panic!("Expected hashed message"),
        };
        info!("HASHED MESSAGE: ====> {:?}", hashed);
        info!("AGGREGATED PUB: ====> {}", aggregated_pub_key);

        let _ = channels[1].send(
            BITVMX_ID,
            IncomingBitVMXApiMessages::DispatchTransactionName(
                program_id,
                program::protocols::cardinal::lock::LOCK_TX.to_string(),
            )
            .to_string()?,
        );

        info!("Sent lock tx");

        std::thread::sleep(std::time::Duration::from_millis(1000));
        info!("Mining blocks to confirm lock tx");
        bitcoin_client.mine_blocks_to_address(10, &wallet)?;
        info!("Wait for confirmation of lock tx");
        get_all(&channels)?;

        //EVENTUALY L2 DECIDED TO SEND THE HAPPY PATH
        info!("Waiting for burn message from channel");

        loop {
            let msg = channel.recv()?;
            if let Some(msg) = msg {
                if msg.0 == "burn" {
                    info!("Ask for burning.");
                    break;
                }
            } else {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }

        //TODO: It should actually be signed in this moment and not before (could be signed but not shared the partials)

        let zkp = "b75f20d1aee5a1a0908edd107a25189ccc38b6d20c5dc33362a066157a6ee60350a09cfbfebe38c8d9f04a6dafe46ae2e30f6638f3eb93c1d2aeff2d52d66d0dcd68bf7f8fc07485dd04a573d233df3663d63e71568bc035ef82e8ab3525f025b487aaa4456aaf93be3141b210cda5165a714225d9fd63163f59d741bdaa8b93";
        let set_zkp = VariableTypes::Input(hex::decode(zkp)?).set_msg(program_id, "zkp")?;
        send_all(&channels, &set_zkp)?;

        let _ = channels[0].send(
            BITVMX_ID,
            IncomingBitVMXApiMessages::DispatchTransactionName(
                program_id,
                program::protocols::cardinal::lock::PUBLISH_ZKP.to_string(),
            )
            .to_string()?,
        );

        info!("Sent publish zkp tx");
        std::thread::sleep(std::time::Duration::from_millis(1000));
        bitcoin_client.mine_blocks_to_address(10, &wallet)?;
        info!("Wait for confirmation of zkp");
        let ret = get_all(&channels)?;
        let msg = OutgoingBitVMXApiMessages::from_str(&ret[0].0)?;
        let (_id, status, name) = match msg {
            OutgoingBitVMXApiMessages::Transaction(id, status, name) => (id, status, name),
            _ => panic!("Expected Transaction message"),
        };
        info!("Transaction observed: {:?} {:?}", status.tx_id, name);

        let _ = channels[1].send(
            BITVMX_ID,
            IncomingBitVMXApiMessages::DispatchTransactionName(
                program_id,
                program::protocols::cardinal::lock::HAPPY_PATH_TX.to_string(),
            )
            .to_string()?,
        );

        info!("Sent happy path tx");
        std::thread::sleep(std::time::Duration::from_millis(1000));
        info!("Mining blocks to confirm happy path tx");
        bitcoin_client.mine_blocks_to_address(10, &wallet)?;
        info!("Wait for confirmation of happy path tx");
        let ret = get_all(&channels)?;
        let msg = OutgoingBitVMXApiMessages::from_str(&ret[0].0)?;
        let (_id, status, _name) = match msg {
            OutgoingBitVMXApiMessages::Transaction(id, status, name) => (id, status, name),
            _ => panic!("Expected Transaction message"),
        };

        info!("Received message from channel: {:?}", status.tx_id);
        info!("happy path secret: {}", fake_secret);
        info!("happy path public: {}", aggregated_happy_path);

        let msg = serde_json::to_string(&(status.tx_id, fake_secret))?;
        channel.send(2, msg)?;
    }

    //Ok(())
}

pub fn hardcoded_unspendable() -> SecpPublicKey {
    // hardcoded unspendable
    let key_bytes =
        hex::decode("02f286025adef23a29582a429ee1b201ba400a9c57e5856840ca139abb629889ad")
            .expect("Invalid hex input");
    SecpPublicKey::from_slice(&key_bytes).expect("Invalid public key")
}

// This method changes the parity of a keypair to be even, this is needed for Taproot.
fn adjust_parity(
    secp: &Secp256k1<All>,
    pubkey: SecpPublicKey,
    seckey: SecretKey,
) -> (SecpPublicKey, SecretKey) {
    let (_, parity) = pubkey.x_only_public_key();

    if parity == Parity::Odd {
        (pubkey.negate(&secp), seckey.negate())
    } else {
        (pubkey, seckey)
    }
}
