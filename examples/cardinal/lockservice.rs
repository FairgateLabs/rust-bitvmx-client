use anyhow::Result;
use bitcoin::{
    key::{rand::rngs::OsRng, Parity, Secp256k1},
    secp256k1::{self, All, PublicKey as SecpPublicKey, SecretKey},
    Amount, Network, PublicKey as BitcoinPubKey, Txid,
};
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
            lock::lock_protocol_dust_cost, lock_config::LockProtocolConfiguration,
        },
        variables::WitnessTypes,
    },
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, L2_ID},
};

use bitvmx_wallet::wallet::{RegtestWallet, Wallet};
use protocol_builder::types::Utxo;
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
                info!("Received message from channel: {:?}", msg);
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
pub fn prepare_bitcoin_running() -> Result<Wallet> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    let wallet_config_file = match config.bitcoin.network {
        Network::Regtest => "config/wallet_regtest.yaml",
        Network::Testnet => "config/wallet_testnet.yaml",
        _ => panic!("Not supported network {}", config.bitcoin.network),
    };

    let wallet_config = bitvmx_settings::settings::load_config_file::<bitvmx_wallet::config::Config>(
        Some(wallet_config_file.to_string()),
    )?;
    let mut wallet = Wallet::from_config(config.bitcoin, wallet_config.wallet)?;
    wallet.fund()?;

    Ok(wallet)
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
    let mut wallet = prepare_bitcoin_running()?;

    //TODO: A channel that talks directly with the broker without going through localhost loopback could be implemented

    let bridge_1 = init_broker("op_1")?;
    let bridge_2 = init_broker("op_2")?;
    let bridge_3 = init_broker("op_3")?;
    //let bridge_4 = init_broker("op_4")?;

    let channels = vec![bridge_1, bridge_2, bridge_3];

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

    //one time per bitvmx instance, we need to get the public key for the speedup funding utxo
    info!("================================================");
    info!("Setting up speedup funding addresses");
    info!("================================================");
    let funding_public_id = Uuid::new_v4();
    let command = IncomingBitVMXApiMessages::GetPubKey(funding_public_id, true).to_string()?;
    send_all(&channels, &command)?;
    let msgs = get_all(&channels)?
        .iter()
        .map(|msg| OutgoingBitVMXApiMessages::from_string(&msg.0).unwrap())
        .collect::<Vec<_>>();
    let funding_key_0 = msgs[0].public_key().unwrap().1;
    let funding_key_1 = msgs[1].public_key().unwrap().1;
    let funding_key_2 = msgs[2].public_key().unwrap().1;
    set_speedup_funding(10_000_000, &funding_key_0, &channels[0], &mut wallet)?;
    set_speedup_funding(10_000_000, &funding_key_1, &channels[1], &mut wallet)?;
    set_speedup_funding(10_000_000, &funding_key_2, &channels[2], &mut wallet)?;

    info!("================================================");
    info!("Setting up aggregated addresses");
    info!("================================================");
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
                    (txid, pubuser, ordinal_fee, preimage, hash) = serde_json::from_str(&msg.0)?;
                    break;
                }
            } else {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }

        //need lockreq txid to subscribe to it

        let lockreqtx_on_chain = Uuid::new_v4();
        let command = IncomingBitVMXApiMessages::SubscribeToTransaction(lockreqtx_on_chain, txid)
            .to_string()?;
        send_all(&channels, &command)?;
        info!("Subscribe to lockreq transaction: {}", lockreqtx_on_chain);

        info!("Wait to mine");
        std::thread::sleep(std::time::Duration::from_millis(2000));
        info!("Mining blocks...");
        for _ in 0..10 {
            wallet.mine(1)?;
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        info!("Waiting bitvmx to notify tx");
        get_all(&channels)?;

        // SETUP LOCK BEGIN
        info!("================================================");
        info!("Setting LOCK");
        info!("================================================");

        let program_id = Uuid::new_v4();
        let lock_protocol_configuration = LockProtocolConfiguration::new(
            program_id,
            aggregated_pub_key,
            aggregated_happy_path,
            hardcoded_unspendable().into(),
            pubuser.into(),
            hash,
            (txid, 0, Some(ordinal_fee.to_sat()), None),
            (txid, 1, Some(lock_protocol_dust_cost(3)), None),
            10,
            100,
        );

        for c in &channels {
            lock_protocol_configuration.setup(&c, addresses.clone(), 0)?;
        }

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

        std::thread::sleep(std::time::Duration::from_millis(3000));
        info!("Mining blocks to confirm lock tx");
        for _ in 0..10 {
            wallet.mine(1)?;
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
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
        for _ in 0..10 {
            wallet.mine(1)?;
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
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

pub fn set_speedup_funding(
    amount: u64,
    pub_key: &BitcoinPubKey,
    channel: &DualChannel,
    wallet: &mut Wallet,
) -> Result<()> {
    // Send funds to the public key
    let funds = wallet.send_to_p2wpkh(&pub_key, amount, Some(1))?;

    let command = IncomingBitVMXApiMessages::DispatchTransaction(Uuid::new_v4(), funds.clone())
        .to_string()?;
    channel.send(BITVMX_ID, command)?;

    // let funds = wallet.fund_p2wpkh(pub_key, amount)?;
    std::thread::sleep(std::time::Duration::from_secs(1));
    info!("Mining a block to confirm speedup funding");
    wallet.mine(1)?;

    let funds_utxo_0 = Utxo::new(funds.compute_txid(), 0, amount, pub_key);
    let command = IncomingBitVMXApiMessages::SetFundingUtxo(funds_utxo_0).to_string()?;
    channel.send(BITVMX_ID, command)?;
    Ok(())
}
