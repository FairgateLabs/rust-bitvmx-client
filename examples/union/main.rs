//! This example demonstrates a complete end-to-end workflow of peg-in and peg-out
//! operations within the Union Bridge.
//!
//! To run this example, use the following command from the `rust-bitvmx-client` directory:
//! `cargo run --example union`

use anyhow::Result;
use bitcoin::{
    key::{rand::rngs::OsRng, Parity, Secp256k1},
    secp256k1::{self, All, PublicKey as SecpPublicKey, SecretKey},
    Address, Amount, Network, PublicKey as BitcoinPubKey, Txid,
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
        self, participant::P2PAddress, variables::{VariableTypes, WitnessTypes}
    },
    types::{
        IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, L2_ID, PROGRAM_TYPE_LOCK,
    },
};

use storage_backend::{storage::Storage, storage_config::StorageConfig};
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use std::{
    str::FromStr,
    sync::{Arc, Barrier, Mutex, Once},
    thread,
};

static INIT: Once = Once::new();

pub fn main() -> Result<()> {
    configure_tracing();

    let config = StorageConfig::new("/tmp/union_broker".to_string(), None);
    let broker_backend = Storage::new(&config)?;
    let broker_backend = Arc::new(Mutex::new(broker_backend));
    let broker_storage = Arc::new(Mutex::new(BrokerStorage::new(broker_backend)));
    let broker_config = BrokerConfig::new(54321, None);
    let mut broker = BrokerSync::new(&broker_config, broker_storage.clone());

    run()?;

    broker.close();
    Ok(())
}

pub fn run() -> Result<()> {
    let mut committee = Committee::new()?;
    committee.run()?;
    Ok(())
}

fn configure_tracing() {
    INIT.call_once(|| {
        let default_modules = [
            "info",
            "libp2p=off",
            "bitvmx_transaction_monitor=off",
            "bitcoin_indexer=off",
            "bitcoin_coordinator=info",
            "p2p_protocol=off",
            "p2p_handler=off",
            "tarpc=off",
            "key_manager=off",
            "memory=off",
        ];
    
        let filter = EnvFilter::builder()
            .parse(default_modules.join(","))
            .expect("Invalid filter");
    
        tracing_subscriber::fmt()
            //.without_time()
            //.with_ansi(false)
            .with_target(true)
            .with_env_filter(filter)
            .init();
    });
}

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

    let wallet = bitcoin_client
        .init_wallet(Network::Regtest, "test_wallet")
        .unwrap();

    info!("Mine 1 blocks to address {:?}", wallet);
    bitcoin_client.mine_blocks_to_address(1, &wallet).unwrap();

    Ok((bitcoin_client, wallet))
}

struct Committee {
    operators: Vec<Operator>,
    addresses: Option<Vec<P2PAddress>>,
}

impl Committee {
    pub fn new() -> Result<Self> {
        let operators = vec![
            Operator::new("op_1")?,
            Operator::new("op_2")?,
            Operator::new("op_3")?,
            Operator::new("op_4")?,
        ];

        Ok(Self { operators, addresses: None })
    }

    pub fn run(&mut self) -> Result<()> {
        info!("Running committee...");
        let aggregation_id = Uuid::new_v4();
        let barrier = Arc::new(Barrier::new(self.operators.len()));
        let addresses = Arc::new(Mutex::new(Vec::new()));
        thread::scope(|s| {
            let handles: Vec<_> = self
                .operators
                .iter_mut()
                .map(|op| {
                    let barrier = barrier.clone();
                    let addresses = addresses.clone();
                    s.spawn(move || op.run(barrier, addresses, aggregation_id))
                })
                .collect();
            for handle in handles {
                handle.join().unwrap()?;
            }
            Ok(())
        })
    }
}

struct Operator {
    channel: DualChannel,
    address: Option<P2PAddress>,
}

impl Operator {
    pub fn new(role: &str) -> Result<Self> {
        let config = Config::new(Some(format!("config/{}.yaml", role)))?;
        let broker_config = BrokerConfig::new(config.broker_port, None);
        let bridge_client = DualChannel::new(&broker_config, L2_ID);
        Ok(Self { channel: bridge_client, address: None })
    }

    pub fn run(
        &mut self,
        barrier: Arc<Barrier>,
        addresses: Arc<Mutex<Vec<P2PAddress>>>,
        aggregation_id: Uuid,
    ) -> Result<()> {
        let address = self.get_peer_info()?;
        addresses.lock().unwrap().push(address);

        barrier.wait();

        let all_addresses = addresses.lock().unwrap().clone();
        self.setup_key(aggregation_id, &all_addresses)?;

        Ok(())
    }

    pub fn get_peer_info(&mut self) -> Result<P2PAddress> {
        let command = IncomingBitVMXApiMessages::GetCommInfo().to_string()?;
        self.channel.send(BITVMX_ID, command)?;
        let msg = wait_message_from_channel(&self.channel)?;
        // info!("Received message from channel: {:?}", msg);

        let address;
        let comm_info = OutgoingBitVMXApiMessages::from_string(&msg.0).unwrap();
        match comm_info {
            OutgoingBitVMXApiMessages::CommInfo(addr) => {
                info!("CommInfo: {:?}", addr);
                address = addr;
            }
            _ => panic!("Expected CommInfo message"),
        }

        self.address = Some(address.clone());

        Ok(address)
    }

    pub fn setup_key(&mut self, aggregation_id: Uuid, addresses: &Vec<P2PAddress>) -> Result<()> {
         let command =
            IncomingBitVMXApiMessages::SetupKey(aggregation_id, addresses.clone(), 0).to_string()?;
        self.channel.send(BITVMX_ID, command)?;

        self.get_aggregated_pub_key()?;

        Ok(())
    }

    pub fn get_aggregated_pub_key(&mut self) -> Result<()> {
        let msg = wait_message_from_channel(&self.channel)?;
        info!("Received message from channel: {:?}", msg);
        let msg = OutgoingBitVMXApiMessages::from_string(&msg.0)?;
        let aggregated_pub_key = match msg {
            OutgoingBitVMXApiMessages::AggregatedPubkey(_uuid, aggregated_pub_key) => {
                info!("Aggregated pubkey: {:?}", aggregated_pub_key);
                aggregated_pub_key
            }
            _ => panic!("Expected AggregatedPubkey message"),
        };

        Ok(())
    }
}
