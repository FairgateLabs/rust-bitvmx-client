//! This example demonstrates a complete end-to-end workflow of peg-in and peg-out
//! operations within the Union Bridge.
//!
//! To run this example, use the following command from the `rust-bitvmx-client` directory:
//! `cargo run --example union`

use anyhow::Result;
use bitvmx_client::{
    client::BitVMXClient,
    config::Config,
    program::participant::P2PAddress,
    types::{L2_ID, OutgoingBitVMXApiMessages::*},
};
use std::{
    sync::{Arc, Barrier, Mutex, Once},
    thread,
};
use tracing::{info, info_span};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;


macro_rules! expect_msg {
    ($self:expr, $pattern:pat => $expr:expr) => {{
        let msg = $self.bitvmx.wait_message(None, None)?;

        if let $pattern = msg {
            Ok($expr)
        } else {
            Err(anyhow::anyhow!(
                "Expected `{}` but got `{:?}`",
                stringify!($pattern),
                msg
            ))
        }
    }};
}


static INIT: Once = Once::new();


pub fn main() -> Result<()> {
    configure_tracing();
    run()?;

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
            .without_time()
            .with_target(true)
            .with_env_filter(filter)
            .init();
    });
}

struct Committee {
    operators: Vec<Operator>,
}

impl Committee {
    pub fn new() -> Result<Self> {
        let operators = vec![
            Operator::new("op_1")?,
            Operator::new("op_2")?,
            Operator::new("op_3")?,
            Operator::new("op_4")?,
        ];

        Ok(Self { operators })
    }

    pub fn run(&mut self) -> Result<()> {
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
                    let span = info_span!("operator", id = %op.id);
                    s.spawn(move || {
                        let _guard = span.enter();
                        op.run(barrier, addresses, aggregation_id)
                    })
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
    id: String,
    bitvmx: BitVMXClient,
    address: Option<P2PAddress>,
    aggregated_key: Option<bitcoin::PublicKey>,
}

impl Operator {
    pub fn new(id: &str) -> Result<Self> {
        let config = Config::new(Some(format!("config/{}.yaml", id)))?;
        let bitvmx = BitVMXClient::new(config.broker_port, L2_ID);

        Ok(Self {
            id: id.to_string(),
            address: None,
            bitvmx,
            aggregated_key: None,
        })
    }

    pub fn run(
        &mut self,
        barrier: Arc<Barrier>,
        addresses: Arc<Mutex<Vec<P2PAddress>>>,
        aggregation_id: Uuid,
    ) -> Result<()> {
        let address = self.get_peer_info()?;
        addresses.lock().unwrap().push(address);

        // wait for all operators to be done with previous step
        barrier.wait();

        let all_addresses = addresses.lock().unwrap().clone();
        self.setup_key(aggregation_id, &all_addresses)?;

        Ok(())
    }

    pub fn get_peer_info(&mut self) -> Result<P2PAddress> {
        // info!("Getting peer info");
        self.bitvmx.get_comm_info()?;
        let addr = expect_msg!(self, CommInfo(addr) => addr)?;

        self.address = Some(addr.clone());
        Ok(addr)
    }

    pub fn setup_key(&mut self, aggregation_id: Uuid, addresses: &Vec<P2PAddress>) -> Result<()> {
        // info!("Setting up key");
        self.bitvmx.setup_key(aggregation_id, addresses.clone(), 0)?;

        let aggregated_key = expect_msg!(self, AggregatedPubkey(_, key) => key)?;
        self.aggregated_key = Some(aggregated_key);
        info!(aggregated_key = ?aggregated_key.inner, "Key setup complete");

        Ok(())
    }
}
