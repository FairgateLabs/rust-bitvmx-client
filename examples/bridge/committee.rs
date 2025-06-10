use anyhow::Result;
use bitvmx_client::{
    client::BitVMXClient,
    config::Config,
    program::participant::P2PAddress,
    types::{L2_ID, OutgoingBitVMXApiMessages::*},
};
use std::{
    sync::{Arc, Barrier, Mutex},
    thread,
};
use tracing::{info, info_span};
use uuid::Uuid;
use bitcoin::PublicKey;

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

pub struct Committee {
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
    aggregated_key: Option<PublicKey>,
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
        // get bitvmx node address and peer id
        let address = self.get_peer_info()?;
        addresses.lock().unwrap().push(address);

        // wait for all operators to be done with previous step
        barrier.wait();

        // setup aggregated key
        let all_addresses = addresses.lock().unwrap().clone();
        self.setup_key(aggregation_id, &all_addresses)?;

        Ok(())
    }

    pub fn get_peer_info(&mut self) -> Result<P2PAddress> {
        self.bitvmx.get_comm_info()?;
        let addr = expect_msg!(self, CommInfo(addr) => addr)?;

        self.address = Some(addr.clone());
        Ok(addr)
    }

    pub fn setup_key(&mut self, aggregation_id: Uuid, addresses: &Vec<P2PAddress>) -> Result<()> {
        self.bitvmx.setup_key(aggregation_id, addresses.clone(), 0)?;

        let aggregated_key = expect_msg!(self, AggregatedPubkey(_, key) => key)?;
        self.aggregated_key = Some(aggregated_key);
        info!(aggregated_key = ?aggregated_key.inner, "Key setup complete");

        Ok(())
    }
}
