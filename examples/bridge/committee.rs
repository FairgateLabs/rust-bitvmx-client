use anyhow::Result;
use bitvmx_client::{
    client::BitVMXClient,
    config::Config,
    program::participant::P2PAddress,
    types::{L2_ID, OutgoingBitVMXApiMessages::*},
};
use std::{thread::{self, sleep}, time::Duration};
use tracing::{info, info_span};
use uuid::Uuid;
use bitcoin::{key::PrivateKey, secp256k1::{self, Secp256k1}, PublicKey};
use std::collections::HashMap;

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
    // TODO come up with a better name for aggregation ids
    aggregation_id_1: Uuid,
    aggregation_id_2: Uuid,
}

impl Committee {
    pub fn new() -> Result<Self> {
        let operators = vec![
            Operator::new("op_1")?,
            Operator::new("op_2")?,
            Operator::new("op_3")?,
            Operator::new("op_4")?,
        ];

        Ok(Self { operators, aggregation_id_1: Uuid::new_v4(), aggregation_id_2: Uuid::new_v4() })
    }

    pub fn setup(&mut self) -> Result<()> {
        // gather all operator addresses
        // in a real scenario, operators should get this from the chain
        let addresses = self.all(|op| op.get_peer_info())?;

        // run setup for each operator
        let aggregation_id_1 = self.aggregation_id_1;
        let aggregation_id_2 = self.aggregation_id_2;
        self.all(|op| op.setup(
            aggregation_id_1,
            aggregation_id_2,
            &addresses,
        ))?;

        Ok(())
    }

    fn all<F, R>(&mut self, f: F) -> Result<Vec<R>>
    where
        F: Fn(&mut Operator) -> Result<R> + Send + Sync + Clone,
        R: Send,
    {
        thread::scope(|s| {
            self.operators
                .iter_mut()
                .map(|op| {
                    let f = f.clone();
                    let span = info_span!("operator", id = %op.id);
                    s.spawn(move || span.in_scope(|| f(op)))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        })
    }
}

struct Keyring {
    // TODO come up with a better name for aggregated keys
    aggregated_key_1: Option<PublicKey>,
    aggregated_key_2: Option<PublicKey>,
    communication_sk: Option<PrivateKey>,
    communication_pk: Option<PublicKey>,
    pairwise_keys: HashMap<P2PAddress, PublicKey>,
}

struct Operator {
    id: String,
    bitvmx: BitVMXClient,
    address: Option<P2PAddress>,
    keyring: Keyring,
}

impl Operator {
    pub fn new(id: &str) -> Result<Self> {
        let config = Config::new(Some(format!("config/{}.yaml", id)))?;
        let bitvmx = BitVMXClient::new(config.broker_port, L2_ID);

        Ok(Self {
            id: id.to_string(),
            address: None,
            bitvmx,
            keyring: Keyring {
                aggregated_key_1: None,
                aggregated_key_2: None,
                communication_sk: None,
                communication_pk: None,
                pairwise_keys: HashMap::new(),
            },
        })
    }

    pub fn get_peer_info(&mut self) -> Result<P2PAddress> {
        self.bitvmx.get_comm_info()?;
        let addr = expect_msg!(self, CommInfo(addr) => addr)?;

        self.address = Some(addr.clone());
        Ok(addr)
    }

    pub fn setup(&mut self, aggregation_id_1: Uuid, aggregation_id_2: Uuid, addresses: &Vec<P2PAddress>) -> Result<()> {
        self.make_communication_key()?;
        self.make_aggregated_keys(aggregation_id_1, aggregation_id_2, addresses)?;
        self.make_pairwise_keys(addresses)?;

        info!(
            id = self.id,
            communication_pk = ?self.keyring.communication_pk,
            aggregated_key_1 = ?self.keyring.aggregated_key_1,
            aggregated_key_2 = ?self.keyring.aggregated_key_2,
            pairwise_keys = ?self.keyring.pairwise_keys,
            "Setup complete"
        );
        Ok(())
    }

    fn make_communication_key(&mut self) -> Result<()> {
        // TODO is this just a regular (sk,pk) pair?
        let secp = Secp256k1::new();
        let mut rng = secp256k1::rand::thread_rng();
        let (secret_key, _) = secp.generate_keypair(&mut rng);
        let private_key = PrivateKey {
            compressed: true,
            network: bitcoin::NetworkKind::Test,
            inner: secret_key,
        };
        let public_key = private_key.public_key(&secp);

        self.keyring.communication_sk = Some(private_key);
        self.keyring.communication_pk = Some(public_key);

        info!(
            id = self.id,
            public_key = ?public_key,
            "Generated communication key"
        );

        Ok(())
    }

    fn make_aggregated_keys(&mut self, aggregation_id_1: Uuid, aggregation_id_2: Uuid, addresses: &Vec<P2PAddress>) -> Result<()> {
        let aggregated_key_1 = self.setup_key(aggregation_id_1, addresses)?;
        self.keyring.aggregated_key_1 = Some(aggregated_key_1);

        let aggregated_key_2 = self.setup_key(aggregation_id_2, addresses)?;
        self.keyring.aggregated_key_2 = Some(aggregated_key_2);

        Ok(())
    }

    fn make_pairwise_keys(&mut self, all_addresses: &Vec<P2PAddress>) -> Result<()> {
        let my_address = self
            .address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Operator address not set"))?
            .clone();

        // Create a sorted list of addresses to have a canonical order of pairs.
        let mut sorted_addresses = all_addresses.clone();
        sorted_addresses.sort();

        for i in 0..sorted_addresses.len() {
            for j in (i + 1)..sorted_addresses.len() {
                println!("i: {}, j: {}", i, j);
                let op1_address = &sorted_addresses[i];
                let op2_address = &sorted_addresses[j];

                // Check if the current operator is part of the pair
                if my_address == *op1_address || my_address == *op2_address {
                    let participants = vec![op1_address.clone(), op2_address.clone()];

                    // Create a deterministic aggregation_id for the pair
                    let namespace = Uuid::NAMESPACE_DNS;
                    let name_to_hash = format!("{:?}{:?}", op1_address, op2_address);
                    let aggregation_id = Uuid::new_v5(&namespace, name_to_hash.as_bytes());

                    let pairwise_key = self.setup_key(aggregation_id, &participants)?;

                    let other_address = if my_address == *op1_address {
                        op2_address
                    } else {
                        op1_address
                    };
                    self.keyring
                        .pairwise_keys
                        .insert(other_address.clone(), pairwise_key);

                    info!(peer = ?other_address, key = ?pairwise_key, "Generated pairwise key");
                }
            }
        }
        Ok(())
    }

    fn setup_key(&mut self, aggregation_id: Uuid, addresses: &Vec<P2PAddress>) -> Result<PublicKey> {
        self.bitvmx.setup_key(aggregation_id, addresses.clone(), 0)?;

        let aggregated_key = expect_msg!(self, AggregatedPubkey(_, key) => key)?;
        info!(aggregated_key = ?aggregated_key.inner, "Key setup complete");

        Ok(aggregated_key)
    }
}
