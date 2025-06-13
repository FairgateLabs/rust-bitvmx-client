use anyhow::Result;
use bitcoind::bitcoind::Bitcoind;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_client::{
    client::BitVMXClient,
    config::Config,
    program::{participant::P2PAddress, protocols::{dispute::TIMELOCK_BLOCKS, protocol_handler::external_fund_tx}, variables::VariableTypes},
    types::{OutgoingBitVMXApiMessages::*, L2_ID, PROGRAM_TYPE_DISPUTE_CORE, PROGRAM_TYPE_DRP, PROGRAM_TYPE_SLOT},
};
#[path = "../../tests/common/mod.rs"]
mod common;
use bitvmx_wallet::wallet::Wallet;
use common::{
    config_trace,
    dispute::{execute_dispute, prepare_dispute},
    get_all, init_bitvmx, init_utxo, mine_and_wait, send_all,
    wait_message_from_channel,
};
use std::{thread, time::Duration};
use tracing::{info, info_span, warn};
use uuid::Uuid;
use bitcoin::{key::PrivateKey, secp256k1::{self, Secp256k1}, Network, PublicKey};
use protocol_builder::{scripts::{SignMode, timelock, check_aggregated_signature}, types::Utxo};
use std::{collections::HashMap, str::FromStr};

use crate::committee::common::{clear_db, FUNDING_ID, INITIAL_BLOCK_COUNT, WALLET_NAME};

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

struct Bitcoin {
    bitcoin_client: BitcoinClient,
    wallet: Wallet,
}

#[derive(Clone)]
enum Role {
    Operator,
    Challenger,
}

pub struct Committee {
    members: Vec<Member>,
    // TODO come up with a better name for aggregation ids
    aggregation_id_1: Uuid,
    aggregation_id_2: Uuid,
    bitcoin: Bitcoin,
}

impl Committee {
    pub fn new() -> Result<Self> {
        let members = vec![
            Member::new("op_1", Role::Operator)?,
            Member::new("op_2", Role::Operator)?,
            Member::new("op_3", Role::Operator)?,
            Member::new("op_4", Role::Challenger)?,
        ];

        let (bitcoin_client, wallet) = get_bitcoin_client()?;

        Ok(Self { members, aggregation_id_1: Uuid::new_v4(), aggregation_id_2: Uuid::new_v4(), bitcoin: Bitcoin { bitcoin_client, wallet } })
    }

    pub fn setup(&mut self) -> Result<()> {
        // gather all operator addresses
        // in a real scenario, operators should get this from the chain
        let _addresses = self.all(|op| op.get_peer_info())?;

        // setup keys
        let aggregation_id_1 = self.aggregation_id_1;
        let aggregation_id_2 = self.aggregation_id_2;

        let members = self.members.clone();
        self.all(|op| op.setup_keys(
            aggregation_id_1,
            aggregation_id_2,
            &members,
        ))?;

        // setup covenants
        let utxo = self.prepare_funding_utxo()?;
        self.all(|op| op.setup_covenants(&members, &utxo, aggregation_id_1))?;

        Ok(())
    }

    fn prepare_funding_utxo(&mut self) -> Result<Utxo> {
        // Protocol fees funding
        let fund_value = 10_000_000;
        let utxo = init_utxo(&self.bitcoin.wallet, self.members[0].keyring.aggregated_key_1.unwrap(), None, fund_value)?;

        Ok(utxo)
    }

    fn all<F, R>(&mut self, f: F) -> Result<Vec<R>>
    where
        F: Fn(&mut Member) -> Result<R> + Send + Sync + Clone,
        R: Send,
    {
        thread::scope(|s| {
            self.members
                .iter_mut()
                .map(|m| {
                    let f = f.clone();
                    let span = info_span!("member", id = %m.id);
                    s.spawn(move || span.in_scope(|| f(m)))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        })
    }
}

#[derive(Clone)]
struct DrpCovenant {
    covenant_id: Uuid,
    counterparty: P2PAddress,
}

#[derive(Clone)]
struct Covenants {
    drp_covenants: Vec<DrpCovenant>,
    // TODO: Add other covenant types here as needed
    // packet_covenants: Vec<PacketCovenant>,
    // dispute_core_covenants: Vec<DisputeCoreCovenant>,
    // multiparty_penalization_covenants: Vec<MultipartyPenalizationCovenant>,
    // pairwise_penalization_covenants: Vec<PairwisePenalizationCovenant>,
}

#[derive(Clone)]
struct Keyring {
    // TODO come up with a better name for aggregated keys
    aggregated_key_1: Option<PublicKey>,
    aggregated_key_2: Option<PublicKey>,
    communication_sk: Option<PrivateKey>,
    communication_pk: Option<PublicKey>,
    pairwise_keys: HashMap<P2PAddress, PublicKey>,
}

#[derive(Clone)]
struct Member {
    id: String,
    role: Role,
    bitvmx: BitVMXClient,
    address: Option<P2PAddress>,
    keyring: Keyring,
    covenants: Covenants,
}

impl Member {
    pub fn new(id: &str, role: Role) -> Result<Self> {
        let config = Config::new(Some(format!("config/{}.yaml", id)))?;
        let bitvmx = BitVMXClient::new(config.broker_port, L2_ID);

        Ok(Self {
            id: id.to_string(),
            role,
            address: None,
            bitvmx,
            keyring: Keyring {
                aggregated_key_1: None,
                aggregated_key_2: None,
                communication_sk: None,
                communication_pk: None,
                pairwise_keys: HashMap::new(),
            },
            covenants: Covenants {
                drp_covenants: Vec::new(),
            },
        })
    }

    pub fn prepare_drp(&mut self, covenant_id: Uuid, member1: &Member, member2: &Member, addresses: &Vec<P2PAddress>, utxo: &Utxo) -> Result<()> {
        let program_path = "../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world.yaml";
        self.bitvmx.set_var(
            covenant_id,
            "program_definition",
            VariableTypes::String(program_path.to_string())
        )?;

        self.bitvmx.set_var(
            covenant_id,
            "aggregated",
            VariableTypes::PubKey(self.keyring.aggregated_key_1.unwrap())
        )?;

        self.bitvmx.set_var(
            covenant_id,
            "FEE",
            VariableTypes::Number(10_000)
        )?;

        // TODO this txid should come from the peg-in setup?
        let txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
        let txid = bitcoin::Txid::from_str(txid_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse txid: {}", e))?;

        // Get the pairwise aggregated key for this pair
        let counterparty_address = self.get_counterparty_address(member1, member2)?;
        let pair_aggregated_pub_key = self.keyring.pairwise_keys.get(&counterparty_address)
            .ok_or_else(|| anyhow::anyhow!("Pairwise key not found for counterparty: {:?}", counterparty_address))?;
        
        let initial_utxo = Utxo::new(txid, 4, 200_000, pair_aggregated_pub_key);
        let prover_win_utxo = Utxo::new(txid, 2, 10_500, pair_aggregated_pub_key);

        let initial_spending_condition = vec![
            timelock(TIMELOCK_BLOCKS, &self.keyring.aggregated_key_1.unwrap(), SignMode::Aggregate), //convert to timelock
            check_aggregated_signature(&pair_aggregated_pub_key, SignMode::Aggregate),
        ];
        let initial_output_type =
            external_fund_tx(&self.keyring.aggregated_key_1.unwrap(), initial_spending_condition, 200_000)?;

        let prover_win_spending_condition = vec![
            check_aggregated_signature(&self.keyring.aggregated_key_1.unwrap(), SignMode::Aggregate), //convert to timelock
            check_aggregated_signature(&pair_aggregated_pub_key, SignMode::Aggregate),
        ];

        let prover_win_output_type =
            external_fund_tx(&self.keyring.aggregated_key_1.unwrap(), prover_win_spending_condition, 10_500)?;

        self.bitvmx.set_var(
            covenant_id,
            "utxo",
            VariableTypes::Utxo((initial_utxo.txid, initial_utxo.vout, Some(initial_utxo.amount), Some(initial_output_type)))
        )?;

        self.bitvmx.set_var(
            covenant_id,
            "utxo_prover_win_action",
            VariableTypes::Utxo((prover_win_utxo.txid, prover_win_utxo.vout, Some(prover_win_utxo.amount), Some(prover_win_output_type)))
        )?;

        Ok(())
    }

    pub fn get_peer_info(&mut self) -> Result<P2PAddress> {
        self.bitvmx.get_comm_info()?;
        let addr = expect_msg!(self, CommInfo(addr) => addr)?;

        self.address = Some(addr.clone());
        Ok(addr)
    }

    fn setup_keys(&mut self, aggregation_id_1: Uuid, aggregation_id_2: Uuid, members: &Vec<Member>) -> Result<()> {
        let addresses: Vec<P2PAddress> = members.iter()
            .filter_map(|m| m.address.clone())
            .collect();
        
        self.make_communication_key()?;
        self.make_aggregated_keys(aggregation_id_1, aggregation_id_2, &addresses)?;
        self.make_pairwise_keys(members, aggregation_id_1)?;

        info!(
            id = self.id,
            communication_pk = ?self.keyring.communication_pk,
            aggregated_key_1 = ?self.keyring.aggregated_key_1,
            aggregated_key_2 = ?self.keyring.aggregated_key_2,
            pairwise_keys = ?self.keyring.pairwise_keys,
            "Keys setup complete"
        );

        Ok(())
    }

    fn setup_covenants(&mut self, members: &Vec<Member>, utxo: &Utxo, aggregation_id_1: Uuid) -> Result<()> {
        self.setup_packet_covenant()?;
        // self.setup_dispute_core_covenant(members)?;
        // self.setup_multiparty_penalization_covenant()?;
        // self.setup_pairwise_penalization_covenant()?;
        self.setup_drp_covenant(members, utxo, aggregation_id_1)?;

        // info!(
        //     id = self.id,
        //     drp_covenants_count = self.covenants.drp_covenants.len(),
        //     "Covenant setup complete"
        // );

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

    fn make_pairwise_keys(&mut self, members: &Vec<Member>, session_id: Uuid) -> Result<()> {
        let my_address = self.address()?.clone();

        // Create a sorted list of members to have a canonical order of pairs.
        let mut sorted_members = members.clone();
        sorted_members.sort_by(|a, b| a.address.cmp(&b.address));

        for i in 0..sorted_members.len() {
            for j in (i + 1)..sorted_members.len() {
                let member1 = &sorted_members[i];
                let member2 = &sorted_members[j];

                let op1_address = member1.address()?;
                let op2_address = member2.address()?;

                // Check if the current operator is part of the pair
                if my_address == *op1_address || my_address == *op2_address {
                    // Skip key generation if both members are Challengers
                    if matches!(member1.role, Role::Challenger) && matches!(member2.role, Role::Challenger) {
                        info!("Skipping key generation between two Challengers: {:?} and {:?}", op1_address, op2_address);
                        continue;
                    }

                    let participants = vec![op1_address.clone(), op2_address.clone()];

                    // Create a deterministic aggregation_id for the pair that includes session_id
                    let namespace = Uuid::NAMESPACE_DNS;
                    let name_to_hash = format!("{:?}{:?}{:?}", op1_address, op2_address, session_id);
                    let aggregation_id = Uuid::new_v5(&namespace, name_to_hash.as_bytes());
                    warn!(
                        id = self.id,
                        op1_address = ?op1_address,
                        op2_address = ?op2_address,
                        session_id = ?session_id,
                        aggregation_id = ?aggregation_id,
                        "aggregation id"
                    );
                    let pairwise_key = self.setup_key(aggregation_id, &participants)?;

                    let other_address = self.get_counterparty_address(member1, member2)?;

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

    fn setup_packet_covenant(&mut self) -> Result<()> {
        // TODO
        Ok(())
    }

    fn setup_dispute_core_covenant(&mut self, members: &Vec<Member>) -> Result<()> {
        let id = Uuid::new_v4();
        let addresses = self.get_addresses(members);

        self.bitvmx.setup(id, PROGRAM_TYPE_DISPUTE_CORE.to_string(), addresses, 0)?;
        Ok(())
    }

    fn setup_multiparty_penalization_covenant(&mut self) -> Result<()> {
        // TODO
        Ok(())
    }

    fn setup_pairwise_penalization_covenant(&mut self) -> Result<()> {
        // TODO
        Ok(())
    }

    fn setup_drp_covenant(&mut self, members: &Vec<Member>, utxo: &Utxo, session_id: Uuid) -> Result<()> {
        // TODO is this the right numbers of drps? we are skipping when both are challengers, but
        // why do challengers need to create drps?
        let my_address = self.address()?.clone();

        // Create a sorted list of members to have a canonical order of pairs.
        let mut sorted_members = members.clone();
        sorted_members.sort_by(|a, b| a.address.cmp(&b.address));

        for i in 0..sorted_members.len() {
            for j in (i + 1)..sorted_members.len() {
                let member1 = &sorted_members[i];
                let member2 = &sorted_members[j];
                
                let op1_address = member1.address()?;
                let op2_address = member2.address()?;

                // Check if the current operator is part of the pair
                if my_address == *op1_address || my_address == *op2_address {
                    // Skip covenant generation if both members are Challengers
                    if matches!(member1.role, Role::Challenger) && matches!(member2.role, Role::Challenger) {
                        info!("Skipping DRP covenant generation between two Challengers: {:?} and {:?}", op1_address, op2_address);
                        continue;
                    }

                    // Unlike pairwise keys, DRP covenants need to be created in both directions
                    // Create covenant for op1_address -> op2_address
                    // let covenant_id_1 = Uuid::new_v4();
                    let namespace = Uuid::NAMESPACE_DNS;
                    let name_to_hash = format!("drp_covenant:{:?}:{:?}:{:?}", op1_address, op2_address, session_id);
                    let covenant_id_1 = Uuid::new_v5(&namespace, name_to_hash.as_bytes());
                    let participants_1 = vec![op1_address.clone(), op2_address.clone()];
                    self.prepare_drp(covenant_id_1, member1, member2, &self.get_addresses(members), utxo)?;
                    self.bitvmx.setup(covenant_id_1, PROGRAM_TYPE_DRP.to_string(), participants_1, 0)?;

                    let other_address_1 = self.get_counterparty_address(member1, member2)?;

                    self.covenants.drp_covenants.push(DrpCovenant {
                        covenant_id: covenant_id_1,
                        counterparty: other_address_1.clone(),
                    });

                    // Create covenant for op2_address -> op1_address  
                    // let covenant_id_2 = Uuid::new_v4();
                    let name_to_hash = format!("drp_covenant:{:?}:{:?}:{:?}", op2_address, op1_address, session_id);
                    let covenant_id_2 = Uuid::new_v5(&namespace, name_to_hash.as_bytes());
                    let participants_2 = vec![op2_address.clone(), op1_address.clone()];
                    self.prepare_drp(covenant_id_2, member2, member1, &self.get_addresses(members), utxo)?;
                    self.bitvmx.setup(covenant_id_2, PROGRAM_TYPE_DRP.to_string(), participants_2, 0)?;

                    self.covenants.drp_covenants.push(DrpCovenant {
                        covenant_id: covenant_id_2,
                        counterparty: other_address_1.clone(),
                    });

                    info!(
                        id = self.id,
                        counterparty = ?other_address_1,
                        covenant_1 = ?covenant_id_1,
                        covenant_2 = ?covenant_id_2,
                        "Setup DRP covenants"
                    );
                }
            }
        }

        Ok(())
    }

    /// Get own address
    fn address(&self) -> Result<&P2PAddress> {
        self.address.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Member address not set for {}", self.id))
    }

    /// Get all addresses from a list of members
    fn get_addresses(&self, members: &Vec<Member>) -> Vec<P2PAddress> {
        members.iter()
            .filter_map(|m| m.address.clone())
            .collect()
    }

    /// Determine the counterparty address in a pair of members
    fn get_counterparty_address(
        &self,
        member1: &Member,
        member2: &Member,
    ) -> Result<P2PAddress> {
        let member1_address = member1.address()?;
        let member2_address = member2.address()?;
        let my_address = self.address()?;

        let counterparty_address = if my_address == member1_address {
            member2_address
        } else if my_address == member2_address {
            member1_address
        } else {
            return Err(anyhow::anyhow!("Current member is not part of the address pair"));
        };

        Ok(counterparty_address.clone())
    }
}

pub fn hardcoded_unspendable() -> PublicKey {
    // hardcoded unspendable
    let key_bytes =
        hex::decode("02f286025adef23a29582a429ee1b201ba400a9c57e5856840ca139abb629889ad")
            .expect("Invalid hex input");
    PublicKey::from_slice(&key_bytes).expect("Invalid public key")
}

// pub fn prepare_bitcoin() -> Result<(BitcoinClient, Bitcoind, Wallet)> {
pub fn get_bitcoin_client() -> Result<(BitcoinClient, Wallet)> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    // let bitcoind = Bitcoind::new(
    //     "bitcoin-regtest",
    //     "ruimarinho/bitcoin-core",
    //     config.bitcoin.clone(),
    // );
    // info!("Starting bitcoind");
    // bitcoind.start()?;

    let wallet_config = match config.bitcoin.network {
        Network::Regtest => "config/wallet_regtest.yaml",
        Network::Testnet => "config/wallet_testnet.yaml",
        _ => panic!("Not supported network {}", config.bitcoin.network),
    };

    let wallet_config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::config::WalletConfig,
    >(Some(wallet_config.to_string()))?;
    if config.bitcoin.network == Network::Regtest {
        clear_db(&wallet_config.storage.path);
        clear_db(&wallet_config.key_storage.path);
    }
    let wallet = Wallet::new(wallet_config, true)?;
    wallet.mine(INITIAL_BLOCK_COUNT)?;

    wallet.create_wallet(WALLET_NAME)?;
    wallet.regtest_fund(WALLET_NAME, FUNDING_ID, 100_000_000)?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    // Ok((bitcoin_client, bitcoind, wallet))
    Ok((bitcoin_client, wallet))
}
