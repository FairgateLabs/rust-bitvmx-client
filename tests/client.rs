use std::{
    net::IpAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::Duration,
};

use anyhow::Result;
use bitcoin::{
    Address,
    Network::{self, Regtest},
    PublicKey,
};
mod common;
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::{
    broker_memstorage::MemStorage,
    rpc::{sync_server::BrokerSync, BrokerConfig},
};
use bitvmx_client::{
    bitvmx::{BitVMX, THROTTLE_TICKS},
    client::BitVMXClient,
    config::Config,
    program::{
        participant::P2PAddress,
        variables::{VariableTypes, WitnessTypes},
    },
    types::{
        IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, L2_ID, PROGRAM_TYPE_LOCK, PROVER_ID,
    },
};
use bitvmx_job_dispatcher_types::prover_messages::ProverJobType;
use common::{clear_db, prepare_bitcoin, INITIAL_BLOCK_COUNT};
use p2p_handler::PeerId;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
mod fixtures;

struct ClientTest {
    program_id: Uuid,
    collaboration_id: Uuid,
    prover: Operator,
    verifier: Operator,
    prover_client: BitVMXClient,
    verifier_client: BitVMXClient,
    bitcoin_client: BitcoinClient,
    miner_address: Address,
    broker: BrokerSync,
    job_dispatcher_handle: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl ClientTest {
    fn new() -> Result<Self> {
        configure_logging();

        let (bitcoin_client, _bitcoind, _wallet) = prepare_bitcoin()?;

        let prover_config = Config::new(Some(format!("config/op_1.yaml")))?;
        let verifier_config = Config::new(Some(format!("config/op_2.yaml")))?;

        let prover = Operator::new(prover_config.clone())?;
        let verifier = Operator::new(verifier_config.clone())?;

        // Start broker server
        // let broker_config = BrokerConfig::new(10000, Some(IpAddr::from([127, 0, 0, 1])));
        let broker_config = BrokerConfig::new(22222, Some(IpAddr::from([127, 0, 0, 1])));
        let broker_storage = Arc::new(Mutex::new(MemStorage::new()));
        let broker = BrokerSync::new(&broker_config, broker_storage);

        // Start job dispatcher in a separate thread
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let job_dispatcher_handle = std::thread::spawn(move || {
            use bitvmx_broker::channel::channel::DualChannel;
            let channel = DualChannel::new(&broker_config, PROVER_ID);
            let check_interval = Duration::from_secs(1);
            if let Err(e) = bitvmx_job_dispatcher::dispatcher_loop::<ProverJobType>(
                channel,
                check_interval,
                running_clone,
            ) {
                error!("Job dispatcher error: {}", e);
            }
        });

        Ok(Self {
            program_id: Uuid::new_v4(),
            collaboration_id: Uuid::new_v4(),
            prover,
            verifier,
            prover_client: BitVMXClient::new(prover_config.broker_port, L2_ID),
            verifier_client: BitVMXClient::new(verifier_config.broker_port, L2_ID),
            bitcoin_client,
            miner_address: Address::from_str("bcrt1q6uv2aekfwz20gpddpuzmw9pe8c9fzf87h9k0fq")?
                .require_network(Regtest)?,
            broker,
            job_dispatcher_handle: Some(job_dispatcher_handle),
            running,
        })
    }

    //
    // API messages
    //

    fn ping(&mut self) -> Result<()> {
        // 1. send ping
        self.prover_client
            .send_message(IncomingBitVMXApiMessages::Ping())
            .unwrap();

        // 2. advance bitvmx state to allow the message to be processed
        self.advance(1);

        // 3. wait for the response
        let _response = self.prover_client.wait_message(None, None);
        //assert_eq!(response.unwrap(), OutgoingBitVMXApiMessages::Pong());

        Ok(())
    }

    fn get_aggregated_pubkey(&mut self) -> Result<PublicKey> {
        self.prover_client.setup_key(
            self.collaboration_id,
            vec![self.prover.address.clone(), self.verifier.address.clone()],
            0,
        )?;

        self.verifier_client.setup_key(
            self.collaboration_id,
            vec![self.prover.address.clone(), self.verifier.address.clone()],
            0,
        )?;

        self.advance(2);

        let response = self.prover_client.wait_message(None, None).unwrap();

        let pubkey1 = if let OutgoingBitVMXApiMessages::AggregatedPubkey(id, pubkey) = response {
            assert_eq!(id, self.collaboration_id);
            pubkey
        } else {
            anyhow::bail!("Expected AggregatedPubkey response, got {:?}", response);
        };

        self.prover_client
            .get_aggregated_pubkey(self.collaboration_id)?;
        self.advance(1);

        let response = self.prover_client.wait_message(None, None).unwrap();

        if let OutgoingBitVMXApiMessages::AggregatedPubkey(id, pubkey2) = response {
            assert_eq!(id, self.collaboration_id);
            assert_eq!(pubkey1, pubkey2, "Aggregated pubkeys should match");
        } else {
            anyhow::bail!("Expected AggregatedPubkey response, got {:?}", response);
        }

        Ok(pubkey1)
    }

    fn set_var(&mut self, pubkey: PublicKey, secret: Vec<u8>) -> Result<()> {
        // Set operators aggregated public key
        self.prover_client.set_var(
            self.program_id,
            "operators_aggregated_pub",
            VariableTypes::PubKey(pubkey),
        )?;

        // Set operators aggregated happy path
        self.prover_client.set_var(
            self.program_id,
            "operators_aggregated_happy_path",
            VariableTypes::PubKey(pubkey), // Using same key for simplicity, in real scenario this would be different
        )?;

        // Set unspendable key
        let unspendable = fixtures::hardcoded_unspendable().into();
        self.prover_client.set_var(
            self.program_id,
            "unspendable",
            VariableTypes::PubKey(unspendable),
        )?;

        // Set secret hash
        self.prover_client.set_var(
            self.program_id,
            "secret",
            VariableTypes::Secret(secret.clone()),
        )?;

        // Create lock request transaction
        let (txid, pubuser, ordinal_fee, protocol_fee) =
            fixtures::create_lockreq_ready(pubkey, secret, Network::Regtest, &self.bitcoin_client)?;

        // Set ordinal UTXO
        self.prover_client.set_var(
            self.program_id,
            "ordinal_utxo",
            VariableTypes::Utxo((txid, 0, Some(ordinal_fee.to_sat()), None)),
        )?;

        // Set protocol fee UTXO
        self.prover_client.set_var(
            self.program_id,
            "protocol_utxo",
            VariableTypes::Utxo((txid, 1, Some(protocol_fee.to_sat()), None)),
        )?;

        // Set user public key
        self.prover_client.set_var(
            self.program_id,
            "user_pubkey",
            VariableTypes::PubKey(bitcoin::PublicKey::from(pubuser)),
        )?;

        self.advance(7);

        Ok(())
    }

    fn get_var(&mut self, pubkey: PublicKey) -> Result<()> {
        self.prover_client
            .get_var(self.program_id, "operators_aggregated_pub".to_string())?;

        self.advance(1);

        let response = self.prover_client.wait_message(None, None).unwrap();

        match response {
            OutgoingBitVMXApiMessages::Variable(id, key, value) => {
                assert_eq!(id, self.program_id);
                assert_eq!(key, "operators_aggregated_pub".to_string());
                assert_eq!(value.pubkey()?, pubkey);
            }
            _ => anyhow::bail!("Expected Variable response, got {:?}", response),
        }

        Ok(())
    }

    fn setup_lock(&mut self) -> Result<()> {
        let addresses = vec![self.prover.address.clone(), self.verifier.address.clone()];

        self.prover_client.setup(
            self.program_id,
            PROGRAM_TYPE_LOCK.to_string(),
            addresses.clone(),
            0,
        )?;
        // self.verifier_client.setup_slot(self.program_id, addresses, 0)?;

        self.advance(1);

        Ok(())
    }

    fn set_witness(&mut self, preimage: String) -> Result<String> {
        self.prover_client.set_witness(
            self.program_id,
            "secret".to_string(),
            WitnessTypes::Secret(preimage.as_bytes().to_vec()),
        )?;

        self.advance(1);

        Ok(preimage)
    }

    fn get_witness(&mut self, preimage: String) -> Result<()> {
        self.prover_client
            .get_witness(self.program_id, "secret".to_string())?;

        self.advance(1);

        let response = self.prover_client.wait_message(None, None).unwrap();

        match response {
            OutgoingBitVMXApiMessages::Witness(id, key, witness) => {
                assert_eq!(id, self.program_id);
                assert_eq!(key, "secret".to_string());
                assert_eq!(witness, WitnessTypes::Secret(preimage.as_bytes().to_vec()));
            }
            _ => anyhow::bail!("Expected Witness response, got {:?}", response),
        }

        Ok(())
    }

    // fn setup(&mut self) -> Result<()> {
    //     let txid =
    //         Txid::from_str("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
    //             .unwrap();
    //     let pubkey = PublicKey::from_str(
    //         "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
    //     )?;

    //     // let prover_funding = Utxo::new("prover_utxo".to_string(), txid, 0, 100_000_000, &pubkey);
    //     let prover_funding = Utxo::new(txid, 0, 100_000_000, &pubkey);
    //     let prover_address = P2PAddress::new(
    //         self.prover_config.p2p_address(),
    //         PeerId::from_str("12D3KooWSYPZx6XNGMTqmjVftriFopc5orpEDmVAZQUcVzSUPcux")?,
    //     );

    //     let verifier_funding =
    //         // Utxo::new("verifier_utxo".to_string(), txid, 0, 100_000_000, &pubkey);
    //         Utxo::new(txid, 0, 100_000_000, &pubkey);
    //     let verifier_address = P2PAddress::new(
    //         self.verifier_config.p2p_address(),
    //         PeerId::from_str("12D3KooWCL2CbGe2uHPo5CSPy7SuWSji9RjP18hRwVdvdMFK8uuC")?,
    //     );

    //     self.prover_client.setup(
    //         self.program_id,
    //         ParticipantRole::Prover,
    //         verifier_address.clone(),
    //         verifier_funding,
    //     )?;

    //     self.verifier_client.setup(
    //         self.program_id,
    //         ParticipantRole::Verifier,
    //         prover_address.clone(),
    //         prover_funding,
    //     )
    // }

    fn subscribe_to_transaction(&mut self, pubkey: PublicKey, secret: Vec<u8>) -> Result<()> {
        // Create and send lock request transaction
        let (txid, _pubuser, _ordinal_fee, _protocol_fee) =
            fixtures::create_lockreq_ready(pubkey, secret, Network::Regtest, &self.bitcoin_client)?;

        // Subscribe to the transaction
        let request_id = Uuid::new_v4();
        self.prover_client
            .subscribe_to_transaction(request_id, txid)?;

        // Mine blocks to ensure the transaction is confirmed
        self.bitcoin_client
            .mine_blocks_to_address(7, &self.miner_address)?;

        self.advance(12);

        // Wait for the transaction status
        let response = self.prover_client.wait_message(None, None).unwrap();
        match response {
            OutgoingBitVMXApiMessages::Transaction(rid, tx_status, _) => {
                assert_eq!(rid, request_id);
                assert_eq!(tx_status.tx_id, txid);
                //assert_eq!(tx_status.status, Finalized);
                assert_eq!(tx_status.confirmations, 6); // BitVMX has an off by one bug
            }
            _ => anyhow::bail!("Expected Transaction response, got {:?}", response),
        }

        Ok(())
    }

    fn _generate_zkp(&mut self) -> Result<()> {
        let request_id = Uuid::new_v4();
        let input = vec![50, 0, 0, 0];

        self.prover_client.generate_zkp(request_id, input)?;
        self.advance(1);

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn proof_ready(&mut self) -> Result<()> {
        let request_id = Uuid::new_v4();
        let input = vec![50, 0, 0, 0];

        // proof was not requested yet
        self.prover_client.proof_ready(request_id)?;
        self.advance(1);

        // it should not be ready
        let response = self.prover_client.wait_message(None, None).unwrap();
        assert!(matches!(
            response,
            OutgoingBitVMXApiMessages::ProofNotReady(request_id)
        ));

        // Generate a proof
        self.prover_client.generate_zkp(request_id, input)?;
        self.advance(1);

        // while proof is not ready, ask proof_ready and wait for the response
        let mut response = OutgoingBitVMXApiMessages::ProofNotReady(request_id);
        while !matches!(response, OutgoingBitVMXApiMessages::ProofReady(request_id)) {
            std::thread::sleep(Duration::from_secs(5));
            info!("Waiting for proof to be ready");
            self.prover_client.proof_ready(request_id)?;
            self.advance(2);
            response = self.prover_client.wait_message(None, None).unwrap();
        }

        assert!(matches!(
            response,
            OutgoingBitVMXApiMessages::ProofReady(request_id)
        ));

        Ok(())
    }

    // fn dispatch_transaction(&mut self) -> Result<()> {
    //     info!("Dispatching transaction: {:?}", self.fixtures.lockreq_tx.clone().compute_txid());
    //     let request_id = Uuid::new_v4();

    //     self.prover_client.dispatch_transaction(request_id, self.fixtures.lockreq_tx.clone())?;

    //     // Wait for the message to arrive before mining
    //     sleep(Duration::from_millis(100));

    //     // BitVMX needs a couple of blocks to discover the transaction
    //     // TODO remove this once the bug is fixed
    //     let bitvmx_block_delay = 3;

    //     // mine 3 blocks
    //     info!("Mining {} blocks", bitvmx_block_delay);
    //     self.bitcoin_client.mine_blocks_to_address(
    //         bitvmx_block_delay,
    //         &self.miner_address,
    //     )?;

    //     let response = self.prover_client.wait_message().unwrap();
    //     match response {
    //         OutgoingBitVMXApiMessages::Transaction(rid, tx_status) => {
    //             assert_eq!(rid, request_id);
    //             assert_eq!(tx_status.tx_id, self.fixtures.lockreq_tx.compute_txid());
    //             assert_eq!(tx_status.status, Confirmed);
    //             assert_eq!(tx_status.confirmations, 2);
    //         }
    //         _ => anyhow::bail!("Expected Transaction response, got {:?}", response),
    //     }

    //     // bitvmx notifies transaction status for 5 more confirmations
    //     // consume all messages
    //     for i in 0..5 {
    //         let confirmations = i + bitvmx_block_delay as u32;
    //         // mine 1 block
    //         info!("Mining 1 block");
    //         self.bitcoin_client.mine_blocks_to_address(
    //             1,
    //             &self.miner_address,
    //         )?;

    //         let response = self.prover_client.wait_message().unwrap();
    //         match response {
    //             OutgoingBitVMXApiMessages::Transaction(rid, tx_status) => {
    //                 assert_eq!(rid, request_id);
    //                 assert_eq!(tx_status.tx_id, self.fixtures.lockreq_tx.compute_txid());
    //                 assert_eq!(tx_status.confirmations, confirmations);
    //                 if confirmations < 6 {
    //                     assert_eq!(tx_status.status, Confirmed);
    //                 } else {
    //                     assert_eq!(tx_status.status, Finalized);
    //                 }
    //             }
    //             _ => anyhow::bail!("Expected Transaction response, got {:?}", response),
    //         }
    //     }

    //     Ok(())
    // }

    // fn get_transaction(&mut self) -> Result<()> {
    //     info!("Getting transaction status: {:?}", self.fixtures.lockreq_tx.compute_txid());

    //     let request_id = Uuid::new_v4();
    //     self.prover_client.get_transaction(request_id, self.fixtures.lockreq_tx.compute_txid())?;
    //     let response = self.prover_client.wait_message().unwrap();
    //     info!("Get Transaction Response: {:?}", response);

    //     match response {
    //         OutgoingBitVMXApiMessages::Transaction(rid, tx_status) => {
    //             assert_eq!(rid, request_id);
    //             assert_eq!(tx_status.tx_id, self.fixtures.lockreq_tx.compute_txid());
    //             assert_eq!(tx_status.confirmations, 7);
    //             assert_eq!(tx_status.status, Finalized);
    //         }
    //         _ => anyhow::bail!("Expected Transaction response, got {:?}", response),
    //     }
    //     Ok(())
    // }

    //
    // helpers
    //

    fn advance(&mut self, ticks: u32) {
        for _ in 0..ticks * THROTTLE_TICKS {
            self.prover.bitvmx.tick().unwrap();
            self.verifier.bitvmx.tick().unwrap();
        }
    }
}

impl Drop for ClientTest {
    fn drop(&mut self) {
        // Signal job dispatcher to stop
        self.running.store(false, Ordering::SeqCst);

        // Close broker
        self.broker.close();

        // Wait for job dispatcher to finish
        if let Some(handle) = self.job_dispatcher_handle.take() {
            let _ = handle.join();
        }
    }
}

fn configure_logging() {
    let default_modules = [
        "info",
        "libp2p=off",
        "bitvmx_transaction_monitor=off",
        "bitcoin_indexer=off",
        "bitcoin_coordinator=off",
        "p2p_protocol=off",
        "p2p_handler=off",
        "tarpc=off",
        "key_manager=off",
        "memory=off",
        "broker=off",
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
}

struct Operator {
    bitvmx: BitVMX,
    address: P2PAddress,
}

impl Operator {
    fn new(config: Config) -> Result<Self> {
        info!("Storage: {:?}", config.storage.path);
        info!("Clearing previous databases");
        clear_db(&config.storage.path);
        clear_db(&config.key_storage.path);
        clear_db(&config.broker_storage.path);

        let bitvmx = BitVMX::new(config)?;
        let address = P2PAddress::new(&bitvmx.address(), PeerId::from_str(&bitvmx.peer_id())?);

        Ok(Self { bitvmx, address })
    }
}

#[ignore]
#[test]
pub fn test_client() -> Result<()> {
    // setup test
    let mut test = ClientTest::new()?;

    // get to the top of the chain
    test.advance(INITIAL_BLOCK_COUNT as u32);

    // initialize secret
    let preimage = "top_secret".to_string();
    let secret = fixtures::sha256(preimage.as_bytes().to_vec());

    // run the tests
    // This tests are coupled. They depend on each other.
    test.ping()?;
    let pubkey = test.get_aggregated_pubkey()?;
    test.subscribe_to_transaction(pubkey, secret.clone())?;
    test.set_var(pubkey, secret)?;
    test.get_var(pubkey)?;
    test.setup_lock()?;
    let preimage = test.set_witness(preimage)?;
    test.get_witness(preimage)?;
    // test.generate_zkp()?;
    #[cfg(target_os = "linux")]
    test.proof_ready()?;

    // test.dispatch_transaction()?;
    // test.get_transaction()?;

    Ok(())
}
