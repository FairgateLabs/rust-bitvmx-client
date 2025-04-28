use std::{str::FromStr, thread::sleep, time::Duration};

use anyhow::Result;
use bitcoin::{absolute::LockTime, transaction::Version, Address, Network::Regtest, PublicKey, Transaction, Txid};

mod common;
use common::{clear_db, init_bitvmx, prepare_bitcoin, wait_message_from_channel, INITIAL_BLOCK_COUNT};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_client::{
    bitvmx::{BitVMX, THROTTLE_TICKS}, client::BitVMXClient, config::Config, program::{participant::{P2PAddress, ParticipantRole}, variables::{VariableTypes, WitnessTypes}}, types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, L2_ID}
};
use bitvmx_transaction_monitor::types::TransactionBlockchainStatus::{Confirmed, Finalized};
use p2p_handler::PeerId;
use protocol_builder::types::Utxo;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;


struct ClientTest {
    program_id: Uuid,
    collaboration_id: Uuid,
    prover: Operator,
    verifier: Operator,
    prover_client: BitVMXClient,
    verifier_client: BitVMXClient,
    bitcoin_client: BitcoinClient,
    miner_address: Address,
}

impl ClientTest {
    fn new() -> Result<Self> {
        configure_logging();

        let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;

        let prover_config = Config::new(Some(format!("config/op_1.yaml")))?;
        let verifier_config = Config::new(Some(format!("config/op_2.yaml")))?;

        let mut prover = Operator::new(prover_config.clone())?;
        let mut verifier = Operator::new(verifier_config.clone())?;

        // get to the top of the chain
        for _ in 0..THROTTLE_TICKS * INITIAL_BLOCK_COUNT as u32 {
            prover.bitvmx.tick().unwrap();
            verifier.bitvmx.tick().unwrap();
        }

        Ok(Self {
            program_id: Uuid::new_v4(),
            collaboration_id: Uuid::new_v4(),
            prover: prover,
            verifier: verifier,
            prover_client: BitVMXClient::new(prover_config.broker_port, L2_ID),
            verifier_client: BitVMXClient::new(verifier_config.broker_port, L2_ID),
            bitcoin_client: bitcoin_client,
            miner_address: Address::from_str("bcrt1q6uv2aekfwz20gpddpuzmw9pe8c9fzf87h9k0fq")?.require_network(Regtest)?,
        })
    }

    fn ping(&mut self) -> Result<()> {
        // 1. send ping
        self.prover_client
            .send_message(IncomingBitVMXApiMessages::Ping())
            .unwrap();

        // 2. advance bitvmx state to allow the message to be processed
        self.advance(1);

        // 3. wait for the response
        let response = self.prover_client.wait_message(None, None);
        assert_eq!(response.unwrap(), OutgoingBitVMXApiMessages::Pong());

        Ok(())
    }

    fn get_aggregated_pubkey(&mut self) -> Result<PublicKey> {
        self.prover_client.setup_key(
            self.collaboration_id,
            vec![self.prover.address.clone(), self.verifier.address.clone()],
            0
        )?;
        
        self.verifier_client.setup_key(
            self.collaboration_id,
            vec![self.prover.address.clone(), self.verifier.address.clone()],
            0
        )?;

        self.advance(2);

        let response1 = self.prover_client.wait_message(None, None).unwrap();

        let pubkey1 = if let OutgoingBitVMXApiMessages::AggregatedPubkey(id, pubkey) = response1 {
            assert_eq!(id, self.collaboration_id);
            pubkey
        } else {
            anyhow::bail!("Expected AggregatedPubkey response, got {:?}", response1);
        };

        self.prover_client.get_aggregated_pubkey(self.collaboration_id)?;
        self.advance(1);

        let response2 = self.prover_client.wait_message(None, None).unwrap();

        if let OutgoingBitVMXApiMessages::AggregatedPubkey(id, pubkey2) = response2 {
            assert_eq!(id, self.collaboration_id);
            assert_eq!(pubkey1, pubkey2, "Aggregated pubkeys should match");
        } else {
            anyhow::bail!("Expected AggregatedPubkey response, got {:?}", response2);
        }

        Ok(pubkey1)
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

    fn subscribe_to_transaction(&mut self) -> Result<()> {
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

    // fn generate_zkp(&mut self) -> Result<()> {
    //     let request_id = Uuid::new_v4();

    //     self.prover_client.generate_zkp(request_id)?;

    //     Ok(())
    // }

    // fn proof_ready(&mut self) -> Result<()> {
    //     Ok(())
    // }

    // fn execute_zkp(&mut self) -> Result<()> {
    //     Ok(())
    // }

    fn set_var(&mut self, pubkey: PublicKey) -> Result<()> {
        self.prover_client.set_var(
            self.program_id,
            "operators_aggregated_pub".to_string(),
            VariableTypes::PubKey(pubkey)
        )?;

        self.advance(1);

        Ok(())
    }

    fn get_var(&mut self, pubkey: PublicKey) -> Result<()> {
        self.prover_client.get_var(
            self.program_id,
            "operators_aggregated_pub".to_string()
        )?;

        self.advance(1);

        let response = self.prover_client.wait_message(None, None).unwrap();

        match response {
            OutgoingBitVMXApiMessages::Variable(id, key, value) => {
                assert_eq!(id, self.program_id);
                assert_eq!(key, "operators_aggregated_pub".to_string());
                assert_eq!(value, VariableTypes::PubKey(pubkey));
            }
            _ => anyhow::bail!("Expected Variable response, got {:?}", response),
        }

        Ok(())
    }

    fn set_witness(&mut self) -> Result<String> {
        let preimage = "top_secret".to_string();

        self.prover_client.set_witness(
            self.program_id,
            "secret".to_string(),
            WitnessTypes::Secret(preimage.as_bytes().to_vec())
        )?;

        self.advance(1);

        Ok(preimage)
    }

    fn get_witness(&mut self, preimage: String) -> Result<()> {
        self.prover_client.get_witness(
            self.program_id,
            "secret".to_string()
        )?;

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

    fn advance(&mut self, ticks: u32) {
        for _ in 0.. ticks * THROTTLE_TICKS {
            self.prover.bitvmx.tick().unwrap();
            self.verifier.bitvmx.tick().unwrap();
        }
    }
}


fn configure_logging() {
    let default_modules = [
        "info",
        "libp2p=off",
        "bitvmx_transaction_monitor=off",
        "bitcoin_indexer=off",
        // "bitcoin_coordinator=off",
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
        info!("Storage: {:?}", config.storage.db);
        info!("Clearing previous databases");
        clear_db(&config.storage.db);
        clear_db(&config.key_storage.path);
        clear_db(&config.broker_storage);

    
        let bitvmx = BitVMX::new(config)?;
        let address = P2PAddress::new(&bitvmx.address(), PeerId::from_str(&bitvmx.peer_id())?);

        Ok(Self { bitvmx, address })
    }
    
}

#[ignore]
#[test]
pub fn test_client() -> Result<()> {
    let mut test = ClientTest::new()?;

    // This tests are coupled. They depend on each other.
    test.ping()?;
    let pubkey = test.get_aggregated_pubkey()?;
    // test.dispatch_transaction()?;
    // test.get_transaction()?;
    // test.generate_zkp()?;
    test.set_var(pubkey)?;
    test.get_var(pubkey)?;
    let preimage = test.set_witness()?;
    test.get_witness(preimage)?;

    Ok(())
}
