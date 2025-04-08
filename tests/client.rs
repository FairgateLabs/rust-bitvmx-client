mod fixtures;

use std::str::FromStr;

use anyhow::Result;
use bitcoin::{absolute::LockTime, transaction::Version, PublicKey, Transaction, Txid};
use bitvmx_client::{client::BitVMXClient, config::Config, program::{participant::{P2PAddress, ParticipantRole}}, types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages}};
use p2p_handler::PeerId;
use protocol_builder::builder::Utxo;
use tracing::{info, error};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use crate::fixtures::setup;

struct ClientTest {
    program_id: Uuid,
    prover_client: BitVMXClient,
    verifier_client: BitVMXClient,
    fixtures: bitcoin::Transaction,
}

impl ClientTest {
    fn new() -> Self {
        configure_logging();

        Self {
            program_id: Uuid::new_v4(),
            prover_client: BitVMXClient::new(22222, 478),
            verifier_client: BitVMXClient::new(33333, 478),
            fixtures: setup().unwrap(),
        }
    }

    fn test_ping(&mut self) -> Result<()> {
        self.prover_client.send_message(IncomingBitVMXApiMessages::Ping()).unwrap();
        let response = self.prover_client.wait_message();

        assert_eq!(response.unwrap(), OutgoingBitVMXApiMessages::Pong());
        Ok(())
    }

    fn test_setup(&mut self) -> Result<()> {
        let txid = Txid::from_str("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b").unwrap();
        let pubkey = PublicKey::from_str("032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af")?;

        let prover_config = Config::new(Some(format!("config/prover.yaml")))?;
        let prover_funding = Utxo::new("prover_utxo".to_string(), txid, 0, 100_000_000, &pubkey);
        let prover_address = P2PAddress::new(
            prover_config.p2p_address(),
            PeerId::from_str("12D3KooWSYPZx6XNGMTqmjVftriFopc5orpEDmVAZQUcVzSUPcux")?);

        let verifier_config = Config::new(Some(format!("config/verifier.yaml")))?;
        let verifier_funding = Utxo::new("verifier_utxo".to_string(), txid, 0, 100_000_000, &pubkey);
        let verifier_address = P2PAddress::new(
            verifier_config.p2p_address(),
            PeerId::from_str("12D3KooWCL2CbGe2uHPo5CSPy7SuWSji9RjP18hRwVdvdMFK8uuC")?);

        self.prover_client.setup(
            self.program_id,
            ParticipantRole::Prover,
            verifier_address.clone(),
            verifier_funding
        )?;

        self.verifier_client.setup(
            self.program_id,
            ParticipantRole::Verifier,
            prover_address.clone(),
            prover_funding
        )

    }

    fn test_get_transaction(&mut self) -> Result<()> {
        Ok(())
    }

    fn test_subscribe_to_transaction(&mut self) -> Result<()> {
        Ok(())
    }

    fn test_dispatch_transaction(&mut self) -> Result<()> {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        self.prover_client.dispatch_transaction(self.program_id, self.fixtures.clone())?;
        Ok(())
    }
}

fn configure_logging() {
    let filter = EnvFilter::builder()
        .parse("info,libp2p=off,bitvmx_transaction_monitor=off,bitcoin_indexer=off,bitcoin_coordinator=off,p2p_protocol=off,p2p_handler=off,tarpc=off") 
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        .without_time()
        .with_target(true)
        .with_env_filter(filter)
        .init();
}


#[ignore]
#[test]
pub fn test_client() -> Result<()> {
    let mut test = ClientTest::new();

    // This tests are coupled. They depend on each other.
    test.test_ping()?;
    // test.test_setup()?;
    // test.test_get_transaction()?;
    // test.test_subscribe_to_transaction()?;
    test.test_dispatch_transaction()?;

    Ok(())
}
