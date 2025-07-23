use crate::{expect_msg, request_pegin::RequestPegin};
use anyhow::Result;
use bitcoin::{PublicKey, Txid};
use tracing::info;

use bitvmx_client::{
    client::BitVMXClient,
    config::Config,
    types::{OutgoingBitVMXApiMessages::*, L2_ID},
};

pub struct User {
    pub config: Config,
    pub id: String,
    pub bitvmx: BitVMXClient,
}

impl User {
    pub fn new(id: &str) -> Result<Self> {
        let config = Config::new(Some(format!("config/{}.yaml", id)))?;
        let bitvmx = BitVMXClient::new(config.broker_port, L2_ID);

        Ok(Self {
            config,
            id: id.to_string(),
            bitvmx,
        })
    }

    pub fn request_pegin(
        &mut self,
        committee_public_key: &PublicKey,
        stream_value: u64,
    ) -> Result<Txid> {
        info!(id = self.id, "Requesting pegin");
        // Enable RSK pegin monitoring using the public API
        self.bitvmx.subscribe_to_rsk_pegin()?;
        info!("Subscribed to RSK pegin");

        // Create a proper RSK pegin transaction and send it as if it was a user transaction
        let mut request_pegin = RequestPegin::new(&self.config)?;
        let packet_number = 0;
        let rsk_address = "7ac5496aee77c1ba1f0854206a26dda82a81d6d8";
        let request_pegin_txid = request_pegin.create_and_send_transaction(
            *committee_public_key,
            stream_value,
            packet_number,
            rsk_address,
        )?;
        info!("Sent RSK pegin transaction to bitcoind");

        // Wait for Bitvmx news PeginTransactionFound message
        info!("Waiting for RSK pegin transaction to be found");
        let (found_txid, tx_status) =
            expect_msg!(self, PeginTransactionFound(txid, tx_status) => (txid, tx_status))?;
        assert_eq!(
            found_txid, request_pegin_txid,
            "Request Pegin Transaction not found"
        );
        assert!(
            tx_status.confirmations > 0,
            "Request Pegin Transaction not confirmed"
        );
        info!("RSK pegin transaction test completed successfully");
        info!("Transaction ID: {}", request_pegin_txid);

        // Get the SPV proof, this should be used by the union client to present to the smart contract
        self.bitvmx.get_spv_proof(found_txid)?;
        let spv_proof = expect_msg!(self, SPVProof(_, Some(spv_proof)) => spv_proof)?;
        info!("SPV proof: {:?}", spv_proof);

        // Union client calls the smart contract PegManager.requestPegin(spv_proof)
        // Smart contracts emits the  PeginRequested event

        Ok(request_pegin_txid)
    }
}
