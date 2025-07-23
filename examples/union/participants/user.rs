use crate::{bitcoin::emulated_user_keypair, expect_msg};
use anyhow::Result;
use bitcoin::{
    absolute,
    hex::FromHex,
    key::Secp256k1,
    secp256k1::{self, All, Message, SecretKey},
    sighash::SighashCache,
    transaction, Address as BitcoinAddress, Amount, Network, OutPoint,
    PrivateKey as BitcoinPrivKey, PublicKey, PublicKey as BitcoinPubKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use protocol_builder::scripts::{build_taproot_spend_info, op_return_script, timelock, SignMode};
use tracing::info;

use bitvmx_client::{
    client::BitVMXClient,
    config::Config,
    types::{OutgoingBitVMXApiMessages::*, L2_ID},
};

pub struct User {
    pub id: String,
    pub bitvmx: BitVMXClient,
    public_key: BitcoinPubKey,
    pub bitcoin_client: BitcoinClient,
    pub address: BitcoinAddress,
    secret_key: SecretKey,
    pub network: Network,
    pub secp: Secp256k1<All>,
}

impl User {
    pub fn new(id: &str) -> Result<Self> {
        let config = Config::new(Some(format!("config/{}.yaml", id)))?;
        let bitvmx = BitVMXClient::new(config.broker_port, L2_ID);
        let bitcoin_client = BitcoinClient::new(
            &config.bitcoin.url,
            &config.bitcoin.username,
            &config.bitcoin.password,
        )?;

        let network = Network::Regtest;
        let secp = Secp256k1::new();
        let (user_address, user_pubkey, user_sk) =
            emulated_user_keypair(&secp, &bitcoin_client, network)?;

        Ok(Self {
            id: id.to_string(),
            bitvmx,
            bitcoin_client,
            public_key: user_pubkey,
            address: user_address,
            secret_key: user_sk,
            network,
            secp,
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
        let packet_number = 0;
        let rsk_address = "7ac5496aee77c1ba1f0854206a26dda82a81d6d8";
        let request_pegin_txid = self.create_and_send_request_pegin_tx(
            *committee_public_key,
            stream_value,
            packet_number,
            rsk_address,
        )?;
        info!("Sent RSK pegin transaction to bitcoind");

        // Wait for Bitvmx news PeginTransactionFound message
        info!("Waiting for RSK pegin transaction to be found");
        let (found_txid, tx_status) =
            expect_msg!(self.bitvmx, PeginTransactionFound(txid, tx_status) => (txid, tx_status))?;
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
        let spv_proof = expect_msg!(self.bitvmx, SPVProof(_, Some(spv_proof)) => spv_proof)?;
        info!("SPV proof: {:?}", spv_proof);

        // Union client calls the smart contract PegManager.requestPegin(spv_proof)
        // Smart contracts emits the  PeginRequested event

        Ok(request_pegin_txid)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        Ok(self.public_key)
    }

    pub fn create_and_send_request_pegin_tx(
        &mut self,
        aggregated_pubkey: PublicKey,
        stream_value: u64,
        packet_number: u64,
        rsk_address: &str,
    ) -> Result<Txid> {
        // We'll create a transaction that will be detected as RSK pegin by the transaction monitor.
        let signed_transaction = self.create_rsk_request_pegin_transaction(
            aggregated_pubkey,
            stream_value,
            packet_number,
            rsk_address,
        )?;
        let txid = self
            .bitcoin_client
            .send_transaction(&signed_transaction)
            .unwrap();

        // Get the transaction and verify it was created
        let request_pegin_tx = self.bitcoin_client.get_transaction(&txid)?.unwrap();
        let request_pegin_txid = request_pegin_tx.compute_txid();

        // Mine blocks to include the transaction
        self.bitcoin_client
            .mine_blocks_to_address(1, &self.address)?;

        Ok(request_pegin_txid)
    }

    fn create_rsk_request_pegin_transaction(
        &mut self,
        aggregated_key: PublicKey,
        stream_value: u64,
        packet_number: u64,
        rsk_address: &str,
    ) -> Result<Transaction> {
        // RSK Pegin constants
        pub const KEY_SPEND_FEE: u64 = 335;
        pub const OP_RETURN_FEE: u64 = 300;
        pub const TIMELOCK_BLOCKS: u16 = 1;

        let value = stream_value;
        let fee = KEY_SPEND_FEE;
        let op_return_fee = OP_RETURN_FEE;
        let total_amount = value + fee + op_return_fee;

        // Fund the user address with enough to cover the taproot output + fees
        let (funding_tx, vout) = self
            .bitcoin_client
            .fund_address(&self.address, Amount::from_sat(total_amount))
            .unwrap();

        // RSK Pegin values
        let rootstock_address = self.address_to_bytes(rsk_address)?;
        let reimbursement_xpk = self.public_key.into();

        // Create the Request pegin transaction
        // Inputs
        let funds_input = TxIn {
            previous_output: OutPoint::new(funding_tx.compute_txid(), vout),
            script_sig: ScriptBuf::default(), // For a p2wpkh script_sig is empty.
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // we want to be able to replace this transaction
            witness: Witness::default(),                // Filled in after, at signing time.
        };

        // Outputs
        // Taproot output
        let op_data = [rootstock_address.as_slice(), value.to_be_bytes().as_slice()].concat();
        let script_op_return = op_return_script(op_data)?;
        let script_timelock = timelock(TIMELOCK_BLOCKS, &self.public_key, SignMode::Single);

        let taproot_spend_info = build_taproot_spend_info(
            &self.secp,
            &aggregated_key.into(),
            &[script_timelock, script_op_return],
        )?;

        let taproot_script_pubkey = ScriptBuf::new_p2tr(
            &self.secp,
            taproot_spend_info.internal_key(),
            taproot_spend_info.merkle_root(),
        );

        let taproot_output = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: taproot_script_pubkey,
        };

        // OP_RETURN output
        let op_return_data = User::request_pegin_op_return_data(
            packet_number,
            rootstock_address,
            reimbursement_xpk,
        )?;
        let op_return_output = TxOut {
            value: Amount::from_sat(0), // OP_RETURN outputs should have 0 value
            script_pubkey: op_return_script(op_return_data)?.get_script().clone(),
        };

        let mut request_pegin_transaction = Transaction {
            version: transaction::Version::TWO,  // Post BIP-68.
            lock_time: absolute::LockTime::ZERO, // Ignore the transaction lvl absolute locktime.
            input: vec![funds_input],
            output: vec![taproot_output, op_return_output],
        };

        let signed_transaction = self
            .sign_p2wpkh_transaction_single_input(&mut request_pegin_transaction, total_amount)?;
        info!(
            "Signed RSK request pegin transaction: {:#?}",
            signed_transaction
        );

        Ok(signed_transaction)
    }

    fn request_pegin_op_return_data(
        packet_number: u64,
        rootstock_address: [u8; 20],
        reimbursement_xpk: XOnlyPublicKey,
    ) -> Result<Vec<u8>> {
        let mut user_data = [0u8; 69];
        user_data.copy_from_slice(
            [
                b"RSK_PEGIN".as_slice(),
                &packet_number.to_be_bytes(),
                &rootstock_address,
                &reimbursement_xpk.serialize(),
            ]
            .concat()
            .as_slice(),
        );
        Ok(user_data.to_vec())
    }

    fn address_to_bytes(&self, address: &str) -> Result<[u8; 20]> {
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(Vec::from_hex(address).unwrap().as_slice());
        Ok(address_bytes)
    }

    fn sign_p2wpkh_transaction_single_input(
        &mut self,
        transaction: &mut Transaction,
        value: u64,
    ) -> Result<Transaction> {
        let user_bitcoin_privkey = BitcoinPrivKey {
            compressed: true,
            network: self.network.into(),
            inner: self.secret_key,
        };

        let user_comp_pubkey =
            bitcoin::CompressedPublicKey::from_private_key(&self.secp, &user_bitcoin_privkey)
                .unwrap();
        let uncompressed_pk =
            secp256k1::PublicKey::from_slice(&user_comp_pubkey.to_bytes()).unwrap();

        // Sign the transactions inputs
        let wpkh = self.public_key.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);
        let mut sighasher = SighashCache::new(transaction);

        let input_index = 0;
        let sighash_type = bitcoin::EcdsaSighashType::All;
        let sighash = sighasher
            .p2wpkh_signature_hash(
                input_index,
                &script_pubkey,
                Amount::from_sat(value),
                sighash_type,
            )
            .expect("failed to create rsk request pegin input sighash");

        let signature = bitcoin::ecdsa::Signature {
            signature: self
                .secp
                .sign_ecdsa(&Message::from(sighash), &self.secret_key),
            sighash_type,
        };

        *sighasher.witness_mut(input_index).unwrap() =
            Witness::p2wpkh(&signature, &uncompressed_pk);

        // Now the transaction is signed
        let signed_transaction = sighasher.into_transaction().to_owned();
        Ok(signed_transaction)
    }
}
