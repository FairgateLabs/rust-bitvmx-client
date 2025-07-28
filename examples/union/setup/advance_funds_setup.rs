use std::{thread, time::Duration};

use anyhow::Result;
use bitcoin::{
    absolute,
    key::{rand::rngs::OsRng, Secp256k1},
    secp256k1::{self, All, Message, PublicKey as SecpPublicKey, SecretKey},
    sighash::SighashCache,
    transaction, Address as BitcoinAddress, Amount, Network, OutPoint,
    PrivateKey as BitcoinPrivKey, PublicKey, PublicKey as BitcoinPubKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Witness,
};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_client::types::OutgoingBitVMXApiMessages::SPVProof;
use bitvmx_client::{client::BitVMXClient, config::Config};
use protocol_builder::scripts::op_return_script;
use tracing::info;
use uuid::Uuid;

use crate::{macros::wait_for_message_blocking, wait_until_msg};

pub struct AdvanceFunds {
    pub bitcoin_client: BitcoinClient,
    pub network: Network,
    pub secp: Secp256k1<All>,
    pub operator_address: BitcoinAddress,
    pub operator_pubkey: BitcoinPubKey,
    pub operator_sk: SecretKey,
}

impl AdvanceFunds {
    pub fn new(config: &Config) -> Result<Self> {
        let bitcoin_client = BitcoinClient::new(
            &config.bitcoin.url,
            &config.bitcoin.username,
            &config.bitcoin.password,
        )?;
        let network = Network::Regtest;

        // Locally created operator keypair
        let secp = Secp256k1::new();
        let (operator_address, operator_pubkey, operator_sk) =
            new_keypair(&secp, &bitcoin_client, network)?;

        Ok(Self {
            bitcoin_client,
            network,
            secp,
            operator_address,
            operator_pubkey,
            operator_sk,
        })
    }

    pub fn create_and_send_tx(
        &mut self,
        user_key: PublicKey,
        stream_value: u64,
        pegout_id: Vec<u8>,
        bitvmx: &BitVMXClient,
    ) -> Result<Transaction> {
        // RSK Pegin constants
        pub const KEY_SPEND_FEE: u64 = 335;
        pub const OP_RETURN_FEE: u64 = 300;

        let value = stream_value;
        let fee = KEY_SPEND_FEE;
        let op_return_fee = OP_RETURN_FEE;
        let total_amount = value + fee + op_return_fee;

        // Fund the operator address to cover the advancement of funds + fees
        let (funding_tx, vout) = self
            .bitcoin_client
            .fund_address(&self.operator_address, Amount::from_sat(total_amount))
            .unwrap();

        // Create the Advance Funds transaction
        // Inputs
        let funds_input = TxIn {
            previous_output: OutPoint::new(funding_tx.compute_txid(), vout),
            script_sig: ScriptBuf::default(), // For a p2wpkh script_sig is empty.
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // we want to be able to replace this transaction
            witness: Witness::default(),                // Filled in after, at signing time.
        };

        // Outputs
        // P2WPKH output for the user to claim the funds
        let advance_funds_output = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new_p2wpkh(&user_key.wpubkey_hash().unwrap()),
        };

        // OP_RETURN output
        let script_op_return = op_return_script(pegout_id)?;
        let op_return_output = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: script_op_return.get_script().clone(),
        };

        let mut advance_funds_transaction = Transaction {
            version: transaction::Version::TWO,  // Post BIP-68.
            lock_time: absolute::LockTime::ZERO, // Ignore the transaction lvl absolute locktime.
            input: vec![funds_input],
            output: vec![advance_funds_output, op_return_output],
        };

        let signed_transaction = self
            .sign_p2wpkh_transaction_single_input(&mut advance_funds_transaction, total_amount)?;

        let advance_funds_uuid = Uuid::new_v4();
        let advance_funds_txid = advance_funds_transaction.compute_txid();
        info!(
            "Advance Funds transaction UUID: {}, txid: {}",
            advance_funds_uuid, advance_funds_txid
        );

        bitvmx.dispatch_transaction(advance_funds_uuid, advance_funds_transaction)?;

        // Need to give some time to bitvmx to receive the transaction in the queue and send it to the bitcoin client.
        // Then bitcoin client will be ready to mine the transaction.
        thread::sleep(Duration::from_secs(1));
        self.mine_blocks(1)?;

        let status = wait_until_msg!(bitvmx, bitvmx_client::types::OutgoingBitVMXApiMessages::Transaction(_, _status, _) => _status);
        info!("Advance funds transaction sent. Status: {:#?}", status);

        // Get the SPV proof, this should be used by the union client to present to the smart contract
        bitvmx.get_spv_proof(advance_funds_txid)?;
        let spv_proof = wait_until_msg!(
            bitvmx,
            SPVProof(_, Some(_spv_proof)) => _spv_proof
        );
        info!("SPV proof: {:?}", spv_proof);

        Ok(signed_transaction)
    }

    fn sign_p2wpkh_transaction_single_input(
        &mut self,
        transaction: &mut Transaction,
        value: u64,
    ) -> Result<Transaction> {
        let operator_bitcoin_privkey = BitcoinPrivKey {
            compressed: true,
            network: self.network.into(),
            inner: self.operator_sk,
        };

        let operator_comp_pubkey =
            bitcoin::CompressedPublicKey::from_private_key(&self.secp, &operator_bitcoin_privkey)
                .unwrap();
        let uncompressed_pk =
            secp256k1::PublicKey::from_slice(&operator_comp_pubkey.to_bytes()).unwrap();

        // Sign the transactions inputs
        let wpkh = self
            .operator_pubkey
            .wpubkey_hash()
            .expect("key is compressed");
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
            .expect("failed to create advance of funds input sighash");

        let signature = bitcoin::ecdsa::Signature {
            signature: self
                .secp
                .sign_ecdsa(&Message::from(sighash), &self.operator_sk),
            sighash_type,
        };

        *sighasher.witness_mut(input_index).unwrap() =
            Witness::p2wpkh(&signature, &uncompressed_pk);

        // Now the transaction is signed
        let signed_transaction = sighasher.into_transaction().to_owned();
        Ok(signed_transaction)
    }

    pub fn mine_blocks(&self, blocks: u64) -> Result<()> {
        self.bitcoin_client
            .mine_blocks_to_address(blocks, &self.operator_address)
            .unwrap();
        Ok(())
    }
}

fn new_keypair(
    secp: &Secp256k1<All>,
    bitcoin_client: &BitcoinClient,
    network: Network,
) -> Result<(bitcoin::Address, BitcoinPubKey, SecretKey)> {
    let mut rng = OsRng;

    let operator_sk = SecretKey::new(&mut rng);
    let operator_pk = SecpPublicKey::from_secret_key(secp, &operator_sk);

    let operator_pubkey = BitcoinPubKey {
        compressed: true,
        inner: operator_pk,
    };

    let operator_address: bitcoin::Address =
        bitcoin_client.get_new_address(operator_pubkey, network);

    info!(
        "Operator Address({}): {:?}",
        operator_address.address_type().unwrap(),
        operator_address
    );

    Ok((operator_address, operator_pubkey, operator_sk))
}
