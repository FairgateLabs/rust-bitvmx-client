use crate::{
    macros::wait_for_message_blocking,
    wait_until_msg,
    wallet::helper::{non_regtest_warning, print_link},
};
use anyhow::Result;
use bitcoin::{
    absolute,
    hex::FromHex,
    key::Secp256k1,
    secp256k1::{self, All, Message, SecretKey},
    sighash::SighashCache,
    transaction, Address, Address as BitcoinAddress, Amount, CompressedPublicKey, Network,
    OutPoint, PrivateKey, PublicKey, PublicKey as BitcoinPubKey, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use operator_comms::operator_comms::AllowList;
use protocol_builder::scripts::{build_taproot_spend_info, op_return_script, timelock, SignMode};
use std::str::FromStr;
use tracing::{error, info};

use bitvmx_client::{
    client::BitVMXClient,
    config::Config,
    program::{protocols::union::types::SPEEDUP_VALUE, variables::PartialUtxo},
    spv_proof::BtcTxSPVProof,
    types::OutgoingBitVMXApiMessages::*,
};

const KEY_SPEND_FEE: u64 = 135;
const OP_RETURN_FEE: u64 = 100;

pub struct User {
    pub id: String,
    pub bitvmx: BitVMXClient,
    public_key: BitcoinPubKey,
    pub bitcoin_client: BitcoinClient,
    pub address: BitcoinAddress,
    secret_key: SecretKey,
    pub network: Network,
    pub secp: Secp256k1<All>,
    pub rsk_address: &'static str, // This is a placeholder, should be replaced with actual RSK address
    request_pegin_utxos: Vec<PartialUtxo>,
    speedup_utxo: Option<PartialUtxo>,
    pub config: Config,
}

impl User {
    pub fn new(id: &str) -> Result<Self> {
        let config = Config::new(Some(format!("config/{}.yaml", id)))?;
        let allow_list = AllowList::from_file(&config.broker.allow_list)?;
        let bitvmx = BitVMXClient::new(
            &config.components,
            &config.broker,
            &config.testing.l2,
            allow_list,
        )?;
        let bitcoin_client = BitcoinClient::new(
            &config.bitcoin.url,
            &config.bitcoin.username,
            &config.bitcoin.password,
        )?;

        let network = config.bitcoin.network;
        let priv_key = PrivateKey::from_str(&config.wallet.clone().receive_key.unwrap())?;
        let user_sk: SecretKey = priv_key.inner;

        let secp = Secp256k1::new();
        let user_pubkey = PublicKey::from_private_key(&secp, &priv_key);

        let compressed_pubkey = CompressedPublicKey::from_private_key(&secp, &priv_key)?;
        let user_address = Address::p2wpkh(&compressed_pubkey, network);

        Ok(Self {
            id: id.to_string(),
            bitvmx,
            bitcoin_client,
            public_key: user_pubkey,
            address: user_address,
            secret_key: user_sk,
            network,
            secp,
            rsk_address: "7ac5496aee77c1ba1f0854206a26dda82a81d6d8",
            request_pegin_utxos: vec![],
            speedup_utxo: None,
            config,
        })
    }

    pub fn get_rsk_address(&self) -> String {
        self.rsk_address.to_string()
    }

    pub fn request_pegin(
        &mut self,
        committee_public_key: &PublicKey,
        stream_value: u64,
    ) -> Result<Txid> {
        info!(id = self.id, "Requesting pegin");

        // Enable RSK pegin monitoring using the public API
        self.bitvmx.subscribe_to_rsk_pegin()?;

        // Create a proper RSK pegin transaction and send it as if it was a user transaction
        let packet_number = 0;

        // We'll create a transaction that will be detected as RSK pegin by the transaction monitor.
        let signed_transaction =
            self.create_request_pegin_tx(*committee_public_key, stream_value, packet_number)?;

        let txid = match self.bitcoin_client.send_transaction(&signed_transaction) {
            Ok(txid) => txid,
            Err(e) => {
                error!("Failed to send request pegin transaction: {}", e);
                return Err(anyhow::anyhow!(
                    "Failed to send request pegin transaction: {}",
                    e
                ));
            }
        };

        info!("Sent request pegin Tx: {}", txid);
        print_link(self.network, txid);

        Ok(txid)
    }

    pub fn get_request_pegin_spv(&self, request_pegin_txid: Txid) -> Result<BtcTxSPVProof> {
        info!(
            "Waiting for RSK pegin transaction to be found. Txid: {}",
            request_pegin_txid
        );

        // Wait for Bitvmx news PeginTransactionFound message
        let (_, _) = wait_until_msg!(&self.bitvmx, PeginTransactionFound(_txid, _tx_status) => (_txid, _tx_status));
        info!("RSK request pegin completed successfully");
        info!("Waiting for SPV proof...");

        // Get the SPV proof, this should be used by the union client to present to the smart contract
        self.bitvmx.get_spv_proof(request_pegin_txid)?;
        let spv_proof = wait_until_msg!(&self.bitvmx, SPVProof(_, Some(_spv_proof)) => _spv_proof);

        info!("SPV proof: {:?}", spv_proof);
        Ok(spv_proof)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        Ok(self.public_key)
    }

    pub fn create_and_send_request_pegin_tx(
        &mut self,
        aggregated_pubkey: PublicKey,
        stream_value: u64,
        packet_number: u64,
    ) -> Result<Txid> {
        // We'll create a transaction that will be detected as RSK pegin by the transaction monitor.
        let signed_transaction =
            self.create_request_pegin_tx(aggregated_pubkey, stream_value, packet_number)?;

        let txid = match self.bitcoin_client.send_transaction(&signed_transaction) {
            Ok(txid) => txid,
            Err(e) => {
                error!("Failed to send request pegin transaction: {}", e);
                return Err(anyhow::anyhow!(
                    "Failed to send request pegin transaction: {}",
                    e
                ));
            }
        };

        // Get the transaction and verify it was created
        let request_pegin_tx = self.bitcoin_client.get_transaction(&txid)?.unwrap();
        let request_pegin_txid = request_pegin_tx.compute_txid();

        Ok(request_pegin_txid)
    }

    pub fn dispatch_tx(&self, tx: Transaction) -> Result<Txid> {
        let txid = self
            .bitcoin_client
            .send_transaction(&tx)
            .map_err(|e| anyhow::anyhow!("Failed to dispatch transaction: {}", e))?;

        Ok(txid)
    }

    fn create_request_pegin_tx(
        &mut self,
        aggregated_key: PublicKey,
        stream_value: u64,
        packet_number: u64,
    ) -> Result<Transaction> {
        pub const TIMELOCK_BLOCKS: u16 = 1;
        let fee = KEY_SPEND_FEE + OP_RETURN_FEE + self.get_extra_fee();

        // Fund the user address with enough to cover the taproot output + fees
        let input_utxo = match self.get_last_request_pegin_utxo() {
            Some(utxo) => utxo.clone(),
            None => {
                error!("No UTXO available for request pegin");
                return Err(anyhow::anyhow!("No UTXO available for request pegin"));
            }
        };
        let input_value = input_utxo.2.unwrap();
        let change_value = input_value - (stream_value + fee);

        info!(
            "Creating request pegin transaction with value: {} sats, total fee: {} sats. Input value: {}. Change: {}",
            stream_value, fee, input_value, change_value
        );
        non_regtest_warning(self.network, "You are about to transfer REAL money.");

        // RSK Pegin values
        let rootstock_address = self.address_to_bytes(self.rsk_address)?;
        let reimbursement_xpk = self.public_key.into();

        // Create the Request pegin transaction
        // Inputs
        let funds_input = TxIn {
            previous_output: OutPoint::new(input_utxo.0, input_utxo.1),
            script_sig: ScriptBuf::default(), // For a p2wpkh script_sig is empty.
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // we want to be able to replace this transaction
            witness: Witness::default(),                // Filled in after, at signing time.
        };

        // Outputs
        // Taproot output
        let op_data = [
            rootstock_address.as_slice(),
            stream_value.to_be_bytes().as_slice(),
        ]
        .concat();
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
            value: Amount::from_sat(stream_value),
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

        let mut outputs = Vec::<TxOut>::from([taproot_output.clone(), op_return_output.clone()]);

        // Change output
        if change_value > 546 {
            info!("Creating change output with value: {} sats", change_value);
            let wpkh = self.public_key.wpubkey_hash().expect("key is compressed");
            let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);
            let change_output = TxOut {
                value: Amount::from_sat(change_value),
                script_pubkey: script_pubkey,
            };

            outputs.push(change_output);
        }

        let mut request_pegin_transaction = Transaction {
            version: transaction::Version::TWO,  // Post BIP-68.
            lock_time: absolute::LockTime::ZERO, // Ignore the transaction lvl absolute locktime.
            input: vec![funds_input],
            output: outputs,
        };

        let signed_transaction = self.sign_p2wpkh_transaction(
            &mut request_pegin_transaction,
            [(0 as usize, input_value)].to_vec(),
        )?;

        info!("Request pegin txid: {}", signed_transaction.compute_txid());
        info!(
            "Request pegin TX size: {} vbytes",
            signed_transaction.vsize()
        );
        self.pop_request_pegin_utxo();
        Ok(signed_transaction)
    }

    pub fn create_and_dispatch_speedup(&mut self, tx_output: OutPoint, fee: u64) -> Result<()> {
        let speedup_tx = self.create_speedup_tx(tx_output, fee)?;

        let speedup_txid = self.dispatch_tx(speedup_tx)?;
        info!("Speedup transaction dispatched: {}", speedup_txid);
        Ok(())
    }

    pub fn create_and_dispatch_user_take_speedup(
        &self,
        tx_output: PartialUtxo,
        fee: u64,
    ) -> Result<()> {
        let speedup_tx = self.create_user_take_speedup_tx(tx_output, fee)?;

        let speedup_txid = self.dispatch_tx(speedup_tx)?;
        info!("User take speedup tx dispatched: {}", speedup_txid);
        Ok(())
    }

    pub fn create_speedup_tx(&mut self, tx_output: OutPoint, fee: u64) -> Result<Transaction> {
        let funding_utxo = match self.get_speedup_utxo() {
            Some(utxo) => utxo, // Amount is not known here
            None => {
                error!("No UTXO available for speedup");
                return Err(anyhow::anyhow!("No UTXO available for speedup"));
            }
        };

        // Create two inputs: one from the funding utxo, one from the output to speed up
        let input_funding = TxIn {
            previous_output: OutPoint::new(funding_utxo.0, funding_utxo.1 as u32),
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        };

        let input_speedup = TxIn {
            previous_output: tx_output,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        };

        // Output: all funds (minus fee) to user address
        let total_in = funding_utxo.2.unwrap(); // You may want to add the value of tx_output if known
        let change = total_in - fee;
        let output = TxOut {
            value: Amount::from_sat(change),
            script_pubkey: self.address.script_pubkey(),
        };

        let mut transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![input_speedup, input_funding],
            output: vec![output],
        };

        // Sign the transaction (this may need to be adapted to sign both inputs)
        let signed_transaction = self.sign_p2wpkh_transaction(
            &mut transaction,
            [(0, SPEEDUP_VALUE), (1, total_in)].to_vec(),
        )?;

        // Update the speedup_utxo to the change output
        self.set_speedup_utxo((signed_transaction.compute_txid(), 0, Some(change), None));

        info!(
            "Speeding up txid: {}. Speedup txid: {}",
            tx_output.txid,
            signed_transaction.compute_txid()
        );

        Ok(signed_transaction)
    }

    pub fn create_user_take_speedup_tx(
        &self,
        tx_output: PartialUtxo,
        fee: u64,
    ) -> Result<Transaction> {
        let input_speedup = TxIn {
            previous_output: OutPoint::new(tx_output.0, tx_output.1 as u32),
            script_sig: ScriptBuf::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        };

        // Output: all funds (minus fee) to user address
        let total_in = tx_output.2.unwrap();
        let output = TxOut {
            value: Amount::from_sat(total_in - fee),
            script_pubkey: self.address.script_pubkey(),
        };

        let mut transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![input_speedup],
            output: vec![output],
        };

        // Sign the transaction (this may need to be adapted to sign both inputs)
        let signed_transaction =
            self.sign_p2wpkh_transaction(&mut transaction, [(0, total_in)].to_vec())?;
        info!(
            "Speeding up user take txid: {}. Speedup txid: {}",
            tx_output.0,
            signed_transaction.compute_txid()
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

    fn sign_p2wpkh_transaction(
        &self,
        transaction: &mut Transaction,
        index_amount: Vec<(usize, u64)>,
    ) -> Result<Transaction> {
        let user_bitcoin_privkey = PrivateKey {
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

        let sighash_type = bitcoin::EcdsaSighashType::All;
        for (input_index, value) in index_amount {
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
        }

        // Now the transaction is signed
        let signed_transaction = sighasher.into_transaction().to_owned();
        Ok(signed_transaction)
    }

    pub fn add_request_pegin_utxo(&mut self, utxo: PartialUtxo) {
        self.request_pegin_utxos.push(utxo);
    }

    fn pop_request_pegin_utxo(&mut self) -> Option<PartialUtxo> {
        self.request_pegin_utxos.pop()
    }

    fn get_last_request_pegin_utxo(&mut self) -> Option<&PartialUtxo> {
        self.request_pegin_utxos.last()
    }

    pub fn set_speedup_utxo(&mut self, utxo: PartialUtxo) {
        self.speedup_utxo = Some(utxo);
    }

    fn get_speedup_utxo(&self) -> Option<PartialUtxo> {
        self.speedup_utxo.clone()
    }

    fn get_extra_fee(&self) -> u64 {
        match self.network {
            Network::Regtest => 1500,
            _ => 0,
        }
    }

    pub fn get_request_pegin_fees(&self) -> u64 {
        return self.get_extra_fee() + OP_RETURN_FEE + KEY_SPEND_FEE;
    }
}
