use anyhow::Result;
use bitcoin::{
    key::{rand::rngs::OsRng, Secp256k1},
    secp256k1::{self, All, Message, PublicKey as SecpPublicKey, SecretKey},
    sighash::SighashCache,
    Address as BitcoinAddress, Amount, Network, PrivateKey as BitcoinPrivKey, PublicKey,
    PublicKey as BitcoinPubKey, ScriptBuf, Transaction, Witness,
};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_client::{
    client::BitVMXClient,
    config::Config,
    program::{
        protocols::union::{
            common::indexed_name,
            types::{AdvanceFundsRequest, ACCEPT_PEGIN_TX, SELECTED_OPERATOR_PUBKEY},
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::OutgoingBitVMXApiMessages::*,
};
use bitvmx_client::{program::participant::P2PAddress, types::PROGRAM_TYPE_ADVANCE_FUNDS};
use protocol_builder::types::OutputType;
use tracing::info;
use uuid::Uuid;

use crate::{macros::wait_for_message_blocking, wait_until_msg};

pub struct AdvanceFunds {}

pub struct AdvanceFundsHelper {
    pub bitcoin_client: BitcoinClient,
    pub network: Network,
    pub secp: Secp256k1<All>,
    pub operator_address: BitcoinAddress,
    pub operator_pubkey: BitcoinPubKey,
    pub operator_sk: SecretKey,
}

impl AdvanceFunds {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        bitvmx: &BitVMXClient,
        protocol_id: Uuid,
        committee_id: Uuid,
        slot_index: usize,
        user_pubkey: PublicKey,
        operator_pubkey: PublicKey,
        my_take_pubkey: PublicKey,
        pegout_id: Vec<u8>,
        my_address: P2PAddress,
        fee: u64,
    ) -> Result<()> {
        // All members should set up the operator pubkey that should advance the funds
        bitvmx.set_var(
            committee_id,
            &indexed_name(SELECTED_OPERATOR_PUBKEY, slot_index),
            VariableTypes::PubKey(operator_pubkey),
        )?;

        if operator_pubkey != my_take_pubkey {
            info!(
                "Skipping advance funds setup. Operator pubkey: {}, my take pubkey: {}",
                operator_pubkey, my_take_pubkey
            );
            return Ok(());
        }

        // Only the selected operator will set up the advance funds protocol
        let request = AdvanceFundsRequest {
            committee_id,
            slot_index,
            pegout_id,
            fee, // This will be set later
            user_pubkey,
            my_take_pubkey,
        };

        bitvmx.set_var(
            protocol_id,
            &AdvanceFundsRequest::name(),
            VariableTypes::String(serde_json::to_string(&request)?),
        )?;

        info!(
            "Advance funds setup for member {} with address {:?}",
            my_take_pubkey, my_address
        );

        bitvmx.setup(
            protocol_id,
            PROGRAM_TYPE_ADVANCE_FUNDS.to_string(),
            vec![my_address],
            0,
        )?;

        Ok(())
    }
}

impl AdvanceFundsHelper {
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

    pub fn fund_operator_wallet(
        &mut self,
        committee_id: Uuid,
        slot_index: usize,
        bitvmx: &BitVMXClient,
    ) -> Result<PartialUtxo> {
        bitvmx.get_var(committee_id, format!("{}_{}", ACCEPT_PEGIN_TX, slot_index))?;

        let utxo = wait_until_msg!(&bitvmx, Variable(_, _, VariableTypes::Utxo(_utxo)) => _utxo);

        // RSK Pegin constants
        pub const KEY_SPEND_FEE: u64 = 335;
        pub const OP_RETURN_FEE: u64 = 300;
        pub const CHANGE: u64 = 1000;

        let total_amount = utxo.2.unwrap() + KEY_SPEND_FEE + OP_RETURN_FEE + CHANGE;

        let id = Uuid::new_v4();
        // Fund the operator address to cover the advancement of funds + fees
        bitvmx.send_funds_to_address(
            id,
            self.operator_address.to_string(),
            total_amount,
            Some(2),
        )?;

        // Wait for the transaction to be sent
        let _txid = wait_until_msg!(
            bitvmx,
            FundsSent(_, _txid) => _txid
        );
        // Mine a block to confirm the transaction
        self.bitcoin_client.mine_blocks(1)?;
        // Wait for the transaction info
        let tx_status = wait_until_msg!(
            &bitvmx,
            Transaction(_, _tx_status, _) => _tx_status
        );
        // Check confirmation threashold
        if tx_status.confirmations < 1 {
            return Err(anyhow::anyhow!(
                "prepare_funding_utxo Transaction not finalized, confirmations: {}",
                tx_status.confirmations
            ));
        }
        let vout = 0;
        let funding_tx = tx_status.tx;

        info!("Funding transaction: {:#?}", funding_tx);

        let funding_utxo = (
            funding_tx.compute_txid(),
            vout,
            Some(total_amount),
            Some(OutputType::segwit_key(total_amount, &self.operator_pubkey)?),
        );

        Ok(funding_utxo)
    }

    pub fn sign_p2wpkh_transaction_single_input(
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
