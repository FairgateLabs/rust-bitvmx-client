use std::{collections::HashMap, rc::Rc};

use bitcoin::{
    key::UntweakedPublicKey, secp256k1, secp256k1::PublicKey as SecpPublicKey, Amount, PublicKey,
    ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey,
};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    scripts::{
        self, build_taproot_spend_info, fake_reveal_secret, reveal_secret, timelock, ProtocolScript,
    },
    types::{input::SighashType, InputArgs, OutputType},
};
use serde::{Deserialize, Serialize};
use storage_backend::storage::Storage;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{errors::BitVMXError, keychain::KeyChain, types::ProgramContext};

use super::{
    participant::ParticipantKeys,
    program::ProtocolParameters,
    protocol_handler::{ProtocolContext, ProtocolHandler},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct SlotProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for SlotProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }

    fn get_transaction_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        match name {
            LOCK_TX => Ok(self.accept_tx(context)?),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }
    fn notify_news(
        &self,
        tx_id: Txid,
        tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
        _parameters: &ProtocolParameters,
    ) -> Result<(), BitVMXError> {
        let name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Program {}: Transaction {} has been seen on-chain",
            self.ctx.id, name
        );
        if name == LOCK_TX && tx_status.confirmations == 5 {
            let witness = tx_status.tx.input[0].witness.clone();
            info!(
                "secret witness {:?}",
                String::from_utf8(witness[1].to_vec())
                    .map_err(|_| BitVMXError::InvalidMessageFormat)?
            );
        }
        Ok(())
    }
}

pub const LOCK_TX: &str = "lock_tx";

impl SlotProtocol {
    pub fn new(program_id: Uuid, storage: Rc<Storage>) -> Self {
        let protocol_name = format!("slot_{}", program_id);
        Self {
            ctx: ProtocolContext::new(program_id, protocol_name, storage),
        }
    }

    pub fn generate_keys(key_chain: &mut KeyChain) -> Result<ParticipantKeys, BitVMXError> {
        let aggregated_1 = key_chain.derive_keypair()?;

        let keys = vec![("aggregated_1".to_string(), aggregated_1.into())];

        Ok(ParticipantKeys::new(keys, vec!["aggregated_1".to_string()]))
    }

    pub fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        // TODO get this from config, all values expressed in satoshis
        let _p2pkh_dust_threshold: u64 = 546;
        let _p2sh_p2wpkh_dust_threshold: u64 = 540;
        let _p2wpkh_dust_threshold: u64 = 99_999_000; // 294;
        let _taproot_dust_threshold: u64 = 330;
        let fee = 1000;

        let secp = secp256k1::Secp256k1::new();

        let ops_agg_pubkey = context
            .globals
            .get_var(&self.ctx.id, "operators_aggregated_pub")?
            .pubkey()?;

        //let internal_key = &utxo.pub_key;
        //let untweaked_key: UntweakedPublicKey = XOnlyPublicKey::from(ops_agg_pubkey);

        let secret = context.globals.get_var(&self.ctx.id, "secret")?;
        let secret = secret.secret()?;

        let ordinal_utxo = context
            .globals
            .get_var(&self.ctx.id, "ordinal_utxo")?
            .utxo()?;

        let protocol_utxo = context
            .globals
            .get_var(&self.ctx.id, "protocol_utxo")?
            .utxo()?;

        let user_pubkey = context
            .globals
            .get_var(&self.ctx.id, "user_pubkey")?
            .pubkey()?;

        warn!(
            "Setup with: {:?} {:?} {:?}",
            ordinal_utxo, protocol_utxo, user_pubkey
        );

        let timelock_script = timelock(10, &user_pubkey);

        // Mark this script as unsigned scritp, so the protocol builder wont try to sign it
        let timelock_script =
            ProtocolScript::new_unsigned_script(timelock_script.get_script().clone(), &user_pubkey);

        let reveal_secret_script = fake_reveal_secret(secret.to_vec(), &ops_agg_pubkey);
        let leaves = vec![timelock_script.clone(), reveal_secret_script.clone()];
        let lockreq_tx_output_taptree = build_taptree_for_lockreq_tx_outputs(
            &secp,
            //unspendable(),
            ops_agg_pubkey.clone().inner,
            timelock_script,
            reveal_secret_script,
        )
        .unwrap();

        let script_pubkey = ScriptBuf::new_p2tr(
            &secp,
            lockreq_tx_output_taptree.internal_key(),
            lockreq_tx_output_taptree.merkle_root(),
        );

        //Description of the output that the LOCK_TX consumes (outputs of LOCK_REQ_TX)
        let prevout_0 = TxOut {
            value: Amount::from_sat(ordinal_utxo.2.unwrap()),
            script_pubkey: script_pubkey.clone(),
        };

        //Description of the output that the LOCK_TX consumes (outputs of LOCK_REQ_TX)
        let prevout_1 = TxOut {
            value: Amount::from_sat(protocol_utxo.2.unwrap()),
            script_pubkey,
        };

        let prevouts = vec![prevout_0, prevout_1];

        //TODO: Add support again for unspendable key
        let output_type_ordinal = OutputType::tr_script(
            ordinal_utxo.2.unwrap(),
            //&unspendable().into(), //this should be the unspendable key?
            &ops_agg_pubkey.into(),
            &leaves,
            true,
            prevouts.clone(),
        )?;

        //TODO: Add support again for unspendable key
        let output_type_protocol = OutputType::tr_script(
            protocol_utxo.2.unwrap(),
            //&unspendable().into(), //this should be the unspendable key?
            &ops_agg_pubkey.into(),
            &leaves,
            true,
            prevouts,
        )?;

        let mut protocol = Protocol::load(
            &self.context().protocol_name,
            self.context().storage.clone().unwrap(),
        )?
        .unwrap_or(Protocol::new(&self.context().protocol_name));

        protocol.add_external_connection(
            ordinal_utxo.0,
            ordinal_utxo.1,
            output_type_ordinal,
            LOCK_TX,
            &SighashType::taproot_all(),
        )?;

        protocol.add_external_connection(
            protocol_utxo.0,
            protocol_utxo.1,
            output_type_protocol,
            LOCK_TX,
            &SighashType::taproot_all(),
        )?;

        let eol_timelock_duration = 100; // TODO: get this from config

        // The following script is the output that user timeout could use as input
        let taproot_script_eol_timelock_expired_tx_lock =
            scripts::timelock(eol_timelock_duration, &user_pubkey);
        // Mark this script as unsigned scritp, so the protocol builder wont try to sign it
        let taproot_script_eol_timelock_expired_tx_lock = ProtocolScript::new_unsigned_script(
            taproot_script_eol_timelock_expired_tx_lock
                .get_script()
                .clone(),
            &user_pubkey,
        );

        //this should be another aggregated to be signed later
        let taproot_script_all_sign_tx_lock = scripts::check_aggregated_signature(&ops_agg_pubkey);

        protocol.add_transaction_output(
            LOCK_TX,
            OutputType::tr_script(
                ordinal_utxo.2.unwrap(),
                &ops_agg_pubkey.into(),
                &[
                    taproot_script_eol_timelock_expired_tx_lock.clone(),
                    taproot_script_all_sign_tx_lock.clone(),
                ],
                false,
                vec![],
            )?, // We do not need prevouts cause the tx is in the graph,
        )?;

        //this could be even a different one, but we will use the same for now
        let taproot_script_protocol_fee_addres_signature_in_tx_lock =
            scripts::check_aggregated_signature(&ops_agg_pubkey);

        const SPEEDUP_DUST: u64 = 500;
        let amount = protocol_utxo.2.unwrap() - fee - SPEEDUP_DUST;
        // [Protocol fees taproot output]
        // taproot output sending the fee (incentive to bridge) to the fee address
        protocol.add_transaction_output(
            LOCK_TX,
            OutputType::tr_script(
                amount,
                &ops_agg_pubkey, // TODO, perhaps we want an un-spendable key here to force the script path spend
                &[taproot_script_protocol_fee_addres_signature_in_tx_lock],
                true,
                vec![],
            )?, // We do not need prevouts cause the tx is in the graph,
        )?;

        let aggregated = computed_aggregated.get("aggregated_1").unwrap();
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(&mut protocol, LOCK_TX, SPEEDUP_DUST, aggregated)?;

        protocol.build(true, &context.key_chain.key_manager)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;

        Ok(())
    }

    pub fn accept_tx(&self, context: &ProgramContext) -> Result<Transaction, BitVMXError> {
        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(LOCK_TX, 0, 1)?
            .unwrap();
        let mut taproot_arg_0 = InputArgs::new_taproot_script_args(1);
        taproot_arg_0.push_taproot_signature(signature)?;

        let secret = context
            .witness
            .get_witness(&self.ctx.id, "secret")?
            .unwrap()
            .secret()?;
        taproot_arg_0.push_slice(&secret);

        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(LOCK_TX, 1, 1)?
            .unwrap();
        let mut taproot_arg_1 = InputArgs::new_taproot_script_args(1);
        taproot_arg_1.push_taproot_signature(signature)?;

        let secret = context
            .witness
            .get_witness(&self.ctx.id, "secret")?
            .unwrap()
            .secret()?;
        taproot_arg_1.push_slice(&secret);

        let tx = self
            .load_protocol()?
            .transaction_to_send(LOCK_TX, &[taproot_arg_0, taproot_arg_1])?;

        info!("Transaction to send: {:?}", tx);
        Ok(tx)
    }
}

fn unspendable() -> SecpPublicKey {
    // hardcoded unspendable
    let key_bytes =
        hex::decode("02f286025adef23a29582a429ee1b201ba400a9c57e5856840ca139abb629889ad")
            .expect("Invalid hex input");
    SecpPublicKey::from_slice(&key_bytes).expect("Invalid public key")
}

fn build_taptree_for_lockreq_tx_outputs(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    unspendable_pub_key: SecpPublicKey,
    timelock_script: ProtocolScript,
    reveal_secret_script: ProtocolScript,
) -> Result<bitcoin::taproot::TaprootSpendInfo, BitVMXError> {
    /* NOTE: we want to force the script path spend, so we will finalize with an un-spendable key */
    let (internal_key_for_taptree_xonly, _parity) = unspendable_pub_key.x_only_public_key();
    println!("Unspendable key: {}", unspendable_pub_key);
    tracing::debug!(
        "X only Unspendable key: {:?} parity: {:?}",
        internal_key_for_taptree_xonly,
        _parity
    );
    let taproot_spend_info = build_taproot_spend_info(
        secp,
        &internal_key_for_taptree_xonly,
        &[timelock_script, reveal_secret_script],
    )?;

    Ok(taproot_spend_info)
}
