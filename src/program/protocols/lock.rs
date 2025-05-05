use std::collections::HashMap;

use bitcoin::{
    hashes::Hash, secp256k1, Amount, PublicKey, ScriptBuf, Sequence, Transaction, TxOut, Txid,
    XOnlyPublicKey,
};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    scripts::{self, build_taproot_spend_info, reveal_secret, timelock, ProtocolScript, SignMode},
    types::{
        input::{InputSpec, LeafSpec, SighashType},
        output::SpendMode,
        InputArgs, OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{errors::BitVMXError, keychain::KeyChain, types::ProgramContext};

use super::{
    super::participant::ParticipantKeys,
    protocol_handler::{ProtocolContext, ProtocolHandler},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct LockProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for LockProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }

    fn get_pregenerated_aggregated_keys(
        &self,
        context: &ProgramContext,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        Ok(vec![(
            "pregenerated".to_string(),
            context
                .globals
                .get_var(&self.ctx.id, "operators_aggregated_pub")?
                .pubkey()?,
        )])
    }

    fn generate_keys(&self, key_chain: &mut KeyChain) -> Result<ParticipantKeys, BitVMXError> {
        let aggregated_1 = key_chain.derive_keypair()?;

        let mut keys = vec![("aggregated_1".to_string(), aggregated_1.into())];

        //TODO: get from a variable the number of bytes required to encode the too_id
        let start_id = key_chain.derive_winternitz_hash160(1)?;
        keys.push((format!("too_id_{}", self.ctx.my_idx), start_id.into()));

        Ok(ParticipantKeys::new(keys, vec!["aggregated_1".to_string()]))
    }

    fn get_transaction_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        match name {
            LOCK_TX => Ok(self.accept_tx(context)?),
            HAPPY_PATH_TX => Ok(self.happy_path()?),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }
    fn notify_news(
        &self,
        tx_id: Txid,
        tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let name = self.get_transaction_name_by_id(tx_id)?;
        if tx_status.confirmations == 1 {
            info!(
                "Program {}: Transaction {} has been seen on-chain",
                self.ctx.id, name
            );
        }
        if name == LOCK_TX && tx_status.confirmations == 1 {
            let witness = tx_status.tx.input[0].witness.clone();
            info!(
                "secret witness {:?}",
                String::from_utf8(witness[1].to_vec())
                    .map_err(|_| BitVMXError::InvalidMessageFormat)?
            );
        }
        Ok(())
    }

    fn build(
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

        let unspendable = context
            .globals
            .get_var(&self.ctx.id, "unspendable")?
            .pubkey()?;

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

        warn!(
            "======== Ops_agg_key: {:?} Unspendable: {:?} User_pubkey{:?}",
            XOnlyPublicKey::from(ops_agg_pubkey).to_string(),
            XOnlyPublicKey::from(unspendable).to_string(),
            XOnlyPublicKey::from(user_pubkey).to_string()
        );

        //THIS SECTION DEFINES THE OUTPUTS OF THE LOCK_REQ_TX
        //THAT WILL BE SPENT BY THE LOCK_TX

        // Mark this script as unsigned script, so the protocol builder wont try to sign it
        let timelock_script = timelock(10, &user_pubkey, SignMode::Skip);
        let timelock_script = ProtocolScript::new(
            timelock_script.get_script().clone(),
            &user_pubkey,
            SignMode::Skip,
        );

        let reveal_secret_script =
            reveal_secret(secret.to_vec(), &ops_agg_pubkey, SignMode::Aggregate);
        let leaves = vec![timelock_script.clone(), reveal_secret_script.clone()];

        let (unspendable_x_only, _parity) = unspendable.inner.x_only_public_key();
        let lockreq_tx_output_taptree = build_taproot_spend_info(
            &secp,
            &unspendable_x_only,
            &[timelock_script, reveal_secret_script],
        )?;

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

        let output_type_ordinal = OutputType::taproot(
            ordinal_utxo.2.unwrap(),
            &unspendable,
            &leaves,
            &SpendMode::ScriptsOnly,
            &prevouts,
        )?;

        let output_type_protocol = OutputType::taproot(
            protocol_utxo.2.unwrap(),
            &unspendable,
            &leaves,
            &SpendMode::ScriptsOnly,
            &prevouts,
        )?;

        let mut protocol = self.load_or_create_protocol();

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

        // START DEFINING THE OUTPUTS OF THE LOCK_TX

        let eol_timelock_duration = 100; // TODO: get this from config

        // The following script is the output that user timeout could use as input
        let taproot_script_eol_timelock_expired_tx_lock =
            scripts::timelock(eol_timelock_duration, &user_pubkey, SignMode::Skip);
        // Mark this script as unsigned script, so the protocol builder wont try to sign it
        let taproot_script_eol_timelock_expired_tx_lock = ProtocolScript::new(
            taproot_script_eol_timelock_expired_tx_lock
                .get_script()
                .clone(),
            &user_pubkey,
            SignMode::Skip,
        );

        //this should be another aggregated to be signed later
        let taproot_script_all_sign_tx_lock =
            scripts::check_aggregated_signature(&ops_agg_pubkey, SignMode::Aggregate);

        protocol.add_transaction_output(
            LOCK_TX,
            &OutputType::taproot(
                ordinal_utxo.2.unwrap(),
                &unspendable,
                &[
                    taproot_script_eol_timelock_expired_tx_lock.clone(),
                    taproot_script_all_sign_tx_lock.clone(),
                ],
                &SpendMode::ScriptsOnly,
                &vec![],
            )?, // We do not need prevouts cause the tx is in the graph,
        )?;

        //this could be even a different one, but we will use the same for now
        let taproot_script_protocol_fee_addres_signature_in_tx_lock =
            scripts::check_aggregated_signature(&ops_agg_pubkey, SignMode::Aggregate);

        const SPEEDUP_DUST: u64 = 500;
        let amount = protocol_utxo.2.unwrap() - fee - SPEEDUP_DUST;
        // [Protocol fees taproot output]
        // taproot output sending the fee (incentive to bridge) to the fee address
        protocol.add_transaction_output(
            LOCK_TX,
            &OutputType::taproot(
                amount,
                &unspendable,
                &[taproot_script_protocol_fee_addres_signature_in_tx_lock],
                &SpendMode::ScriptsOnly,
                &vec![],
            )?, // We do not need prevouts cause the tx is in the graph,
        )?;

        self.add_happy_path(
            context,
            &mut protocol,
            &unspendable,
            ordinal_utxo.2.unwrap(),
            amount - fee - SPEEDUP_DUST,
        )?;

        let aggregated = computed_aggregated.get("aggregated_1").unwrap();
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(&mut protocol, LOCK_TX, SPEEDUP_DUST, aggregated)?;
        pb.add_speedup_output(&mut protocol, HAPPY_PATH_TX, SPEEDUP_DUST, aggregated)?;

        protocol.build(&context.key_chain.key_manager)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;

        Ok(())
    }
}

pub const LOCK_TX: &str = "lock_tx";
pub const HAPPY_PATH_TX: &str = "happy_path_tx";

impl LockProtocol {
    pub fn new(context: ProtocolContext) -> Self {
        Self { ctx: context }
    }

    pub fn add_happy_path(
        &self,
        context: &ProgramContext,
        protocol: &mut Protocol,
        unspendable: &PublicKey,
        amount_ordinal: u64,
        amount_protocol: u64,
    ) -> Result<(), BitVMXError> {
        // START DEFINING THE HAPPY_PATH_TX
        let ops_agg_happy_path = context
            .globals
            .get_var(&self.ctx.id, "operators_aggregated_happy_path")?
            .pubkey()?;

        let happy_path_check =
            scripts::check_aggregated_signature(&ops_agg_happy_path, SignMode::Skip);

        protocol.add_transaction(HAPPY_PATH_TX)?;
        protocol.add_transaction_input(
            Hash::all_zeros(),
            0,
            HAPPY_PATH_TX,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            &SighashType::taproot_all(),
        )?;
        protocol.add_transaction_input(
            Hash::all_zeros(),
            1,
            HAPPY_PATH_TX,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            &SighashType::taproot_all(),
        )?;

        protocol.add_transaction_output(
            HAPPY_PATH_TX,
            &OutputType::taproot(
                amount_ordinal,
                &unspendable,
                &[happy_path_check.clone()],
                &SpendMode::ScriptsOnly,
                &vec![],
            )?,
        )?;
        protocol.add_transaction_output(
            HAPPY_PATH_TX,
            &OutputType::taproot(
                amount_protocol,
                &unspendable,
                &[happy_path_check.clone()],
                &SpendMode::ScriptsOnly,
                &vec![],
            )?,
        )?;
        protocol.connect("spend_hp_1", LOCK_TX, 0, HAPPY_PATH_TX, InputSpec::Index(0))?;
        protocol.connect("spend_hp_2", LOCK_TX, 1, HAPPY_PATH_TX, InputSpec::Index(1))?;

        Ok(())
    }

    pub fn accept_tx(&self, context: &ProgramContext) -> Result<Transaction, BitVMXError> {
        let secret = context
            .witness
            .get_witness(&self.ctx.id, "secret")?
            .unwrap()
            .secret()?;

        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(LOCK_TX, 0, 1)?
            .unwrap();
        let mut taproot_arg_0 = InputArgs::new_taproot_script_args(LeafSpec::Index(1));
        taproot_arg_0.push_taproot_signature(signature)?;
        //info!("signature =====>: {:?}", signature);
        taproot_arg_0.push_slice(&secret);

        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(LOCK_TX, 1, 1)?
            .unwrap();
        let mut taproot_arg_1 = InputArgs::new_taproot_script_args(LeafSpec::Index(1));
        taproot_arg_1.push_taproot_signature(signature)?;
        taproot_arg_1.push_slice(&secret);

        let tx = self
            .load_protocol()?
            .transaction_to_send(LOCK_TX, &[taproot_arg_0, taproot_arg_1])?;

        info!("Transaction to send: {:?}", tx);
        Ok(tx)
    }

    pub fn happy_path(&self) -> Result<Transaction, BitVMXError> {
        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(HAPPY_PATH_TX, 0, 1)?
            .unwrap();
        let mut taproot_arg_0 = InputArgs::new_taproot_script_args(LeafSpec::Index(1));
        taproot_arg_0.push_taproot_signature(signature)?;

        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(HAPPY_PATH_TX, 1, 0)?
            .unwrap();
        let mut taproot_arg_1 = InputArgs::new_taproot_script_args(LeafSpec::Index(0));
        taproot_arg_1.push_taproot_signature(signature)?;

        let tx = self
            .load_protocol()?
            .transaction_to_send(HAPPY_PATH_TX, &[taproot_arg_0, taproot_arg_1])?;

        info!("Transaction to send: {:?}", tx);
        Ok(tx)
    }
}
