use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid, XOnlyPublicKey};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    scripts::{self, reveal_secret, timelock, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        InputArgs, OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{errors::BitVMXError, program::variables::VariableTypes, types::ProgramContext};

use super::{
    super::participant::ParticipantKeys,
    protocol_handler::{ProtocolContext, ProtocolHandler},
};

pub const LOCK_REQ_TX: &str = "lock_req_tx";
pub const LOCK_TX: &str = "lock_tx";
pub const PUBLISH_ZKP: &str = "publish_zkp";
pub const HAPPY_PATH_TX: &str = "happy_path_tx";

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
                .unwrap()
                .pubkey()?,
        )])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let aggregated_1 = program_context.key_chain.derive_keypair()?;

        let mut keys = vec![("aggregated_1".to_string(), aggregated_1.into())];

        //TODO: get from a variable the number of bytes required to encode the too_id
        let start_id = program_context.key_chain.derive_winternitz_hash160(1)?;
        keys.push((format!("too_id_{}", self.ctx.my_idx), start_id.into()));

        if self.ctx.my_idx == 0 {
            let start_id = program_context.key_chain.derive_winternitz_hash160(128)?;
            keys.push(("zkp".to_string(), start_id.into()));
        }

        Ok(ParticipantKeys::new(keys, vec!["aggregated_1".to_string()]))
    }

    fn get_transaction_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        match name {
            LOCK_TX => Ok(self.accept_tx(context)?),
            PUBLISH_ZKP => Ok(self.publish_zkp(context)?),
            HAPPY_PATH_TX => Ok(self.happy_path()?),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }
    fn notify_news(
        &self,
        tx_id: Txid,
        _vout: Option<u32>,
        tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
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
        keys: Vec<ParticipantKeys>,
        computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        // TODO get this from config, all values expressed in satoshis

        //let secp = secp256k1::Secp256k1::new();

        let fee = context
            .globals
            .get_var(&self.ctx.id, "FEE")?
            .unwrap()
            .number()? as u64;

        let ops_agg_pubkey = context
            .globals
            .get_var(&self.ctx.id, "operators_aggregated_pub")?
            .unwrap()
            .pubkey()?;

        let unspendable = context
            .globals
            .get_var(&self.ctx.id, "unspendable")?
            .unwrap()
            .pubkey()?;

        let secret = context.globals.get_var(&self.ctx.id, "secret")?.unwrap();
        let secret = secret.secret()?;

        let ordinal_utxo = context
            .globals
            .get_var(&self.ctx.id, "ordinal_utxo")?
            .unwrap()
            .utxo()?;

        let protocol_utxo = context
            .globals
            .get_var(&self.ctx.id, "protocol_utxo")?
            .unwrap()
            .utxo()?;

        let user_pubkey = context
            .globals
            .get_var(&self.ctx.id, "user_pubkey")?
            .unwrap()
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

        let reveal_secret_script =
            reveal_secret(secret.to_vec(), &ops_agg_pubkey, SignMode::Aggregate);
        let leaves = vec![timelock_script.clone(), reveal_secret_script.clone()];

        let output_type_ordinal =
            OutputType::taproot(ordinal_utxo.2.unwrap(), &unspendable, &leaves)?;

        let output_type_protocol =
            OutputType::taproot(protocol_utxo.2.unwrap(), &unspendable, &leaves)?;

        let mut protocol = self.load_or_create_protocol();
        protocol.add_external_transaction(LOCK_REQ_TX)?;

        protocol.add_transaction_output(LOCK_REQ_TX, &output_type_ordinal)?;
        protocol.add_transaction_output(LOCK_REQ_TX, &output_type_protocol)?;

        assert_eq!(ordinal_utxo.0, protocol_utxo.0);

        protocol.add_connection(
            "LOCK_REQ_TX__LOCK_TX_ORDINAL",
            LOCK_REQ_TX,
            OutputSpec::Index(0),
            LOCK_TX,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            Some(ordinal_utxo.0),
        )?;

        protocol.add_connection(
            "LOCK_REQ_TX__LOCK_TX_PROTOCOL",
            LOCK_REQ_TX,
            OutputSpec::Index(1),
            LOCK_TX,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            Some(protocol_utxo.0),
        )?;

        // START DEFINING THE OUTPUTS OF THE LOCK_TX

        let eol_timelock_duration = 100; // TODO: get this from config

        // The following script is the output that user timeout could use as input
        let taproot_script_eol_timelock_expired_tx_lock =
            scripts::timelock(eol_timelock_duration, &user_pubkey, SignMode::Skip);

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
            )?, // We do not need prevouts cause the tx is in the graph,
        )?;

        //this could be even a different one, but we will use the same for now
        let taproot_script_protocol_fee_addres_signature_in_tx_lock =
            scripts::check_aggregated_signature(&ops_agg_pubkey, SignMode::Aggregate);

        const SPEEDUP_DUST: u64 = 500;
        let fee_zkp = context
            .globals
            .get_var(&self.ctx.id, "FEE_ZKP")?
            .unwrap_or(VariableTypes::Number(0))
            .number()
            .unwrap_or(0) as u64;

        let amount = self.checked_sub(protocol_utxo.2.unwrap(), fee + fee_zkp + SPEEDUP_DUST)?;
        // [Protocol fees taproot output]
        // taproot output sending the fee (incentive to bridge) to the fee address
        protocol.add_transaction_output(
            LOCK_TX,
            &OutputType::taproot(
                amount,
                &unspendable,
                &[taproot_script_protocol_fee_addres_signature_in_tx_lock],
            )?,
        )?;

        if fee_zkp > 0 {
            self.add_winternitz_check(
                &ops_agg_pubkey,
                &mut protocol,
                &keys[0],
                fee_zkp,
                SPEEDUP_DUST,
                &vec!["zkp"],
                LOCK_TX,
                PUBLISH_ZKP,
            )?;
        }

        self.add_happy_path(
            context,
            &mut protocol,
            &unspendable,
            ordinal_utxo.2.unwrap(),
            self.checked_sub(amount, fee + SPEEDUP_DUST)?,
        )?;

        let aggregated = computed_aggregated.get("aggregated_1").unwrap();
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(&mut protocol, LOCK_TX, SPEEDUP_DUST, aggregated)?;
        pb.add_speedup_output(&mut protocol, HAPPY_PATH_TX, SPEEDUP_DUST, aggregated)?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;

        Ok(())
    }
}

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
            .unwrap()
            .pubkey()?;

        let happy_path_check =
            scripts::check_aggregated_signature(&ops_agg_happy_path, SignMode::Skip);

        protocol.add_connection(
            "spend_hp_1",
            LOCK_TX,
            0.into(),
            HAPPY_PATH_TX,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            None,
        )?;

        protocol.add_connection(
            "spend_hp_2",
            LOCK_TX,
            1.into(),
            HAPPY_PATH_TX,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            None,
        )?;

        protocol.add_transaction_output(
            HAPPY_PATH_TX,
            &OutputType::taproot(amount_ordinal, &unspendable, &[happy_path_check.clone()])?,
        )?;
        protocol.add_transaction_output(
            HAPPY_PATH_TX,
            &OutputType::taproot(amount_protocol, &unspendable, &[happy_path_check.clone()])?,
        )?;

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
        let mut taproot_arg_0 = InputArgs::new_taproot_script_args(1);
        taproot_arg_0.push_taproot_signature(signature)?;
        //info!("signature =====>: {:?}", signature);
        taproot_arg_0.push_slice(&secret);

        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(LOCK_TX, 1, 1)?
            .unwrap();
        let mut taproot_arg_1 = InputArgs::new_taproot_script_args(1);
        taproot_arg_1.push_taproot_signature(signature)?;
        taproot_arg_1.push_slice(&secret);

        let tx = self
            .load_protocol()?
            .transaction_to_send(LOCK_TX, &[taproot_arg_0, taproot_arg_1])?;

        info!("Transaction to send: {:?}", tx);
        Ok(tx)
    }

    pub fn publish_zkp(&self, context: &ProgramContext) -> Result<Transaction, BitVMXError> {
        self.get_signed_tx(context, PUBLISH_ZKP, 0, 0, false, 0)
    }
    pub fn happy_path(&self) -> Result<Transaction, BitVMXError> {
        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(HAPPY_PATH_TX, 0, 1)?
            .unwrap();
        let mut taproot_arg_0 = InputArgs::new_taproot_script_args(1);
        taproot_arg_0.push_taproot_signature(signature)?;

        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(HAPPY_PATH_TX, 1, 0)?
            .unwrap();
        let mut taproot_arg_1 = InputArgs::new_taproot_script_args(0);
        taproot_arg_1.push_taproot_signature(signature)?;

        let tx = self
            .load_protocol()?
            .transaction_to_send(HAPPY_PATH_TX, &[taproot_arg_0, taproot_arg_1])?;

        info!("Transaction to send: {:?}", tx);
        Ok(tx)
    }

    pub fn add_winternitz_check(
        &self,
        aggregated: &PublicKey,
        protocol: &mut Protocol,
        keys: &ParticipantKeys,
        amount: u64,
        amount_speedup: u64,
        var_names: &Vec<&str>,
        from: &str,
        to: &str,
    ) -> Result<(), BitVMXError> {
        info!("Adding winternitz check for {} to {}", from, to);
        info!("Amount: {}", amount);
        info!("Speedup: {}", amount_speedup);
        let names_and_keys = var_names
            .iter()
            .map(|v| (*v, keys.get_winternitz(v).unwrap()))
            .collect();

        let winternitz_check = scripts::verify_winternitz_signatures(
            aggregated,
            &names_and_keys,
            SignMode::Aggregate,
        )?;

        let leaves = [winternitz_check];

        let output_type = OutputType::taproot(amount, aggregated, &leaves)?;

        protocol.add_connection(
            &format!("{}__{}", from, to),
            from,
            output_type.into(),
            to,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        let pb = ProtocolBuilder {};
        //put the amount here as there is no output yet
        pb.add_speedup_output(protocol, to, amount_speedup, aggregated)?;

        Ok(())
    }
}
