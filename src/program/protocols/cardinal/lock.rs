use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid, XOnlyPublicKey};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    graph::graph::GraphOptions,
    scripts::{self, reveal_secret, timelock, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::SpeedupData,
        InputArgs, OutputType, Utxo,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            cardinal::lock_config::LockProtocolConfiguration,
            protocol_handler::{ProtocolContext, ProtocolHandler},
        },
        variables::VariableTypes,
    },
    types::ProgramContext,
};

pub const LOCK_REQ_TX: &str = "lock_req_tx";
pub const LOCK_TX: &str = "lock_tx";
pub const HAPPY_PATH_TX: &str = "happy_path_tx";

#[derive(Clone, Serialize, Deserialize)]
pub struct LockProtocol {
    ctx: ProtocolContext,
}

pub const MIN_RELAY_FEE: u64 = 1;
pub const DUST: u64 = 500 * MIN_RELAY_FEE;
pub fn lock_protocol_dust_cost(participants: u8) -> u64 {
    DUST * (participants as u64 + 3)
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
        let speedup = program_context.key_chain.derive_keypair()?;

        program_context.globals.set_var(
            &self.ctx.id,
            "speedup",
            VariableTypes::PubKey(speedup.clone()),
        )?;

        let keys = vec![("speedup".to_string(), speedup.into())];

        Ok(ParticipantKeys::new(keys, vec![]))
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        match name {
            LOCK_TX => Ok((self.accept_tx(context))?),
            HAPPY_PATH_TX => Ok((self.happy_path()?, None)),
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
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let LockProtocolConfiguration {
            operators_aggregated_pub,
            operators_aggregated_pub_happy_path,
            unspendable,
            user_pubkey,
            secret,
            ordinal_utxo,
            protocol_utxo,
            timelock_blocks,
            eol_timelock_duration,
            ..
        } = LockProtocolConfiguration::new_from_globals(self.ctx.id, &context.globals)?;

        warn!(
            "Setup with: {:?} {:?} {:?}",
            ordinal_utxo, protocol_utxo, user_pubkey
        );

        warn!(
            "======== Ops_agg_key: {:?} Unspendable: {:?} User_pubkey{:?}",
            XOnlyPublicKey::from(operators_aggregated_pub).to_string(),
            XOnlyPublicKey::from(unspendable).to_string(),
            XOnlyPublicKey::from(user_pubkey).to_string()
        );

        //THIS SECTION DEFINES THE OUTPUTS OF THE LOCK_REQ_TX
        //THAT WILL BE SPENT BY THE LOCK_TX

        // Mark this script as unsigned script, so the protocol builder wont try to sign it
        let timelock_script = timelock(timelock_blocks, &user_pubkey, SignMode::Skip);

        let reveal_secret_script = reveal_secret(
            secret.to_vec(),
            &operators_aggregated_pub,
            SignMode::Aggregate,
        );
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

        // The following script is the output that user timeout could use as input
        let taproot_script_eol_timelock_expired_tx_lock =
            scripts::timelock(eol_timelock_duration, &user_pubkey, SignMode::Skip);

        //this should be another aggregated to be signed later
        let taproot_script_all_sign_tx_lock =
            scripts::check_aggregated_signature(&operators_aggregated_pub, SignMode::Aggregate);

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
            scripts::check_aggregated_signature(&operators_aggregated_pub, SignMode::Aggregate);

        let amount = self.checked_sub(protocol_utxo.2.unwrap(), DUST * (keys.len() as u64 + 1))?;
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

        self.add_happy_path(
            &mut protocol,
            &operators_aggregated_pub_happy_path,
            &unspendable,
            ordinal_utxo.2.unwrap(),
            self.checked_sub(amount, DUST)?,
        )?;

        let pb = ProtocolBuilder {};
        for k in keys {
            pb.add_speedup_output(&mut protocol, LOCK_TX, DUST, k.get_public("speedup")?)?;
        }

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize(GraphOptions::Default)?);
        self.save_protocol(protocol)?;

        Ok(())
    }

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!("LockProtocol setup complete for program {}", self.ctx.id);
        Ok(())
    }
}

impl LockProtocol {
    pub fn new(context: ProtocolContext) -> Self {
        Self { ctx: context }
    }

    pub fn add_happy_path(
        &self,
        protocol: &mut Protocol,
        ops_agg_happy_path: &PublicKey,
        unspendable: &PublicKey,
        amount_ordinal: u64,
        amount_protocol: u64,
    ) -> Result<(), BitVMXError> {
        // START DEFINING THE HAPPY_PATH_TX

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

    pub fn accept_tx(
        &self,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        //Gets the
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

        let txid = tx.compute_txid();
        let speedup = context
            .globals
            .get_var(&self.ctx.id, "speedup")?
            .unwrap()
            .pubkey()?;
        let speedup_utxo = Utxo::new(txid, 2 + self.ctx.my_idx as u32, DUST, &speedup);

        debug!("Transaction to send: {:?}", tx);
        Ok((tx, Some(speedup_utxo.into())))
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

        debug!("Transaction to send: {:?}", tx);
        Ok(tx)
    }
}
