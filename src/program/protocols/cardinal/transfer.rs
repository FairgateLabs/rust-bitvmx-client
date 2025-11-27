use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    builder::ProtocolBuilder,
    errors::ProtocolBuilderError,
    graph::graph::GraphOptions,
    scripts::{self, SignMode},
    types::{
        connection::InputSpec,
        input::{SighashType, SpendMode},
        output::SpeedupData,
        InputArgs, OutputType,
    },
};
use key_manager::key_type::BitcoinKeyType;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            cardinal::{transfer_config::TransferConfig, OPERATORS_AGGREGATED_PUB},
            protocol_handler::{ProtocolContext, ProtocolHandler},
        },
        variables::VariableTypes,
    },
    types::ProgramContext,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct TransferProtocol {
    ctx: ProtocolContext,
}
pub const MIN_RELAY_FEE: u64 = 1;
pub const DUST: u64 = 500 * MIN_RELAY_FEE;

pub const ASSET_TX: &str = "ASSET_TX";
pub const GID_TX: &str = "GID_TX_";
pub const OPERATOR_WON_TX: &str = "OPERATOR_WON_TX";
pub const TOO_TX: &str = "TOO_TX_";

pub fn gid_tx(op: u32, gid: u32) -> String {
    format!("{}{}_{}", GID_TX, op, gid)
}
pub fn operator_won_tx_name(op: u32) -> String {
    format!("{}{}", OPERATOR_WON_TX, op)
}

pub fn too_tx(op: u32, gid: u32) -> String {
    format!("{}{}_{}", TOO_TX, op, gid)
}

pub fn pub_too_group(gid: u32) -> String {
    format!("pub_too_group_{}", gid)
}

pub fn op_gid(op: u32, gid: u32) -> String {
    format!("op_{}_gid_{}", op, gid)
}

pub fn op_won(op: u32) -> String {
    format!("op_{}_won_tx", op)
}

impl ProtocolHandler for TransferProtocol {
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
                .get_var(&self.ctx.id, OPERATORS_AGGREGATED_PUB)?
                .unwrap()
                .pubkey()?,
        )])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let speedup = program_context.key_chain.derive_keypair(BitcoinKeyType::P2tr)?;

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
        if name.starts_with(TOO_TX) {
            let op_and_id: Vec<u32> = name
                .strip_prefix(TOO_TX)
                .unwrap_or("0_0")
                .split('_')
                .map(|s| s.parse::<u32>().unwrap())
                .collect();
            let tx = self.transfer(op_and_id[0], op_and_id[1])?;
            let speedup_data = self.get_speedup_data_from_tx(&tx, context, None)?;
            return Ok((tx, Some(speedup_data)));
        }

        Err(BitVMXError::InvalidTransactionName(name.to_string()))
    }

    fn notify_news(
        &self,
        _tx_id: Txid,
        _vout: Option<u32>,
        _tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn build(
        &self,
        keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let tc = TransferConfig::new_from_globals(self.ctx.id, &context.globals)?;

        let operator_txs = tc.get_utxos(self.context().storage.as_ref().unwrap().clone())?;

        //create the protocol
        let mut protocol = self.load_or_create_protocol();

        let pb = ProtocolBuilder {};

        protocol.add_external_transaction(ASSET_TX)?;
        protocol.add_unknown_outputs(ASSET_TX, tc.locked_asset_utxo.1)?;
        protocol.add_transaction_output(ASSET_TX, tc.locked_asset_utxo.3.as_ref().unwrap())?;

        for op in 0..tc.operator_count {
            let (gidtxs, operator_won_tx) = &operator_txs[op as usize];

            let operator_won_tx_name_str = operator_won_tx_name(op);
            protocol.add_external_transaction(&operator_won_tx_name_str)?;
            protocol.add_unknown_outputs(&operator_won_tx_name_str, operator_won_tx.1)?;
            protocol.add_transaction_output(
                &operator_won_tx_name_str,
                operator_won_tx.3.as_ref().unwrap(),
            )?;

            for gid in 0..tc.too_groups {
                let gidtx = &gidtxs[gid as usize];

                let gid_tx_name = gid_tx(op, gid + 1);
                protocol.add_external_transaction(&gid_tx_name)?;
                protocol.add_unknown_outputs(&gid_tx_name, gidtx.1)?;

                let txname = too_tx(op, gid + 1);

                //add the assest as first input
                protocol.add_connection(
                    &format!("{}__{}", ASSET_TX, &txname),
                    ASSET_TX,
                    (tc.locked_asset_utxo.1 as usize).into(),
                    &txname,
                    InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
                    None,
                    Some(tc.locked_asset_utxo.0),
                )?;

                //gid enabler
                protocol.add_connection(
                    &format!("{}__{}", gid_tx_name, &txname),
                    &gid_tx_name,
                    gidtx.3.as_ref().unwrap().clone().into(),
                    &txname,
                    InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
                    None,
                    Some(gidtx.0),
                )?;

                //won enabler
                protocol.add_connection(
                    &format!("{}__{}", operator_won_tx_name_str, &txname),
                    &operator_won_tx_name_str,
                    (operator_won_tx.1 as usize).into(),
                    &txname,
                    InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
                    None,
                    Some(operator_won_tx.0),
                )?;

                //asset output to gid pub key
                let asset_output = scripts::check_aggregated_signature(
                    &tc.groups_pub_keys[gid as usize],
                    SignMode::Skip,
                );

                protocol.add_transaction_output(
                    &txname,
                    &OutputType::taproot(
                        tc.locked_asset_utxo.2.unwrap(),
                        &tc.unspendable,
                        &[asset_output],
                    )?, // We do not need prevouts cause the tx is in the graph,
                )?;

                // add one output to test
                let speedup_key = keys[op as usize].get_public("speedup")?;
                pb.add_speedup_output(&mut protocol, &txname, DUST, speedup_key)?;
            }
        }

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize(GraphOptions::Default)?);
        self.save_protocol(protocol)?;
        Ok(())
    }

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            "TransferProtocol setup complete for program {}",
            self.ctx.id
        );
        Ok(())
    }
}

impl TransferProtocol {
    pub fn new(context: ProtocolContext) -> Self {
        Self { ctx: context }
    }

    pub fn transfer(&self, op: u32, gid: u32) -> Result<Transaction, ProtocolBuilderError> {
        let mut all_signatures = vec![];
        let name = &too_tx(op, gid);

        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(&name, 0, 1)?
            .unwrap();

        let mut spending_args = InputArgs::new_taproot_script_args(1);
        spending_args.push_taproot_signature(signature)?;
        all_signatures.push(spending_args);

        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(&name, 1, 0)?
            .unwrap();

        let mut spending_args = InputArgs::new_taproot_script_args(0);
        spending_args.push_taproot_signature(signature)?;
        all_signatures.push(spending_args);

        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(&name, 2, 0)?
            .unwrap();

        let mut spending_args = InputArgs::new_taproot_script_args(0);
        spending_args.push_taproot_signature(signature)?;
        all_signatures.push(spending_args);

        self.load_protocol()?
            .transaction_to_send(&too_tx(op, gid), &all_signatures)
    }
}
