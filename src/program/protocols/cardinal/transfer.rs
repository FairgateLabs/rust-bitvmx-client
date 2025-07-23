use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
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
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            cardinal::{
                slot::{self},
                LOCKED_ASSET_UTXO, OPERATORS_AGGREGATED_PUB, OPERATOR_COUNT, SLOT_PROGRAM_ID,
                SPEEDUP_DUST, UNSPENDABLE,
            },
            claim::ClaimGate,
            protocol_handler::{external_fund_tx, ProtocolContext, ProtocolHandler},
        },
        variables::PartialUtxo,
    },
    types::{ProgramContext, PROGRAM_TYPE_SLOT},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct TransferProtocol {
    ctx: ProtocolContext,
}

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
        _program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        Ok(ParticipantKeys::new(vec![], vec![]))
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        if name.starts_with(TOO_TX) {
            let op_and_id: Vec<u32> = name
                .strip_prefix(TOO_TX)
                .unwrap_or("0_0")
                .split('_')
                .map(|s| s.parse::<u32>().unwrap())
                .collect();
            return Ok((self.transfer(op_and_id[0], op_and_id[1])?, None));
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
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let speedup_dust = context
            .globals
            .get_var(&self.ctx.id, SPEEDUP_DUST)?
            .unwrap()
            .number()? as u64;

        let unspendable = context
            .globals
            .get_var(&self.ctx.id, UNSPENDABLE)?
            .unwrap()
            .pubkey()?;

        let ops_agg_pubkey = context
            .globals
            .get_var(&self.ctx.id, OPERATORS_AGGREGATED_PUB)?
            .unwrap()
            .pubkey()?;

        let operator_count = context
            .globals
            .get_var(&self.ctx.id, OPERATOR_COUNT)?
            .unwrap()
            .number()?;

        let too_groups = 2_u32.pow(operator_count as u32) - 1;

        let groups_pub_keys: Vec<PublicKey> = (1..=too_groups)
            .map(|gid| {
                context
                    .globals
                    .get_var(&self.ctx.id, &pub_too_group(gid))
                    .unwrap()
                    .unwrap()
                    .pubkey()
                    .unwrap()
            })
            .collect();

        let locked_asset_utxo = context
            .globals
            .get_var(&self.ctx.id, LOCKED_ASSET_UTXO)?
            .unwrap()
            .utxo()?;

        let mut operator_txs = Vec::new();

        if let Some(var) = context.globals.get_var(&self.ctx.id, SLOT_PROGRAM_ID)? {
            //GET TXS FROM SLOT PROGRAM
            let slot_program_id = var.string()?;
            let slot_uuid = Uuid::parse_str(&slot_program_id).unwrap();

            let protocol_name = format!("{}_{}", PROGRAM_TYPE_SLOT, slot_uuid);
            let protocol = Protocol::load(
                &protocol_name,
                self.context().storage.as_ref().unwrap().clone(),
            )?
            .unwrap();
            info!("Slot program: {}", protocol_name);

            for op in 0..operator_count {
                //  let gidtxs: Vec<PartialUtxo> = (1..=too_groups)
                // pub type PartialUtxo = (Txid, u32, Option<u64>, Option<OutputType>);
                let op_won_tx = protocol
                    .transaction_by_name(&ClaimGate::tx_success(&slot::claim_name(op as usize)))?;
                let tx_id = op_won_tx.compute_txid();

                let vout = 0;
                let amount = speedup_dust;
                let verify_aggregated_action =
                    scripts::check_aggregated_signature(&ops_agg_pubkey, SignMode::Aggregate);
                let output_action =
                    external_fund_tx(&ops_agg_pubkey, vec![verify_aggregated_action], amount)?;

                let operator_won_tx = (tx_id, vout, Some(amount), Some(output_action));

                let mut gidtxs = vec![];

                for gid in 1..=too_groups {
                    let gittx =
                        protocol.transaction_by_name(&slot::group_id_tx(op as usize, gid as u8))?;
                    let tx_id = gittx.compute_txid();

                    let vout = 0;
                    let amount = speedup_dust;
                    let verify_aggregated_action =
                        scripts::check_aggregated_signature(&ops_agg_pubkey, SignMode::Aggregate);
                    let output_action =
                        external_fund_tx(&ops_agg_pubkey, vec![verify_aggregated_action], amount)?;
                    gidtxs.push((tx_id, vout, Some(amount), Some(output_action)));
                }
                operator_txs.push((gidtxs, operator_won_tx));
            }
        } else {
            //EXTERNALLY SET TXS
            for op in 0..operator_count {
                let gidtxs: Vec<PartialUtxo> = (1..=too_groups)
                    .map(|gid| {
                        context
                            .globals
                            .get_var(&self.ctx.id, &op_gid(op, gid))
                            .unwrap()
                            .unwrap()
                            .utxo()
                            .unwrap()
                    })
                    .collect();

                let operator_won_tx = context
                    .globals
                    .get_var(&self.ctx.id, &op_won(op))?
                    .unwrap()
                    .utxo()
                    .unwrap();

                operator_txs.push((gidtxs, operator_won_tx));
            }
        }

        //create the protocol
        let mut protocol = self.load_or_create_protocol();

        let pb = ProtocolBuilder {};

        protocol.add_external_transaction(ASSET_TX)?;
        protocol.add_unknown_outputs(ASSET_TX, locked_asset_utxo.1)?;
        protocol.add_transaction_output(ASSET_TX, locked_asset_utxo.3.as_ref().unwrap())?;

        for op in 0..operator_count {
            let (gidtxs, operator_won_tx) = &operator_txs[op as usize];

            let operator_won_tx_name_str = operator_won_tx_name(op);
            protocol.add_external_transaction(&operator_won_tx_name_str)?;
            protocol.add_unknown_outputs(&operator_won_tx_name_str, operator_won_tx.1)?;
            protocol.add_transaction_output(
                &operator_won_tx_name_str,
                operator_won_tx.3.as_ref().unwrap(),
            )?;

            for gid in 0..too_groups {
                let gidtx = &gidtxs[gid as usize];

                let gid_tx_name = gid_tx(op, gid + 1);
                protocol.add_external_transaction(&gid_tx_name)?;
                protocol.add_unknown_outputs(&gid_tx_name, gidtx.1)?;

                let txname = too_tx(op, gid + 1);

                //add the assest as first input
                protocol.add_connection(
                    &format!("{}__{}", ASSET_TX, &txname),
                    ASSET_TX,
                    (locked_asset_utxo.1 as usize).into(),
                    &txname,
                    InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
                    None,
                    Some(locked_asset_utxo.0),
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
                    &groups_pub_keys[gid as usize],
                    SignMode::Skip,
                );

                protocol.add_transaction_output(
                    &txname,
                    &OutputType::taproot(
                        locked_asset_utxo.2.unwrap(),
                        &unspendable,
                        &[asset_output],
                    )?, // We do not need prevouts cause the tx is in the graph,
                )?;

                // add one output to test
                pb.add_speedup_output(&mut protocol, &txname, speedup_dust, &ops_agg_pubkey)?;
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
