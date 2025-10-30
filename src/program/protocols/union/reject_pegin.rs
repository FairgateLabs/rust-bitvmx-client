use std::collections::HashMap;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::types::{
                Committee, RejectPeginData, DUST_VALUE, REJECT_PEGIN_TX, REQUEST_PEGIN_TX,
            },
        },
    },
    types::ProgramContext,
};
use bitcoin::{script::PushBytesBuf, Amount, PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use protocol_builder::{
    builder::Protocol,
    graph::graph::GraphOptions,
    scripts::{verify_signature, SignMode},
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

#[derive(Clone, Serialize, Deserialize)]
pub struct RejectPegInProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for RejectPegInProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }

    fn get_pregenerated_aggregated_keys(
        &self,
        _context: &ProgramContext,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        Ok([].to_vec())
    }

    fn generate_keys(&self, _context: &mut ProgramContext) -> Result<ParticipantKeys, BitVMXError> {
        Ok(ParticipantKeys::new(vec![], vec![]))
    }

    fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let data: RejectPeginData = self.reject_pegin(context)?;
        let pegin_request_txid = data.txid;
        let committee = self.committee(context, data.committee_id)?;
        let take_aggregated_key = committee.take_aggregated_key;

        let mut protocol = self.load_or_create_protocol();

        let mut enabler_scripts = vec![];
        for member in &committee.members {
            enabler_scripts.push(verify_signature(&member.dispute_key, SignMode::Single)?)
        }

        // External connection from request peg-in to accept peg-in
        protocol.add_external_transaction(REQUEST_PEGIN_TX)?;
        protocol.add_unknown_outputs(REQUEST_PEGIN_TX, 2)?;

        // External connection from request peg-in to accept peg-in
        protocol.add_connection(
            "accept_enabler_conn",
            REQUEST_PEGIN_TX,
            OutputType::taproot(DUST_VALUE, &take_aggregated_key, &enabler_scripts)?.into(),
            REJECT_PEGIN_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::Script {
                    leaf: data.member_index,
                },
            ),
            None,
            Some(pegin_request_txid),
        )?;

        // NOTE: Need to add some bytes to OP_RETURN to reach the minimum tx size
        let message = "disable_request_pegin";
        let mut data = PushBytesBuf::with_capacity(message.len());
        data.extend_from_slice(message.as_bytes())
            .map_err(|_| BitVMXError::SerializationError)?;

        protocol.add_transaction_output(
            REJECT_PEGIN_TX,
            &OutputType::SegwitUnspendable {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new_op_return(&data),
            },
        )?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);
        self.save_protocol(protocol)?;

        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        if name == REJECT_PEGIN_TX {
            self.reject_tx(context)
        } else {
            Err(BitVMXError::InvalidTransactionName(name.to_string()))
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
        let tx_name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Reject Pegin protocol received news of transaction: {}, txid: {} with {} confirmations",
            tx_name, tx_id, tx_status.confirmations
        );

        Ok(())
    }

    fn setup_complete(&self, context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        // self.send_pegin_accepted(&program_context, &take_aggregated_key)?;
        let (tx, speedup) = self.reject_tx(context)?;
        info!(
            id = self.ctx.my_idx,
            "Auto-dispatching {} transaction: {}",
            REJECT_PEGIN_TX,
            tx.compute_txid()
        );

        // Dispatch the transaction through the bitcoin coordinator
        context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            format!("reject_pegin_{}:{}", self.ctx.id, REJECT_PEGIN_TX), // Context string
            None,                                                        // Dispatch immediately
        )?;

        info!(
            id = self.ctx.my_idx,
            "RejectPegInProtocol setup complete for program {}", self.ctx.id
        );
        Ok(())
    }
}

impl RejectPegInProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn reject_pegin(&self, context: &ProgramContext) -> Result<RejectPeginData, BitVMXError> {
        let data = context
            .globals
            .get_var(&self.ctx.id, &RejectPeginData::name())?
            .unwrap()
            .string()?;

        let data: RejectPeginData = serde_json::from_str(&data)?;
        Ok(data)
    }

    fn reject_tx(
        &self,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        let member_leaf_index = self.reject_pegin(context)?.member_index;
        let name = REJECT_PEGIN_TX;

        info!(
            id = self.ctx.my_idx,
            "Loading {} for RejectPeginProtocol. Member leaf index: {}", name, member_leaf_index
        );

        let protocol: Protocol = self.load_protocol()?;
        let enabler_signature = protocol
            .input_taproot_script_spend_signature(name, 0, member_leaf_index)?
            .unwrap();

        let mut enabler_input = InputArgs::new_taproot_script_args(member_leaf_index);
        enabler_input.push_taproot_signature(enabler_signature)?;

        let tx = self
            .load_protocol()?
            .transaction_to_send(name, &[enabler_input])?;

        Ok((tx, None))
    }

    fn committee(
        &self,
        context: &ProgramContext,
        committee_id: Uuid,
    ) -> Result<Committee, BitVMXError> {
        let committee = context
            .globals
            .get_var(&committee_id, &Committee::name())?
            .unwrap()
            .string()?;

        let committee: Committee = serde_json::from_str(&committee)?;
        Ok(committee)
    }
}
