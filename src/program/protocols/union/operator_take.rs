use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::types::*,
        },
        variables::PartialUtxo,
    },
    types::ProgramContext,
};

use bitcoin::{Amount, PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    builder::Protocol,
    scripts::{self, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::SpeedupData,
        OutputType,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

#[derive(Clone, Serialize, Deserialize)]
pub struct OperatorTakeProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for OperatorTakeProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
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
        // TODO
        Ok(())
    }

    fn get_pregenerated_aggregated_keys(
        &self,
        _context: &ProgramContext,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        // Predefined aggregated keys for this protocol
        todo!()
    }

    fn generate_keys(
        &self,
        _program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        Ok(ParticipantKeys::new(vec![], vec![]))
    }

    fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let accept_peg_in_utxo = self.utxo("accept_peg_in_utxo", context)?;
        let fee = self.number("fee", context)? as u64;
        let operator_pubkey = self.committee(context)?.my_take_pubkey;

        //create the protocol
        let mut protocol = self.load_or_create_protocol();

        // Declare the external accept peg-in transaction
        protocol.add_external_transaction(ACCEPT_PEG_IN_TX)?;
        protocol.add_transaction_output(ACCEPT_PEG_IN_TX, &accept_peg_in_utxo.3.unwrap())?;

        // Connect the user take transaction with the accept peg-in transaction
        protocol.add_connection(
            "operator_take",
            ACCEPT_PEG_IN_TX,
            (accept_peg_in_utxo.1 as usize).into(),
            OPERATOR_TAKE_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(accept_peg_in_utxo.0),
        )?;

        // Add the user output to the user take transaction
        let mut amount = accept_peg_in_utxo.2.unwrap();
        amount = self.checked_sub(amount, fee)?;

        let wpkh = operator_pubkey.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

        protocol.add_transaction_output(
            OPERATOR_TAKE_TX,
            &OutputType::SegwitPublicKey {
                value: Amount::from_sat(amount),
                script_pubkey,
                public_key: operator_pubkey,
            },
        )?;

        // TODO: review if we should add an speedup output to the operator take transaction and skip fee
        // due to this transactions will be signed in accept pegin but used after a pegout

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;
        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        Err(BitVMXError::InvalidTransactionName(name.to_string()))
    }
}

impl OperatorTakeProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn utxo(&self, name: &str, context: &ProgramContext) -> Result<PartialUtxo, BitVMXError> {
        context.globals.get_var(&self.ctx.id, name)?.unwrap().utxo()
    }

    fn number(&self, name: &str, context: &ProgramContext) -> Result<u32, BitVMXError> {
        context
            .globals
            .get_var(&self.ctx.id, name)?
            .unwrap()
            .number()
    }

    fn committee(&self, context: &ProgramContext) -> Result<CommitteeCreated, BitVMXError> {
        let committee_created = context
            .globals
            .get_var(&self.ctx.id, &CommitteeCreated::name())?
            .unwrap()
            .string()?;

        let committee_created: CommitteeCreated = serde_json::from_str(&committee_created)?;
        Ok(committee_created)
    }
}
