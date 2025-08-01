use std::collections::HashMap;

use bitcoin::{Amount, PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    errors::ProtocolBuilderError,
    graph::graph::GraphOptions,
    scripts::SignMode,
    types::{
        connection::{InputSpec, OutputSpec},
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
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::types::{PegOutRequest, ACCEPT_PEGIN_TX, SPEED_UP_VALUE, USER_TAKE_TX},
        },
        variables::PartialUtxo,
    },
    types::ProgramContext,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct UserTakeProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for UserTakeProtocol {
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
            "take_aggregated".to_string(),
            self.take_aggregated_key(context)?,
        )])
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
        let pegout_request = self.pegout_request(context)?;
        let accept_pegin_utxo = self.accept_pegin_utxo(
            context,
            &pegout_request.committee_id,
            pegout_request.slot_id,
        )?;
        let user_pubkey = pegout_request.user_pubkey;
        let fee = pegout_request.fee;

        //create the protocol
        let mut protocol = self.load_or_create_protocol();

        // Connect the user take transaction with the accept peg-in transaction
        protocol.add_connection(
            "user_take",
            ACCEPT_PEGIN_TX,
            OutputSpec::Auto(accept_pegin_utxo.3.unwrap()),
            USER_TAKE_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(accept_pegin_utxo.0),
        )?;

        // Add the user output to the user take transaction
        let mut amount = accept_pegin_utxo.2.unwrap();
        amount = self.checked_sub(amount, fee)?;
        amount = self.checked_sub(amount, SPEED_UP_VALUE)?;

        let wpkh = user_pubkey.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

        protocol.add_transaction_output(
            USER_TAKE_TX,
            &OutputType::SegwitPublicKey {
                value: Amount::from_sat(amount),
                script_pubkey: script_pubkey.clone(),
                public_key: user_pubkey,
            },
        )?;

        // Speed up transaction
        protocol.add_transaction_output(
            USER_TAKE_TX,
            &OutputType::SegwitPublicKey {
                value: Amount::from_sat(SPEED_UP_VALUE),
                script_pubkey: script_pubkey.clone(),
                public_key: user_pubkey,
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
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        match name {
            USER_TAKE_TX => Ok((self.user_take_tx()?, None)),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
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

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            id = self.ctx.my_idx,
            "UserTakeProtocol setup complete for program {}", self.ctx.id
        );
        Ok(())
    }
}

impl UserTakeProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn pegout_request(&self, context: &ProgramContext) -> Result<PegOutRequest, BitVMXError> {
        let pegout_request = context
            .globals
            .get_var(&self.ctx.id, &PegOutRequest::name())?
            .unwrap()
            .string()?;

        let pegout_request: PegOutRequest = serde_json::from_str(&pegout_request)?;
        Ok(pegout_request)
    }

    fn take_aggregated_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        Ok(self.pegout_request(context)?.take_aggregated_key)
    }

    fn accept_pegin_utxo(
        &self,
        context: &ProgramContext,
        committee_id: &Uuid,
        slot_index: u32,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(
                committee_id,
                &format!("{}_{}", ACCEPT_PEGIN_TX, slot_index).to_string(),
            )?
            .unwrap()
            .utxo()?)
    }

    pub fn user_take_tx(&self) -> Result<Transaction, ProtocolBuilderError> {
        let signature = self
            .load_protocol()?
            .input_taproot_key_spend_signature(USER_TAKE_TX, 0)?
            .unwrap();
        let mut taproot_arg = InputArgs::new_taproot_key_args();
        taproot_arg.push_taproot_signature(signature)?;

        self.load_protocol()?
            .transaction_to_send(USER_TAKE_TX, &[taproot_arg])
    }
}
