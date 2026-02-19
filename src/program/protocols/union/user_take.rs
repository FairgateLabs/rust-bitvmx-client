use std::collections::HashMap;

use bitcoin::{PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    graph::graph::GraphOptions,
    scripts::SignMode,
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::SpeedupData,
        OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{
                common::{collect_input_signatures, indexed_name, InputSigningInfo},
                errors::{ProtocolError, ProtocolErrorType},
                types::{
                    PegOutAccepted, PegOutRequest, ACCEPT_PEGIN_TX, CANCEL_TAKE0_TX, SPEEDUP_VALUE,
                    USER_TAKE_FEE, USER_TAKE_TX,
                },
            },
        },
        variables::{PartialUtxo, VariableTypes},
    },
    send_to_l2,
    types::{OutgoingBitVMXApiMessages, ProgramContext},
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
            pegout_request.slot_index,
        )?;
        let user_pubkey = pegout_request.user_pubkey;

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

        let etake_utxo = self.etake_utxo(
            context,
            &pegout_request.committee_id,
            pegout_request.slot_index,
        )?;

        // Connect the user take transaction with the Accept pegin Etake0 enabler output
        protocol.add_connection(
            "user_take",
            ACCEPT_PEGIN_TX,
            OutputSpec::Auto(etake_utxo.3.unwrap()),
            USER_TAKE_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(etake_utxo.0),
        )?;

        // Add the user output to the user take transaction
        let user_amount =
            self.checked_sub(accept_pegin_utxo.2.unwrap(), USER_TAKE_FEE + SPEEDUP_VALUE)?;

        let wpkh = user_pubkey.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

        protocol.add_transaction_output(
            USER_TAKE_TX,
            &OutputType::SegwitPublicKey {
                value: user_amount.into(),
                script_pubkey: script_pubkey.clone(),
                public_key: user_pubkey,
            },
        )?;

        protocol.add_transaction_output(
            USER_TAKE_TX,
            &OutputType::SegwitPublicKey {
                value: SPEEDUP_VALUE.into(),
                script_pubkey: script_pubkey.clone(),
                public_key: user_pubkey,
            },
        )?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;

        // Validate USER_TAKE_TX sighash
        let user_take_sighash = protocol
            .get_hashed_message(USER_TAKE_TX, 0, 0)?
            .unwrap()
            .as_ref()
            .to_vec();

        if user_take_sighash != pegout_request.pegout_sighash {
            let error = ProtocolError {
                uuid: self.ctx.id,
                protocol_name: self.ctx.protocol_name.clone(),
                source: ProtocolErrorType::InvalidSighash {
                    expected: hex::encode(pegout_request.pegout_sighash),
                    found: hex::encode(user_take_sighash.clone()),
                },
            };
            let data = send_to_l2!(self, context, ProtocolError, error);
            error!(id = self.ctx.my_idx, "Failed to accept user take: {}", data);
            return Err(BitVMXError::InvalidParameter(error.to_string()));
        }

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
        tx_id: Txid,
        _vout: Option<u32>,
        tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        let tx_name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "User Take protocol received news of transaction: {}, txid: {} with {} confirmations",
            tx_name, tx_id, tx_status.confirmations
        );

        Ok(())
    }

    fn setup_complete(&self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        info!(
            id = self.ctx.my_idx,
            "UserTakeProtocol setup complete for program {}", self.ctx.id
        );

        self.send_pegout_accepted(&program_context)?;

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
        slot_index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(committee_id, &indexed_name(ACCEPT_PEGIN_TX, slot_index))?
            .unwrap()
            .utxo()?)
    }

    pub fn user_take_tx(&self) -> Result<Transaction, BitVMXError> {
        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            USER_TAKE_TX,
            &vec![
                InputSigningInfo::KeySpend { input_index: 0 },
                InputSigningInfo::KeySpend { input_index: 1 },
            ],
        )?;

        let tx = protocol.transaction_to_send(USER_TAKE_TX, &args)?;
        Ok(tx)
    }

    fn etake_utxo(
        &self,
        context: &ProgramContext,
        committee_id: &Uuid,
        slot_index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(committee_id, &indexed_name(CANCEL_TAKE0_TX, slot_index))?
            .unwrap()
            .utxo()?)
    }

    pub fn send_pegout_accepted(
        &self,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let pegout_request = self.pegout_request(program_context)?;
        let take_aggregated_key = pegout_request.take_aggregated_key;

        let mut protocol = self.load_protocol()?;
        let user_take_sighash = protocol
            .get_hashed_message(USER_TAKE_TX, 0, 0)?
            .unwrap()
            .as_ref()
            .to_vec();

        let nonces = program_context
            .key_chain
            .get_nonces(&take_aggregated_key, &self.ctx.protocol_name)?;

        if nonces.is_empty() {
            return Err(BitVMXError::MissingPublicNonces(
                take_aggregated_key.to_string(),
                self.ctx.protocol_name.to_string(),
            ));
        }

        let signatures = program_context
            .key_chain
            .get_signatures(&take_aggregated_key, &self.ctx.protocol_name)?;

        if signatures.is_empty() {
            return Err(BitVMXError::MissingPartialSignatures(
                take_aggregated_key.to_string(),
                self.ctx.protocol_name.to_string(),
            ));
        }

        let user_take_txid = protocol.transaction_by_name(USER_TAKE_TX)?.compute_txid();

        // TODO: verify that the signature we are getting from the array of signatures is the proper one
        let pegout_accepted = PegOutAccepted {
            user_take_txid,
            committee_id: pegout_request.committee_id,
            user_take_sighash,
            user_take_nonce: nonces[0].1.clone(),
            user_take_signature: signatures[0].1.clone(),
        };

        let data = serde_json::to_string(&OutgoingBitVMXApiMessages::Variable(
            self.ctx.id,
            PegOutAccepted::name(),
            VariableTypes::String(serde_json::to_string(&pegout_accepted)?),
        ))?;

        info!(
            id = self.ctx.my_idx,
            "Sending pegout accepted data for UserTakeProtocol: {}", data
        );

        // Send the pegout accepted data to the broker channel
        program_context
            .broker_channel
            .send(&program_context.components_config.l2, data)?;

        Ok(())
    }
}
