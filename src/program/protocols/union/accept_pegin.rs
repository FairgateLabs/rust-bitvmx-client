use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use emulator::loader::program;
use protocol_builder::{
    scripts::SignMode,
    types::{
        connection::InputSpec,
        input::{SighashType, SpendMode},
        output::SpeedupData,
        OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::types::{PegInRequest, ACCEPT_PEGIN_TX, REQUEST_PEGIN_TX},
        },
        variables::VariableTypes,
    },
    types::{OutgoingBitVMXApiMessages, ProgramContext, L2_ID},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct AcceptPegInProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for AcceptPegInProtocol {
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
        let pegin_request = self.pegin_request(context)?;

        Ok(vec![(
            "take_aggregated".to_string(),
            pegin_request.take_aggregated_key,
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
        let pegin_request = self.pegin_request(context)?;
        let txid = pegin_request.txid;
        let amount = pegin_request.amount;
        let take_aggregated_key = pegin_request.take_aggregated_key;

        let mut protocol = self.load_or_create_protocol();

        // External connection from request peg-in to accept peg-in
        protocol.add_connection(
            "accept_pegin_request",
            REQUEST_PEGIN_TX,
            OutputType::taproot(amount, &take_aggregated_key, &[])?.into(),
            ACCEPT_PEGIN_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(txid),
        )?;

        protocol.add_transaction_output(
            ACCEPT_PEGIN_TX,
            &OutputType::taproot(amount, &take_aggregated_key, &[])?,
        )?;

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

    fn setup_complete(&self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        let pegin_request = self.pegin_request(program_context)?;
        let take_aggregated_key = pegin_request.take_aggregated_key;

        self.send_signing_info(&program_context, &take_aggregated_key)?;

        info!(
            id = self.ctx.my_idx,
            "AcceptPegInProtocol setup complete for program {}", self.ctx.id
        );
        Ok(())
    }
}

impl AcceptPegInProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn pegin_request(&self, context: &ProgramContext) -> Result<PegInRequest, BitVMXError> {
        let pegin_request = context
            .globals
            .get_var(&self.ctx.id, &PegInRequest::name())?
            .unwrap()
            .string()?;

        let pegin_request: PegInRequest = serde_json::from_str(&pegin_request)?;
        Ok(pegin_request)
    }

    fn send_signing_info(
        &self,
        program_context: &ProgramContext,
        take_aggregated_key: &PublicKey,
    ) -> Result<(), BitVMXError> {
        let nonces = program_context
            .key_chain
            .get_nonces(&take_aggregated_key, &self.ctx.protocol_name)?;

        if nonces.is_empty() {
            return Err(BitVMXError::MissingPublicNonces(
                take_aggregated_key.to_string(),
                self.ctx.protocol_name.to_string(),
            ));
        }

        assert_eq!(
            nonces.len(),
            1,
            "Expected exactly one nonce for AcceptPegInProtocol, found {}",
            nonces.len()
        );

        let signatures = program_context
            .key_chain
            .get_signatures(&take_aggregated_key, &self.ctx.protocol_name)?;

        if signatures.is_empty() {
            return Err(BitVMXError::MissingPartialSignatures(
                take_aggregated_key.to_string(),
                self.ctx.protocol_name.to_string(),
            ));
        }

        assert_eq!(
            signatures.len(),
            1,
            "Expected exactly one partial signature for AcceptPegInProtocol, found {}",
            signatures.len()
        );

        let data = serde_json::to_string(&OutgoingBitVMXApiMessages::Variable(
            self.ctx.id,
            "signing_info".to_string(),
            VariableTypes::String(serde_json::to_string(&(
                take_aggregated_key.clone(),
                nonces[0].1.clone(),
                signatures[0].1.clone(),
            ))?),
        ))?;

        program_context.broker_channel.send(L2_ID, data)?;

        // program_context.globals.set_var(
        //     &self.ctx.id,
        //     &"signing_info",
        //     VariableTypes::String(serde_json::to_string(&(
        //         &self.ctx.id,
        //         &"signing_info",
        //         take_aggregated_key.clone(),
        //         nonces[0].1.clone(),
        //         signatures[0].1.clone(),
        //     ))?),
        // )?;

        Ok(())
    }
}
