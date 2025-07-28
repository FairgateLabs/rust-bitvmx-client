use std::collections::HashMap;

use bitcoin::{Amount, PublicKey, ScriptBuf, Transaction, Txid};
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
use tracing::info;
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{
                common::get_dispute_core_id,
                types::{
                    PegInAccepted, PegInRequest, ACCEPT_PEGIN_TX, CHALLENGE_ENABLER,
                    OPERATOR_TAKE_ENABLER, OPERATOR_WON_ENABLER, REIMBURSEMENT_KICKOFF_TX,
                    REQUEST_PEGIN_TX,
                },
            },
        },
        variables::{PartialUtxo, VariableTypes},
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
        let pegin_request_txid = pegin_request.txid;
        let amount = pegin_request.amount;
        let take_aggregated_key = &pegin_request.take_aggregated_key;

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
            Some(pegin_request_txid),
        )?;

        let accept_pegin_output = OutputType::taproot(amount, &take_aggregated_key, &[])?;
        protocol.add_transaction_output(ACCEPT_PEGIN_TX, &accept_pegin_output)?;

        let slot_index = pegin_request.slot_index as usize;

        // Operator take transactions
        // Loop over operators and create take 1 and take 2 transactions
        for (index, take_key) in pegin_request.operators_take_key.iter().enumerate() {
            let dispute_protocol_id = get_dispute_core_id(pegin_request.committee_id, take_key);

            let challenge_enabler =
                self.challenge_enabler(context, dispute_protocol_id, slot_index)?;
            let operator_take_enabler =
                self.operator_take_enabler(context, dispute_protocol_id, slot_index)?;
            let operator_won_enabler =
                self.operator_won_enabler(context, dispute_protocol_id, slot_index)?;

            let kickoff_tx_name = &format!("{}_OP_{}", REIMBURSEMENT_KICKOFF_TX, index);
            let try_take2_tx_name = &format!("TRY_TAKE2_TX_OP_{}", index);

            // Create kickoff transaction reference
            self.create_transaction_reference(
                &mut protocol,
                kickoff_tx_name,
                &mut vec![operator_take_enabler.clone(), challenge_enabler.clone()],
            )?;

            // Create won enabler transaction reference
            self.create_transaction_reference(
                &mut protocol,
                try_take2_tx_name,
                &mut vec![operator_won_enabler.clone()],
            )?;

            self.create_operator_take_transaction(
                &mut protocol,
                index as u32,
                amount,
                take_key,
                pegin_request_txid,
                kickoff_tx_name,
                operator_take_enabler.clone(),
                challenge_enabler.clone(),
            )?;

            self.create_operator_won_transaction(
                &mut protocol,
                index as u32,
                amount,
                take_key,
                pegin_request_txid,
                kickoff_tx_name,
                operator_take_enabler.clone(),
                try_take2_tx_name,
                operator_won_enabler.clone(),
            )?;
        }

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;

        let tx = protocol.transaction_by_name(ACCEPT_PEGIN_TX)?;
        let txid = tx.compute_txid();
        let output_index = 0;

        // Save Accept Pegin transaction under committee_id to be used in user take
        context.globals.set_var(
            &pegin_request.committee_id,
            &format!("{}_{}", ACCEPT_PEGIN_TX, slot_index).to_string(),
            VariableTypes::Utxo((
                txid,
                output_index,
                Some(tx.output.get(output_index as usize).unwrap().value.to_sat()),
                Some(accept_pegin_output),
            )),
        )?;

        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);
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

    fn operator_take_enabler(
        &self,
        context: &ProgramContext,
        dispute_protocol_id: Uuid,
        index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(
                &dispute_protocol_id,
                &var_name(OPERATOR_TAKE_ENABLER, index),
            )?
            .unwrap()
            .utxo()?)
    }

    fn operator_won_enabler(
        &self,
        context: &ProgramContext,
        dispute_protocol_id: Uuid,
        index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(&dispute_protocol_id, &var_name(OPERATOR_WON_ENABLER, index))?
            .unwrap()
            .utxo()?)
    }

    fn challenge_enabler(
        &self,
        context: &ProgramContext,
        dispute_protocol_id: Uuid,
        index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(&dispute_protocol_id, &var_name(CHALLENGE_ENABLER, index))?
            .unwrap()
            .utxo()?)
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

        // TODO: Check if we want this assertion
        // We expect nonces for: ACCEPT_PEGIN_TX + 4 operator_take + 4 operator_won + 4 per try_take_2 = 9 total
        // let expected_nonces = 13;
        // assert_eq!(
        //     nonces.len(),
        //     expected_nonces,
        //     "Expected exactly {} nonces for AcceptPegInProtocol, found {}",
        //     expected_nonces,
        //     nonces.len()
        // );

        let signatures = program_context
            .key_chain
            .get_signatures(&take_aggregated_key, &self.ctx.protocol_name)?;

        if signatures.is_empty() {
            return Err(BitVMXError::MissingPartialSignatures(
                take_aggregated_key.to_string(),
                self.ctx.protocol_name.to_string(),
            ));
        }

        // FIXME: Do we want this assertion?
        // assert_eq!(
        //     signatures.len(),
        //     1,
        //     "Expected exactly one partial signature for AcceptPegInProtocol, found {}",
        //     signatures.len()
        // );

        let mut protocol = self.load_protocol()?;
        let operator_take_tx_name = &format!("OPERATOR_TAKE_TX_OP_{}", self.ctx.my_idx);
        let operator_take_sighash = protocol
            .get_hashed_message(operator_take_tx_name, 0, 0)?
            .unwrap()
            .as_ref()
            .to_vec();

        let operator_won_tx_name = &format!("OPERATOR_WON_TX_OP_{}", self.ctx.my_idx);
        let operator_won_sighash = protocol
            .get_hashed_message(operator_won_tx_name, 0, 0)?
            .unwrap()
            .as_ref()
            .to_vec();

        let pegin_accepted = PegInAccepted {
            operator_take_sighash,
            operator_won_sighash,
            take_aggregated_key: take_aggregated_key.clone(),
            accept_pegin_nonce: nonces[0].1.clone(),
            accept_pegin_signature: signatures[0].1.clone(),
        };

        let data = serde_json::to_string(&OutgoingBitVMXApiMessages::Variable(
            self.ctx.id,
            "pegin_accepted".to_string(),
            VariableTypes::String(serde_json::to_string(&pegin_accepted)?),
        ))?;

        info!(
            id = self.ctx.my_idx,
            "Sending pegin accepted data for AcceptPegInProtocol: {}", data
        );

        // Send the pegin accepted data to the broker channel
        program_context.broker_channel.send(L2_ID, data)?;

        Ok(())
    }

    fn create_operator_take_transaction(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        index: u32,
        amount: u64,
        take_pubkey: &PublicKey,
        pegin_txid: Txid,
        kickoff_tx_name: &str,
        take_enabler: PartialUtxo,
        challenge_enabler: PartialUtxo,
    ) -> Result<(), BitVMXError> {
        let operator_take_tx_name = &format!("OPERATOR_TAKE_TX_OP_{}", index);
        // protocol.add_transaction(operator_take_tx_name)?;

        // Pegin input
        self.add_accept_pegin_connection(protocol, operator_take_tx_name, pegin_txid)?;

        // Input All takes enabler
        self.add_all_takes_enabler_input(
            protocol,
            operator_take_tx_name,
            kickoff_tx_name,
            take_enabler,
        )?;

        // Input from reimbursement kickoff with timelock
        protocol.add_connection(
            "challenge_enabler_conn",
            kickoff_tx_name,
            OutputSpec::Index(challenge_enabler.1 as usize),
            operator_take_tx_name,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(challenge_enabler.0),
        )?;

        // // Operator Output
        self.add_operator_output(protocol, operator_take_tx_name, amount, take_pubkey)?;
        Ok(())
    }

    fn create_operator_won_transaction(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        index: u32,
        amount: u64,
        take_pubkey: &PublicKey,
        pegin_txid: Txid,
        kickoff_tx_name: &str,
        take_enabler: PartialUtxo,
        try_take2_tx_name: &str,
        won_enabler: PartialUtxo,
    ) -> Result<(), BitVMXError> {
        // Operator won transaction
        let operator_won_tx_name = &format!("OPERATOR_WON_TX_OP_{}", index);
        // protocol.add_transaction(operator_won_tx_name)?;

        // Pegin input
        self.add_accept_pegin_connection(protocol, operator_won_tx_name, pegin_txid)?;

        // Input All takes enabler
        self.add_all_takes_enabler_input(
            protocol,
            operator_won_tx_name,
            kickoff_tx_name,
            take_enabler,
        )?;

        // Input from try take 2 with timelock
        protocol.add_connection(
            "try_take2_conn",
            try_take2_tx_name,
            OutputSpec::Index(won_enabler.1 as usize),
            operator_won_tx_name,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(won_enabler.0),
        )?;

        // Operator Output
        // TODO: Modify amount based on Miro
        self.add_operator_output(protocol, operator_won_tx_name, amount, take_pubkey)?;

        Ok(())
    }

    fn add_accept_pegin_connection(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        tx_name: &str,
        pegin_txid: Txid,
    ) -> Result<(), BitVMXError> {
        protocol.add_connection(
            "accept_pegin_conn",
            ACCEPT_PEGIN_TX,
            OutputSpec::Index(0),
            tx_name,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(pegin_txid),
        )?;
        Ok(())
    }

    fn add_all_takes_enabler_input(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        tx_name: &str,
        kickoff_tx_name: &str,
        take_enabler: PartialUtxo,
    ) -> Result<(), BitVMXError> {
        protocol.add_connection(
            "take_enabler_conn",
            kickoff_tx_name,
            OutputSpec::Index(take_enabler.1 as usize),
            tx_name,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(take_enabler.0),
        )?;
        Ok(())
    }

    fn add_operator_output(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        tx_name: &str,
        amount: u64,
        take_pubkey: &PublicKey,
    ) -> Result<(), BitVMXError> {
        let wpkh = take_pubkey.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

        protocol.add_transaction_output(
            tx_name,
            &OutputType::SegwitPublicKey {
                value: Amount::from_sat(amount),
                script_pubkey,
                public_key: *take_pubkey,
            },
        )?;

        Ok(())
    }

    fn create_transaction_reference(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        tx_name: &str,
        utxos: &mut Vec<PartialUtxo>,
    ) -> Result<(), BitVMXError> {
        // Create transaction
        protocol.add_transaction(tx_name)?;

        // Sort UTXOs by index
        utxos.sort_by_key(|utxo| utxo.1);
        let mut last_index = 0;

        for utxo in utxos {
            // If there is a gap in the indices, add unknown outputs
            if utxo.1 > last_index + 1 {
                protocol.add_unknown_outputs(tx_name, utxo.1 - last_index)?;
            }

            // Add the UTXO as an output
            protocol.add_transaction_output(tx_name, &utxo.clone().3.unwrap())?;
            last_index = utxo.1;
        }

        Ok(())
    }
}

// This should be imported from a common utility module
// This same function is used in `dispute_core.rs` and `accept_pegin.rs`
fn var_name(prefix: &str, index: usize) -> String {
    format!("{}_{}", prefix, index)
}
