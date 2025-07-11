use std::collections::HashMap;

use bitcoin::{hashes::Hash, Amount, PublicKey, ScriptBuf, Sequence, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    scripts::SignMode,
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::SpeedupData,
        OutputType,
    },
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tracing::info;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::types::{
                PegInRequest, ACCEPT_PEGIN_TX, DUST_VALUE, OPERATOR_TAKE_KEYS,
                REIMBURSEMENT_KICKOFF_TX, REIMBURSEMENT_KICKOFF_TXID, REQUEST_PEGIN_TX,
            },
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
        let pegin_request_txid = pegin_request.txid;
        let amount = pegin_request.amount;
        let take_aggregated_key = &pegin_request.take_aggregated_key;
        let take_pubkeys = self.take_pubkeys(context)?;
        let reimbursement_kickoff_txid = self.reimbursement_kickoff_txid(context)?;

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

        protocol.add_transaction_output(
            ACCEPT_PEGIN_TX,
            &OutputType::taproot(amount, &take_aggregated_key, &[])?,
        )?;

        // FIXME: This should be created in the dispute core protocol. It was created here just to reference it.
        self.create_reimbursement_kickoff_tx_tmp(&mut protocol, take_aggregated_key)?;

        // Operator take transactions
        // Loop over operators and create take 1 and take 2 transactions
        for (index, take_pubkey) in take_pubkeys.iter().enumerate() {
            self.create_operator_take_transaction(
                &mut protocol,
                index as u32,
                amount,
                take_pubkey,
                take_aggregated_key,
                pegin_request_txid,
                reimbursement_kickoff_txid,
            )?;

            // self.create_operator_won_transaction(
            //     &mut protocol,
            //     index as u32,
            //     amount,
            //     take_pubkey,
            //     pegin_request_txid,
            // reimbursement_kickoff_tx
            // )?;
        }

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

    fn take_pubkeys(&self, context: &ProgramContext) -> Result<Vec<PublicKey>, BitVMXError> {
        let take_keys_json = context
            .globals
            .get_var(&self.ctx.id, OPERATOR_TAKE_KEYS)?
            .unwrap()
            .string()?;

        let take_keys: Vec<PublicKey> = serde_json::from_str(&take_keys_json)?;
        Ok(take_keys)
    }

    fn reimbursement_kickoff_txid(&self, context: &ProgramContext) -> Result<Txid, BitVMXError> {
        let txid_str = context
            .globals
            .get_var(&self.ctx.id, REIMBURSEMENT_KICKOFF_TXID)?
            .unwrap()
            .string()?;

        // TODO: Fix this error handling
        let txid = Txid::from_str(&txid_str)
            .map_err(|e| BitVMXError::InvalidVariableType(format!("Invalid Txid: {e}")))?;
        Ok(txid)
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
                // TODO send sighash of the transaction
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

    fn create_operator_take_transaction(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        index: u32,
        amount: u64,
        take_pubkey: &PublicKey,
        take_aggregated_key: &PublicKey,
        pegin_txid: Txid,
        reimbursement_kickoff_tx: Txid,
    ) -> Result<(), BitVMXError> {
        let operator_take_tx_name = &format!("operator_take_{}", index);
        // protocol.add_transaction(operator_take_tx_name)?;

        // Pegin input
        self.add_accept_pegin_connection(
            protocol,
            format!("from_accept_pegin_output"),
            operator_take_tx_name,
            pegin_txid,
        )?;

        // Input All takes enabler
        self.add_all_takes_enabler_input(
            protocol,
            take_aggregated_key,
            operator_take_tx_name,
            reimbursement_kickoff_tx,
        )?;

        // // Input from reimbursement kickoff with timelock
        self.add_reimbursement_kickoff_timelock_input(protocol, operator_take_tx_name)?;

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
        take_aggregated_key: &PublicKey,
        pegin_txid: Txid,
        reimbursement_kickoff_txid: Txid,
    ) -> Result<(), BitVMXError> {
        // Operator won transaction
        let operator_won_tx_name = &format!("operator_won_{}", index);
        // protocol.add_transaction(operator_won_tx_name)?;

        // Pegin input
        self.add_accept_pegin_connection(
            protocol,
            format!("operator_won_{}_connection", index),
            operator_won_tx_name,
            pegin_txid,
        )?;

        // Input All takes enabler
        self.add_all_takes_enabler_input(
            protocol,
            take_aggregated_key,
            operator_won_tx_name,
            reimbursement_kickoff_txid,
        )?;

        // Input from try take 2 with timelock
        self.add_try_take_2_timelock_input(protocol, operator_won_tx_name)?;

        // Operator Output
        // TODO: Modify amount based on Miro
        self.add_operator_output(protocol, operator_won_tx_name, amount, take_pubkey)?;

        Ok(())
    }

    fn add_accept_pegin_connection(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        connection_name: String,
        operator_take_tx_name: &str,
        pegin_txid: Txid,
    ) -> Result<(), BitVMXError> {
        protocol.add_connection(
            &connection_name,
            ACCEPT_PEGIN_TX,
            OutputSpec::Index(0),
            operator_take_tx_name,
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
        take_aggregated_key: &PublicKey,
        tx_name: &str,
        reimbursement_kickoff_txid: Txid,
    ) -> Result<(), BitVMXError> {
        protocol.add_connection(
            "reimbursement_kickoff_all_takes_enabler",
            REIMBURSEMENT_KICKOFF_TX,
            0.into(),
            tx_name,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(reimbursement_kickoff_txid),
        )?;
        Ok(())
    }

    fn add_reimbursement_kickoff_timelock_input(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        // TODO: Replace with actual REIMBURSEMENT_KICKOFF_TX UTXO reference
        protocol.add_connection(
            "reimbursement_kickoff_timelock_connection",
            REIMBURSEMENT_KICKOFF_TX,
            1.into(),
            tx_name,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;
        Ok(())
    }

    fn add_try_take_2_timelock_input(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        // TODO: Replace with actual TRY_TAKE_2_TX UTXO reference
        protocol.add_transaction_input(
            Hash::all_zeros(),
            0, // Hardcoded output index for try take 2
            tx_name,
            Sequence::ENABLE_LOCKTIME_NO_RBF,
            &SpendMode::Script { leaf: 0 },
            &SighashType::taproot_all(),
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

    pub fn create_reimbursement_kickoff_tx_tmp(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        take_aggregated_key: &PublicKey,
    ) -> Result<(), BitVMXError> {
        protocol.add_transaction(REIMBURSEMENT_KICKOFF_TX)?;

        // Add the REIMBURSEMENT_KICKOFF_TX connections
        // Connection to prevent the take transactions to occur (No Take)
        protocol.add_transaction_output(
            REIMBURSEMENT_KICKOFF_TX,
            &OutputType::taproot(
                DUST_VALUE,
                &take_aggregated_key,
                &[], //&vec![value_0_script, value_1_script],
            )?,
        )?;

        //CHALLENGE_TX connection (T)
        // TODO review the SpendMode
        protocol.add_transaction_output(
            REIMBURSEMENT_KICKOFF_TX,
            &OutputType::taproot(
                DUST_VALUE,
                &take_aggregated_key,
                &[], //&vec![value_0_script, value_1_script],
            )?,
        )?;
        Ok(())
    }
}
