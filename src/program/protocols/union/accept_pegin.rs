use std::collections::HashMap;

use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{
                common::{create_transaction_reference, get_dispute_core_pid, indexed_name},
                types::{
                    Committee, PegInAccepted, PegInRequest, ACCEPT_PEGIN_TX,
                    DISPUTE_CORE_LONG_TIMELOCK, OPERATOR_LEAF_INDEX, OPERATOR_TAKE_ENABLER,
                    OPERATOR_TAKE_TX, OPERATOR_WON_ENABLER, OPERATOR_WON_TX, P2TR_FEE,
                    REIMBURSEMENT_KICKOFF_TX, REQUEST_PEGIN_TX, SPEED_UP_VALUE,
                },
            },
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::{OutgoingBitVMXApiMessages, ProgramContext, L2_ID},
};
use bitcoin::{hex::FromHex, Amount, PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    graph::graph::GraphOptions,
    scripts::{op_return_script, timelock, ProtocolScript, SignMode},
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
        let pegin_request: PegInRequest = self.pegin_request(context)?;
        let pegin_request_txid = pegin_request.txid;
        let mut amount = self.checked_sub(pegin_request.amount, P2TR_FEE)?;
        amount = self.checked_sub(amount, SPEED_UP_VALUE)?;

        let take_aggregated_key = &pegin_request.take_aggregated_key;

        let mut protocol = self.load_or_create_protocol();

        let leaves = self.request_pegin_leaves(
            pegin_request.amount,
            pegin_request.rootstock_address,
            pegin_request.reimbursement_pubkey,
        )?;

        // External connection from request peg-in to accept peg-in
        protocol.add_connection(
            "accept_pegin_request",
            REQUEST_PEGIN_TX,
            OutputType::taproot(pegin_request.amount, &take_aggregated_key, &leaves)?.into(),
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

        // Speed up transaction (User pay for it)
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(
            &mut protocol,
            ACCEPT_PEGIN_TX,
            SPEED_UP_VALUE,
            &pegin_request.reimbursement_pubkey,
        )?;

        let indexes = self
            .committee(context, pegin_request.committee_id)?
            .indexes_map();

        // Loop over operators and create take 1 and take 2 transactions
        for (index, take_key) in pegin_request.operators_take_key.iter().enumerate() {
            let dispute_protocol_id = get_dispute_core_pid(pegin_request.committee_id, take_key);
            let operator_index = indexes.get(take_key).ok_or(BitVMXError::VariableNotFound(
                pegin_request.committee_id,
                take_key.to_string(),
            ))?;

            // Operator take transaction data
            let operator_take_enabler =
                self.operator_take_enabler(context, dispute_protocol_id, pegin_request.slot_index)?;
            let kickoff_tx_name = &indexed_name(REIMBURSEMENT_KICKOFF_TX, index);

            // Create kickoff transaction reference
            create_transaction_reference(
                &mut protocol,
                kickoff_tx_name,
                &mut vec![operator_take_enabler.clone()],
            )?;

            self.create_operator_take_transaction(
                &mut protocol,
                *operator_index,
                amount,
                take_key,
                pegin_request_txid,
                kickoff_tx_name,
                operator_take_enabler.clone(),
            )?;

            // Operator won transaction data
            let operator_won_enabler =
                self.operator_won_enabler(context, dispute_protocol_id, pegin_request.slot_index)?;
            let reveal_tx_name = &format!("REVEAL_TX_OP_{}", index);

            // Create won enabler transaction reference
            create_transaction_reference(
                &mut protocol,
                reveal_tx_name,
                &mut vec![operator_won_enabler.clone()],
            )?;

            self.create_operator_won_transaction(
                &mut protocol,
                *operator_index,
                amount,
                take_key,
                pegin_request_txid,
                reveal_tx_name,
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
            &indexed_name(ACCEPT_PEGIN_TX, pegin_request.slot_index),
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
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        if name == ACCEPT_PEGIN_TX {
            self.accept_pegin_tx()
        } else if name.starts_with(OPERATOR_TAKE_TX) {
            self.operator_take_tx(context, name)
        } else if name.starts_with(OPERATOR_WON_TX) {
            self.operator_won_tx(context, name)
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
            "Accept Pegin protocol received news of transaction: {}, txid: {} with {} confirmations",
            tx_name, tx_id, tx_status.confirmations
        );
        Ok(())
    }

    fn setup_complete(&self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        let pegin_request: PegInRequest = self.pegin_request(program_context)?;
        let take_aggregated_key = pegin_request.take_aggregated_key;

        self.send_pegin_accepted(&program_context, &take_aggregated_key)?;

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
        slot_index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(
                &dispute_protocol_id,
                &indexed_name(OPERATOR_TAKE_ENABLER, slot_index),
            )?
            .unwrap()
            .utxo()?)
    }

    fn operator_won_enabler(
        &self,
        context: &ProgramContext,
        dispute_protocol_id: Uuid,
        slot_index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(
                &dispute_protocol_id,
                &indexed_name(OPERATOR_WON_ENABLER, slot_index),
            )?
            .unwrap()
            .utxo()?)
    }

    fn send_pegin_accepted(
        &self,
        context: &ProgramContext,
        take_aggregated_key: &PublicKey,
    ) -> Result<(), BitVMXError> {
        let pegin_request: PegInRequest = self.pegin_request(context)?;

        let nonces = context
            .key_chain
            .get_nonces(&take_aggregated_key, &self.ctx.protocol_name)?;

        if nonces.is_empty() {
            return Err(BitVMXError::MissingPublicNonces(
                take_aggregated_key.to_string(),
                self.ctx.protocol_name.to_string(),
            ));
        }

        let signatures = context
            .key_chain
            .get_signatures(&take_aggregated_key, &self.ctx.protocol_name)?;

        if signatures.is_empty() {
            return Err(BitVMXError::MissingPartialSignatures(
                take_aggregated_key.to_string(),
                self.ctx.protocol_name.to_string(),
            ));
        }

        let mut protocol = self.load_protocol()?;

        let mut operator_take_sighash = vec![0; 32];
        let mut operator_won_sighash = vec![0; 32];

        // Just send operator take and won sighash if we are a prover
        if self.committee(context, pegin_request.committee_id)?.members[self.ctx.my_idx].role
            == ParticipantRole::Prover
        {
            let operator_take_tx_name = &indexed_name(OPERATOR_TAKE_TX, self.ctx.my_idx);
            operator_take_sighash = protocol
                .get_hashed_message(operator_take_tx_name, 0, 0)?
                .unwrap()
                .as_ref()
                .to_vec();

            let operator_won_tx_name = &indexed_name(OPERATOR_WON_TX, self.ctx.my_idx);
            operator_won_sighash = protocol
                .get_hashed_message(operator_won_tx_name, 0, 0)?
                .unwrap()
                .as_ref()
                .to_vec();
        }

        let accept_pegin_txid = protocol
            .transaction_by_name(ACCEPT_PEGIN_TX)?
            .compute_txid();

        // TODO: verify that the signature we are getting from the array of signatures is the proper one
        // FIXME: Should signatures and nonces array be indexed by self.ctx.my_idx?
        let pegin_accepted = PegInAccepted {
            committee_id: pegin_request.committee_id,
            accept_pegin_txid,
            accept_pegin_nonce: nonces[0].1.clone(),
            accept_pegin_signature: signatures[0].1.clone(),
            operator_take_sighash,
            operator_won_sighash,
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
        context.broker_channel.send(L2_ID, data)?;

        Ok(())
    }

    fn create_operator_take_transaction(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        operator_index: usize,
        amount: u64,
        take_pubkey: &PublicKey,
        pegin_txid: Txid,
        kickoff_tx_name: &str,
        take_enabler: PartialUtxo,
    ) -> Result<(), BitVMXError> {
        let operator_take_tx_name = &indexed_name(OPERATOR_TAKE_TX, operator_index);

        // Pegin input
        self.add_accept_pegin_connection(protocol, operator_take_tx_name, pegin_txid)?;

        protocol.add_connection(
            "take_enabler_conn",
            kickoff_tx_name,
            OutputSpec::Index(take_enabler.1 as usize),
            operator_take_tx_name,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::None),
            Some(DISPUTE_CORE_LONG_TIMELOCK),
            Some(take_enabler.0),
        )?;

        let operator_amount = self.checked_sub(amount, SPEED_UP_VALUE)?;

        // Operator Output
        self.add_operator_output(
            protocol,
            operator_take_tx_name,
            operator_amount,
            take_pubkey,
        )?;

        // Speed up transaction (Operator pay for it)
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(
            protocol,
            operator_take_tx_name,
            SPEED_UP_VALUE,
            &take_pubkey,
        )?;

        Ok(())
    }

    fn create_operator_won_transaction(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        operator_index: usize,
        amount: u64,
        take_pubkey: &PublicKey,
        pegin_txid: Txid,
        reveal_tx_name: &str,
        won_enabler: PartialUtxo,
    ) -> Result<(), BitVMXError> {
        // Operator won transaction
        let operator_won_tx_name = &indexed_name(OPERATOR_WON_TX, operator_index);

        // Pegin input
        self.add_accept_pegin_connection(protocol, operator_won_tx_name, pegin_txid)?;

        // Input from try take 2 with timelock
        protocol.add_connection(
            "reveal_conn",
            reveal_tx_name,
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

        let operator_amount = self.checked_sub(amount, SPEED_UP_VALUE)?;

        // Operator Output
        self.add_operator_output(protocol, operator_won_tx_name, operator_amount, take_pubkey)?;

        // Speed up transaction (Operator pay for it)
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(protocol, operator_won_tx_name, SPEED_UP_VALUE, &take_pubkey)?;

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

    pub fn accept_pegin_tx(&self) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(
            id = self.ctx.my_idx,
            "Loading AcceptPegIn transaction for AcceptPegInProtocol"
        );

        let signature = self
            .load_protocol()?
            .input_taproot_key_spend_signature(ACCEPT_PEGIN_TX, 0)?
            .unwrap();
        let mut taproot_arg = InputArgs::new_taproot_key_args();
        taproot_arg.push_taproot_signature(signature)?;

        let tx = self
            .load_protocol()?
            .transaction_to_send(ACCEPT_PEGIN_TX, &[taproot_arg])?;
        Ok((tx, None))
    }

    pub fn operator_take_tx(
        &self,
        context: &ProgramContext,
        name: &str,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        let op_leaf_index = self.operator_leaf_index(context)?;
        info!(
            id = self.ctx.my_idx,
            "Loading {} tx for AcceptPegInProtocol. Name: {}. Op leaf index: {}",
            OPERATOR_TAKE_TX,
            name,
            op_leaf_index
        );

        let mut protocol: Protocol = self.load_protocol()?;
        let pegin_signature = protocol
            .input_taproot_key_spend_signature(name, 0)?
            .unwrap();

        let reimbursement_signature = protocol.sign_taproot_input(
            name,
            1,
            &SpendMode::Script {
                leaf: op_leaf_index,
            },
            context.key_chain.key_manager.as_ref(),
            "",
        )?;

        let mut accept_pegin_args = InputArgs::new_taproot_key_args();
        accept_pegin_args.push_taproot_signature(pegin_signature)?;

        let mut reimbursement_args = InputArgs::new_taproot_script_args(op_leaf_index);
        reimbursement_args
            .push_taproot_signature(reimbursement_signature[op_leaf_index].unwrap())?;

        let tx = self
            .load_protocol()?
            .transaction_to_send(name, &[accept_pegin_args, reimbursement_args])?;
        Ok((tx, None))
    }

    fn operator_leaf_index(&self, context: &ProgramContext) -> Result<usize, BitVMXError> {
        Ok(context
            .globals
            .get_var(&self.ctx.id, OPERATOR_LEAF_INDEX)?
            .unwrap()
            .number()? as usize)
    }

    pub fn operator_won_tx(
        &self,
        _context: &ProgramContext,
        name: &str,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(
            id = self.ctx.my_idx,
            "Loading {} tx for AcceptPegInProtocol. Name: {}", OPERATOR_WON_TX, name
        );
        let args = InputArgs::new_taproot_key_args();
        // TODO: add the necessary arguments to args
        let tx = self.load_protocol()?.transaction_to_send(name, &[args])?;
        Ok((tx, None))
    }

    pub fn request_pegin_leaves(
        &self,
        amount: u64,
        rootstock_address: String,
        reimbursement_pubkey: PublicKey,
    ) -> Result<Vec<ProtocolScript>, BitVMXError> {
        pub const TIMELOCK_BLOCKS: u16 = 1;

        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(
            Vec::from_hex(&rootstock_address.to_string())
                .unwrap()
                .as_slice(),
        );

        // // Taproot output
        let op_data = [address_bytes.as_slice(), amount.to_be_bytes().as_slice()].concat();
        let script_op_return = op_return_script(op_data)?;
        let script_timelock = timelock(TIMELOCK_BLOCKS, &reimbursement_pubkey, SignMode::Single);

        let leaves = vec![script_timelock, script_op_return];

        Ok(leaves)
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
