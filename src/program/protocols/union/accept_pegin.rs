use std::collections::HashMap;

use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{
                common::{
                    create_transaction_reference, extract_index, get_dispute_core_pid,
                    get_operator_output_type, indexed_name,
                },
                types::{
                    Committee, PegInAccepted, PegInRequest, ACCEPT_PEGIN_TX,
                    DISPUTE_CORE_LONG_TIMELOCK, LAST_OPERATOR_TAKE_UTXO, OPERATOR_LEAF_INDEX,
                    OPERATOR_TAKE_ENABLER, OPERATOR_TAKE_TX, OPERATOR_WON_ENABLER, OPERATOR_WON_TX,
                    P2TR_FEE, REIMBURSEMENT_KICKOFF_TX, REQUEST_PEGIN_TX, REVEAL_IN_PROGRESS,
                    SPEEDUP_KEY, SPEEDUP_VALUE,
                },
            },
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::{OutgoingBitVMXApiMessages, ProgramContext},
};
use bitcoin::{hex::FromHex, PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    graph::graph::GraphOptions,
    scripts::{op_return_script, timelock, ProtocolScript, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::{MessageId, SpeedupData},
        InputArgs, OutputType, Utxo,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
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
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let speedup_key = program_context.key_chain.derive_keypair()?;
        let mut keys = vec![];

        keys.push((
            SPEEDUP_KEY.to_string(),
            PublicKeyType::Public(speedup_key.clone()),
        ));

        program_context.globals.set_var(
            &self.ctx.id,
            SPEEDUP_KEY,
            VariableTypes::PubKey(speedup_key),
        )?;

        Ok(ParticipantKeys::new(keys, vec![]))
    }

    fn build(
        &self,
        keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let pegin_request: PegInRequest = self.pegin_request(context)?;
        let pegin_request_txid = pegin_request.txid;
        let mut user_output_amount = self.checked_sub(pegin_request.amount, P2TR_FEE)?;
        user_output_amount = self.checked_sub(user_output_amount, SPEEDUP_VALUE)?;

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

        let accept_pegin_output =
            OutputType::taproot(user_output_amount, &take_aggregated_key, &[])?;
        protocol.add_transaction_output(ACCEPT_PEGIN_TX, &accept_pegin_output)?;

        // Speed up transaction (User pay for it)
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(
            &mut protocol,
            ACCEPT_PEGIN_TX,
            SPEEDUP_VALUE,
            &pegin_request.reimbursement_pubkey,
        )?;

        let members = self.committee(context, pegin_request.committee_id)?.members;

        // Loop over operators and create take 1 and take 2 transactions
        for operator_index in pegin_request.operator_indexes {
            let take_key = members[operator_index].take_key;
            let dispute_key = members[operator_index].dispute_key;
            let speedup_key = keys[operator_index].get_public(SPEEDUP_KEY)?;

            let dispute_protocol_id = get_dispute_core_pid(pegin_request.committee_id, &take_key);

            // Operator take transaction data
            let operator_take_enabler =
                self.operator_take_enabler(context, dispute_protocol_id, pegin_request.slot_index)?;
            let kickoff_tx_name = &indexed_name(REIMBURSEMENT_KICKOFF_TX, operator_index);

            // Create kickoff transaction reference
            create_transaction_reference(
                &mut protocol,
                kickoff_tx_name,
                &mut vec![operator_take_enabler.clone()],
            )?;

            self.create_operator_take_transaction(
                &mut protocol,
                operator_index,
                user_output_amount,
                &dispute_key,
                speedup_key,
                pegin_request_txid,
                kickoff_tx_name,
                operator_take_enabler.clone(),
            )?;

            // Operator won transaction data
            let operator_won_enabler =
                self.operator_won_enabler(context, dispute_protocol_id, pegin_request.slot_index)?;
            let reveal_tx_name = &format!("REVEAL_TX_OP_{}", operator_index);

            // Create won enabler transaction reference
            create_transaction_reference(
                &mut protocol,
                reveal_tx_name,
                &mut vec![operator_won_enabler.clone()],
            )?;

            self.create_operator_won_transaction(
                &mut protocol,
                operator_index,
                user_output_amount,
                &dispute_key,
                speedup_key,
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
        context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        let tx_name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Accept Pegin protocol for slot {} received news of transaction: {}, txid: {} with {} confirmations",
            self.pegin_request(context)?.slot_index, tx_name, tx_id, tx_status.confirmations
        );

        if tx_name.starts_with(OPERATOR_TAKE_TX) || tx_name.starts_with(OPERATOR_WON_TX) {
            let operator_index = match tx_name.clone() {
                name if name.starts_with(OPERATOR_TAKE_TX) => {
                    extract_index(&tx_name.clone(), OPERATOR_TAKE_TX)?
                }
                name if name.starts_with(OPERATOR_WON_TX) => {
                    extract_index(&tx_name.clone(), OPERATOR_WON_TX)?
                }
                _ => {
                    return Err(BitVMXError::InvalidTransactionName(format!(
                        "{} is not supported to call update_operator_take_utxo",
                        tx_name
                    )));
                }
            };

            if tx_name.starts_with(OPERATOR_WON_TX) {
                self.clean_reveal_in_progress(context, operator_index)?;
            }

            if operator_index == self.ctx.my_idx {
                // Both, OPERATOR_TAKE_TX and OPERATOR_WON_TX, have the same output index to reimburse funds to the operator
                let output_index: u32 = 0;
                let amount = tx_status.tx.output[output_index as usize].value.to_sat();
                let utxo = (
                    tx_id,
                    output_index,
                    Some(amount),
                    Some(get_operator_output_type(
                        &self.my_dispute_key(context)?,
                        amount,
                    )?),
                );

                self.update_operator_take_utxo(context, utxo)?;
            }
        }

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

        let message_id = MessageId::new_string_id(ACCEPT_PEGIN_TX, 0, 2); // 2 corresponds to key spend (it's equal to scripts_len())
        let nonce = context.key_chain.get_nonce(
            &take_aggregated_key,
            &self.ctx.protocol_name,
            &message_id,
        )?;

        let signature = context.key_chain.get_signature(
            &take_aggregated_key,
            &self.ctx.protocol_name,
            &message_id,
        )?;

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

        let accept_pegin_sighash = protocol
            .get_hashed_message(ACCEPT_PEGIN_TX, 0, 2)?
            .unwrap()
            .as_ref()
            .to_vec();

        let pegin_accepted = PegInAccepted {
            committee_id: pegin_request.committee_id,
            accept_pegin_txid,
            accept_pegin_sighash,
            accept_pegin_nonce: nonce,
            accept_pegin_signature: signature,
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
        context
            .broker_channel
            .send(&context.components_config.l2, data)?;

        Ok(())
    }

    fn create_operator_take_transaction(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        operator_index: usize,
        accept_pegin_output_amount: u64,
        dispute_key: &PublicKey,
        speedup_key: &PublicKey,
        pegin_txid: Txid,
        kickoff_tx_name: &str,
        take_enabler: PartialUtxo,
    ) -> Result<(), BitVMXError> {
        let operator_take_tx_name = &indexed_name(OPERATOR_TAKE_TX, operator_index);

        // Pegin input
        self.add_accept_pegin_connection(protocol, operator_take_tx_name, pegin_txid)?;

        let operator_input_amount = accept_pegin_output_amount + take_enabler.2.unwrap();
        let operator_output_amount =
            self.checked_sub(operator_input_amount, P2TR_FEE + SPEEDUP_VALUE)?;

        protocol.add_connection(
            "take_enabler_conn",
            kickoff_tx_name,
            OutputSpec::Index(take_enabler.1 as usize),
            operator_take_tx_name,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::None),
            Some(DISPUTE_CORE_LONG_TIMELOCK),
            Some(take_enabler.0),
        )?;

        // Operator Output
        self.add_operator_output(
            protocol,
            operator_take_tx_name,
            operator_output_amount,
            dispute_key,
        )?;

        // Speed up transaction (Operator pay for it)
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(protocol, operator_take_tx_name, SPEEDUP_VALUE, &speedup_key)?;

        Ok(())
    }

    fn create_operator_won_transaction(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        operator_index: usize,
        accept_pegin_output_amount: u64,
        dispute_key: &PublicKey,
        speedup_key: &PublicKey,
        pegin_txid: Txid,
        reveal_tx_name: &str,
        won_enabler: PartialUtxo,
    ) -> Result<(), BitVMXError> {
        // Operator won transaction
        let operator_won_tx_name = &indexed_name(OPERATOR_WON_TX, operator_index);

        // Pegin input
        self.add_accept_pegin_connection(protocol, operator_won_tx_name, pegin_txid)?;

        let operator_input_amount = accept_pegin_output_amount + won_enabler.2.unwrap();
        let operator_output_amount =
            self.checked_sub(operator_input_amount, P2TR_FEE + SPEEDUP_VALUE)?;

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

        // Operator Output
        self.add_operator_output(
            protocol,
            operator_won_tx_name,
            operator_output_amount,
            dispute_key,
        )?;

        // Speed up transaction (Operator pay for it)
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(protocol, operator_won_tx_name, SPEEDUP_VALUE, &speedup_key)?;

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
        dispute_key: &PublicKey,
    ) -> Result<(), BitVMXError> {
        protocol
            .add_transaction_output(tx_name, &get_operator_output_type(dispute_key, amount)?)?;

        Ok(())
    }

    fn accept_pegin_tx(&self) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
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

    fn operator_take_tx(
        &self,
        context: &ProgramContext,
        name: &str,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        let op_leaf_index = self.operator_leaf_index(context)?;

        info!(
            id = self.ctx.my_idx,
            "Loading {} for AcceptPegInProtocol. Name: {}. Op leaf index: {}",
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

        let txid = tx.compute_txid();

        let speedup_key = self.my_speedup_key(context)?;
        let speedup_vout = (tx.output.len() - 1) as u32;
        let speedup_utxo = Utxo::new(txid, speedup_vout, SPEEDUP_VALUE, &speedup_key);

        Ok((tx, Some(speedup_utxo.into())))
    }

    fn operator_leaf_index(&self, context: &ProgramContext) -> Result<usize, BitVMXError> {
        Ok(context
            .globals
            .get_var(&self.ctx.id, OPERATOR_LEAF_INDEX)?
            .unwrap()
            .number()? as usize)
    }

    fn operator_won_tx(
        &self,
        context: &ProgramContext,
        name: &str,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(
            id = self.ctx.my_idx,
            "Loading {} for AcceptPegInProtocol. Name: {}", OPERATOR_WON_TX, name
        );
        let args = InputArgs::new_taproot_key_args();
        // TODO: add the necessary arguments to args
        let tx = self.load_protocol()?.transaction_to_send(name, &[args])?;
        let txid = tx.compute_txid();

        let speedup_key = self.my_speedup_key(context)?;
        let speedup_vout = (tx.output.len() - 1) as u32;
        let speedup_utxo = Utxo::new(txid, speedup_vout, SPEEDUP_VALUE, &speedup_key);

        Ok((tx, Some(speedup_utxo.into())))
    }

    fn request_pegin_leaves(
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

    fn my_speedup_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        Ok(context
            .globals
            .get_var(&self.ctx.id, SPEEDUP_KEY)?
            .unwrap()
            .pubkey()?)
    }

    fn update_operator_take_utxo(
        &self,
        context: &ProgramContext,
        utxo: PartialUtxo,
    ) -> Result<(), BitVMXError> {
        info!(
            id = self.ctx.my_idx,
            "Updating operator take UTXO for AcceptPegInProtocol: {:?}", utxo
        );
        context.globals.set_var(
            &self.pegin_request(context)?.committee_id,
            &LAST_OPERATOR_TAKE_UTXO,
            VariableTypes::Utxo(utxo),
        )?;
        Ok(())
    }

    fn my_dispute_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        let committee = self.committee(context, self.pegin_request(context)?.committee_id)?;
        Ok(committee.members[self.ctx.my_idx].dispute_key.clone())
    }

    fn clean_reveal_in_progress(
        &self,
        context: &ProgramContext,
        operator_index: usize,
    ) -> Result<(), BitVMXError> {
        let request = self.pegin_request(context)?;
        let operator_take_key =
            self.committee(context, request.committee_id)?.members[operator_index].take_key;

        let dispute_protocol_id = get_dispute_core_pid(request.committee_id, &operator_take_key);

        let reveal_in_progress = self.get_reveal_in_progress(context, dispute_protocol_id)?;

        if reveal_in_progress.is_none() {
            warn!(
                id = self.ctx.my_idx,
                "Not cleaning {} for dispute protocol: {}. It was already empty and current request is for slot_index: {}",
                REVEAL_IN_PROGRESS,
                dispute_protocol_id,
                request.slot_index
            );
            return Ok(());
        }

        if reveal_in_progress == Some(request.slot_index as u32) {
            context
                .globals
                .unset_var(&dispute_protocol_id, REVEAL_IN_PROGRESS)?;

            info!(
                id = self.ctx.my_idx,
                "Cleaned {} for dispute protocol: {}", REVEAL_IN_PROGRESS, dispute_protocol_id
            );
        } else {
            warn!(
                id = self.ctx.my_idx,
                "Not cleaning {} for dispute protocol: {}. It is set to slot_index: {} and current request is for slot_index: {}",
                REVEAL_IN_PROGRESS,
                dispute_protocol_id,
                reveal_in_progress.unwrap(),
                request.slot_index
            );
        }

        Ok(())
    }

    fn get_reveal_in_progress(
        &self,
        program_context: &ProgramContext,
        protocol_id: Uuid,
    ) -> Result<Option<u32>, BitVMXError> {
        match program_context
            .globals
            .get_var(&protocol_id, REVEAL_IN_PROGRESS)?
        {
            Some(var) => Ok(Some(var.number()?)),
            None => Ok(None),
        }
    }
}
