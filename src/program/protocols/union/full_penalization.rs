use core::convert::Into;
use std::collections::HashMap;

use bitcoin::{Amount, PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    graph::graph::GraphOptions,
    scripts::{ProtocolScript, SignMode},
    types::{
        connection::InputSpec,
        input::{SighashType, SpendMode},
        output::SpeedupData,
        InputArgs, OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{
                common::{
                    create_transaction_reference, double_indexed_name, get_dispute_core_pid,
                    get_initial_deposit_output_type, indexed_name, triple_indexed_name,
                },
                types::{
                    Committee, FullPenalizationData, DISPUTE_AGGREGATED_KEY,
                    DISPUTE_CORE_SHORT_TIMELOCK, DUST_VALUE, OPERATOR_TAKE_ENABLER,
                    OP_DISABLER_DIRECTORY_TX, OP_DISABLER_DIRECTORY_UTXO, OP_DISABLER_TX,
                    OP_INITIAL_DEPOSIT_AMOUNT, OP_INITIAL_DEPOSIT_OUT_SCRIPT,
                    OP_INITIAL_DEPOSIT_TX, OP_INITIAL_DEPOSIT_TXID, OP_LAZY_DISABLER_TX,
                    REIMBURSEMENT_KICKOFF_TX, SPEEDUP_VALUE, WT_DISABLER_DIRECTORY_TX,
                    WT_DISABLER_TX, WT_START_ENABLER_UTXOS,
                },
            },
        },
        variables::PartialUtxo,
    },
    types::ProgramContext,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct FullPenalizationProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for FullPenalizationProtocol {
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
        let data = self.full_penalization_data(context)?;
        let committee = self.committee(context, data.committee_id)?;

        Ok(vec![(
            DISPUTE_AGGREGATED_KEY.to_string(),
            committee.dispute_aggregated_key,
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
        info!(
            "Building Full Penalization Protocol for program {}",
            self.ctx.id
        );

        let data: FullPenalizationData = self.full_penalization_data(context)?;
        let committee = self.committee(context, data.committee_id)?;
        let mut protocol = self.load_or_create_protocol();

        // Create Operator disabler directory and disablers
        self.create_operator_disablers(&mut protocol, &committee, &data, context)?;

        self.create_watchtower_disablers(&mut protocol, &committee, &data, context)?;

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
        if name.starts_with(OP_LAZY_DISABLER_TX) {
            Ok(self.op_lazy_disabler_tx(name, context)?)
        } else if name.starts_with(OP_DISABLER_TX) {
            Ok(self.op_disabler_tx(name, context)?)
        } else if name.starts_with(OP_DISABLER_DIRECTORY_TX) {
            Ok(self.op_disabler_directory_tx(name, context)?)
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
            "Full Penalization protocol received news of transaction: {}, txid: {} with {} confirmations",
            tx_name, tx_id, tx_status.confirmations
        );

        Ok(())
    }

    fn setup_complete(&self, _context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            "FullPenalizationProtocol setup complete for program {}",
            self.ctx.id
        );

        Ok(())
    }
}

impl FullPenalizationProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn full_penalization_data(
        &self,
        context: &ProgramContext,
    ) -> Result<FullPenalizationData, BitVMXError> {
        let request = context
            .globals
            .get_var(&self.ctx.id, &FullPenalizationData::name())?
            .unwrap()
            .string()?;

        let data: FullPenalizationData = serde_json::from_str(&request)?;
        Ok(data)
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

    fn op_initial_deposit_txid(
        &self,
        context: &ProgramContext,
        dispute_core_pid: Uuid,
    ) -> Result<Txid, BitVMXError> {
        let txid = context
            .globals
            .get_var(&dispute_core_pid, OP_INITIAL_DEPOSIT_TXID)?
            .unwrap()
            .string()?
            .parse::<Txid>()
            .map_err(|e| {
                BitVMXError::InvalidVariableType(format!("Failed to parse txid from string: {}", e))
            })?;
        Ok(txid)
    }

    fn op_initial_deposit_amount(
        &self,
        context: &ProgramContext,
        dispute_core_pid: Uuid,
    ) -> Result<u64, BitVMXError> {
        let amount = context
            .globals
            .get_var(&dispute_core_pid, OP_INITIAL_DEPOSIT_AMOUNT)?
            .unwrap()
            .amount()?;
        Ok(amount)
    }

    fn op_initial_deposit_out_scripts(
        &self,
        context: &ProgramContext,
        dispute_core_pid: Uuid,
        slot_index: usize,
    ) -> Result<Vec<ProtocolScript>, BitVMXError> {
        let data = context
            .globals
            .get_var(
                &dispute_core_pid,
                &indexed_name(OP_INITIAL_DEPOSIT_OUT_SCRIPT, slot_index),
            )?
            .unwrap()
            .string()?;

        let scripts: Vec<ProtocolScript> = serde_json::from_str(&data)?;
        Ok(scripts)
    }

    fn wt_start_enabler_utxos(
        &self,
        context: &ProgramContext,
        dispute_core_pid: Uuid,
    ) -> Result<Vec<PartialUtxo>, BitVMXError> {
        let data = context
            .globals
            .get_var(&dispute_core_pid, &WT_START_ENABLER_UTXOS)?
            .unwrap()
            .string()?;

        let utxos: Vec<PartialUtxo> = serde_json::from_str(&data)?;
        Ok(utxos)
    }

    fn create_operator_disabler(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        committee: &Committee,
        operator_index: usize,
        watchtower_index: usize,
        initial_deposit_name: &str,
        disabler_directory_utxo: &PartialUtxo,
        take_enablers: &Vec<PartialUtxo>,
        initial_deposit_utxos: &Vec<PartialUtxo>,
    ) -> Result<(), BitVMXError> {
        let packet_size = committee.packet_size;
        let op_disabler_directory_name =
            double_indexed_name(OP_DISABLER_DIRECTORY_TX, operator_index, watchtower_index);

        protocol.add_connection(
            "funds",
            &initial_deposit_name,
            (disabler_directory_utxo.1 as usize).into(),
            &op_disabler_directory_name,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(disabler_directory_utxo.0),
        )?;

        for slot_index in 0..packet_size as usize {
            let op_disabler_name =
                triple_indexed_name(OP_DISABLER_TX, operator_index, watchtower_index, slot_index);

            let initial_deposit_utxo = &initial_deposit_utxos[slot_index];

            debug!("{} to {}", initial_deposit_name, op_disabler_name);
            protocol.add_connection(
                "from_initial_deposit",
                &initial_deposit_name,
                (initial_deposit_utxo.1 as usize).into(),
                &op_disabler_name,
                InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
                None,
                Some(initial_deposit_utxo.0),
            )?;

            debug!("{} to {}", op_disabler_directory_name, op_disabler_name);
            protocol.add_connection(
                "from_disabler_directory",
                &op_disabler_directory_name,
                OutputType::taproot(DUST_VALUE, &committee.dispute_aggregated_key, &[])?.into(),
                &op_disabler_name,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::KeyOnly {
                        key_path_sign: SignMode::Aggregate,
                    },
                ),
                None,
                None,
            )?;

            // Output is unspendable. Everything is paid in fees to make sure this TXs is mined.
            // If output goes to challenger WT it could decided no to dispatch or no to speedup it.
            debug!("Output for {}", op_disabler_name);
            protocol.add_transaction_output(
                &op_disabler_name,
                &OutputType::SegwitUnspendable {
                    value: Amount::from_sat(0),
                    script_pubkey: ScriptBuf::new_op_return(&[0u8; 0]),
                },
            )?;

            // Create Lazy Operator disablers
            // Operator take transaction data
            let op_lazy_disabler_name = triple_indexed_name(
                OP_LAZY_DISABLER_TX,
                operator_index,
                watchtower_index,
                slot_index,
            );
            let take_enabler = take_enablers[slot_index].clone();

            debug!(
                "take enabler index {} to {}",
                slot_index, op_lazy_disabler_name
            );
            protocol.add_connection(
                "reimbursement_kickoff_conn",
                &double_indexed_name(REIMBURSEMENT_KICKOFF_TX, operator_index, slot_index),
                (take_enabler.1 as usize).into(),
                &op_lazy_disabler_name,
                InputSpec::Auto(SighashType::taproot_all(), SpendMode::None),
                Some(DISPUTE_CORE_SHORT_TIMELOCK),
                Some(take_enabler.0),
            )?;

            debug!(
                "{} to {}",
                op_disabler_directory_name, op_lazy_disabler_name
            );
            protocol.add_connection(
                "from_disabler_directory",
                &op_disabler_directory_name,
                slot_index.into(),
                &op_lazy_disabler_name,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::KeyOnly {
                        key_path_sign: SignMode::Aggregate,
                    },
                ),
                None,
                None,
            )?;

            // Output is unspendable. Everything is paid in fees to make sure this TXs is mined.
            // If output goes to challenger WT it could decided no to dispatch or no to speedup it.
            debug!("Output for {}", op_lazy_disabler_name);
            protocol.add_transaction_output(
                &op_lazy_disabler_name,
                &OutputType::SegwitUnspendable {
                    value: Amount::from_sat(0),
                    script_pubkey: ScriptBuf::new_op_return(&[0u8; 0]),
                },
            )?;
        }

        // Maybe this speedup here could be removed.
        // Right not it's needed to make all disable directory tx different, if not they all have same txid for a particular operator.
        // Soon they will be connected to dispute channels
        protocol.add_transaction_output(
            &op_disabler_directory_name,
            &OutputType::segwit_key(
                SPEEDUP_VALUE,
                &committee.members[watchtower_index].dispute_key,
            )?,
        )?;

        Ok(())
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

    fn disabler_directory_utxo(
        &self,
        context: &ProgramContext,
        dispute_protocol_id: Uuid,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(&dispute_protocol_id, &OP_DISABLER_DIRECTORY_UTXO)?
            .unwrap()
            .utxo()?)
    }

    fn op_lazy_disabler_tx(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        // NOTE: OP_LAZY_DISABLER_TX_<OP>_<WT>_<SLOT> it's tied to:
        // - Operator index
        // - Watchtower index
        // - Slot
        // Here watchtower index it's ignored and it dispatch the TX corresponding to
        // current member, due to it should sign the output script leaf in the reimbursement kickoff.
        info!(id = self.ctx.my_idx, "Loading {} tx", name);

        let mut protocol = self.load_protocol()?;
        let my_index = self.ctx.my_idx;

        let kickoff_sig = protocol.sign_taproot_input(
            name,
            0,
            &SpendMode::Script {
                leaf: my_index as usize,
            },
            context.key_chain.key_manager.as_ref(),
            "",
        )?;
        let mut kickoff_input = InputArgs::new_taproot_script_args(my_index);
        kickoff_input.push_taproot_signature(kickoff_sig[my_index].unwrap())?;

        let directory_sig = protocol
            .input_taproot_key_spend_signature(name, 1)?
            .unwrap();
        let mut directory_input = InputArgs::new_taproot_key_args();
        directory_input.push_taproot_signature(directory_sig)?;

        let tx = protocol.transaction_to_send(&name, &[kickoff_input, directory_input])?;

        let txid = tx.compute_txid();
        info!(
            id = my_index,
            "Signed {}, txid: {} with signatures: [{:?},{:?}]",
            name,
            txid,
            kickoff_sig,
            directory_sig
        );

        Ok((tx, None))
    }

    fn op_disabler_tx(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} tx", name);

        let protocol = self.load_protocol()?;

        // Operator inital deposit signature through script path
        let op_deposit_script_index = 1;
        let mut op_deposit_input = InputArgs::new_taproot_script_args(op_deposit_script_index);
        let op_initial_deposit_sig = protocol
            .input_taproot_script_spend_signature(name, 0, op_deposit_script_index)?
            .unwrap();
        op_deposit_input.push_taproot_signature(op_initial_deposit_sig)?;

        // Directory key spend signature
        let directory_sig = protocol
            .input_taproot_key_spend_signature(name, 1)?
            .unwrap();
        let mut directory_input = InputArgs::new_taproot_key_args();
        directory_input.push_taproot_signature(directory_sig)?;

        let tx = protocol.transaction_to_send(&name, &[op_deposit_input, directory_input])?;

        info!(
            id = self.ctx.my_idx,
            "Signed {}, txid: {} with signatures: [{:?},{:?}]",
            name,
            tx.compute_txid(),
            op_initial_deposit_sig,
            directory_sig
        );

        Ok((tx, None))
    }

    fn op_disabler_directory_tx(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} tx", name);

        let protocol = self.load_protocol()?;
        let my_index = self.ctx.my_idx;

        let op_initial_deposit_sig = protocol
            .input_taproot_key_spend_signature(name, 0)?
            .unwrap();
        let mut op_initial_deposit_input = InputArgs::new_taproot_key_args();
        op_initial_deposit_input.push_taproot_signature(op_initial_deposit_sig)?;

        let tx = protocol.transaction_to_send(&name, &[op_initial_deposit_input])?;

        let txid = tx.compute_txid();
        info!(
            id = my_index,
            "Signed {} with txid: {} with signatures: [{:?}] ", name, txid, op_initial_deposit_sig,
        );

        Ok((tx, None))
    }

    fn create_operator_disablers(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        committee: &Committee,
        data: &FullPenalizationData,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let member_count = committee.members.len();
        for operator_index in 0..member_count {
            if committee.members[operator_index].role != ParticipantRole::Prover {
                debug!("Skipping member {} as it is not a prover", operator_index);
                continue;
            }

            let (
                initial_deposit_name,
                disabler_directory_utxo,
                take_enablers,
                initial_deposit_utxos,
            ) = self.create_op_initial_deposit_tx(
                protocol,
                operator_index,
                data.committee_id,
                committee,
                context,
            )?;

            for watchtower_index in 0..member_count {
                if operator_index == watchtower_index {
                    continue;
                }

                debug!(
                    "Creating operator disabler for operator {} with watchtower {}",
                    operator_index, watchtower_index
                );

                self.create_operator_disabler(
                    protocol,
                    &committee,
                    operator_index,
                    watchtower_index,
                    &initial_deposit_name,
                    &disabler_directory_utxo,
                    &take_enablers,
                    &initial_deposit_utxos,
                )?;
            }
        }
        Ok(())
    }

    fn create_op_initial_deposit_tx(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        operator_index: usize,
        committee_id: Uuid,
        committee: &Committee,
        context: &ProgramContext,
    ) -> Result<(String, PartialUtxo, Vec<PartialUtxo>, Vec<PartialUtxo>), BitVMXError> {
        let dispute_core_pid =
            get_dispute_core_pid(committee_id, &committee.members[operator_index].take_key);

        let disabler_directory_utxo = self.disabler_directory_utxo(context, dispute_core_pid)?;

        let amount = self.op_initial_deposit_amount(context, dispute_core_pid)?;
        let op_initial_deposit_txid = self.op_initial_deposit_txid(context, dispute_core_pid)?;

        let mut take_enablers: Vec<PartialUtxo> = vec![];
        let mut initial_deposit_utxos: Vec<PartialUtxo> = vec![];

        for slot_index in 0..committee.packet_size as usize {
            // Load reimbursement take enablers for the operator and create TX reference just once.
            let take_enabler = self.operator_take_enabler(context, dispute_core_pid, slot_index)?;
            take_enablers.push(take_enabler.clone());

            create_transaction_reference(
                protocol,
                &double_indexed_name(REIMBURSEMENT_KICKOFF_TX, operator_index, slot_index),
                &mut vec![take_enabler],
            )?;

            let scripts =
                self.op_initial_deposit_out_scripts(context, dispute_core_pid, slot_index)?;

            let output_type = get_initial_deposit_output_type(
                amount,
                &committee.members[operator_index].dispute_key,
                scripts.as_slice(),
            )?;

            // Load initial deposit UTXOs and create TX reference just once.
            initial_deposit_utxos.push((
                op_initial_deposit_txid,
                slot_index as u32,
                Some(amount),
                Some(output_type),
            ));
        }

        initial_deposit_utxos.push(disabler_directory_utxo.clone());

        let initial_deposit_name = indexed_name(OP_INITIAL_DEPOSIT_TX, operator_index);
        create_transaction_reference(protocol, &initial_deposit_name, &mut initial_deposit_utxos)?;

        Ok((
            initial_deposit_name,
            disabler_directory_utxo,
            take_enablers,
            initial_deposit_utxos,
        ))
    }

    fn create_watchtower_disablers(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        committee: &Committee,
        data: &FullPenalizationData,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let member_count = committee.members.len();

        for wt_index in 0..member_count {
            let dispute_core_pid =
                get_dispute_core_pid(data.committee_id, &committee.members[wt_index].take_key);

            let wt_start_enabler_utxos = self.wt_start_enabler_utxos(context, dispute_core_pid)?;
            let wt_start_enabler_name = indexed_name(WT_START_ENABLER_UTXOS, wt_index);
            create_transaction_reference(
                protocol,
                &wt_start_enabler_name,
                &mut wt_start_enabler_utxos.clone(),
            )?;

            for op_index in 0..member_count {
                if wt_index == op_index
                    || committee.members[op_index].role != ParticipantRole::Prover
                {
                    continue;
                }
                debug!(
                    "Creating watchtower disabler for watchtower {} with member {}",
                    wt_index, op_index
                );

                let wt_disabler_directory_name =
                    double_indexed_name(WT_DISABLER_DIRECTORY_TX, wt_index, op_index);

                let disabler_directory_utxo = wt_start_enabler_utxos[member_count].clone();

                // Funds input
                protocol.add_connection(
                    "funds",
                    &wt_start_enabler_name,
                    (disabler_directory_utxo.1 as usize).into(),
                    &wt_disabler_directory_name,
                    InputSpec::Auto(
                        SighashType::taproot_all(),
                        SpendMode::All {
                            key_path_sign: SignMode::Aggregate,
                        },
                    ),
                    None,
                    Some(disabler_directory_utxo.0),
                )?;

                // TODO: Add input from dispute channel when available

                for member_index in 0..member_count {
                    let wt_disabler_name =
                        triple_indexed_name(WT_DISABLER_TX, wt_index, op_index, member_index);

                    let utxo = wt_start_enabler_utxos[member_index].clone();
                    protocol.add_connection(
                        "from_start_enabler",
                        &wt_start_enabler_name,
                        (utxo.1 as usize).into(),
                        &wt_disabler_name,
                        // First script leaf is the disabler
                        InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
                        None,
                        Some(utxo.0),
                    )?;

                    protocol.add_connection(
                        "from_disabler_directory",
                        &wt_disabler_directory_name,
                        OutputType::taproot(DUST_VALUE, &committee.dispute_aggregated_key, &[])?
                            .into(),
                        &wt_disabler_name,
                        InputSpec::Auto(
                            SighashType::taproot_all(),
                            SpendMode::KeyOnly {
                                key_path_sign: SignMode::Aggregate,
                            },
                        ),
                        None,
                        None,
                    )?;
                }
            }
        }

        Ok(())
    }
}
