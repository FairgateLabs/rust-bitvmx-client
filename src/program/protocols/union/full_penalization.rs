use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use core::convert::Into;
use std::{collections::HashMap, vec};

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use key_manager::winternitz::WinternitzType;
use protocol_builder::{
    graph::graph::GraphOptions,
    scripts::{op_return_script, ProtocolScript, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::SpeedupData,
        OutputType, Utxo,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole},
        protocols::{
            claim::ClaimGate,
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{
                common::{
                    add_speedups, collect_input_signatures, create_transaction_reference,
                    double_indexed_name, extract_double_index, extract_triple_index,
                    get_dispute_core_pid, get_initial_deposit_output_type,
                    get_op_disabler_directory_output_value, indexed_name, save_penalized_member,
                    triple_indexed_name, InputSigningInfo, WinternitzData,
                },
                dispute_core::{
                    CHALLENGE_KEY, OP_INITIAL_DEPOSIT_TX_DISABLER_LEAF,
                    WT_INIT_CHALLENGE_TX_COSIGN_DISABLER_LEAF, WT_START_ENABLER_TX_DISABLER_LEAF,
                },
                dispute_core_claim_gate::CLAIM_GATE_INIT_STOPPER_COMMITTEE_LEAF,
                types::{
                    ClaimInitUtxos, Committee, FullPenalizationData, PacketSettings,
                    PenalizedMember, CLAIM_INIT_TX, CLAIM_INIT_UTXOS, DISPUTE_AGGREGATED_KEY,
                    DUST_VALUE, INPUT_NOT_REVEALED_ENABLER, INPUT_NOT_REVEALED_TX,
                    OPERATOR_TAKE_ENABLER, OPERATOR_WON_ENABLER, OP_CLAIM_GATE_SUCCESS,
                    OP_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO, OP_DISABLER_DIRECTORY_TX,
                    OP_DISABLER_DIRECTORY_UTXO, OP_DISABLER_TX, OP_INITIAL_DEPOSIT_AMOUNT,
                    OP_INITIAL_DEPOSIT_OUT_SCRIPT, OP_INITIAL_DEPOSIT_TX, OP_INITIAL_DEPOSIT_TXID,
                    OP_LAZY_DISABLER_TX, REIMBURSEMENT_KICKOFF_TX, REVEAL_INPUT_TX, SPEEDUP_VALUE,
                    STOPPER_TX, STOP_OP_WON_TX, TAKE_AGGREGATED_KEY, WT_CLAIM_GATE,
                    WT_CLAIM_GATE_SUCCESS, WT_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO,
                    WT_COSIGN_DISABLER_TX, WT_DISABLER_DIRECTORY_TX, WT_DISABLER_DIRECTORY_UTXO,
                    WT_DISABLER_TX, WT_INIT_CHALLENGE_TX, WT_INIT_CHALLENGE_UTXOS,
                    WT_START_ENABLER_TX,
                },
            },
        },
        variables::PartialUtxo,
    },
    types::{ProgramContext, PROGRAM_TYPE_DISPUTE_CORE},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct FullPenalizationProtocol {
    ctx: ProtocolContext,
}

type ClaimInitUtxosByWatchtower = Vec<Vec<Option<ClaimInitUtxos>>>;

impl ProtocolHandler for FullPenalizationProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }

    fn get_pregenerated_aggregated_keys<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        let data = self.full_penalization_data(context)?;
        let committee = self.committee(context, data.committee_id)?;

        Ok(vec![
            (
                DISPUTE_AGGREGATED_KEY.to_string(),
                committee.dispute_aggregated_key,
            ),
            (
                TAKE_AGGREGATED_KEY.to_string(),
                committee.take_aggregated_key,
            ),
        ])
    }

    fn build<BC: BitcoinCoordinatorApi>(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        info!(
            "Building FullPenalizationProtocol for program {}",
            self.ctx.id
        );

        let data: FullPenalizationData = self.full_penalization_data(context)?;
        let committee = self.committee(context, data.committee_id)?;
        self.set_requested_confirmations(context, committee.settings.pegin_confirmations)?;

        let mut protocol = self.load_or_create_protocol();
        let claim_init_utxos =
            self.load_claim_init_utxos(context, &committee, data.committee_id)?;

        // CLAIM_INIT_TX is external to FullPenalization and is consumed by both the watchtower
        // disablers and STOPPER_TX transactions.
        self.create_claim_init_references(&mut protocol, &committee, &claim_init_utxos)?;

        // Create Operator disabler directory and disablers
        self.create_operator_disablers(&mut protocol, &committee, &data, context)?;

        self.create_watchtower_disablers(
            &mut protocol,
            &committee,
            &data,
            context,
            &claim_init_utxos,
        )?;

        self.create_stopper_txs(&mut protocol, &committee, &data, context, &claim_init_utxos)?;

        protocol.build(&context.key_manager, &self.ctx.protocol_name)?;
        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);
        self.save_protocol(protocol)?;
        Ok(())
    }

    fn get_transaction_by_name<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        if name.starts_with(OP_LAZY_DISABLER_TX) {
            Ok(self.op_lazy_disabler_tx(name, context)?)
        } else if name.starts_with(STOPPER_TX) {
            Ok(self.stopper_tx(name)?)
        } else if name.starts_with(OP_DISABLER_TX) {
            Ok(self.op_disabler_tx(name, context)?)
        } else if name.starts_with(WT_DISABLER_TX) {
            Ok(self.wt_disabler_tx(name, context)?)
        } else if name.starts_with(OP_DISABLER_DIRECTORY_TX) {
            Ok(self.disabler_directory_tx(name, context, ParticipantRole::Prover)?)
        } else if name.starts_with(WT_DISABLER_DIRECTORY_TX) {
            Ok(self.disabler_directory_tx(name, context, ParticipantRole::Verifier)?)
        } else if name.starts_with(WT_COSIGN_DISABLER_TX) {
            Ok(self.wt_cosign_disabler_tx(name, context)?)
        } else {
            Err(BitVMXError::InvalidTransactionName(name.to_string()))
        }
    }

    fn notify_news<BC: BitcoinCoordinatorApi>(
        &self,
        tx_id: Txid,
        _vout: Option<u32>,
        tx_status: TransactionStatus,
        _context: String,
        program_context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        let tx_name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "FullPenalizationProtocol received news of transaction: {}, txid: {} with {} confirmations",
            tx_name, tx_id, tx_status.confirmations
        );

        if tx_name.starts_with(OP_DISABLER_DIRECTORY_TX) {
            self.handle_op_disabler_directory_tx(program_context, &tx_name)?;
        } else if tx_name.starts_with(WT_DISABLER_DIRECTORY_TX) {
            self.handle_wt_disabler_directory_tx(program_context, &tx_name)?;
        } else if tx_name.starts_with(STOPPER_TX) {
            self.handle_stopper_tx(program_context, &tx_name)?;
        }

        Ok(())
    }

    fn setup_complete<BC: BitcoinCoordinatorApi>(
        &self,
        _context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
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

    fn full_penalization_data<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
    ) -> Result<FullPenalizationData, BitVMXError> {
        let request = context
            .globals
            .get_var(&self.ctx.id, &FullPenalizationData::name())?
            .unwrap()
            .string()?;

        let data: FullPenalizationData = serde_json::from_str(&request)?;
        Ok(data)
    }

    fn committee<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
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

    fn op_initial_deposit_txid<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
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

    fn op_initial_deposit_amount<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        dispute_core_pid: Uuid,
    ) -> Result<u64, BitVMXError> {
        let amount = context
            .globals
            .get_var(&dispute_core_pid, OP_INITIAL_DEPOSIT_AMOUNT)?
            .unwrap()
            .amount()?;
        Ok(amount)
    }

    fn op_initial_deposit_out_scripts<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
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

    fn wt_init_challenge_utxos<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        dispute_core_pid: Uuid,
    ) -> Result<Vec<Option<PartialUtxo>>, BitVMXError> {
        let data = context
            .globals
            .get_var(&dispute_core_pid, &WT_INIT_CHALLENGE_UTXOS)?
            .unwrap()
            .string()?;

        let utxos: Vec<Option<PartialUtxo>> = serde_json::from_str(&data)?;
        Ok(utxos)
    }

    fn claim_init_utxos<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        dispute_core_pid: Uuid,
    ) -> Result<Vec<Option<ClaimInitUtxos>>, BitVMXError> {
        let data = context
            .globals
            .get_var(&dispute_core_pid, &CLAIM_INIT_UTXOS)?
            .unwrap()
            .string()?;

        let utxos: Vec<Option<ClaimInitUtxos>> = serde_json::from_str(&data)?;
        Ok(utxos)
    }

    fn load_claim_init_utxos<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        committee: &Committee,
        committee_id: Uuid,
    ) -> Result<ClaimInitUtxosByWatchtower, BitVMXError> {
        committee
            .members
            .iter()
            .map(|member| {
                self.claim_init_utxos(
                    context,
                    get_dispute_core_pid(committee_id, &member.take_key),
                )
            })
            .collect()
    }

    fn input_not_revealed_enabler<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        dispute_core_pid: Uuid,
        slot_index: usize,
        wt_index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(
                &dispute_core_pid,
                &double_indexed_name(INPUT_NOT_REVEALED_ENABLER, slot_index, wt_index),
            )?
            .unwrap()
            .utxo()?)
    }

    fn create_claim_init_references(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        committee: &Committee,
        claim_init_utxos: &ClaimInitUtxosByWatchtower,
    ) -> Result<(), BitVMXError> {
        for wt_index in 0..committee.members.len() {
            for op_index in 0..committee.members.len() {
                if wt_index == op_index
                    || committee.members[op_index].role != ParticipantRole::Prover
                {
                    continue;
                }

                let stoppers = claim_init_utxos[wt_index][op_index].clone().unwrap();
                create_transaction_reference(
                    protocol,
                    &double_indexed_name(CLAIM_INIT_TX, wt_index, op_index),
                    &mut vec![stoppers.wt_stopper, stoppers.op_stopper],
                )?;
            }
        }

        Ok(())
    }

    fn create_stopper_txs<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        committee: &Committee,
        data: &FullPenalizationData,
        context: &ProgramContext<BC>,
        claim_init_utxos: &ClaimInitUtxosByWatchtower,
    ) -> Result<(), BitVMXError> {
        for op_index in 0..committee.members.len() {
            if committee.members[op_index].role != ParticipantRole::Prover {
                continue;
            }

            let op_dispute_core_pid =
                get_dispute_core_pid(data.committee_id, &committee.members[op_index].take_key);

            for slot_index in 0..committee.packet_size as usize {
                let mut enablers = vec![];
                for wt_index in 0..committee.members.len() {
                    enablers.push(self.input_not_revealed_enabler(
                        context,
                        op_dispute_core_pid,
                        slot_index,
                        wt_index,
                    )?);
                }

                let input_not_revealed_name =
                    double_indexed_name(INPUT_NOT_REVEALED_TX, op_index, slot_index);
                create_transaction_reference(protocol, &input_not_revealed_name, &mut enablers)?;

                for wt_index in 0..committee.members.len() {
                    if wt_index == op_index {
                        continue;
                    }

                    let wt_stopper = claim_init_utxos[wt_index][op_index]
                        .clone()
                        .unwrap()
                        .wt_stopper;
                    let claim_init_name = double_indexed_name(CLAIM_INIT_TX, wt_index, op_index);
                    let stopper_name =
                        triple_indexed_name(STOPPER_TX, wt_index, op_index, slot_index);

                    protocol.add_connection(
                        "from_input_not_revealed_enabler",
                        &input_not_revealed_name,
                        (enablers[wt_index].1 as usize).into(),
                        &stopper_name,
                        InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
                        None,
                        Some(enablers[wt_index].0),
                    )?;

                    protocol.add_connection(
                        "from_watchtower_stopper",
                        &claim_init_name,
                        (wt_stopper.1 as usize).into(),
                        &stopper_name,
                        InputSpec::Auto(
                            SighashType::taproot_all(),
                            SpendMode::Script {
                                leaf: CLAIM_GATE_INIT_STOPPER_COMMITTEE_LEAF,
                            },
                        ),
                        None,
                        Some(wt_stopper.0),
                    )?;

                    protocol.add_transaction_output(
                        &stopper_name,
                        &OutputType::segwit_unspendable(
                            op_return_script(vec![])?.get_script().clone(),
                        )?,
                    )?;
                }
            }
        }

        Ok(())
    }

    fn stopper_tx(&self, name: &str) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} tx", name);

        let mut protocol = self.load_protocol()?;
        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![
                InputSigningInfo::Edcsa { input_index: 0 },
                InputSigningInfo::ScriptSpend {
                    input_index: 1,
                    script_index: CLAIM_GATE_INIT_STOPPER_COMMITTEE_LEAF,
                    winternitz_data: None,
                },
            ],
        )?;

        let tx = protocol.transaction_to_send(name, &args)?;
        info!(
            id = self.ctx.my_idx,
            "Signed {}, txid: {}",
            name,
            tx.compute_txid()
        );

        Ok((tx, None))
    }

    fn handle_stopper_tx<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        let (wt_index, op_index, _) = extract_triple_index(tx_name)?;

        // Only the watchtower that owns this STOPPER_TX can start its WT claim gate.
        if self.ctx.my_idx != wt_index {
            return Ok(());
        }

        let data = self.full_penalization_data(context)?;
        let committee = self.committee(context, data.committee_id)?;
        let dispute_core_pid =
            get_dispute_core_pid(data.committee_id, &committee.members[wt_index].take_key);
        let claim_gate_name =
            ClaimGate::tx_start(&double_indexed_name(WT_CLAIM_GATE, wt_index, op_index));
        let protocol = self.load_protocol_by_name(PROGRAM_TYPE_DISPUTE_CORE, dispute_core_pid)?;
        let (tx, speedup) = protocol.get_transaction_by_name(&claim_gate_name, context)?;
        let txid = tx.compute_txid();

        context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            Context::ProgramId(dispute_core_pid).to_string()?,
            None,
            self.requested_confirmations(context),
        )?;

        info!(
            id = self.ctx.my_idx,
            "Dispatched {} with txid: {}", claim_gate_name, txid
        );

        Ok(())
    }

    fn create_operator_disabler<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        context: &ProgramContext<BC>,
        committee_id: Uuid,
        committee: &Committee,
        op_index: usize,
        wt_index: usize,
        initial_deposit_name: &str,
        disabler_directory_utxo: &PartialUtxo,
        take_enablers: &Vec<PartialUtxo>,
        initial_deposit_utxos: &Vec<PartialUtxo>,
        operator_won_enablers: &Vec<PartialUtxo>,
        settings: &PacketSettings,
    ) -> Result<(), BitVMXError> {
        let packet_size = committee.packet_size;
        let op_disabler_directory_name =
            double_indexed_name(OP_DISABLER_DIRECTORY_TX, wt_index, op_index);

        let wt_claim_success_name = double_indexed_name(WT_CLAIM_GATE_SUCCESS, wt_index, op_index);
        let wt_claim_success_utxo =
            self.wt_claim_success_utxo(context, committee, committee_id, wt_index, op_index)?;

        create_transaction_reference(
            protocol,
            &wt_claim_success_name,
            &mut vec![wt_claim_success_utxo.clone()],
        )?;

        // Input to disabler directory from initial deposit UTXO
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

        protocol.add_connection(
            "wt_success",
            &wt_claim_success_name,
            (wt_claim_success_utxo.1 as usize).into(),
            &op_disabler_directory_name,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(wt_claim_success_utxo.0),
        )?;

        for slot_index in 0..packet_size as usize {
            // Create operator disabler for each slot
            let op_disabler_name =
                triple_indexed_name(OP_DISABLER_TX, wt_index, op_index, slot_index);

            let initial_deposit_utxo = &initial_deposit_utxos[slot_index];

            // Connect initial deposit to OP_DISABLER
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

            // Connect disabler directory to OP_DISABLER
            debug!("{} to {}", op_disabler_directory_name, op_disabler_name);
            let disabler_directory_output_value =
                get_op_disabler_directory_output_value(committee.members.len());
            protocol.add_connection(
                "from_disabler_directory",
                &op_disabler_directory_name,
                OutputType::taproot(
                    disabler_directory_output_value,
                    &committee.dispute_aggregated_key,
                    &[],
                )?
                .into(),
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

            // OP DISABLER output
            add_speedups(protocol, &op_disabler_name, committee)?;

            // Create Lazy Operator disablers
            // Operator take transaction data
            let op_lazy_disabler_name =
                triple_indexed_name(OP_LAZY_DISABLER_TX, wt_index, op_index, slot_index);
            let take_enabler = take_enablers[slot_index].clone();

            debug!(
                "take enabler index {} to {}",
                slot_index, op_lazy_disabler_name
            );
            // Connect REIMBURSEMENT KICKOFF to OP LAZY DISABLER
            protocol.add_connection(
                "reimbursement_kickoff_conn",
                &double_indexed_name(REIMBURSEMENT_KICKOFF_TX, op_index, slot_index),
                (take_enabler.1 as usize).into(),
                &op_lazy_disabler_name,
                InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
                Some(settings.short_timelock),
                Some(take_enabler.0),
            )?;

            debug!(
                "{} to {}",
                op_disabler_directory_name, op_lazy_disabler_name
            );

            // Connect disabler directory to OP LAZY DISABLER
            protocol.add_connection(
                "from_disabler_directory",
                &op_disabler_directory_name,
                OutputSpec::Last,
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

            // OP LAZY DISABLER output
            add_speedups(protocol, &op_lazy_disabler_name, committee)?;

            // Create STOP OPERATOR WON TX
            let reveal_name = &double_indexed_name(REVEAL_INPUT_TX, op_index, slot_index);
            let stop_op_won_name =
                triple_indexed_name(STOP_OP_WON_TX, wt_index, op_index, slot_index);

            // OP DISABLER DIRECTORY to STOP_OP_WON_TX
            protocol.add_connection(
                "from_dis_directory",
                &op_disabler_directory_name,
                OutputSpec::Last,
                &stop_op_won_name,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::KeyOnly {
                        key_path_sign: SignMode::Aggregate,
                    },
                ),
                None,
                None,
            )?;

            // Connect REVEAL INPUT TX to STOP_OP_WON_TX
            protocol.add_connection(
                "from_reveal_input",
                &reveal_name,
                (operator_won_enablers[slot_index].1 as usize).into(),
                &stop_op_won_name,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::KeyOnly {
                        key_path_sign: SignMode::Aggregate,
                    },
                ),
                None,
                Some(operator_won_enablers[slot_index].0),
            )?;

            add_speedups(protocol, &stop_op_won_name, committee)?;
        }

        // OP DISABLER DIRECTORY output
        protocol.add_transaction_output(
            &op_disabler_directory_name,
            &OutputType::segwit_key(SPEEDUP_VALUE, &committee.members[wt_index].dispute_key)?,
        )?;

        Ok(())
    }

    fn operator_take_enabler<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        dispute_core_pid: Uuid,
        slot_index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(
                &dispute_core_pid,
                &indexed_name(OPERATOR_TAKE_ENABLER, slot_index),
            )?
            .unwrap()
            .utxo()?)
    }

    fn operator_won_enabler<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        dispute_core_pid: Uuid,
        slot_index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(
                &dispute_core_pid,
                &indexed_name(OPERATOR_WON_ENABLER, slot_index),
            )?
            .unwrap()
            .utxo()?)
    }

    fn op_disabler_directory_utxo<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        dispute_core_pid: Uuid,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(&dispute_core_pid, &OP_DISABLER_DIRECTORY_UTXO)?
            .unwrap()
            .utxo()?)
    }

    fn wt_disabler_directory_utxo<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        dispute_core_pid: Uuid,
    ) -> Result<PartialUtxo, BitVMXError> {
        Ok(context
            .globals
            .get_var(&dispute_core_pid, &WT_DISABLER_DIRECTORY_UTXO)?
            .unwrap()
            .utxo()?)
    }

    fn stop_operator_won_tx(
        &self,
        name: &str,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} tx", name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![
                InputSigningInfo::KeySpend { input_index: 0 },
                InputSigningInfo::KeySpend { input_index: 1 },
            ],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        let txid = tx.compute_txid();

        info!(id = self.ctx.my_idx, "Signed {}, txid: {}", name, txid);

        Ok((tx, None))
    }

    fn op_lazy_disabler_tx<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        // NOTE: OP_LAZY_DISABLER_TX_<WT>_<OP>_<SLOT> it's tied to:
        // - Watchtower index
        // - Operator index
        // - Slot
        // Here watchtower index it's ignored and it dispatch the TX corresponding to
        // current member, due to it should sign the output script leaf in the reimbursement kickoff.
        info!(id = self.ctx.my_idx, "Loading {} tx", name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![
                InputSigningInfo::ScriptSpend {
                    input_index: 0,
                    script_index: self.ctx.my_idx,
                    winternitz_data: Some(WinternitzData {
                        data: vec![1u8],
                        key_type: WinternitzType::HASH160,
                        key_name: CHALLENGE_KEY.to_string(),
                        key_manager: &context.key_manager,
                    }),
                },
                InputSigningInfo::KeySpend { input_index: 1 },
            ],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        let txid = tx.compute_txid();

        info!(id = self.ctx.my_idx, "Signed {}, txid: {}", name, txid);

        Ok((tx, None))
    }

    fn op_disabler_tx<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        _context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} tx", name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![
                InputSigningInfo::ScriptSpend {
                    input_index: 0,
                    script_index: OP_INITIAL_DEPOSIT_TX_DISABLER_LEAF,
                    winternitz_data: None,
                },
                InputSigningInfo::KeySpend { input_index: 1 },
            ],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        let txid = tx.compute_txid();

        info!(id = self.ctx.my_idx, "Signed {}, txid: {}.", name, txid);

        Ok((tx, None))
    }

    fn wt_disabler_tx<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        debug!(id = self.ctx.my_idx, "Loading {} tx", name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![
                InputSigningInfo::ScriptSpend {
                    input_index: 0,
                    script_index: WT_START_ENABLER_TX_DISABLER_LEAF,
                    winternitz_data: None,
                },
                InputSigningInfo::KeySpend { input_index: 1 },
            ],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        let txid = tx.compute_txid();

        let committee =
            self.committee(context, self.full_penalization_data(context)?.committee_id)?;

        // Speedup data
        let speedup_utxo = Utxo::new(
            txid,
            0,
            SPEEDUP_VALUE,
            &committee.members[self.ctx.my_idx].dispute_key,
        );

        debug!(id = self.ctx.my_idx, "Signed {}, txid: {}.", name, txid);

        Ok((tx, Some(speedup_utxo.into())))
    }

    fn wt_cosign_disabler_tx<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        debug!(id = self.ctx.my_idx, "Loading {} tx", name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![
                InputSigningInfo::ScriptSpend {
                    input_index: 0,
                    script_index: WT_INIT_CHALLENGE_TX_COSIGN_DISABLER_LEAF,
                    winternitz_data: None,
                },
                InputSigningInfo::KeySpend { input_index: 1 },
            ],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        let txid = tx.compute_txid();

        let committee =
            self.committee(context, self.full_penalization_data(context)?.committee_id)?;

        // Speedup data
        let speedup_utxo = Utxo::new(
            txid,
            self.ctx.my_idx as u32,
            SPEEDUP_VALUE,
            &committee.members[self.ctx.my_idx].dispute_key,
        );

        debug!(id = self.ctx.my_idx, "Signed {}, txid: {}.", name, txid);

        Ok((tx, Some(speedup_utxo.into())))
    }

    fn disabler_directory_tx<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
        role: ParticipantRole,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} tx", name);
        let (wt_index, op_index) = extract_double_index(name)?;

        let speedup = if role == ParticipantRole::Prover {
            // WT is responsible for speedup OP disabler directory.
            wt_index == self.ctx.my_idx
        } else {
            // OP is responsible for speedup WT disabler directory.
            op_index == self.ctx.my_idx
        };

        let mut protocol = self.load_protocol()?;
        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![
                InputSigningInfo::KeySpend { input_index: 0 },
                InputSigningInfo::KeySpend { input_index: 1 },
            ],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        let txid = tx.compute_txid();

        let committee =
            self.committee(context, self.full_penalization_data(context)?.committee_id)?;

        let speedup_data = if speedup {
            // Speedup data
            let speedup_utxo = Utxo::new(
                txid,
                tx.output.len() as u32 - 1,
                SPEEDUP_VALUE,
                &committee.members[self.ctx.my_idx].dispute_key,
            );
            Some(speedup_utxo.into())
        } else {
            None
        };

        info!(id = self.ctx.my_idx, "Signed {} with txid: {} ", name, txid);
        Ok((tx, speedup_data))
    }

    fn create_operator_disablers<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        committee: &Committee,
        data: &FullPenalizationData,
        context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        let member_count = committee.members.len();
        let settings = &committee.settings;

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

            let dispute_protocol_pid = get_dispute_core_pid(
                data.committee_id,
                &committee.members[operator_index].take_key,
            );
            let mut operator_won_enablers = vec![];

            for slot_index in 0..committee.packet_size as usize {
                let operator_won_enabler =
                    self.operator_won_enabler(context, dispute_protocol_pid, slot_index)?;

                operator_won_enablers.push(operator_won_enabler.clone());

                let reveal_name = &double_indexed_name(REVEAL_INPUT_TX, operator_index, slot_index);
                create_transaction_reference(
                    protocol,
                    reveal_name,
                    &mut vec![operator_won_enabler.clone()],
                )?;
            }

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
                    context,
                    data.committee_id,
                    &committee,
                    operator_index,
                    watchtower_index,
                    &initial_deposit_name,
                    &disabler_directory_utxo,
                    &take_enablers,
                    &initial_deposit_utxos,
                    &operator_won_enablers,
                    settings,
                )?;
            }
        }
        Ok(())
    }

    fn create_op_initial_deposit_tx<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        operator_index: usize,
        committee_id: Uuid,
        committee: &Committee,
        context: &ProgramContext<BC>,
    ) -> Result<(String, PartialUtxo, Vec<PartialUtxo>, Vec<PartialUtxo>), BitVMXError> {
        let dispute_core_pid =
            get_dispute_core_pid(committee_id, &committee.members[operator_index].take_key);

        let disabler_directory_utxo = self.op_disabler_directory_utxo(context, dispute_core_pid)?;

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
                amount.into(),
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

    fn create_watchtower_disablers<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        committee: &Committee,
        data: &FullPenalizationData,
        context: &ProgramContext<BC>,
        claim_init_utxos: &ClaimInitUtxosByWatchtower,
    ) -> Result<(), BitVMXError> {
        let member_count = committee.members.len();

        for wt_index in 0..member_count {
            let dispute_core_pid =
                get_dispute_core_pid(data.committee_id, &committee.members[wt_index].take_key);

            let init_challenge_utxos = self.wt_init_challenge_utxos(context, dispute_core_pid)?;
            let disabler_directory_utxo =
                self.wt_disabler_directory_utxo(context, dispute_core_pid)?;

            create_transaction_reference(
                protocol,
                &indexed_name(WT_START_ENABLER_TX, wt_index),
                &mut vec![disabler_directory_utxo.clone()],
            )?;

            // Create the WT INIT CHALLENGE references just once. CLAIM_INIT references are
            // created centrally because they are shared with STOPPER_TX.
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

                let cosign_utxo = init_challenge_utxos[op_index].clone().unwrap();
                create_transaction_reference(
                    protocol,
                    &double_indexed_name(WT_INIT_CHALLENGE_TX, wt_index, op_index),
                    &mut vec![cosign_utxo],
                )?;
            }

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

                self.create_watchtower_disabler(
                    protocol,
                    context,
                    data.committee_id,
                    &committee,
                    wt_index,
                    op_index,
                    &init_challenge_utxos,
                    &claim_init_utxos[wt_index],
                    &disabler_directory_utxo,
                )?;
            }
        }

        Ok(())
    }

    fn create_watchtower_disabler<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &mut protocol_builder::builder::Protocol,
        context: &ProgramContext<BC>,
        committee_id: Uuid,
        committee: &Committee,
        wt_index: usize, // WT who is going to be disabled
        op_index: usize, // OP who won the challenge and caused the WT to be disabled
        init_challenge_utxos: &Vec<Option<PartialUtxo>>,
        claim_init_utxos: &Vec<Option<ClaimInitUtxos>>,
        disabler_directory_utxo: &PartialUtxo,
    ) -> Result<(), BitVMXError> {
        let wt_disabler_directory_name =
            double_indexed_name(WT_DISABLER_DIRECTORY_TX, wt_index, op_index);

        let op_claim_success_name = double_indexed_name(OP_CLAIM_GATE_SUCCESS, wt_index, op_index);
        let op_claim_success_utxo =
            self.op_claim_success_utxo(context, committee, committee_id, wt_index, op_index)?;

        create_transaction_reference(
            protocol,
            &op_claim_success_name,
            &mut vec![op_claim_success_utxo.clone()],
        )?;

        // Funds input to disabler directory from start enabler UTXO
        protocol.add_connection(
            "funds",
            &indexed_name(WT_START_ENABLER_TX, wt_index),
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

        protocol.add_connection(
            "op_success",
            &op_claim_success_name,
            (op_claim_success_utxo.1 as usize).into(),
            &wt_disabler_directory_name,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(op_claim_success_utxo.0),
        )?;

        for member_index in 0..committee.members.len() {
            if claim_init_utxos[member_index].is_none() {
                continue;
            }

            let wt_init_challenge_name =
                &double_indexed_name(WT_INIT_CHALLENGE_TX, wt_index, member_index);
            let claim_init_name = &double_indexed_name(CLAIM_INIT_TX, wt_index, member_index);

            // WT_DISABLER_TX
            let op_stopper = claim_init_utxos[member_index].clone().unwrap().op_stopper;
            let wt_disabler_name =
                triple_indexed_name(WT_DISABLER_TX, wt_index, op_index, member_index);

            // Connection from CLAIM INIT stopper to WT_DISABLER
            // Need to consume op_stopper to prevent WT to disabler it
            protocol.add_connection(
                "from_stopper",
                claim_init_name,
                (op_stopper.1 as usize).into(),
                &wt_disabler_name,
                // First script leaf verify aggregated key
                InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
                None,
                Some(op_stopper.0),
            )?;

            // Connection from disabler directory to WT_DISABLER
            protocol.add_connection(
                "from_disabler_directory",
                &wt_disabler_directory_name,
                OutputType::taproot(DUST_VALUE, &committee.dispute_aggregated_key, &[])?.into(),
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

            // WT DISABLER output
            // Challenged operator is the only one interested on speed up this disabler.
            protocol.add_transaction_output(
                &wt_disabler_name,
                &OutputType::segwit_key(SPEEDUP_VALUE, &committee.members[op_index].dispute_key)?,
            )?;

            // WT_COSIGN_DISABLER_TX
            let wt_init_challenge_cosign = init_challenge_utxos[member_index].clone().unwrap();
            let wt_cosign_disabler_name =
                triple_indexed_name(WT_COSIGN_DISABLER_TX, wt_index, op_index, member_index);

            // Connection from WT INIT CHALLENGE cosign to WT_COSIGN_DISABLER_TX
            protocol.add_connection(
                "from_cosign",
                wt_init_challenge_name,
                (wt_init_challenge_cosign.1 as usize).into(),
                &wt_cosign_disabler_name,
                // Leaf 2 verify aggregated key
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::Script {
                        leaf: WT_INIT_CHALLENGE_TX_COSIGN_DISABLER_LEAF,
                    },
                ),
                None,
                Some(wt_init_challenge_cosign.0),
            )?;

            // Connection from disabler directory to WT_COSIGN_DISABLER_TX
            protocol.add_connection(
                "from_disabler_directory",
                &wt_disabler_directory_name,
                OutputType::taproot(DUST_VALUE, &committee.dispute_aggregated_key, &[])?.into(),
                &wt_cosign_disabler_name,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::KeyOnly {
                        key_path_sign: SignMode::Aggregate,
                    },
                ),
                None,
                None,
            )?;

            // WT_COSIGN_DISABLER_TX output
            add_speedups(protocol, &wt_cosign_disabler_name, committee)?;
        }

        // Add speed up value
        protocol.add_transaction_output(
            &wt_disabler_directory_name,
            &OutputType::segwit_key(SPEEDUP_VALUE, &committee.members[op_index].dispute_key)?,
        )?;

        Ok(())
    }

    fn handle_wt_disabler_directory_tx<BC: BitcoinCoordinatorApi>(
        &self,
        program_context: &ProgramContext<BC>,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        info!("Handling: {}", tx_name);

        let (wt_index, op_index) = extract_double_index(tx_name)?;

        save_penalized_member(
            program_context,
            self.full_penalization_data(program_context)?.committee_id,
            &PenalizedMember {
                member_index: wt_index,
                role: ParticipantRole::Verifier,
                challenger_index: op_index,
            },
        )?;

        if wt_index == self.ctx.my_idx {
            info!(
                id = self.ctx.my_idx,
                "Skipping dispatch of watchtowers disablers for self"
            );
            return Ok(());
        }

        let committee = self.committee(
            program_context,
            self.full_penalization_data(program_context)?.committee_id,
        )?;

        let mut txs = vec![];

        for (member_index, member) in committee.members.iter().enumerate() {
            // Disabler are just for those outputs that correspond to a Prover and not self
            if wt_index == member_index || member.role != ParticipantRole::Prover {
                continue;
            }

            let disabler_name =
                triple_indexed_name(WT_DISABLER_TX, wt_index, op_index, member_index);
            let (tx, speedup) = self.wt_disabler_tx(&disabler_name, program_context)?;
            txs.push((disabler_name, tx, speedup));
        }

        self.dispatch_batch(program_context, txs)?;

        Ok(())
    }

    fn handle_op_disabler_directory_tx<BC: BitcoinCoordinatorApi>(
        &self,
        program_context: &ProgramContext<BC>,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        info!("Handling: {}", tx_name);

        let (wt_index, op_index) = extract_double_index(tx_name)?;

        save_penalized_member(
            program_context,
            self.full_penalization_data(program_context)?.committee_id,
            &PenalizedMember {
                member_index: op_index,
                role: ParticipantRole::Prover,
                challenger_index: wt_index,
            },
        )?;

        if op_index == self.ctx.my_idx {
            info!(
                id = self.ctx.my_idx,
                "Skipping dispatch of operator disablers for self"
            );
            return Ok(());
        }

        let committee = self.committee(
            program_context,
            self.full_penalization_data(program_context)?.committee_id,
        )?;

        let mut txs = vec![];

        for slot_index in 0..committee.packet_size as usize {
            let disabler_name = triple_indexed_name(OP_DISABLER_TX, wt_index, op_index, slot_index);
            let (tx, speedup) = self.op_disabler_tx(&disabler_name, program_context)?;
            txs.push((disabler_name, tx, speedup));

            let stop_op_won_name =
                triple_indexed_name(STOP_OP_WON_TX, wt_index, op_index, slot_index);
            let (tx, speedup) = self.stop_operator_won_tx(&stop_op_won_name)?;
            txs.push((stop_op_won_name, tx, speedup));

            let lazy_disabler_name =
                triple_indexed_name(OP_LAZY_DISABLER_TX, wt_index, op_index, slot_index);

            // This signature could fail if WT already used winternitz to sign reimbursement kickoff transaction to init the challenge.
            // In this case, we want to skip creation of lazy disabler but we don't want to fail the whole batch just because of that.
            let result = self.op_lazy_disabler_tx(&lazy_disabler_name, program_context);
            if let Err(e) = &result {
                warn!(
                    id = self.ctx.my_idx,
                    "Failed to create lazy disabler {}: {}. Skipping it.", lazy_disabler_name, e
                );
                continue;
            }
            let (tx, speedup) = result?;
            txs.push((lazy_disabler_name, tx, speedup));
        }

        self.dispatch_batch(program_context, txs)?;

        Ok(())
    }

    fn dispatch_batch<BC: BitcoinCoordinatorApi>(
        &self,
        program_context: &ProgramContext<BC>,
        txs: Vec<(String, Transaction, Option<SpeedupData>)>,
    ) -> Result<(), BitVMXError> {
        for (tx_name, tx, speedup) in txs {
            // Dispatch the transaction through the bitcoin coordinator
            let txid = tx.compute_txid();
            program_context.bitcoin_coordinator.dispatch(
                tx,
                speedup,
                Context::ProgramId(self.ctx.id).to_string()?,
                None,
                self.requested_confirmations(program_context),
            )?;

            info!(
                id = self.ctx.my_idx,
                "{} dispatched with txid: {}", tx_name, txid
            );
        }

        Ok(())
    }

    fn wt_claim_success_utxo<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        committee: &Committee,
        committee_id: Uuid,
        wt_index: usize,
        op_index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        let dispute_core_pid =
            get_dispute_core_pid(committee_id, &committee.members[wt_index].take_key);

        context
            .globals
            .get_var(
                &dispute_core_pid,
                &double_indexed_name(WT_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO, wt_index, op_index),
            )?
            .unwrap()
            .utxo()
    }

    fn op_claim_success_utxo<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        committee: &Committee,
        committee_id: Uuid,
        wt_index: usize,
        op_index: usize,
    ) -> Result<PartialUtxo, BitVMXError> {
        let dispute_core_pid =
            get_dispute_core_pid(committee_id, &committee.members[wt_index].take_key);

        context
            .globals
            .get_var(
                &dispute_core_pid,
                &double_indexed_name(OP_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO, wt_index, op_index),
            )?
            .unwrap()
            .utxo()
    }
}
