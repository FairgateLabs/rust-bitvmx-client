use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeyDeclaration, ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            claim::{ClaimGate, CLAIM_GATE_START, CLAIM_GATE_STOP, CLAIM_GATE_SUCCESS},
            dispute::{self, program_input_prev_prefix, program_input_prev_protocol},
            protocol_handler::{action_wins_prefix, ProtocolContext, ProtocolHandler},
            union::{
                common::{
                    add_speedups, collect_input_signatures, create_transaction_reference,
                    double_indexed_name, estimate_fee, extract_double_index, extract_index,
                    extract_index_from_claim_gate, get_accept_pegin_pid, get_dispatch_action,
                    get_dispute_channel_pid, get_dispute_core_pid, get_dispute_pair_key_name,
                    get_full_penalization_pid, get_initial_deposit_output_type, get_my_idx,
                    get_op_disabler_directory_output_value, get_reveal_output_value, indexed_name,
                    load_penalized_member, set_my_idx, triple_indexed_name, InputSigningInfo,
                    WinternitzData,
                },
                dispute_core_claim_gate::{
                    ClaimGateAction, CLAIM_GATE_INIT_STOPPER_COMMITTEE_LEAF,
                },
                scripts,
                types::*,
            },
        },
        variables::{PartialUtxo, VariableTypes},
    },
    spv_proof::get_spv_proof,
    types::{
        OutgoingBitVMXApiMessages, ProgramContext, PROGRAM_TYPE_ACCEPT_PEGIN,
        PROGRAM_TYPE_DISPUTE_CORE, PROGRAM_TYPE_DRP, PROGRAM_TYPE_FULL_PENALIZATION,
    },
};
use bitcoin::{Amount, PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use bitcoin_scriptexec::scriptint_vec;
use core::result::Result::Ok;
use key_manager::winternitz::{WinternitzPublicKey, WinternitzType};
use key_manager::{key_type::BitcoinKeyType, winternitz::WinternitzSignature};
use protocol_builder::{
    builder::Protocol,
    graph::graph::GraphOptions,
    scripts::{
        op_return_script, timelock, verify_signature, verify_winternitz_signature_timelock,
        ProtocolScript, SignMode,
    },
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::{AmountType, SpeedupData},
        InputArgs, OutputType, Utxo,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info, warn};
use uuid::Uuid;

pub const PEGOUT_ID: &str = "PEGOUT_ID";
pub const PEGOUT_ID_KEY: &str = "PEGOUT_ID_KEY";
pub const PEGOUT_ID_KEY_WORDS: usize = 8; // Number of words the PEGOUT_ID_KEY is split into (32 bytes / 4 bytes per key)
pub const CHALLENGE_KEY: &str = "CHALLENGE_KEY";
pub const SLOT_ID_KEY: &str = "SLOT_ID_KEY";
const SLOT_ID_KEYS: &str = "SLOT_ID_KEYS";
const PEGOUT_ID_KEYS: &str = "PEGOUT_ID_KEYS";
const MEMBERS_SLOT_ID_KEYS: &str = "MEMBERS_SLOT_ID_KEYS";
const INIT_CHALLENGE_SLOT: &str = "INIT_CHALLENGE_SLOT";
const CLAIM_INIT_MINED: &str = "CLAIM_INIT_MINED";

pub const OP_COSIGN_SLOT_KEY: &str = "OP_COSIGN_SLOT_KEY";
pub const OP_COSIGN_PEGOUT_ID_KEY: &str = "OP_COSIGN_PEGOUT_ID_KEY";
pub const WT_COSIGN_SLOT_KEY: &str = "WT_COSIGN_SLOT_KEY";
pub const WT_COSIGN_PEGOUT_ID_KEY: &str = "WT_COSIGN_PEGOUT_ID_KEY";

const CLAIM_GATE_FEE: u64 = 335; // TODO: Validate this value

pub const OP_INITIAL_DEPOSIT_TX_REIMBURSMENT_LEAF: usize = 0;
pub const OP_INITIAL_DEPOSIT_TX_DISABLER_LEAF: usize = 1;
pub const WT_START_ENABLER_TX_DISABLER_LEAF: usize = 0;

const REVEAL_INPUT_TX_REVEAL_INDEX: usize = 0;
const REVEAL_INPUT_TX_REVEAL_LEAF: usize = 0;
const REVEAL_INPUT_TX_COMMITTEE_LEAF: usize = 1;

const WT_INIT_CHALLENGE_COSIGN_INDEX: usize = 0;
const WT_INIT_CHALLENGE_TX_COSIGN_LEAF: usize = 0;
const WT_INIT_CHALLENGE_TX_TIMELOCK_LEAF: usize = 1;
pub const WT_INIT_CHALLENGE_TX_COSIGN_DISABLER_LEAF: usize = 2;

const WT_INIT_CHALLENGE_COSIGN_VOUT: u32 = 0;

// CLAIM_INIT_TX output layout. Vouts 0..=4 are produced by the two ClaimGate::new calls in
// create_claim_init: the WT gate adds the exclusive success output (0), its start output (1) and
// its stopper (2); the OP gate adds its start output (3) and its stopper (4). The two speedups
// are appended afterwards. Keep these in sync with ClaimGate::new.
const CLAIM_INIT_WT_STOPPER_VOUT: u32 = 2;
const CLAIM_INIT_OP_STOPPER_VOUT: u32 = 4;
const CLAIM_INIT_WT_SPEEDUP_OUTPUT_OFFSET_FROM_END: u32 = 2;
const CLAIM_INIT_OP_SPEEDUP_OUTPUT_OFFSET_FROM_END: u32 = 1;

const OP_COSIGN_INIT_CHALLENGE_INDEX: usize = 0;
const OP_COSIGN_TX_TIMELOCK_LEAF: usize = 0;

const COSIGN_SLOT_SIZE: usize = 4;

enum DisputeCoreTxType {
    WtStartEnabler,
    ProtocolFunding,
    OperatorDisablerDirectory {
        wt_index: usize,
        op_index: usize,
    },
    WatchtowerDisablerDirectory {
        wt_index: usize,
        op_index: usize,
    },
    OperatorTake {
        op_index: usize,
        slot_index: usize,
        block_height: Option<u32>,
    },
    OperatorWon {
        op_index: usize,
        slot_index: usize,
        block_height: Option<u32>,
    },
    Challenge {
        slot_index: usize,
        block_height: Option<u32>,
    },
    WatchtowerNoChallenge {
        wt_index: usize,
        op_index: usize,
        block_height: Option<u32>,
    },
    OperatorNoCosign {
        wt_index: usize,
        op_index: usize,
        block_height: Option<u32>,
    },
    OperatorCosign {
        wt_index: usize,
        op_index: usize,
    },
    ClaimInit {
        wt_index: usize,
        op_index: usize,
    },
    RevealInput {
        slot_index: usize,
    },
    InputNotRevealed {
        slot_index: usize,
        block_height: Option<u32>,
    },
    Stopper {
        wt_index: usize,
        op_index: usize,
        slot_index: usize,
    },
    TwoDisputePenalization {
        slot_index_prev: usize,
        slot_index_curr: usize,
    },
    PenalizationStopOperatorWon {
        wt_index: usize,
        op_index: usize,
        slot_index: usize,
    },
    PenalizationOperatorLazyDisabler {
        wt_index: usize,
        op_index: usize,
        slot_index: usize,
    },
    PenalizationWatchtowerCosignDisabler {
        wt_index: usize,
        op_disabler_directory_index: usize,
        op_index: usize,
    },
    PenalizationWatchtowerDisabler {
        wt_index: usize,
        op_disabler_directory_index: usize,
        op_index: usize,
    },
}

impl DisputeCoreTxType {
    pub fn tx_name(&self) -> String {
        match self {
            DisputeCoreTxType::WtStartEnabler => WT_START_ENABLER_TX.to_string(),
            DisputeCoreTxType::ProtocolFunding => PROTOCOL_FUNDING_TX.to_string(),
            DisputeCoreTxType::OperatorDisablerDirectory { wt_index, op_index } => {
                double_indexed_name(OP_DISABLER_DIRECTORY_TX, *wt_index, *op_index)
            }
            DisputeCoreTxType::WatchtowerDisablerDirectory { wt_index, op_index } => {
                double_indexed_name(WT_DISABLER_DIRECTORY_TX, *wt_index, *op_index)
            }
            DisputeCoreTxType::OperatorTake { op_index, .. } => {
                indexed_name(OPERATOR_TAKE_TX, *op_index)
            }
            DisputeCoreTxType::OperatorWon { op_index, .. } => {
                indexed_name(OPERATOR_WON_TX, *op_index)
            }
            DisputeCoreTxType::Challenge { slot_index, .. } => {
                indexed_name(CHALLENGE_TX, *slot_index)
            }
            DisputeCoreTxType::WatchtowerNoChallenge {
                wt_index, op_index, ..
            } => double_indexed_name(WT_NO_CHALLENGE_TX, *wt_index, *op_index),
            DisputeCoreTxType::OperatorNoCosign {
                wt_index, op_index, ..
            } => double_indexed_name(OP_NO_COSIGN_TX, *wt_index, *op_index),
            DisputeCoreTxType::OperatorCosign { wt_index, op_index } => {
                double_indexed_name(OP_COSIGN_TX, *wt_index, *op_index)
            }
            DisputeCoreTxType::ClaimInit { wt_index, op_index } => {
                double_indexed_name(CLAIM_INIT_TX, *wt_index, *op_index)
            }
            DisputeCoreTxType::RevealInput { slot_index } => {
                indexed_name(REVEAL_INPUT_TX, *slot_index)
            }
            DisputeCoreTxType::InputNotRevealed { slot_index, .. } => {
                indexed_name(INPUT_NOT_REVEALED_TX, *slot_index)
            }
            DisputeCoreTxType::Stopper {
                wt_index,
                op_index,
                slot_index,
            } => triple_indexed_name(STOPPER_TX, *wt_index, *op_index, *slot_index),
            DisputeCoreTxType::TwoDisputePenalization {
                slot_index_prev,
                slot_index_curr,
            } => {
                let (min, max) = if slot_index_prev < slot_index_curr {
                    (*slot_index_prev, *slot_index_curr)
                } else {
                    (*slot_index_curr, *slot_index_prev)
                };
                double_indexed_name(TWO_DISPUTE_PENALIZATION_TX, min, max)
            }
            DisputeCoreTxType::PenalizationStopOperatorWon {
                wt_index,
                op_index,
                slot_index,
            } => triple_indexed_name(STOP_OP_WON_TX, *wt_index, *op_index, *slot_index),
            DisputeCoreTxType::PenalizationOperatorLazyDisabler {
                wt_index,
                op_index,
                slot_index,
            } => triple_indexed_name(OP_LAZY_DISABLER_TX, *wt_index, *op_index, *slot_index),
            DisputeCoreTxType::PenalizationWatchtowerCosignDisabler {
                wt_index,
                op_disabler_directory_index,
                op_index,
            } => triple_indexed_name(
                WT_COSIGN_DISABLER_TX,
                *wt_index,
                *op_disabler_directory_index,
                *op_index,
            ),
            DisputeCoreTxType::PenalizationWatchtowerDisabler {
                wt_index,
                op_disabler_directory_index,
                op_index,
            } => triple_indexed_name(
                WT_DISABLER_TX,
                *wt_index,
                *op_disabler_directory_index,
                *op_index,
            ),
        }
    }

    pub fn block_height(&self) -> Option<u32> {
        match self {
            DisputeCoreTxType::OperatorTake { block_height, .. } => *block_height,
            DisputeCoreTxType::OperatorWon { block_height, .. } => *block_height,
            DisputeCoreTxType::Challenge { block_height, .. } => *block_height,
            DisputeCoreTxType::WatchtowerNoChallenge { block_height, .. } => *block_height,
            DisputeCoreTxType::OperatorNoCosign { block_height, .. } => *block_height,
            DisputeCoreTxType::InputNotRevealed { block_height, .. } => *block_height,
            _ => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeCoreProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for DisputeCoreProtocol {
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
        let committee = self.committee(context)?;
        Ok(vec![
            (
                TAKE_AGGREGATED_KEY.to_string(),
                committee.take_aggregated_key.clone(),
            ),
            (
                DISPUTE_AGGREGATED_KEY.to_string(),
                committee.dispute_aggregated_key.clone(),
            ),
        ])
    }

    fn generate_keys<BC: BitcoinCoordinatorApi>(
        &self,
        context: &mut ProgramContext<BC>,
    ) -> Result<ParticipantKeyDeclaration, BitVMXError> {
        let committee = self.committee(context)?;
        let packet_size = committee.packet_size;
        let data = self.dispute_core_data(context)?;
        let mut keys = vec![];

        let speedup_key = context.key_manager.next_keypair(BitcoinKeyType::P2tr)?;

        keys.push((
            SPEEDUP_KEY.to_string(),
            PublicKeyType::Public(speedup_key.clone()),
        ));

        context.globals.set_var(
            &self.ctx.id,
            SPEEDUP_KEY,
            VariableTypes::PubKey(speedup_key),
        )?;

        let dispute_pair_keys =
            self.get_dispute_pair_keys(&context, data.committee_id, &committee.members)?;

        keys.extend(dispute_pair_keys);

        if self.is_prover(context)? {
            let slot_id_keys =
                self.load_or_create_slot_id_keys(&context, &data.committee_id, &committee)?;

            let pegout_id_keys =
                self.load_or_create_pegout_id_keys(&context, &data.committee_id, &committee)?;

            for slot_index in 0..packet_size as usize {
                keys.push((
                    indexed_name(PEGOUT_ID_KEY, slot_index).to_string(),
                    pegout_id_keys[slot_index].clone(),
                ));

                keys.push((
                    indexed_name(SLOT_ID_KEY, slot_index).to_string(),
                    slot_id_keys[slot_index].clone(),
                ));
            }

            // OP_COSIGN_PEGOUT_ID_KEY should be split in words size. Pegout ID has 32 bytes, then 8 keys of 4 bytes are needed.
            for word in 0..PEGOUT_ID_KEY_WORDS {
                keys.push((
                    double_indexed_name(OP_COSIGN_PEGOUT_ID_KEY, self.ctx.my_idx, word).to_string(),
                    PublicKeyType::Winternitz(
                        context
                            .key_manager
                            .next_winternitz(4, WinternitzType::HASH160)?,
                    ),
                ));
            }
            keys.push((
                OP_COSIGN_SLOT_KEY.to_string(),
                PublicKeyType::Winternitz(
                    context
                        .key_manager
                        .next_winternitz(COSIGN_SLOT_SIZE, WinternitzType::HASH160)?,
                ),
            ));
        }

        for slot_index in 0..packet_size as usize {
            keys.push((
                indexed_name(CHALLENGE_KEY, slot_index),
                PublicKeyType::Winternitz(
                    context
                        .key_manager
                        .next_winternitz(1, WinternitzType::HASH160)?,
                ),
            ));
        }

        if data.member_index == self.ctx.my_idx {
            for (member_index, member) in committee.members.iter().enumerate() {
                if member.role == ParticipantRole::Prover {
                    keys.push((
                        indexed_name(WT_COSIGN_SLOT_KEY, member_index),
                        PublicKeyType::Winternitz(
                            context
                                .key_manager
                                .next_winternitz(COSIGN_SLOT_SIZE, WinternitzType::HASH160)?,
                        ),
                    ));

                    // WT_COSIGN_PEGOUT_ID_KEY should be split in words size. Pegout ID has 32 bytes, then 8 keys of 4 bytes are needed.
                    for word in 0..PEGOUT_ID_KEY_WORDS {
                        keys.push((
                            double_indexed_name(WT_COSIGN_PEGOUT_ID_KEY, member_index, word)
                                .to_string(),
                            PublicKeyType::Winternitz(
                                context
                                    .key_manager
                                    .next_winternitz(4, WinternitzType::HASH160)?,
                            ),
                        ));
                    }
                }
            }
        }

        ParticipantKeyDeclaration::new(keys, vec![])
    }

    fn build<BC: BitcoinCoordinatorApi>(
        &self,
        keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        info!("Building DisputeCoreProtocol for program {}", self.ctx.id);

        set_my_idx(context, self.ctx.id, self.ctx.my_idx)?;
        let committee = self.committee(context)?;
        let dispute_core_data = self.dispute_core_data(context)?;

        self.set_requested_confirmations(context, committee.settings.pegin_confirmations)?;
        self.validate_keys(&keys, context, dispute_core_data.committee_id)?;

        self.set_drp_variables(context, dispute_core_data.committee_id, &committee, &keys)?;

        let mut protocol = self.load_or_create_protocol();
        let settings = &committee.settings;
        let member = &committee.members[dispute_core_data.member_index];
        let mut reimbursement_outputs = vec![];

        self.create_wt_start_enabler_output(
            &mut protocol,
            &dispute_core_data,
            &member.dispute_key,
            &committee.dispute_aggregated_key.clone(),
        )?;

        let (
            mut init_challenge_cosign_outputs,
            mut claim_init_outputs,
            mut disabler_directory_output,
            mut op_cosign_outputs,
        ) = self.create_wt_start_enabler(
            &mut protocol,
            &dispute_core_data,
            &committee,
            &keys,
            settings,
        )?;

        let operator_won_script = timelock(
            settings.op_won_timelock,
            &committee.take_aggregated_key,
            SignMode::Aggregate,
        );

        let mut reveal_output: OutputType = OutputType::taproot(
            get_reveal_output_value(committee.members.len()),
            &committee.dispute_aggregated_key,
            &[operator_won_script],
        )?;

        // If member is an operator create Operator initial deposit and dispute cores
        if member.role == ParticipantRole::Prover {
            self.create_op_initial_deposit(
                &mut protocol,
                &member.dispute_key,
                &committee.dispute_aggregated_key,
            )?;

            reimbursement_outputs =
                self.create_reimbursement_output(&dispute_core_data, &keys, &committee, &settings)?;

            for i in 0..committee.packet_size as usize {
                self.create_dispute_core(
                    &mut protocol,
                    &committee,
                    &dispute_core_data,
                    i,
                    &keys,
                    reimbursement_outputs[i].clone(),
                    context,
                    &reveal_output,
                    &settings,
                )?;

                self.create_two_dispute_penalization(&mut protocol, i, &committee)?;
            }
        }

        // Add speedup output
        protocol.add_transaction_output(
            &PROTOCOL_FUNDING_TX,
            &OutputType::segwit_key(
                SPEEDUP_VALUE,
                keys[dispute_core_data.member_index].get_public(SPEEDUP_KEY)?,
            )?,
        )?;

        protocol.compute_minimum_output_values()?;
        self.add_funding_change(&mut protocol, &member.dispute_key, &dispute_core_data)?;

        protocol.build(&context.key_manager, &self.ctx.protocol_name)?;
        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);

        self.save_protocol(protocol)?;

        if member.role == ParticipantRole::Prover {
            self.save_op_utxos(
                context,
                &committee,
                &mut reimbursement_outputs,
                &mut reveal_output,
            )?;
        }

        self.save_wt_utxos(
            context,
            &committee,
            &dispute_core_data,
            &mut init_challenge_cosign_outputs,
            &mut claim_init_outputs,
            &mut disabler_directory_output,
            &mut op_cosign_outputs,
        )?;

        Ok(())
    }

    fn get_transaction_by_name<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!("Getting transaction by name: {}", name);
        if name == PROTOCOL_FUNDING_TX {
            Ok(self.protocol_funding_tx(context)?)
        } else if name == WT_START_ENABLER_TX {
            Ok(self.wt_start_enabler_tx(context)?)
        } else if name == OP_INITIAL_DEPOSIT_TX {
            Ok(self.sign_aggregated_input(name, context, true)?)
        } else if name.starts_with(REIMBURSEMENT_KICKOFF_TX) {
            Ok(self.reimbursement_kickoff_tx(name, context)?)
        } else if name.starts_with(CHALLENGE_TX) {
            Ok(self.challenge_tx(name, context)?)
        } else if name.starts_with(REVEAL_INPUT_TX) {
            Ok(self.reveal_input_tx(name, context)?)
        } else if name.starts_with(INPUT_NOT_REVEALED_TX) {
            Ok(self.input_not_revealed_tx(name, context)?)
        } else if name == WT_SELF_DISABLER_TX || name == OP_SELF_DISABLER_TX {
            Ok(self.sign_aggregated_input(name, context, false)?)
        } else if name.starts_with(WT_INIT_CHALLENGE_TX) {
            Ok(self.wt_init_challenge_tx(name, context)?)
        } else if name.starts_with(CLAIM_INIT_TX) {
            Ok(self.claim_init_tx(name, context)?)
        } else if (name.starts_with(WT_CLAIM_GATE) || name.starts_with(OP_CLAIM_GATE))
            && name.ends_with(CLAIM_GATE_START)
        {
            let action = ClaimGateAction::Start;
            Ok(self.claim_gate_tx(context, name, &action.inputs(), action.with_speedup())?)
        } else {
            Err(BitVMXError::InvalidTransactionName(name.to_string()))
        }
    }

    fn notify_news<BC: BitcoinCoordinatorApi>(
        &self,
        tx_id: Txid,
        _vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        info!("Notified of transaction: {}. Context: {}", tx_id, context);

        let tx_name = self.get_transaction_name_by_id(tx_id)?;

        info!(
            "DisputeCoreProtocol received news of transaction: {}, txid: {} with {} confirmations. Context: {}",
            tx_name, tx_id, tx_status.confirmations, context
        );

        if tx_name.starts_with(REIMBURSEMENT_KICKOFF_TX) {
            self.handle_reimbursement_kickoff_transaction(
                program_context,
                &tx_status,
                tx_id,
                &tx_name,
            )?;
        } else if tx_name.starts_with(CHALLENGE_TX) {
            let slot_index = extract_index(&tx_name, CHALLENGE_TX)?;

            self.handle_challenge_tx(program_context, slot_index, &tx_status)?;
        } else if tx_name.starts_with(REVEAL_INPUT_TX) {
            // Handle double reveal penalization if needed
            if self
                .handle_double_reveal(program_context, extract_index(&tx_name, REVEAL_INPUT_TX)?)?
            {
                return Ok(());
            } else {
                self.handle_reveal_input_tx(program_context, &tx_name, &tx_status)?;
            }
        } else if tx_name.starts_with(INPUT_NOT_REVEALED_TX) {
            self.handle_input_not_revealed_tx(program_context, &tx_name)?;
        } else if tx_name.starts_with(CLAIM_INIT_TX) {
            self.handle_claim_init_tx(program_context, &tx_name)?;
        } else if tx_name.starts_with(WT_INIT_CHALLENGE_TX) {
            self.handle_wt_init_challenge(program_context, &tx_name, &tx_status)?;
        } else if tx_name.starts_with(OP_COSIGN_TX) {
            self.handle_op_cosign_tx(program_context, &tx_name, &tx_status)?;
        } else if tx_name.starts_with(WT_CLAIM_GATE) {
            self.handle_wt_claim_gate_txs(program_context, &tx_name, &tx_status)?;
        } else if tx_name.starts_with(OP_CLAIM_GATE) {
            self.handle_op_claim_gate_txs(program_context, &tx_name, &tx_status)?;
        } else if tx_name.starts_with(OP_NO_COSIGN_TX) {
            self.handle_op_no_cosign_tx(program_context, &tx_name)?;
        } else if tx_name.starts_with(WT_NO_CHALLENGE_TX) {
            self.handle_wt_no_challenge_tx(program_context, &tx_name)?;
        }

        Ok(())
    }

    fn notify_external_news<BC: BitcoinCoordinatorApi>(
        &self,
        tx_id: Txid,
        _vout: Option<u32>,
        _tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        info!(
            "Notified of external transaction: {}, Context: {}",
            tx_id, context
        );

        let (pid, name) = match Context::from_string(&context)? {
            Context::Protocol(program_id, name) => (program_id, name),
            _ => {
                return Err(BitVMXError::InvalidParameter(
                    "Expected Context::Protocol".to_string(),
                ))
            }
        };

        let protocol = self.load_protocol_by_name(&name, pid)?;
        let tx_name = protocol.get_transaction_name_by_id(tx_id)?;

        info!("Notified of external transaction: {}", tx_name);

        if tx_name.starts_with(&action_wins_prefix(&ParticipantRole::Prover)) {
            self.handle_action_wins(program_context, &tx_name, ParticipantRole::Prover, pid)?;
        } else if tx_name.starts_with(&action_wins_prefix(&ParticipantRole::Verifier)) {
            self.handle_action_wins(program_context, &tx_name, ParticipantRole::Verifier, pid)?;
        } else if tx_name == dispute::START_CH {
            self.handle_start_challenge(program_context, pid)?;
        }

        Ok(())
    }

    fn setup_complete<BC: BitcoinCoordinatorApi>(
        &self,
        program_context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            id = self.ctx.my_idx,
            "DisputeCoreProtocol {} setup complete", self.ctx.id
        );

        // Automatically get and dispatch the PROTOCOL_FUNDING_TX transaction
        if self.is_my_dispute_core(program_context)? {
            self.dispatch(program_context, DisputeCoreTxType::ProtocolFunding)?;

            // TODO: Dispatched it here, but it should be dispatched just when needed (challenge case)
            self.dispatch(program_context, DisputeCoreTxType::WtStartEnabler)?;
        } else {
            info!(
                id = self.ctx.my_idx,
                "Not my dispute_core, skipping dispatch of {} transaction", PROTOCOL_FUNDING_TX
            );
        }

        Ok(())
    }
}

impl DisputeCoreProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn create_wt_start_enabler_output(
        &self,
        protocol: &mut Protocol,
        dispute_core_data: &DisputeCoreData,
        watchtower_dispute_key: &PublicKey,
        dispute_aggregated_key: &PublicKey,
    ) -> Result<(), BitVMXError> {
        let funding_utxo = dispute_core_data.funding_utxo.clone();

        // Connect the PROTOCOL_FUNDING_TX transaction to the operator funding transaction.
        // Create the funding transaction reference
        create_transaction_reference(protocol, &FUNDING_TX, &mut [funding_utxo.clone()].to_vec())?;

        // The operator_utxo must be of type P2WPKH
        protocol.add_connection(
            "funds",
            &FUNDING_TX,
            (funding_utxo.1 as usize).into(),
            &PROTOCOL_FUNDING_TX,
            InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::None),
            None,
            Some(funding_utxo.0),
        )?;

        // Connect the initial deposit transaction to the PROTOCOL_FUNDING_TX transaction.
        protocol.add_connection(
            "initial_deposit",
            &PROTOCOL_FUNDING_TX,
            OutputSpec::Auto(OutputType::taproot(
                AmountType::Auto,
                dispute_aggregated_key,
                &[],
            )?),
            &WT_START_ENABLER_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        // Connect the self-disabler (recover funds) transaction.
        protocol.add_connection(
            "self_disabler",
            &PROTOCOL_FUNDING_TX,
            OutputSpec::Index(0),
            &WT_SELF_DISABLER_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        protocol.add_transaction_output(
            &WT_SELF_DISABLER_TX,
            &OutputType::segwit_key(AmountType::Recover, watchtower_dispute_key)?,
        )?;

        return Ok(());
    }

    fn is_challengeable_operator(
        &self,
        data: &DisputeCoreData,
        committee: &Committee,
        op_index: usize,
    ) -> bool {
        committee.members[op_index].role == ParticipantRole::Prover && data.member_index != op_index
    }

    fn create_wt_start_enabler(
        &self,
        protocol: &mut Protocol,
        data: &DisputeCoreData,
        committee: &Committee,
        keys: &Vec<ParticipantKeys>,
        settings: &PacketSettings,
    ) -> Result<
        (
            Vec<Option<OutputType>>,
            Vec<Option<ClaimInitOutputs>>,
            OutputType,
            Vec<Option<OutputType>>,
        ),
        BitVMXError,
    > {
        let wt_speedup_key = keys[data.member_index].get_public(SPEEDUP_KEY)?;
        let wt_dispute_key = &committee.members[data.member_index].dispute_key;
        let mut init_challenge_cosign_outputs: Vec<Option<OutputType>> = vec![];
        let mut op_cosign_outputs: Vec<Option<OutputType>> = vec![];
        let challenge_cost = dispute::protocol_cost();

        // First output block of WT_START_ENABLER_TX: one output per member, funding
        // WT_INIT_CHALLENGE_TX for every member that is an operator other than the owner of this
        // dispute core. Skipped members still get an output so the block always holds exactly one
        // entry per member.
        for op_index in 0..committee.members.len() {
            if !self.is_challengeable_operator(data, committee, op_index) {
                protocol.add_transaction_output(
                    WT_START_ENABLER_TX,
                    &OutputType::taproot(AmountType::Auto, wt_dispute_key, &vec![])?,
                )?;

                init_challenge_cosign_outputs.push(None);
                op_cosign_outputs.push(None);
                continue;
            }

            let op_dispute_key = &committee.members[op_index].dispute_key;

            let wt_cosign_slot_key = keys[data.member_index]
                .get_winternitz(&indexed_name(WT_COSIGN_SLOT_KEY, op_index))?;

            let mut wt_cosign_pegout_id_keys = vec![];
            let mut op_cosign_pegout_id_keys = vec![];
            for word in 0..PEGOUT_ID_KEY_WORDS {
                let wt_key_name = double_indexed_name(WT_COSIGN_PEGOUT_ID_KEY, op_index, word);
                wt_cosign_pegout_id_keys
                    .push(keys[data.member_index].get_winternitz(&wt_key_name)?);

                let op_key_name = double_indexed_name(OP_COSIGN_PEGOUT_ID_KEY, op_index, word);
                op_cosign_pegout_id_keys.push(keys[op_index].get_winternitz(&op_key_name)?);
            }

            let mut scripts = vec![];
            for slot in 0..committee.packet_size as usize {
                let op_slot_id_key =
                    keys[op_index].get_winternitz(&indexed_name(SLOT_ID_KEY, slot))?;

                let op_pegout_id_key =
                    keys[op_index].get_winternitz(&indexed_name(PEGOUT_ID_KEY, slot))?;

                // Validate OP signature and WT slot_id Winternitz signature
                let mut s = scripts::init_challenge_script(
                    wt_dispute_key,
                    self.get_sign_mode(data.member_index),
                    slot as u32,
                    op_index,
                    &op_slot_id_key,
                    op_pegout_id_key,
                    &wt_cosign_slot_key,
                    &wt_cosign_pegout_id_keys,
                )?;

                // Validate slot id in the script. It's used to extract the leaf index when detected a transaction spending the WT_START_ENABLER_TX output, to know which slot is being challenged.
                s.set_assert_leaf_id(slot as u32);
                scripts.push(s);
            }

            let init_challenge_name =
                double_indexed_name(WT_INIT_CHALLENGE_TX, data.member_index, op_index);
            let op_cosign_name = double_indexed_name(OP_COSIGN_TX, data.member_index, op_index);
            let op_no_cosign_name =
                double_indexed_name(OP_NO_COSIGN_TX, data.member_index, op_index);
            let wt_no_challenge_name =
                double_indexed_name(WT_NO_CHALLENGE_TX, data.member_index, op_index);

            protocol.add_connection(
                "init_challenge",
                WT_START_ENABLER_TX,
                OutputType::taproot(AmountType::Auto, &wt_dispute_key, &scripts)?.into(),
                &init_challenge_name,
                InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
                None,
                None,
            )?;

            let op_cosign_slot_key = keys[op_index].get_winternitz(OP_COSIGN_SLOT_KEY)?;
            let cosign_script = scripts::cosign_script(
                op_dispute_key,
                self.get_sign_mode(op_index),
                op_index,
                op_cosign_slot_key,
                wt_cosign_slot_key,
                &op_cosign_pegout_id_keys,
                &wt_cosign_pegout_id_keys,
            )?;

            let verify_dispute_aggregated =
                verify_signature(&committee.dispute_aggregated_key, SignMode::Aggregate)?;

            let op_no_cosign_timelock_script = timelock(
                settings.op_no_cosign_timelock,
                &wt_dispute_key,
                self.get_sign_mode(data.member_index),
            );

            let init_challenge_output = OutputType::taproot(
                AmountType::Auto,
                op_dispute_key,
                &vec![
                    cosign_script,
                    op_no_cosign_timelock_script,
                    verify_dispute_aggregated.clone(),
                ],
            )?;

            protocol.add_connection(
                "op_cosign",
                &init_challenge_name,
                init_challenge_output.clone().into(),
                &op_cosign_name,
                InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
                None,
                None,
            )?;

            init_challenge_cosign_outputs.push(Some(init_challenge_output));

            // NOTE: DRP consumes leaf 1 hardcoded.
            let verify_wt_signature =
                verify_signature(wt_dispute_key, self.get_sign_mode(data.member_index))?;

            let wt_not_challenge_timelock_script = timelock(
                settings.wt_no_challenge_timelock,
                &committee.dispute_aggregated_key,
                SignMode::Aggregate,
            );

            let op_cosign_output = OutputType::taproot(
                challenge_cost,
                wt_dispute_key,
                &vec![wt_not_challenge_timelock_script, verify_wt_signature],
            )?;

            op_cosign_outputs.push(Some(op_cosign_output.clone()));

            protocol.add_connection(
                "wt_no_challenge",
                &op_cosign_name,
                op_cosign_output.into(),
                &wt_no_challenge_name,
                InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
                Some(settings.wt_no_challenge_timelock),
                None,
            )?;

            // OP NO COSIGN TX. The remaining input, consuming the WT claim gate stopper, is added
            // by create_claim_init.
            protocol.add_connection(
                "op_no_cosign",
                &init_challenge_name,
                OutputSpec::Index(0),
                &op_no_cosign_name,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::Script {
                        leaf: WT_INIT_CHALLENGE_TX_TIMELOCK_LEAF,
                    },
                ),
                Some(settings.op_no_cosign_timelock),
                None,
            )?;

            protocol.add_transaction_output(
                &init_challenge_name,
                &OutputType::segwit_key(SPEEDUP_VALUE, &wt_speedup_key)?,
            )?;
        }

        // Second output block of WT_START_ENABLER_TX: one output per member funding
        // CLAIM_INIT_TX, which carries both claim gates. Same skip rule as the first block.
        let mut claim_init_outputs: Vec<Option<ClaimInitOutputs>> = vec![];

        for op_index in 0..committee.members.len() {
            if !self.is_challengeable_operator(data, committee, op_index) {
                protocol.add_transaction_output(
                    WT_START_ENABLER_TX,
                    &OutputType::taproot(
                        AmountType::Auto,
                        &committee.dispute_aggregated_key,
                        &vec![],
                    )?,
                )?;

                claim_init_outputs.push(None);
                continue;
            }

            claim_init_outputs.push(Some(
                self.create_claim_init(protocol, data, committee, keys, settings, op_index)?,
            ));
        }

        let op_count = committee
            .members
            .iter()
            .filter(|m| m.role == ParticipantRole::Prover)
            .count() as u64;

        let wt_disabler_directory_fee = estimate_fee(2, op_count as usize * 2 + 1, 1);

        let disabler_directory_funds_output = OutputType::taproot(
            SPEEDUP_VALUE * op_count * 2 as u64 + wt_disabler_directory_fee,
            &committee.dispute_aggregated_key,
            &[],
        )?;
        protocol.add_transaction_output(&WT_START_ENABLER_TX, &disabler_directory_funds_output)?;

        // Add speedup output
        protocol.add_transaction_output(
            &WT_START_ENABLER_TX,
            &OutputType::segwit_key(SPEEDUP_VALUE, &wt_speedup_key)?,
        )?;

        Ok((
            init_challenge_cosign_outputs,
            claim_init_outputs,
            disabler_directory_funds_output,
            op_cosign_outputs,
        ))
    }

    /// Creates CLAIM_INIT_TX_<wt>_<op>, spending a WT_START_ENABLER_TX output locked to the
    /// dispute aggregated key. It holds the WT and OP claim gates plus the two stopper outputs
    /// consumed by OP_NO_COSIGN_TX and WT_NO_CHALLENGE_TX, and ends with a speedup output for the
    /// watchtower followed by one for the operator.
    fn create_claim_init(
        &self,
        protocol: &mut Protocol,
        data: &DisputeCoreData,
        committee: &Committee,
        keys: &Vec<ParticipantKeys>,
        settings: &PacketSettings,
        op_index: usize,
    ) -> Result<ClaimInitOutputs, BitVMXError> {
        let wt_speedup_key = keys[data.member_index].get_public(SPEEDUP_KEY)?;
        let op_speedup_key = keys[op_index].get_public(SPEEDUP_KEY)?;

        let claim_init_name = double_indexed_name(CLAIM_INIT_TX, data.member_index, op_index);
        let op_no_cosign_name = double_indexed_name(OP_NO_COSIGN_TX, data.member_index, op_index);
        let wt_no_challenge_name =
            double_indexed_name(WT_NO_CHALLENGE_TX, data.member_index, op_index);
        let wt_claim_name = double_indexed_name(WT_CLAIM_GATE, data.member_index, op_index);
        let op_claim_name = double_indexed_name(OP_CLAIM_GATE, data.member_index, op_index);

        protocol.add_connection(
            "claim_init",
            WT_START_ENABLER_TX,
            OutputType::taproot(AmountType::Auto, &committee.dispute_aggregated_key, &vec![])?
                .into(),
            &claim_init_name,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        let key_pair_name = get_dispute_pair_key_name(data.member_index, op_index);
        let key_pair = keys[data.member_index].get_public(&key_pair_name)?;

        // Create WT claim gate
        let wt_claim_gate = ClaimGate::new(
            protocol,
            &claim_init_name,
            &wt_claim_name,
            (wt_speedup_key, self.get_sign_mode(data.member_index)),
            &committee.dispute_aggregated_key,
            CLAIM_GATE_FEE,
            DUST_VALUE,
            vec![op_speedup_key],
            Some(vec![key_pair]),
            settings.claim_gate_timelock,
            1, // Single output to connect to FullPenalization
            vec![],
            true,
            None,
        )?;

        if wt_claim_gate.stoppers.len() != 1 {
            return Err(BitVMXError::InvalidParameter(
                "Expected exactly one stopper output in WT claim gate".to_string(),
            ));
        }

        // Create OP claim gate
        let op_claim_gate = ClaimGate::new(
            protocol,
            &claim_init_name,
            &op_claim_name,
            (op_speedup_key, self.get_sign_mode(op_index)),
            &committee.dispute_aggregated_key,
            CLAIM_GATE_FEE,
            DUST_VALUE,
            vec![wt_speedup_key],
            Some(vec![key_pair]),
            settings.claim_gate_timelock,
            1, // Single output to connect to FullPenalization
            vec![],
            false,
            wt_claim_gate.exclusive_success_vout,
        )?;

        if op_claim_gate.stoppers.len() != 1 {
            return Err(BitVMXError::InvalidParameter(
                "Expected exactly one stopper output in OP claim gate".to_string(),
            ));
        }

        // OP NO COSIGN TX. Consumes the WT claim gate stopper so the OP can no longer be stopped
        // by it. Input 0 comes from WT_INIT_CHALLENGE_TX and is added by create_wt_start_enabler.
        protocol.add_connection(
            "op_no_cosign",
            &claim_init_name,
            OutputSpec::Index(wt_claim_gate.vout + 1),
            &op_no_cosign_name,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::Script {
                    leaf: CLAIM_GATE_INIT_STOPPER_COMMITTEE_LEAF,
                },
            ),
            None,
            None,
        )?;

        protocol.add_transaction_output(
            &op_no_cosign_name,
            &OutputType::segwit_unspendable(op_return_script(vec![])?.get_script().clone())?,
        )?;

        // WT NO CHALLENGE TX
        protocol.add_connection(
            "wt_no_challenge",
            &claim_init_name,
            OutputSpec::Index(op_claim_gate.vout + 1),
            &wt_no_challenge_name,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::Script {
                    leaf: CLAIM_GATE_INIT_STOPPER_COMMITTEE_LEAF,
                },
            ),
            None,
            None,
        )?;

        // TODO: Should we add an output to recover challenge funds? it's about 38_000 sats.
        protocol.add_transaction_output(
            &wt_no_challenge_name,
            &OutputType::segwit_unspendable(op_return_script(vec![])?.get_script().clone())?,
        )?;

        // Speedup outputs are kept last so their vouts can be derived relative to the output
        // count. The watchtower output precedes the operator output.
        protocol.add_transaction_output(
            &claim_init_name,
            &OutputType::segwit_key(SPEEDUP_VALUE, wt_speedup_key)?,
        )?;
        protocol.add_transaction_output(
            &claim_init_name,
            &OutputType::segwit_key(SPEEDUP_VALUE, op_speedup_key)?,
        )?;

        Ok(ClaimInitOutputs {
            wt_stopper: wt_claim_gate.stoppers[0].clone(),
            op_stopper: op_claim_gate.stoppers[0].clone(),
        })
    }

    fn create_op_initial_deposit(
        &self,
        protocol: &mut Protocol,
        operator_dispute_key: &PublicKey,
        dispute_aggregated_key: &PublicKey,
    ) -> Result<(), BitVMXError> {
        // Connect the initial deposit transaction to the PROTOCOL_FUNDING_TX transaction.
        protocol.add_connection(
            "initial_deposit",
            &PROTOCOL_FUNDING_TX,
            OutputSpec::Auto(OutputType::taproot(
                AmountType::Auto,
                dispute_aggregated_key,
                &[],
            )?),
            &OP_INITIAL_DEPOSIT_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        // Connect the self-disabler (recover funds) transaction.
        protocol.add_connection(
            "self_disabler",
            &PROTOCOL_FUNDING_TX,
            OutputSpec::Index(1),
            &OP_SELF_DISABLER_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        protocol.add_transaction_output(
            &OP_SELF_DISABLER_TX,
            &OutputType::segwit_key(AmountType::Recover, operator_dispute_key)?,
        )?;

        Ok(())
    }

    fn create_reimbursement_output(
        &self,
        dispute_core_data: &DisputeCoreData,
        keys: &Vec<ParticipantKeys>,
        committee: &Committee,
        settings: &PacketSettings,
    ) -> Result<Vec<OutputType>, BitVMXError> {
        let mut outputs = vec![];
        let member_count = keys.len();
        let owner_index = dispute_core_data.member_index;

        if keys.len() != committee.members.len() {
            return Err(BitVMXError::InvalidList(
                "Keys length does not match committee members length".to_string(),
            ));
        }

        for slot_index in 0..committee.packet_size {
            let mut scripts = vec![];
            let key_name = indexed_name(CHALLENGE_KEY, slot_index as usize);

            for member_index in 0..member_count {
                // If this is the operator owning the dispute core, we use a long timelock for the operator take transaction,
                // otherwise a short one for the challenge transaction.
                let script = if member_index == owner_index {
                    timelock(
                        settings.long_timelock,
                        &committee.members[member_index].dispute_key.clone(),
                        self.get_sign_mode(member_index),
                    )
                } else {
                    verify_winternitz_signature_timelock(
                        settings.short_timelock,
                        &committee.dispute_aggregated_key,
                        CHALLENGE_KEY,
                        keys[member_index].get_winternitz(&key_name)?,
                        SignMode::Aggregate,
                    )?
                };
                scripts.push(script);
            }

            outputs.push(OutputType::taproot(
                AmountType::Auto,
                &committee.take_aggregated_key,
                scripts.as_slice(),
            )?)
        }

        Ok(outputs)
    }

    fn create_dispute_core<BC: BitcoinCoordinatorApi>(
        &self,
        protocol: &mut Protocol,
        committee: &Committee,
        dispute_core_data: &DisputeCoreData,
        dispute_core_index: usize,
        keys: &Vec<ParticipantKeys>,
        reimbursement_output: OutputType,
        context: &ProgramContext<BC>,
        reveal_output: &OutputType,
        settings: &PacketSettings,
    ) -> Result<(), BitVMXError> {
        // Operator keys
        let operator_keys = keys[dispute_core_data.member_index].clone();
        let operator_dispute_key = &committee.members[dispute_core_data.member_index].dispute_key;

        // Aggregated keys
        let dispute_aggregated_key = &committee.dispute_aggregated_key;

        // Pegout ID key
        let pegout_id_name = indexed_name(PEGOUT_ID_KEY, dispute_core_index);
        let pegout_id_key = operator_keys.get_winternitz(&pegout_id_name)?;

        // TX names
        let reimbursement_kickoff = indexed_name(REIMBURSEMENT_KICKOFF_TX, dispute_core_index);
        let challenge = indexed_name(CHALLENGE_TX, dispute_core_index);
        let reveal_input = indexed_name(REVEAL_INPUT_TX, dispute_core_index);
        let input_not_revealed = indexed_name(INPUT_NOT_REVEALED_TX, dispute_core_index);

        let start_reimbursement = scripts::verify_winternitz(
            dispute_aggregated_key,
            SignMode::Aggregate,
            &pegout_id_name,
            pegout_id_key,
        )?;

        let validate_dispute_key = protocol_builder::scripts::verify_signature(
            dispute_aggregated_key,
            SignMode::Aggregate,
        )?;

        // Save start_reimbursement script by dispute_core_index. It will be used in FullPenalizationProtocol
        context.globals.set_var(
            &self.ctx.id,
            &indexed_name(OP_INITIAL_DEPOSIT_OUT_SCRIPT, dispute_core_index),
            VariableTypes::String(serde_json::to_string(&[
                &start_reimbursement,
                &validate_dispute_key,
            ])?),
        )?;

        // We use the operator's dispute key as internal key to use the key spend path for self disablement.
        protocol.add_connection(
            "start_dispute_core",
            &OP_INITIAL_DEPOSIT_TX,
            get_initial_deposit_output_type(
                AmountType::Auto,
                operator_dispute_key,
                &[start_reimbursement, validate_dispute_key],
            )?
            .into(),
            &reimbursement_kickoff,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            None,
        )?;

        protocol.add_connection(
            "challenge",
            &reimbursement_kickoff,
            reimbursement_output.into(),
            &challenge,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            Some(settings.short_timelock),
            None,
        )?;

        let key_name = &indexed_name(SLOT_ID_KEY, dispute_core_index);
        let slot_id_key = operator_keys.get_winternitz(key_name)?;
        let reveal_script = protocol_builder::scripts::verify_winternitz_signatures_aux(
            &operator_dispute_key,
            &vec![(key_name, slot_id_key)],
            self.get_sign_mode(dispute_core_data.member_index),
            false,
            None,
        )?;

        let not_reveal_script = protocol_builder::scripts::timelock(
            settings.input_not_revealed_timelock,
            &committee.dispute_aggregated_key,
            SignMode::Aggregate,
        );

        protocol.add_connection(
            "reveal_input",
            &challenge,
            OutputType::taproot(
                AmountType::Auto,
                dispute_aggregated_key,
                &[reveal_script, not_reveal_script],
            )?
            .into(),
            &reveal_input,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            None,
        )?;

        protocol.add_transaction_output(&reveal_input, reveal_output)?;

        protocol.add_connection(
            "input_not_revealed",
            &challenge,
            OutputSpec::Index(0),
            &input_not_revealed,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            Some(settings.input_not_revealed_timelock),
            None,
        )?;

        self.add_dispute_core_speedup_outputs(
            protocol,
            keys,
            dispute_core_index,
            dispute_core_data.member_index,
            committee,
        )?;

        Ok(())
    }

    fn create_two_dispute_penalization(
        &self,
        protocol: &mut Protocol,
        dispute_core_index: usize,
        committee: &Committee,
    ) -> Result<(), BitVMXError> {
        let last_reveal = indexed_name(REVEAL_INPUT_TX, dispute_core_index);

        if dispute_core_index == 0 {
            // No previous reveal transaction to connect to.
            return Ok(());
        }

        for i in 0..dispute_core_index {
            let prev_reveal = indexed_name(REVEAL_INPUT_TX, i);
            let two_dispute_penalization =
                double_indexed_name(TWO_DISPUTE_PENALIZATION_TX, i, dispute_core_index);

            protocol.add_connection(
                "prev_reveal",
                &prev_reveal,
                OutputSpec::Index(0),
                &two_dispute_penalization,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::KeyOnly {
                        key_path_sign: SignMode::Aggregate,
                    },
                ),
                None,
                None,
            )?;

            protocol.add_connection(
                "last_reveal",
                &last_reveal,
                OutputSpec::Index(0),
                &two_dispute_penalization,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::KeyOnly {
                        key_path_sign: SignMode::Aggregate,
                    },
                ),
                None,
                None,
            )?;

            add_speedups(protocol, &two_dispute_penalization, committee)?;
        }

        Ok(())
    }

    fn add_dispute_core_speedup_outputs(
        &self,
        protocol: &mut Protocol,
        keys: &Vec<ParticipantKeys>,
        dispute_core_index: usize,
        operator_index: usize,
        committee: &Committee,
    ) -> Result<(), BitVMXError> {
        let reimbursement_kickoff = indexed_name(REIMBURSEMENT_KICKOFF_TX, dispute_core_index);
        let challenge = indexed_name(CHALLENGE_TX, dispute_core_index);
        let reveal_input = indexed_name(REVEAL_INPUT_TX, dispute_core_index);
        let input_not_revealed = indexed_name(INPUT_NOT_REVEALED_TX, dispute_core_index);
        let operator_speedup_key = keys[operator_index].get_public(SPEEDUP_KEY)?;

        // Add a speedup output to the initial_deposit transaction when the last initial deposit
        // output has been added.
        if dispute_core_index == (committee.packet_size - 1) as usize {
            // Operator output for disabler directory
            // NOTE: 1 additional outputs: speedup.
            let directory_fee = estimate_fee(2, committee.packet_size as usize + 1, 1);
            let disabler_directory_amount = committee.packet_size as u64 * get_op_disabler_directory_output_value(committee.members.len()) // The other half of SPEEDUP_VALUE came from REVEAL_INPUT_TX
                    + SPEEDUP_VALUE
                    + directory_fee;
            protocol.add_transaction_output(
                &OP_INITIAL_DEPOSIT_TX,
                &OutputType::taproot(
                    disabler_directory_amount,
                    &committee.dispute_aggregated_key,
                    &[],
                )?,
            )?;

            protocol.add_transaction_output(
                &OP_INITIAL_DEPOSIT_TX,
                &OutputType::segwit_key(AmountType::Auto, operator_speedup_key)?,
            )?;
        }

        // Add a speedup output to the reimbursement_kickoff transaction.
        protocol.add_transaction_output(
            &reimbursement_kickoff,
            &OutputType::segwit_key(AmountType::Auto, operator_speedup_key)?,
        )?;

        for i in 0..keys.len() {
            // Challenge outputs are CPFP speedups.
            let speedup_output =
                OutputType::segwit_key(AmountType::Auto, keys[i].get_public(SPEEDUP_KEY)?)?;
            protocol.add_transaction_output(&challenge, &speedup_output)?;

            // INPUT_NOT_REVEALED outputs are enablers for each member's STOPPER_TX and are therefore locked with member dispute keys.
            protocol.add_transaction_output(
                &input_not_revealed,
                &OutputType::segwit_key(AmountType::Auto, &committee.members[i].dispute_key)?,
            )?;
        }

        // Add a speedup output to the reveal_input transaction.
        protocol.add_transaction_output(
            &reveal_input,
            &OutputType::segwit_key(AmountType::Auto, operator_speedup_key)?,
        )?;

        Ok(())
    }

    fn add_funding_change(
        &self,
        protocol: &mut Protocol,
        member_change_key: &PublicKey,
        dispute_core_data: &DisputeCoreData,
    ) -> Result<(), BitVMXError> {
        // Add a change output to the PROTOCOL_FUNDING_TX transaction
        let funding_amount = dispute_core_data.funding_utxo.2.unwrap();
        let tx = protocol.transaction_by_name(&PROTOCOL_FUNDING_TX)?;
        let fees = estimate_fee(1, tx.output.len() + 1, 1);
        let mut total_cost = 0;

        for i in 0..tx.output.len() {
            total_cost += tx.output[i].value.to_sat();
        }

        let change = self.checked_sub(funding_amount, total_cost + fees)?;

        if change > DUST_VALUE {
            info!(
                "Adding change output of {} sats to {} transaction. Change exceeds dust value: {} sats",
                change, PROTOCOL_FUNDING_TX, DUST_VALUE
            );
            protocol
                .add_transaction_output(
                    &PROTOCOL_FUNDING_TX,
                    &OutputType::segwit_key(change, member_change_key)?,
                )
                .map_err(|e| BitVMXError::ProtocolBuilderError(e))?;
        }

        Ok(())
    }

    fn protocol_funding_tx<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        let tx_name = PROTOCOL_FUNDING_TX;
        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            tx_name,
            &vec![InputSigningInfo::SignEdcsa {
                input_index: 0,
                key_manager: context.key_manager.as_ref(),
            }],
        )?;

        let tx = protocol.transaction_to_send(&tx_name, &args)?;

        let txid = tx.compute_txid();
        let speedup_key = self.my_speedup_key(context)?;
        let speedup_vout = (tx.output.len() - 2) as u32;
        let speedup_utxo = Utxo::new(txid, speedup_vout, SPEEDUP_VALUE, &speedup_key);

        Ok((tx, Some(speedup_utxo.into())))
    }

    fn reimbursement_kickoff_tx<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        let leaf_index = 0;
        let slot_index = extract_index(name, REIMBURSEMENT_KICKOFF_TX)?;
        info!(id = self.ctx.my_idx, "Loading {} tx", name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![InputSigningInfo::ScriptSpend {
                input_index: 0,
                script_index: leaf_index,
                winternitz_data: Some(WinternitzData {
                    data: self.pegout_id(context, slot_index)?,
                    key_name: indexed_name(PEGOUT_ID_KEY, slot_index),
                    key_type: WinternitzType::HASH160,
                    key_manager: context.key_manager.as_ref(),
                }),
            }],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        info!(id = self.ctx.my_idx, "Signed {} tx", name);

        let txid = tx.compute_txid();
        let speedup_key = self.my_speedup_key(context)?;
        let speedup_vout = (tx.output.len() - 1) as u32;
        let speedup_utxo = Utxo::new(txid, speedup_vout, SPEEDUP_VALUE, &speedup_key);

        Ok((tx, Some(speedup_utxo.into())))
    }

    fn challenge_tx<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![InputSigningInfo::ScriptSpend {
                input_index: 0,
                script_index: self.ctx.my_idx,
                winternitz_data: Some(WinternitzData {
                    data: vec![1u8],
                    key_name: CHALLENGE_KEY.to_string(),
                    key_type: WinternitzType::HASH160,
                    key_manager: context.key_manager.as_ref(),
                }),
            }],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        info!(id = self.ctx.my_idx, "Signed {} tx", name);

        // Speedup data
        let speedup_utxo = Utxo::new(
            tx.compute_txid(),
            1 + self.ctx.my_idx as u32,
            SPEEDUP_VALUE,
            &self.my_speedup_key(context)?,
        );

        Ok((tx, Some(speedup_utxo.into())))
    }

    fn wt_init_challenge_tx<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", name);

        let (_, op_index) = extract_double_index(name)?;

        let protocol = self.load_protocol()?;
        let slot_index = self.get_number(
            context,
            &self.ctx.id,
            &indexed_name(INIT_CHALLENGE_SLOT, op_index),
        )? as usize;
        let input_index = 0;

        // Prepare signatures
        let wt_dispute_key_signature = protocol
            .input_taproot_script_spend_signature(name, input_index, slot_index)?
            .unwrap();

        let script = protocol.get_script_to_spend(name, input_index as u32, slot_index as u32)?;
        let wt_key_name = indexed_name(WT_COSIGN_SLOT_KEY, op_index);

        let key = script.get_key(&wt_key_name).ok_or_else(|| {
                BitVMXError::InvalidParameter(format!(
                    "Winternitz key '{}' not found in script. Tx name: {}. Input index: {}. Script index: {}",
                    wt_key_name, name, input_index, slot_index
                ))
            })?;

        let wt_slot_id_signature = context.key_manager.sign_winternitz_message_by_index(
            (slot_index as u32).to_be_bytes().as_slice(),
            WinternitzType::HASH160,
            key.derivation_index(),
        )?;

        // Create input arguments
        let mut input_args = InputArgs::new_taproot_script_args(slot_index);

        // Get OP slot key signature
        let op_slot_key_signature = context
            .witness
            .get_witness(
                &self.ctx.id,
                &double_indexed_name(SLOT_ID_KEY, op_index, slot_index),
            )?
            .unwrap()
            .winternitz()?;

        // Get OP Pegout Id signature
        let witness = context
            .witness
            .get_witness(
                &self.ctx.id,
                &double_indexed_name(PEGOUT_ID_KEY, op_index, slot_index),
            )?
            .unwrap();

        let op_pegout_id_signature = witness.winternitz()?;
        let pegout_id = witness.winternitz()?.message_bytes();
        info!("Pegout ID: {:?}", pegout_id);

        let wt_pegout_id_signatures = self.sign_pegout_id_words(
            context,
            &script,
            WT_COSIGN_PEGOUT_ID_KEY,
            op_index,
            &self.vec_to_words(&pegout_id),
        )?;

        // Signatures are reversed in sign_pegout_id_words
        for sig in wt_pegout_id_signatures {
            input_args.push_winternitz_signature(sig);
        }

        input_args.push_winternitz_signature(op_pegout_id_signature);
        input_args.push_winternitz_signature(op_slot_key_signature);
        input_args.push_winternitz_signature(wt_slot_id_signature);
        input_args.push_taproot_signature(wt_dispute_key_signature)?;
        input_args.push_slice(scriptint_vec(slot_index as i64).as_slice());

        let tx = protocol.transaction_to_send(&name, &[input_args])?;
        info!(id = self.ctx.my_idx, "Signed {} tx", name);

        // Speedup data
        let speedup_utxo = Utxo::new(
            tx.compute_txid(),
            tx.output.len() as u32 - 1,
            SPEEDUP_VALUE,
            &self.my_speedup_key(context)?,
        );

        Ok((tx, Some(speedup_utxo.into())))
    }

    /// Signs CLAIM_INIT_TX. Its single input is a key path spend with the dispute aggregated key.
    /// The speedup UTXO is selected for the local participant: the watchtower output is followed
    /// by the operator output.
    fn claim_init_tx<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", name);

        let mut protocol = self.load_protocol()?;
        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![InputSigningInfo::KeySpend { input_index: 0 }],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        info!(id = self.ctx.my_idx, "Signed {}", name);

        let (wt_index, op_index) = extract_double_index(name)?;
        let output_count = u32::try_from(tx.output.len())
            .map_err(|_| BitVMXError::InvalidParameter(format!("Too many outputs in {}", name)))?;
        if output_count < CLAIM_INIT_WT_SPEEDUP_OUTPUT_OFFSET_FROM_END {
            return Err(BitVMXError::InvalidParameter(format!(
                "{} must contain WT and OP speedup outputs",
                name
            )));
        }

        let speedup_vout = if self.ctx.my_idx == wt_index {
            output_count - CLAIM_INIT_WT_SPEEDUP_OUTPUT_OFFSET_FROM_END
        } else if self.ctx.my_idx == op_index {
            output_count - CLAIM_INIT_OP_SPEEDUP_OUTPUT_OFFSET_FROM_END
        } else {
            return Err(BitVMXError::InvalidParameter(format!(
                "Member {} cannot speed up {} for watchtower {} and operator {}",
                self.ctx.my_idx, name, wt_index, op_index
            )));
        };

        let speedup_utxo = Utxo::new(
            tx.compute_txid(),
            speedup_vout,
            SPEEDUP_VALUE,
            &self.my_speedup_key(context)?,
        );

        Ok((tx, Some(speedup_utxo.into())))
    }

    fn sign_pegout_id_words<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        script: &ProtocolScript,
        key_prefix: &str,
        op_index: usize,
        pegout_id_words: &Vec<u32>,
    ) -> Result<Vec<WinternitzSignature>, BitVMXError> {
        let mut signatures = vec![];

        for word in (0..PEGOUT_ID_KEY_WORDS).rev() {
            let key_name = double_indexed_name(key_prefix, op_index, word);

            let key = script.get_key(&key_name).ok_or_else(|| {
                BitVMXError::InvalidParameter(format!(
                    "Winternitz key '{}' not found in script.",
                    key_name
                ))
            })?;

            let signature = context.key_manager.sign_winternitz_message_by_index(
                pegout_id_words[word].to_be_bytes().as_ref(),
                WinternitzType::HASH160,
                key.derivation_index(),
            )?;

            signatures.push(signature);
        }
        Ok(signatures)
    }

    fn vec_to_words(&self, data: &Vec<u8>) -> Vec<u32> {
        data.chunks(4)
            .map(|chunk| {
                let mut word = [0u8; 4];
                word[..chunk.len()].copy_from_slice(chunk);
                u32::from_be_bytes(word)
            })
            .collect()
    }

    fn get_number<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        pid: &Uuid,
        var_name: &str,
    ) -> Result<u32, BitVMXError> {
        Ok(context.globals.get_var(pid, var_name)?.unwrap().number()?)
    }

    fn set_number<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        pid: &Uuid,
        var_name: &str,
        value: u32,
    ) -> Result<(), BitVMXError> {
        context
            .globals
            .set_var(pid, var_name, VariableTypes::Number(value))
    }

    fn dispute_core_data<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
    ) -> Result<DisputeCoreData, BitVMXError> {
        let data = context
            .globals
            .get_var(&self.ctx.id, &DisputeCoreData::name())?
            .unwrap()
            .string()?;

        let data: DisputeCoreData = serde_json::from_str(&data)?;
        Ok(data)
    }

    fn committee<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
    ) -> Result<Committee, BitVMXError> {
        let committee_id = self.committee_id(context)?;

        let committee = context
            .globals
            .get_var(&committee_id, &Committee::name())?
            .unwrap()
            .string()?;

        let committee: Committee = serde_json::from_str(&committee)?;
        Ok(committee)
    }

    fn is_prover<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
    ) -> Result<bool, BitVMXError> {
        match self.committee(context)?.members[self.ctx.my_idx].role {
            ParticipantRole::Prover => Ok(true),
            _ => Ok(false),
        }
    }

    fn my_speedup_key<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
    ) -> Result<PublicKey, BitVMXError> {
        Ok(context
            .globals
            .get_var(&self.ctx.id, SPEEDUP_KEY)?
            .unwrap()
            .pubkey()?)
    }

    // fn my_dispute_key<BC: BitcoinCoordinatorApi>(&self, context: &ProgramContext<BC>) -> Result<PublicKey, BitVMXError> {
    //     let committee = self.committee(context)?;
    //     Ok(committee.members[self.ctx.my_idx].dispute_key.clone())
    // }

    fn committee_id<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
    ) -> Result<Uuid, BitVMXError> {
        Ok(self.dispute_core_data(context)?.committee_id)
    }

    fn monitored_member_take_key<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
    ) -> Result<PublicKey, BitVMXError> {
        let committee = self.committee(context)?;
        let data = self.dispute_core_data(context)?;
        Ok(committee.members[data.member_index].take_key)
    }

    fn funds_advanced<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        slot_id: usize,
    ) -> Result<Option<AdvanceFundsRegistered>, BitVMXError> {
        let committee_id = self.committee_id(context)?;
        let funds_advanced_key = AdvanceFundsRegistered::name(slot_id);

        match context
            .globals
            .get_var(&committee_id, &funds_advanced_key)?
        {
            Some(funds_advanced_var) => {
                Ok(Some(serde_json::from_str(&funds_advanced_var.string()?)?))
            }
            None => Ok(None),
        }
    }

    fn get_reveal_in_progress<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
    ) -> Result<Option<u32>, BitVMXError> {
        match context.globals.get_var(&self.ctx.id, REVEAL_IN_PROGRESS)? {
            Some(var) => Ok(Some(var.number()?)),
            None => Ok(None),
        }
    }

    fn set_reveal_in_progress<BC: BitcoinCoordinatorApi>(
        &self,
        program_context: &ProgramContext<BC>,
        slot_index: usize,
    ) -> Result<(), BitVMXError> {
        info!(
            id = self.ctx.my_idx,
            "Setting reimbursement in progress for slot index: {}", slot_index
        );

        program_context.globals.set_var(
            &self.ctx.id,
            REVEAL_IN_PROGRESS,
            VariableTypes::Number(slot_index as u32),
        )
    }

    fn handle_wt_claim_gate_txs<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
        tx_status: &TransactionStatus,
    ) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Handling {}", tx_name);

        let (wt_index, op_index) = extract_index_from_claim_gate(tx_name)?;

        if tx_name.ends_with(CLAIM_GATE_START) {
            if self.is_my_dispute_core(context)? {
                let committee = self.committee(context)?;
                let settings = committee.settings;
                let blocks = self.get_dispatch_height(tx_status, settings.claim_gate_timelock)?;
                self.dispatch_claim_gate(
                    context,
                    ClaimGateAction::Success {
                        block_height: Some(blocks),
                    },
                    WT_CLAIM_GATE,
                    op_index,
                )?;
            } else {
                self.dispatch_claim_gate(
                    context,
                    ClaimGateAction::Stop {
                        with_speedup: self.ctx.my_idx == wt_index,
                    },
                    WT_CLAIM_GATE,
                    op_index,
                )?;
            }
        } else if tx_name.contains(CLAIM_GATE_STOP) {
            info!(
                id = self.ctx.my_idx,
                "Claim stopped for watchtower: {}", wt_index
            );
        } else if tx_name.ends_with(CLAIM_GATE_SUCCESS) {
            self.dispatch(
                context,
                DisputeCoreTxType::OperatorDisablerDirectory { wt_index, op_index },
            )?;
        } else {
            error!(
                id = self.ctx.my_idx,
                "Unknown claim gate transaction name: {}", tx_name
            );
        }

        Ok(())
    }

    fn get_drp_op_index<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        pid: Uuid,
        wt_index: usize,
    ) -> Result<Option<usize>, BitVMXError> {
        let committee_id = self.committee_id(context)?;
        let committee = self.committee(context)?;

        // Look for the operator index that matches the DisputeChannel program ID in the context
        let maybe_index = committee
            .members
            .iter()
            .enumerate()
            .find(|(op_index, _)| get_dispute_channel_pid(committee_id, *op_index, wt_index) == pid)
            .map(|(op_index, _)| op_index);

        Ok(maybe_index)
    }

    fn handle_start_challenge<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        pid: Uuid,
    ) -> Result<(), BitVMXError> {
        info!("Handling start challenge. PID: {}", pid);

        // Need to load my_idx from storage because self.ctx.my_idx has my index on DRP
        let my_idx = get_my_idx(context, self.ctx.id)?;
        let wt_index = self.dispute_core_data(context)?.member_index;

        if wt_index == my_idx {
            info!("Start challenge triggered by watchtower for PID {}. Ignoring since I'm the watchtower.", pid);
            return Ok(());
        }

        let drp_op_index = match self.get_drp_op_index(context, pid, wt_index)? {
            Some(index) => index,
            None => {
                error!("PID {} do not match DisputeChannel program", pid);
                return Ok(());
            }
        };

        info!(
            "DisputeChannel operator index for PID {} is {}",
            pid, drp_op_index
        );

        self.cancel_dispatch(
            context,
            &double_indexed_name(WT_NO_CHALLENGE_TX, wt_index, drp_op_index),
            None,
        );
        Ok(())
    }

    fn handle_action_wins<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
        role: ParticipantRole,
        pid: Uuid,
    ) -> Result<(), BitVMXError> {
        // Need to load my_idx from storage because self.ctx.my_idx has my index on DRP
        let my_idx = get_my_idx(context, self.ctx.id)?;

        info!(
            id = my_idx,
            "Handling wins action {}. PID: {}", tx_name, pid
        );

        let wt_index = self.dispute_core_data(context)?.member_index;
        let drp_op_index = match self.get_drp_op_index(context, pid, wt_index)? {
            Some(index) => index,
            None => {
                error!("PID {} do not match DisputeChannel program", pid);
                return Ok(());
            }
        };

        info!(
            "DisputeChannel operator index for PID {} is {}",
            pid, drp_op_index
        );

        if role == ParticipantRole::Prover {
            if my_idx == drp_op_index {
                self.dispatch_claim_gate(
                    context,
                    ClaimGateAction::Start,
                    OP_CLAIM_GATE,
                    drp_op_index,
                )?;
            }
        } else if role == ParticipantRole::Verifier {
            if my_idx == wt_index {
                self.dispatch_claim_gate(
                    context,
                    ClaimGateAction::Start,
                    WT_CLAIM_GATE,
                    drp_op_index,
                )?;
            }
        }

        Ok(())
    }

    fn handle_op_no_cosign_tx<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Handling {}", tx_name);
        let (_, op_index) = extract_double_index(tx_name)?;

        if self.is_my_dispute_core(context)? {
            self.dispatch_claim_gate(context, ClaimGateAction::Start, WT_CLAIM_GATE, op_index)?;
        }

        Ok(())
    }

    fn handle_wt_no_challenge_tx<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Handling {}", tx_name);
        let (_, op_index) = extract_double_index(tx_name)?;

        if op_index == self.ctx.my_idx {
            self.dispatch_claim_gate(context, ClaimGateAction::Start, OP_CLAIM_GATE, op_index)?;
        }

        Ok(())
    }

    fn handle_op_claim_gate_txs<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
        tx_status: &TransactionStatus,
    ) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Handling {}", tx_name);

        let (wt_index, op_index) = extract_index_from_claim_gate(tx_name)?;

        if tx_name.ends_with(CLAIM_GATE_START) {
            if self.ctx.my_idx == op_index {
                let committee = self.committee(context)?;
                let settings = committee.settings;
                let blocks = self.get_dispatch_height(tx_status, settings.claim_gate_timelock)?;
                self.dispatch_claim_gate(
                    context,
                    ClaimGateAction::Success {
                        block_height: Some(blocks),
                    },
                    OP_CLAIM_GATE,
                    op_index,
                )?;
            } else {
                self.dispatch_claim_gate(
                    context,
                    ClaimGateAction::Stop {
                        with_speedup: self.ctx.my_idx == wt_index,
                    },
                    OP_CLAIM_GATE,
                    op_index,
                )?;
            }
        } else if tx_name.contains(CLAIM_GATE_STOP) {
            info!(
                id = self.ctx.my_idx,
                "Claim stopped for operator: {}", op_index
            );
        } else if tx_name.ends_with(CLAIM_GATE_SUCCESS) {
            self.dispatch(
                context,
                DisputeCoreTxType::WatchtowerDisablerDirectory { wt_index, op_index },
            )?;
        } else {
            error!(
                id = self.ctx.my_idx,
                "Unknown claim gate transaction name: {}", tx_name
            );
        }

        Ok(())
    }

    fn claim_gate_tx<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        name: &str,
        signing_infos: &Vec<InputSigningInfo>,
        with_speedup: bool,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", name);

        let mut protocol = self.load_protocol()?;
        let args = collect_input_signatures(&mut protocol, name, signing_infos)?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        info!(id = self.ctx.my_idx, "Signed {}", name);

        let speedup_utxo: Option<SpeedupData> = if with_speedup {
            Some(
                Utxo::new(
                    tx.compute_txid(),
                    tx.output.len() as u32 - 1,
                    SPEEDUP_VALUE,
                    &self.my_speedup_key(context)?,
                )
                .into(),
            )
        } else {
            None
        };

        Ok((tx, speedup_utxo))
    }

    fn get_dispatch_height(
        &self,
        tx_status: &TransactionStatus,
        timelock: u16,
    ) -> Result<u32, BitVMXError> {
        let block_height = tx_status
            .block_info
            .as_ref()
            .ok_or(BitVMXError::InvalidParameter(
                "TransactionStatus missing block_info".to_string(),
            ))?
            .height;

        Ok(block_height + timelock as u32)
    }

    fn dispatch_claim_gate<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        action: ClaimGateAction,
        prefix: &str,
        op_index: usize,
    ) -> Result<(), BitVMXError> {
        let data = self.dispute_core_data(context)?;
        let base = double_indexed_name(prefix, data.member_index, op_index);
        let tx_name = action.tx_name(&base);
        info!(id = self.ctx.my_idx, "Claim gate dispatching {}", tx_name);

        let (tx, speedup) =
            self.claim_gate_tx(context, &tx_name, &action.inputs(), action.with_speedup())?;

        self.log_and_dispatch(
            context,
            &tx_name,
            tx,
            speedup,
            action.block_height(),
            self.ctx.id,
        )?;

        Ok(())
    }

    fn handle_op_cosign_tx<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
        tx_status: &TransactionStatus,
    ) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Handling {}", tx_name);
        let committee = self.committee(context)?;
        let settings = committee.settings;
        let (wt_index, op_index) = extract_double_index(tx_name)?;

        let protocol = self.load_protocol()?;
        self.decode_witness_for_tx(
            tx_name,
            OP_COSIGN_INIT_CHALLENGE_INDEX as u32,
            context,
            tx_status.tx_or_err()?,
            Some(WT_INIT_CHALLENGE_TX_COSIGN_LEAF as u32),
            Some(protocol),
            None,
        )?;

        let witness = context
            .witness
            .get_witness(&self.ctx.id, &indexed_name(OP_COSIGN_SLOT_KEY, op_index))?
            .unwrap();

        // Re set witness with _0 postfix due to it's a single value
        context.witness.set_witness(
            &self.ctx.id,
            &double_indexed_name(OP_COSIGN_SLOT_KEY, op_index, 0),
            witness.clone(),
        )?;

        if self.is_my_dispute_core(context)? {
            self.cancel_dispatch(
                context,
                &double_indexed_name(OP_NO_COSIGN_TX, wt_index, op_index),
                None,
            );

            let drp_pid =
                get_dispute_channel_pid(self.committee_id(context)?, op_index, self.ctx.my_idx);
            let drp_protocol = self.load_protocol_by_name(PROGRAM_TYPE_DRP, drp_pid)?;

            let (tx, speedup) = drp_protocol.get_transaction_by_name(dispute::START_CH, context)?;

            self.log_and_dispatch(context, dispute::START_CH, tx, speedup, None, drp_pid)?;
        } else if op_index == self.ctx.my_idx {
            let block_height =
                Some(self.get_dispatch_height(tx_status, settings.wt_no_challenge_timelock)?);
            let data = self.dispute_core_data(context)?;

            self.dispatch(
                context,
                DisputeCoreTxType::WatchtowerNoChallenge {
                    wt_index: data.member_index,
                    op_index,
                    block_height,
                },
            )?;
        }

        Ok(())
    }

    fn claim_init_mined_key(op_index: usize) -> String {
        indexed_name(CLAIM_INIT_MINED, op_index)
    }

    fn is_claim_init_mined<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        protocol_id: &Uuid,
        op_index: usize,
    ) -> Result<bool, BitVMXError> {
        Ok(context
            .globals
            .get_var(protocol_id, &Self::claim_init_mined_key(op_index))?
            .unwrap_or_else(|| VariableTypes::Bool(false))
            .bool()?)
    }

    fn handle_claim_init_tx<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        let (_, op_index) = extract_double_index(tx_name)?;

        context.globals.set_var(
            &self.ctx.id,
            &Self::claim_init_mined_key(op_index),
            VariableTypes::Bool(true),
        )?;

        info!(
            id = self.ctx.my_idx,
            "Recorded {} as mined for operator {} in protocol {}", tx_name, op_index, self.ctx.id
        );

        Ok(())
    }

    fn wt_no_challenge_tx(
        &self,
        name: &str,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![
                InputSigningInfo::ScriptSpend {
                    input_index: 0,
                    script_index: OP_COSIGN_TX_TIMELOCK_LEAF,
                    winternitz_data: None,
                },
                InputSigningInfo::ScriptSpend {
                    input_index: 1,
                    script_index: CLAIM_GATE_INIT_STOPPER_COMMITTEE_LEAF,
                    winternitz_data: None,
                },
            ],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        info!(id = self.ctx.my_idx, "Signed {}", name);

        Ok((tx, None))
    }

    fn handle_wt_init_challenge<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
        tx_status: &TransactionStatus,
    ) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Handling {}", tx_name);

        let committee = self.committee(context)?;
        let settings = committee.settings;
        let data = self.dispute_core_data(context)?;
        let (_, op_index) = extract_double_index(tx_name)?;

        if self.is_my_dispute_core(context)? {
            let block_height =
                Some(self.get_dispatch_height(tx_status, settings.op_no_cosign_timelock)?);
            self.dispatch(
                context,
                DisputeCoreTxType::OperatorNoCosign {
                    wt_index: data.member_index,
                    op_index,
                    block_height,
                },
            )?;
            return Ok(());
        }

        if self.handle_penalized_watchtower(context, &data, op_index)? {
            info!(
                id = self.ctx.my_idx,
                "Watchtower already penalized for member index: {}, skipping OP_COSIGN dispatch",
                data.member_index
            );
            return Ok(());
        }

        if op_index == self.ctx.my_idx {
            if !self.is_claim_init_mined(context, &self.ctx.id, op_index)? {
                info!(
                id = self.ctx.my_idx,
                "CLAIM_INIT_TX is not mined for operator {}, dispatching it with the operator speedup",
                op_index
            );
                self.dispatch(
                    context,
                    DisputeCoreTxType::ClaimInit {
                        wt_index: data.member_index,
                        op_index,
                    },
                )?;
            }

            // OP should save WT cosign data from the witness, and then dispatch OP_COSIGN tx
            self.dispatch_op_cosign(context, tx_name, tx_status, data.member_index, op_index)?;
        }

        Ok(())
    }

    fn dispatch_op_cosign<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
        tx_status: &TransactionStatus,
        wt_index: usize,
        op_index: usize,
    ) -> Result<(), BitVMXError> {
        let protocol = self.load_protocol()?;
        let leaf: (Vec<String>, u32) = self.decode_witness_for_tx(
            tx_name,
            WT_INIT_CHALLENGE_COSIGN_INDEX as u32,
            context,
            tx_status.tx_or_err()?,
            None,
            Some(protocol),
            None,
        )?;

        info!(
            id = self.ctx.my_idx,
            "Decoded witness for {}, leaf: {}", tx_name, leaf.1
        );

        // It's OK to save the leaf data directly (without indexing it) because this OP could be challenged by this WT just once.
        // This protocol should not handle WT_INIT_CHALLENGE TXs from others OPs.
        self.set_number(context, &self.ctx.id, INIT_CHALLENGE_SLOT, leaf.1)?;

        self.dispatch(
            context,
            DisputeCoreTxType::OperatorCosign { wt_index, op_index },
        )?;

        Ok(())
    }

    fn handle_penalized_watchtower<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        data: &DisputeCoreData,
        op_index: usize,
    ) -> Result<bool, BitVMXError> {
        // op_index is the OP that is being challenged by the WT that is probably penalized.
        match load_penalized_member(
            context,
            data.committee_id,
            data.member_index,
            ParticipantRole::Verifier,
        )? {
            Some(penalized_member) => {
                info!(
                    id = self.ctx.my_idx,
                    "Watchtower already penalized for member index: {}, skipping OP_COSIGN dispatch",
                    data.member_index
                );

                self.dispatch(
                    context,
                    DisputeCoreTxType::PenalizationWatchtowerDisabler {
                        wt_index: penalized_member.member_index,
                        op_disabler_directory_index: penalized_member.challenger_index,
                        op_index,
                    },
                )?;

                self.dispatch(
                    context,
                    DisputeCoreTxType::PenalizationWatchtowerCosignDisabler {
                        wt_index: penalized_member.member_index,
                        op_disabler_directory_index: penalized_member.challenger_index,
                        op_index,
                    },
                )?;

                return Ok(true);
            }
            None => {
                return Ok(false);
            }
        }
    }

    fn op_no_cosign_tx(
        &self,
        name: &str,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![
                InputSigningInfo::ScriptSpend {
                    input_index: 0,
                    script_index: WT_INIT_CHALLENGE_TX_TIMELOCK_LEAF,
                    winternitz_data: None,
                },
                InputSigningInfo::ScriptSpend {
                    input_index: 1,
                    script_index: CLAIM_GATE_INIT_STOPPER_COMMITTEE_LEAF,
                    winternitz_data: None,
                },
            ],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        info!(id = self.ctx.my_idx, "Signed {}", name);

        Ok((tx, None))
    }

    fn op_cosign_tx<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", name);
        let protocol = self.load_protocol()?;
        let input_index = OP_COSIGN_INIT_CHALLENGE_INDEX;

        // This value is saved in handle_wt_init_challenge when OP receives WT_INIT_CHALLENGE tx
        let slot_index = self.get_number(context, &self.ctx.id, INIT_CHALLENGE_SLOT)? as usize;
        let (_, op_index) = extract_double_index(name)?;

        // Prepare signatures
        let op_dispute_key_signature = protocol
            .input_taproot_script_spend_signature(
                name,
                input_index,
                WT_INIT_CHALLENGE_TX_COSIGN_LEAF,
            )?
            .unwrap();

        let script = protocol.get_script_to_spend(
            name,
            input_index as u32,
            WT_INIT_CHALLENGE_TX_COSIGN_LEAF as u32,
        )?;

        let op_key_name = indexed_name(OP_COSIGN_SLOT_KEY, op_index);

        let key = script.get_key(&op_key_name).ok_or_else(|| {
                BitVMXError::InvalidParameter(format!(
                    "Winternitz key '{}' not found in script. Tx name: {}. Input index: {}. Script index: {}",
                    op_key_name, name, input_index, slot_index
                ))
            })?;

        // Get WT slot index signature
        let wt_slot_witness = context
            .witness
            .get_witness(&self.ctx.id, &indexed_name(WT_COSIGN_SLOT_KEY, op_index))?
            .unwrap();

        let wt_slot = wt_slot_witness.winternitz()?.message_bytes();
        let wt_slot_index_signature = wt_slot_witness.winternitz()?;

        // OP Cosign slot
        let op_slot_index_signature = context.key_manager.sign_winternitz_message_by_index(
            &wt_slot,
            WinternitzType::HASH160,
            key.derivation_index(),
        )?;

        // Create input arguments
        let mut input_args =
            InputArgs::new_taproot_script_args(WT_INIT_CHALLENGE_TX_COSIGN_LEAF as usize);

        for word in (0..PEGOUT_ID_KEY_WORDS).rev() {
            let wt_key_name = double_indexed_name(WT_COSIGN_PEGOUT_ID_KEY, op_index, word);
            let wt_witness = context
                .witness
                .get_witness(&self.ctx.id, &wt_key_name)?
                .unwrap();

            let wt_word = wt_witness.winternitz()?.message_bytes();
            let wt_word_signature = wt_witness.winternitz()?;

            let op_key_name = double_indexed_name(OP_COSIGN_PEGOUT_ID_KEY, op_index, word);
            let key = script.get_key(&op_key_name).ok_or_else(|| {
                BitVMXError::InvalidParameter(format!(
                    "Winternitz key '{}' not found in script. Tx name: {}. Input index: {}. Script index: {}",
                    op_key_name, name, input_index, slot_index
                ))
            })?;

            // OP Cosign pegout ID word signature
            let op_word_cosign_signature = context.key_manager.sign_winternitz_message_by_index(
                &wt_word,
                WinternitzType::HASH160,
                key.derivation_index(),
            )?;

            input_args.push_winternitz_signature(wt_word_signature);
            input_args.push_winternitz_signature(op_word_cosign_signature);
        }

        input_args.push_winternitz_signature(wt_slot_index_signature);
        input_args.push_winternitz_signature(op_slot_index_signature);
        input_args.push_taproot_signature(op_dispute_key_signature)?;

        let tx = protocol.transaction_to_send(&name, &[input_args])?;
        info!(id = self.ctx.my_idx, "Signed {}", name);

        Ok((tx, None))
    }

    fn handle_reveal_input_tx<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
        tx_status: &TransactionStatus,
    ) -> Result<(), BitVMXError> {
        let slot_index = extract_index(&tx_name, REVEAL_INPUT_TX)?;
        info!(
            id = self.ctx.my_idx,
            "Handling reveal input tx for slot {}", slot_index
        );

        if self.is_my_dispute_core(context)? {
            // Operator won scenario, schedule OPERATOR_WON_TX
            info!(
                id = self.ctx.my_idx,
                "This is my dispute_core, scheduling OPERATOR_WON_TX for slot {}", slot_index
            );

            let committee = self.committee(context)?;
            let settings = committee.settings;
            self.dispatch(
                context,
                DisputeCoreTxType::OperatorWon {
                    op_index: self.ctx.my_idx,
                    slot_index,
                    block_height: Some(
                        self.get_dispatch_height(tx_status, settings.op_won_timelock)?,
                    ),
                },
            )?;

            return Ok(());
        }

        self.cancel_dispatch(
            context,
            &indexed_name(INPUT_NOT_REVEALED_TX, slot_index),
            None,
        );

        let data = self.dispute_core_data(context)?;

        // WT: Dispatch disabler if operator is already penalized.
        if self.check_stop_op_won(context, &data, slot_index)? {
            return Ok(());
        }

        self.dispatch_init_challenge(context, tx_name, tx_status, slot_index, &data)?;

        Ok(())
    }

    fn handle_input_not_revealed_tx<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        // INPUT_NOT_REVEALED_TX belongs to the challenged operator's dispute core. Every other
        // committee member acts as a verifier and dispatches CLAIM_INIT_TX plus the STOPPER_TX
        // for its watchtower/operator/slot tuple.
        if self.is_my_dispute_core(context)? {
            return Ok(());
        }

        let data = self.dispute_core_data(context)?;
        let wt_index = self.ctx.my_idx;
        let op_index = data.member_index;
        let committee = self.committee(context)?;
        let wt_dispute_core_id =
            get_dispute_core_pid(data.committee_id, &committee.members[wt_index].take_key);

        if !self.is_claim_init_mined(context, &wt_dispute_core_id, op_index)? {
            self.dispatch(context, DisputeCoreTxType::ClaimInit { wt_index, op_index })?;
        }

        self.dispatch(
            context,
            DisputeCoreTxType::Stopper {
                wt_index,
                op_index,
                slot_index: extract_index(tx_name, INPUT_NOT_REVEALED_TX)?,
            },
        )
    }

    fn dispatch_init_challenge<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
        tx_status: &TransactionStatus,
        slot_index: usize,
        data: &DisputeCoreData,
    ) -> Result<(), BitVMXError> {
        // WT: save data and dispatch WT_INIT_CHALLENGE_TX
        let committee = self.committee(context)?;
        let wt_dispute_core_id = get_dispute_core_pid(
            data.committee_id,
            &committee.members[self.ctx.my_idx].take_key,
        );

        // Save data to sign init challenge in wt own dispute core
        // Save SLOT index indexed by OPERATOR_INDEX, so we can have multiple challenges in parallel if needed.
        self.set_number(
            context,
            &wt_dispute_core_id,
            &indexed_name(INIT_CHALLENGE_SLOT, data.member_index),
            slot_index as u32,
        )?;

        let protocol = self.load_protocol()?;
        self.decode_witness_for_tx(
            tx_name,
            REVEAL_INPUT_TX_REVEAL_INDEX as u32,
            context,
            tx_status.tx_or_err()?,
            Some(REVEAL_INPUT_TX_REVEAL_LEAF as u32),
            Some(protocol),
            None,
        )?;

        let key_name = &indexed_name(SLOT_ID_KEY, slot_index);
        let witness = context
            .witness
            .get_witness(&self.ctx.id, key_name)?
            .unwrap();

        let key_name = double_indexed_name(SLOT_ID_KEY, data.member_index, slot_index);
        // Save witness in WT dispute core, indexed by operator index, so we can have multiple challenges in parallel if needed.
        context
            .witness
            .set_witness(&wt_dispute_core_id, &key_name, witness)?;

        // Load wt dispute core and dispatch init challenge tx
        self.dispatch(
            context,
            DisputeCoreTxType::ClaimInit {
                wt_index: self.ctx.my_idx,
                op_index: data.member_index,
            },
        )?;

        let protocol = self.load_protocol_by_name(PROGRAM_TYPE_DISPUTE_CORE, wt_dispute_core_id)?;

        let init_challenge_name =
            double_indexed_name(WT_INIT_CHALLENGE_TX, self.ctx.my_idx, data.member_index);

        let (tx, speedup) = protocol.get_transaction_by_name(&init_challenge_name, context)?;

        self.log_and_dispatch(
            context,
            &init_challenge_name,
            tx,
            speedup,
            None,
            wt_dispute_core_id,
        )?;

        Ok(())
    }

    fn check_stop_op_won<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        data: &DisputeCoreData,
        slot_index: usize,
    ) -> Result<bool, BitVMXError> {
        match load_penalized_member(
            context,
            data.committee_id,
            data.member_index,
            ParticipantRole::Prover,
        )? {
            Some(penalized_member) => {
                info!(
                    id = self.ctx.my_idx,
                    "Operator already penalized for member index: {}, skipping WT_INIT_CHALLENGE_TX dispatch",
                    data.member_index
                );

                self.dispatch(
                    context,
                    DisputeCoreTxType::PenalizationStopOperatorWon {
                        wt_index: penalized_member.challenger_index,
                        op_index: penalized_member.member_index,
                        slot_index,
                    },
                )?;

                return Ok(true);
            }
            None => {
                return Ok(false);
            }
        }
    }

    fn handle_challenge_tx<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        slot_index: usize,
        tx_status: &TransactionStatus,
    ) -> Result<(), BitVMXError> {
        if self.is_my_dispute_core(context)? {
            info!(
                id = self.ctx.my_idx,
                "This is my dispute_core, checking for operator take dispatch for slot {}",
                slot_index
            );

            self.cancel_operator_take(context, slot_index);
            self.dispatch(context, DisputeCoreTxType::RevealInput { slot_index })?;
        } else {
            // Schedule input not revealed dispatch transaction
            let committee = self.committee(context)?;
            let settings = committee.settings;
            let block_height =
                Some(self.get_dispatch_height(tx_status, settings.input_not_revealed_timelock)?);

            self.dispatch(
                context,
                DisputeCoreTxType::InputNotRevealed {
                    slot_index,
                    block_height,
                },
            )?;
        }

        Ok(())
    }

    fn cancel_operator_take<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        slot_index: usize,
    ) {
        let tx_name = indexed_name(OPERATOR_TAKE_TX, self.ctx.my_idx);

        let committee_id = match self.committee_id(context) {
            Ok(id) => id,
            Err(e) => {
                warn!(
                id = self.ctx.my_idx,
                "Failed to get committee ID, cannot cancel operator take for slot {}. Error: {}",
                slot_index,
                e
            );
                return;
            }
        };

        let pid = get_accept_pegin_pid(committee_id, slot_index);

        self.cancel_dispatch(context, &tx_name, Some((PROGRAM_TYPE_ACCEPT_PEGIN, pid)));
    }

    fn reveal_input_tx<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", name);
        let mut protocol = self.load_protocol()?;
        let slot_index = extract_index(name, REVEAL_INPUT_TX)? as u16;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![InputSigningInfo::ScriptSpend {
                input_index: REVEAL_INPUT_TX_REVEAL_INDEX,
                script_index: REVEAL_INPUT_TX_REVEAL_LEAF,
                winternitz_data: Some(WinternitzData {
                    data: slot_index.to_be_bytes().to_vec(),
                    key_name: indexed_name(SLOT_ID_KEY, slot_index as usize),
                    key_type: WinternitzType::HASH160,
                    key_manager: context.key_manager.as_ref(),
                }),
            }],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        info!(id = self.ctx.my_idx, "Signed {}", name);

        // Speedup data
        let speedup_utxo = Utxo::new(
            tx.compute_txid(),
            tx.output.len() as u32 - 1,
            SPEEDUP_VALUE,
            &self.my_speedup_key(context)?,
        );

        Ok((tx, Some(speedup_utxo.into())))
    }

    fn input_not_revealed_tx<BC: BitcoinCoordinatorApi>(
        &self,
        name: &str,
        _context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![InputSigningInfo::ScriptSpend {
                input_index: 0,
                script_index: REVEAL_INPUT_TX_COMMITTEE_LEAF,
                winternitz_data: None,
            }],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        info!(id = self.ctx.my_idx, "Signed {}", name);

        Ok((tx, None))
    }

    fn handle_double_reveal<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        slot_index: usize,
    ) -> Result<bool, BitVMXError> {
        let reveal_in_progress = self.get_reveal_in_progress(context)?;
        if reveal_in_progress.is_none() {
            info!(
                id = self.ctx.my_idx,
                "No reveal in progress, setting slot index: {} as in progress", slot_index
            );
            self.set_reveal_in_progress(context, slot_index)?;
            return Ok(false);
        } else {
            info!(
                id = self.ctx.my_idx,
                "Reveal already in progress for slot index: {}, dispatching double reveal penalization for slots {} and {}",
                reveal_in_progress.unwrap(),
                reveal_in_progress.unwrap(),
                slot_index
            );

            self.dispatch(
                context,
                DisputeCoreTxType::TwoDisputePenalization {
                    slot_index_prev: reveal_in_progress.unwrap() as usize,
                    slot_index_curr: slot_index,
                },
            )?;

            info!(id = self.ctx.my_idx, "Cleaning REVEAL_IN_PROGRESS");
            // Asumming the penalization tx was dispatched and mined,
            context
                .globals
                .unset_var(&self.ctx.id, REVEAL_IN_PROGRESS)?;

            return Ok(true);
        }
    }

    fn two_dispute_penalization_tx(
        &self,
        mut slot_index_prev: usize,
        mut slot_index_last: usize,
    ) -> Result<(Transaction, Option<SpeedupData>, String), BitVMXError> {
        if slot_index_last < slot_index_prev {
            (slot_index_last, slot_index_prev) = (slot_index_prev, slot_index_last);
        }

        let name = double_indexed_name(
            TWO_DISPUTE_PENALIZATION_TX,
            slot_index_prev,
            slot_index_last,
        );

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            &name,
            &vec![
                InputSigningInfo::KeySpend { input_index: 0 },
                InputSigningInfo::KeySpend { input_index: 1 },
            ],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;

        Ok((tx, None, name))
    }

    fn handle_reimbursement_kickoff_transaction<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_status: &TransactionStatus,
        tx_id: Txid,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        info!("Handling kickoff txid: {}. Name: {}", tx_id, tx_name);

        // Extract slot_index from transaction name
        let slot_index = extract_index(tx_name, REIMBURSEMENT_KICKOFF_TX)?;
        info!("Extracted slot index: {}", slot_index);

        let committee = self.committee(context)?;
        let settings = committee.settings;

        if self.is_my_dispute_core(context)? {
            info!("My dispute_core. Dispatch OP Take for slot: {}", slot_index);

            // Handle operator take if needed
            let block_height = self.get_dispatch_height(tx_status, settings.long_timelock + 1)?;
            self.dispatch(
                context,
                DisputeCoreTxType::OperatorTake {
                    op_index: self.ctx.my_idx,
                    slot_index,
                    block_height: Some(block_height),
                },
            )?;
        } else {
            info!("Not my dispute_core, checking lazy disabler and challenge");

            if self.check_op_lazy_disabler(context, slot_index)? {
                info!("Dispatching lazy disabler for slot: {}", slot_index);
                return Ok(());
            }

            if !self.validate_reimbursement(context, slot_index, tx_status, tx_name)? {
                info!("Dispatching challenge for slot: {}", slot_index);
                self.dispatch(
                    context,
                    DisputeCoreTxType::Challenge {
                        slot_index,
                        block_height: Some(
                            self.get_dispatch_height(tx_status, settings.short_timelock)?,
                        ),
                    },
                )?;
            }
        }

        self.send_reimbursement_kickoff_spv(context, tx_id, slot_index)?;

        Ok(())
    }

    fn validate_reimbursement<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        slot_index: usize,
        tx_status: &TransactionStatus,
        tx_name: &str,
    ) -> Result<bool, BitVMXError> {
        // Handle challenge if needed
        let funds_advanced_var = self.funds_advanced(context, slot_index)?;
        let data = self.dispute_core_data(context)?;
        let committee = self.committee(context)?;
        let wt_dispute_core_id = get_dispute_core_pid(
            data.committee_id,
            &committee.members[self.ctx.my_idx].take_key,
        );

        // First decode the witness
        let protocol = self.load_protocol()?;
        self.decode_witness_for_tx(
            tx_name,
            0,
            context,
            tx_status.tx_or_err()?,
            Some(OP_INITIAL_DEPOSIT_TX_REIMBURSMENT_LEAF as u32),
            Some(protocol),
            None,
        )?;

        let witness = context
            .witness
            .get_witness(&self.ctx.id, &indexed_name(PEGOUT_ID_KEY, slot_index))?
            .unwrap();

        let pegout_id = witness.winternitz()?.message_bytes();

        // Save witness in WT dispute core, indexed by operator index, so we can have multiple challenges in parallel if needed.
        context.witness.set_witness(
            &wt_dispute_core_id,
            &double_indexed_name(PEGOUT_ID_KEY, data.member_index, slot_index),
            witness,
        )?;

        // After saving the witness, check if need to initialize challenge
        if funds_advanced_var.is_none() {
            info!("Funds advanced is none");
            // If funds were not advanced, we need to challenge the transaction
            return Ok(false);
        }

        let funds_advanced = funds_advanced_var.unwrap();

        // Compare if the monitored operator is the selected one
        if funds_advanced.operator_pubkey != self.monitored_member_take_key(context)? {
            info!("Unauthorized operator detected.");
            return Ok(false);
        }

        if funds_advanced.pegout_id != pegout_id {
            info!(
                "Pegout ID mismatch. Expected: {:?}. Found on witness: {:?}",
                funds_advanced.pegout_id, pegout_id
            );
            return Ok(false);
        }

        info!("Reimbursement kickoff transaction validated successfully.");
        Ok(true)
    }

    fn check_op_lazy_disabler<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        slot_index: usize,
    ) -> Result<bool, BitVMXError> {
        let data = self.dispute_core_data(context)?;

        // Check if operator is already penalized
        match load_penalized_member(
            context,
            data.committee_id,
            data.member_index,
            ParticipantRole::Prover,
        )? {
            Some(penalized_member) => {
                info!(
                    id = self.ctx.my_idx,
                    "Operator already penalized for member index: {}, skipping CHALLENGE_TX dispatch",
                    data.member_index
                );

                self.dispatch(
                    context,
                    DisputeCoreTxType::PenalizationOperatorLazyDisabler {
                        wt_index: penalized_member.challenger_index,
                        op_index: penalized_member.member_index,
                        slot_index,
                    },
                )?;

                return Ok(true);
            }
            None => {
                return Ok(false);
            }
        }
    }

    fn send_reimbursement_kickoff_spv<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        txid: Txid,
        slot_index: usize,
    ) -> Result<(), BitVMXError> {
        let tx_info = context.bitcoin_coordinator.get_transaction(txid);

        let proof = match tx_info {
            Ok(utx) => Some(get_spv_proof(txid, utx.block_info.unwrap())?),
            Err(e) => {
                warn!(
                    "Failed to retrieve transaction info for txid {}: {:?}",
                    txid, e
                );
                None
            }
        };

        let response = UnionSPVNotification {
            txid,
            committee_id: self.dispute_core_data(context)?.committee_id,
            slot_index,
            spv_proof: proof,
            tx_type: UnionTxType::ReimbursementKickoff,
        };

        let data = serde_json::to_string(&OutgoingBitVMXApiMessages::Variable(
            self.ctx.id,
            UnionSPVNotification::name(),
            VariableTypes::String(serde_json::to_string(&response)?),
        ))?;

        info!(
            id = self.ctx.my_idx,
            "Sending reimbursement kickoff SPV data: {}", data
        );

        context
            .broker_channel
            .send_service(&context.components_config.l2, data)?;

        Ok(())
    }

    fn dispatch<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_type: DisputeCoreTxType,
    ) -> Result<(), BitVMXError> {
        let tx_name = tx_type.tx_name();
        info!(
            id = self.ctx.my_idx,
            "Dispatch {} from protocol {}", tx_name, self.ctx.id
        );
        let mut program_id = self.ctx.id;

        let (tx, speedup) = match tx_type {
            DisputeCoreTxType::WtStartEnabler => self.wt_start_enabler_tx(context)?,
            DisputeCoreTxType::ProtocolFunding => self.protocol_funding_tx(context)?,
            DisputeCoreTxType::Challenge { .. } => self.challenge_tx(&tx_name.clone(), context)?,
            DisputeCoreTxType::WatchtowerNoChallenge { .. } => self.wt_no_challenge_tx(&tx_name)?,
            DisputeCoreTxType::OperatorNoCosign { .. } => self.op_no_cosign_tx(&tx_name)?,
            DisputeCoreTxType::OperatorCosign { .. } => self.op_cosign_tx(&tx_name, context)?,
            DisputeCoreTxType::ClaimInit { wt_index, .. } => {
                let dispute_core_data = self.dispute_core_data(context)?;
                let committee = self.committee(context)?;
                let pid = get_dispute_core_pid(
                    dispute_core_data.committee_id,
                    &committee.members[wt_index].take_key,
                );
                let protocol = self.load_protocol_by_name(PROGRAM_TYPE_DISPUTE_CORE, pid)?;
                program_id = pid;
                protocol.get_transaction_by_name(&tx_name, context)?
            }
            DisputeCoreTxType::RevealInput { .. } => self.reveal_input_tx(&tx_name, context)?,
            DisputeCoreTxType::InputNotRevealed { .. } => {
                self.input_not_revealed_tx(&tx_name, context)?
            }
            DisputeCoreTxType::TwoDisputePenalization {
                slot_index_prev,
                slot_index_curr,
                ..
            } => {
                let (tx, speedup, _) =
                    self.two_dispute_penalization_tx(slot_index_prev, slot_index_curr)?;
                (tx, speedup)
            }
            DisputeCoreTxType::Stopper { .. }
            | DisputeCoreTxType::PenalizationStopOperatorWon { .. }
            | DisputeCoreTxType::PenalizationOperatorLazyDisabler { .. }
            | DisputeCoreTxType::PenalizationWatchtowerDisabler { .. }
            | DisputeCoreTxType::OperatorDisablerDirectory { .. }
            | DisputeCoreTxType::WatchtowerDisablerDirectory { .. }
            | DisputeCoreTxType::PenalizationWatchtowerCosignDisabler { .. } => {
                let dispute_core_data: DisputeCoreData = self.dispute_core_data(context)?;
                let pid = get_full_penalization_pid(dispute_core_data.committee_id);
                let protocol = self.load_protocol_by_name(PROGRAM_TYPE_FULL_PENALIZATION, pid)?;
                program_id = pid; // Update program_id so it notify the correct program when TX is mined
                protocol.get_transaction_by_name(&tx_name, context)?
            }
            DisputeCoreTxType::OperatorTake { slot_index, .. }
            | DisputeCoreTxType::OperatorWon { slot_index, .. } => {
                let dispute_core_data: DisputeCoreData = self.dispute_core_data(context)?;
                let pid = get_accept_pegin_pid(dispute_core_data.committee_id, slot_index);
                let protocol = self.load_protocol_by_name(PROGRAM_TYPE_ACCEPT_PEGIN, pid)?;
                program_id = pid; // Update program_id so it notify the correct program when TX is mined
                protocol.get_transaction_by_name(&tx_name, context)?
            }
        };

        self.log_and_dispatch(
            context,
            &tx_name,
            tx,
            speedup,
            tx_type.block_height(),
            program_id,
        )?;

        Ok(())
    }

    fn wt_start_enabler_tx<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(
            id = self.ctx.my_idx,
            "Loading {} for DisputeCore", WT_START_ENABLER_TX
        );

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            WT_START_ENABLER_TX,
            &vec![InputSigningInfo::KeySpend { input_index: 0 }],
        )?;

        let tx = protocol.transaction_to_send(WT_START_ENABLER_TX, &args)?;
        info!(id = self.ctx.my_idx, "Signed {}", WT_START_ENABLER_TX);

        // Speedup data
        let speedup_utxo = Utxo::new(
            tx.compute_txid(),
            tx.output.len() as u32 - 1,
            SPEEDUP_VALUE,
            &self.my_speedup_key(context)?,
        );

        Ok((tx, Some(speedup_utxo.into())))
    }

    fn is_my_dispute_core<BC: BitcoinCoordinatorApi>(
        &self,
        program_context: &ProgramContext<BC>,
    ) -> Result<bool, BitVMXError> {
        let dispute_core_data = self.dispute_core_data(program_context)?;
        Ok(dispute_core_data.member_index == self.ctx.my_idx)
    }

    fn save_op_utxos<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        committee: &Committee,
        reimbursement_outputs: &mut Vec<OutputType>,
        reveal_output: &mut OutputType,
    ) -> Result<(), BitVMXError> {
        let protocol = self.load_or_create_protocol();
        let dispute_aggregated_key = &committee.dispute_aggregated_key;

        for i in 0..committee.packet_size as usize {
            let name = indexed_name(REIMBURSEMENT_KICKOFF_TX, i);
            let reimbursement_kickoff_tx: &Transaction = protocol.transaction_by_name(&name)?;

            let reimbursement_output_index = 0;
            let reimbursement_output_value =
                reimbursement_kickoff_tx.output[reimbursement_output_index].value;
            reimbursement_outputs[i].set_value(reimbursement_output_value.clone());

            let operator_take_utxo = (
                reimbursement_kickoff_tx.compute_txid(),
                reimbursement_output_index as u32,
                Some(reimbursement_output_value.to_sat()),
                Some(reimbursement_outputs[i].clone()),
            );

            let name = indexed_name(REVEAL_INPUT_TX, i);
            let reveal_tx = protocol.transaction_by_name(&name)?;
            let reveal_output_index = 0;
            let reveal_output_value = reveal_tx.output[reveal_output_index].value;
            reveal_output.set_value(reveal_output_value);

            let operator_won_utxo = (
                reveal_tx.compute_txid(),
                reveal_output_index as u32,
                Some(reveal_output_value.to_sat()),
                Some(reveal_output.clone()),
            );

            context.globals.set_var(
                &self.ctx.id,
                &indexed_name(OPERATOR_TAKE_ENABLER, i),
                VariableTypes::Utxo(operator_take_utxo.clone()),
            )?;

            context.globals.set_var(
                &self.ctx.id,
                &indexed_name(OPERATOR_WON_ENABLER, i),
                VariableTypes::Utxo(operator_won_utxo.clone()),
            )?;

            let input_not_revealed_name = indexed_name(INPUT_NOT_REVEALED_TX, i);
            let input_not_revealed_tx = protocol.transaction_by_name(&input_not_revealed_name)?;

            for member_index in 0..committee.members.len() {
                let output = &input_not_revealed_tx.output[member_index];
                let output_type = OutputType::segwit_key(
                    output.value.to_sat(),
                    &committee.members[member_index].dispute_key,
                )?;

                context.globals.set_var(
                    &self.ctx.id,
                    &double_indexed_name(INPUT_NOT_REVEALED_ENABLER, i, member_index),
                    VariableTypes::Utxo((
                        input_not_revealed_tx.compute_txid(),
                        member_index as u32,
                        Some(output.value.to_sat()),
                        Some(output_type),
                    )),
                )?;
            }
        }

        // NOTE: Should we save the whole UTXOS as in reimbursement_kickoff_utxos?
        // Maybe we should improve reimbursement_kickoff_utxos to be a vector of TXIDs, and save just once the amount and the output type
        // - Reimbursement: Multiples TXIDs with same amount and output type
        // - Initial Deposit: Single TXID and amount, with different output script. (output script is save in create_dispute_core function)

        // Save initial deposit txid and output amount
        let initial_deposit_tx: &Transaction =
            protocol.transaction_by_name(OP_INITIAL_DEPOSIT_TX)?;
        let initial_deposit_txid = initial_deposit_tx.compute_txid();
        let output_value = initial_deposit_tx.output[0].value.to_sat();
        info!(
            id = self.ctx.my_idx,
            "Saving initial deposit txid: {} and amount: {}", initial_deposit_txid, output_value
        );

        context.globals.set_var(
            &self.ctx.id,
            OP_INITIAL_DEPOSIT_TXID,
            VariableTypes::String(initial_deposit_txid.to_string()),
        )?;

        context.globals.set_var(
            &self.ctx.id,
            OP_INITIAL_DEPOSIT_AMOUNT,
            VariableTypes::Amount(output_value),
        )?;

        let op_disabler_directory_outout = committee.packet_size as usize;
        let output_value = initial_deposit_tx.output[op_disabler_directory_outout]
            .value
            .to_sat();

        let op_disabler_directory_utxo = (
            initial_deposit_txid,
            op_disabler_directory_outout as u32,
            Some(output_value),
            Some(OutputType::taproot(
                output_value,
                dispute_aggregated_key,
                &[],
            )?),
        );

        info!("Saving op disabler utxo: {:?}", op_disabler_directory_utxo);
        context.globals.set_var(
            &self.ctx.id,
            &OP_DISABLER_DIRECTORY_UTXO,
            VariableTypes::Utxo(op_disabler_directory_utxo),
        )?;

        Ok(())
    }

    fn save_wt_utxos<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        committee: &Committee,
        data: &DisputeCoreData,
        init_challenge_cosign_outputs: &mut Vec<Option<OutputType>>,
        claim_init_outputs: &mut Vec<Option<ClaimInitOutputs>>,
        disabler_directory_output: &mut OutputType,
        op_cosign_outputs: &mut Vec<Option<OutputType>>,
    ) -> Result<(), BitVMXError> {
        let protocol = self.load_or_create_protocol();

        let wt_start_enabler_tx = protocol.transaction_by_name(WT_START_ENABLER_TX)?;
        let wt_start_enabler_txid = wt_start_enabler_tx.compute_txid();

        // WT_START_ENABLER_TX holds two blocks of one output per member: the WT_INIT_CHALLENGE_TX
        // funding outputs followed by the CLAIM_INIT_TX funding outputs.
        let disabler_directory_vout = committee.members.len() * 2;
        let output_value = wt_start_enabler_tx.output[disabler_directory_vout]
            .value
            .to_sat();
        disabler_directory_output.set_value(Amount::from_sat(output_value));

        let disabler_directory_utxo = (
            wt_start_enabler_txid,
            disabler_directory_vout as u32,
            Some(output_value),
            Some(disabler_directory_output.clone()),
        );

        context.globals.set_var(
            &self.ctx.id,
            &WT_DISABLER_DIRECTORY_UTXO,
            VariableTypes::Utxo(disabler_directory_utxo),
        )?;

        let claim_success_output =
            ClaimGate::output_from_aggregated(&committee.dispute_aggregated_key, DUST_VALUE)?;

        let mut init_challenge_utxos: Vec<Option<PartialUtxo>> = vec![];
        let mut claim_init_utxos: Vec<Option<ClaimInitUtxos>> = vec![];
        let mut op_cosign_utxos = vec![];

        for (op_index, member) in committee.members.clone().iter().enumerate() {
            if member.role == ParticipantRole::Prover && data.member_index != op_index {
                let wt_claim_name = double_indexed_name(WT_CLAIM_GATE, data.member_index, op_index);
                let op_claim_name = double_indexed_name(OP_CLAIM_GATE, data.member_index, op_index);

                let op_success = format!("{}_SUCCESS", op_claim_name);
                let wt_success = format!("{}_SUCCESS", wt_claim_name);

                let wt_success_tx = protocol.transaction_by_name(&wt_success)?;
                let wt_success_txid = wt_success_tx.compute_txid();

                context.globals.set_var(
                    &self.ctx.id,
                    &double_indexed_name(
                        WT_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO,
                        data.member_index,
                        op_index,
                    ),
                    VariableTypes::Utxo((
                        wt_success_txid,
                        0,
                        Some(DUST_VALUE),
                        Some(claim_success_output.clone()),
                    )),
                )?;

                let op_success_tx = protocol.transaction_by_name(&op_success)?;
                let op_success_txid = op_success_tx.compute_txid();
                context.globals.set_var(
                    &self.ctx.id,
                    &double_indexed_name(
                        OP_CLAIM_SUCCESS_DISABLER_DIRECTORY_UTXO,
                        data.member_index,
                        op_index,
                    ),
                    VariableTypes::Utxo((
                        op_success_txid,
                        0,
                        Some(DUST_VALUE),
                        Some(claim_success_output.clone()),
                    )),
                )?;

                let claim_init = double_indexed_name(CLAIM_INIT_TX, data.member_index, op_index);
                let claim_init_txid = protocol.transaction_by_name(&claim_init)?.compute_txid();

                let stoppers = claim_init_outputs[op_index].clone().unwrap();

                let wt_stopper: PartialUtxo = (
                    claim_init_txid,
                    CLAIM_INIT_WT_STOPPER_VOUT,
                    Some(stoppers.wt_stopper.get_value_or_err()?.to_sat()),
                    Some(stoppers.wt_stopper),
                );

                let op_stopper: PartialUtxo = (
                    claim_init_txid,
                    CLAIM_INIT_OP_STOPPER_VOUT,
                    Some(stoppers.op_stopper.get_value_or_err()?.to_sat()),
                    Some(stoppers.op_stopper),
                );

                claim_init_utxos.push(Some(ClaimInitUtxos {
                    wt_stopper,
                    op_stopper,
                }));

                let wt_init_challenge =
                    double_indexed_name(WT_INIT_CHALLENGE_TX, data.member_index, op_index);
                let wt_init_challenge_tx = protocol.transaction_by_name(&wt_init_challenge)?;
                let wt_init_challenge_txid = wt_init_challenge_tx.compute_txid();

                let mut cosign_output = init_challenge_cosign_outputs[op_index].clone().unwrap();
                let cosign_output_value =
                    wt_init_challenge_tx.output[WT_INIT_CHALLENGE_COSIGN_VOUT as usize].value;

                cosign_output.set_value(cosign_output_value);

                init_challenge_utxos.push(Some((
                    wt_init_challenge_txid,
                    WT_INIT_CHALLENGE_COSIGN_VOUT,
                    Some(cosign_output_value.to_sat()),
                    Some(cosign_output),
                )));

                let op_cosign = double_indexed_name(OP_COSIGN_TX, data.member_index, op_index);
                let op_cosign_tx = protocol.transaction_by_name(&op_cosign)?;
                let op_cosign_txid = op_cosign_tx.compute_txid();
                let op_cosign_output = op_cosign_outputs[op_index].clone().unwrap();
                let op_cosign_vout = 0;
                op_cosign_utxos.push(Some((
                    op_cosign_txid,
                    op_cosign_vout,
                    Some(op_cosign_output.get_value_or_err()?.to_sat()),
                    Some(op_cosign_output),
                )));
            } else {
                init_challenge_utxos.push(None);
                claim_init_utxos.push(None);
                op_cosign_utxos.push(None);
            }
        }

        context.globals.set_var(
            &self.ctx.id,
            &WT_INIT_CHALLENGE_UTXOS,
            VariableTypes::String(serde_json::to_string(&init_challenge_utxos)?),
        )?;

        context.globals.set_var(
            &self.ctx.id,
            &CLAIM_INIT_UTXOS,
            VariableTypes::String(serde_json::to_string(&claim_init_utxos)?),
        )?;

        context.globals.set_var(
            &self.ctx.id,
            &OP_COSIGN_UTXOS,
            VariableTypes::String(serde_json::to_string(&op_cosign_utxos)?),
        )?;

        Ok(())
    }

    fn pegout_id<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        slot_index: usize,
    ) -> Result<Vec<u8>, BitVMXError> {
        let key = indexed_name(PEGOUT_ID, slot_index);
        context
            .globals
            .get_var(&self.ctx.id, &key)?
            .ok_or_else(|| {
                BitVMXError::InvalidParameter(format!(
                    "Key {} not set in uuid: {}",
                    key, self.ctx.id
                ))
            })?
            .input()
    }

    fn sign_aggregated_input<BC: BitcoinCoordinatorApi>(
        &self,
        tx_name: &str,
        context: &ProgramContext<BC>,
        with_speedup: bool,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", tx_name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            tx_name,
            &vec![InputSigningInfo::KeySpend { input_index: 0 }],
        )?;

        let tx = protocol.transaction_to_send(&tx_name, &args)?;
        let speedout = if with_speedup {
            Some(SpeedupData::new(Utxo::new(
                tx.compute_txid(),
                (tx.output.len() - 1) as u32,
                SPEEDUP_VALUE,
                &self.my_speedup_key(context)?,
            )))
        } else {
            None
        };

        Ok((tx, speedout))
    }

    fn load_or_create_slot_id_keys<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        committee_id: &Uuid,
        committee: &Committee,
    ) -> Result<Vec<PublicKeyType>, BitVMXError> {
        let mut slot_id_keys: Vec<PublicKeyType> =
            match context.globals.get_var(&committee_id, SLOT_ID_KEYS)? {
                Some(var) => serde_json::from_str(&var.string()?)?,
                None => Vec::new(),
            };

        // Load SLOT_ID_KEYS if they were previously generated
        // If not present, generate and store them
        if slot_id_keys.is_empty() {
            for _ in 0..committee.packet_size as usize {
                slot_id_keys.push(PublicKeyType::Winternitz(
                    context
                        .key_manager
                        .next_winternitz(2, WinternitzType::HASH160)?, // Sign 2 bytes of u16 slot id.
                ));
            }

            context.globals.set_var(
                committee_id,
                SLOT_ID_KEYS,
                VariableTypes::String(serde_json::to_string(&slot_id_keys)?),
            )?;
        } else if slot_id_keys.len() != committee.packet_size as usize {
            return Err(BitVMXError::InvalidParameter(format!(
                "Expected {} slot_id_keys but found {}",
                committee.packet_size,
                slot_id_keys.len()
            )));
        }

        Ok(slot_id_keys)
    }

    fn load_or_create_pegout_id_keys<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        committee_id: &Uuid,
        committee: &Committee,
    ) -> Result<Vec<PublicKeyType>, BitVMXError> {
        let mut pegout_id_keys: Vec<PublicKeyType> =
            match context.globals.get_var(&committee_id, PEGOUT_ID_KEYS)? {
                Some(var) => serde_json::from_str(&var.string()?)?,
                None => Vec::new(),
            };

        if pegout_id_keys.is_empty() {
            for _ in 0..committee.packet_size as usize {
                pegout_id_keys.push(PublicKeyType::Winternitz(
                    context
                        .key_manager
                        .next_winternitz(PEGOUT_ID_KEY_WORDS * 4, WinternitzType::HASH160)?,
                ));
            }

            context.globals.set_var(
                committee_id,
                PEGOUT_ID_KEYS,
                VariableTypes::String(serde_json::to_string(&pegout_id_keys)?),
            )?;
        } else if pegout_id_keys.len() != committee.packet_size as usize {
            return Err(BitVMXError::InvalidParameter(format!(
                "Expected {} pegout_id_keys but found {}",
                committee.packet_size,
                pegout_id_keys.len()
            )));
        }
        Ok(pegout_id_keys)
    }

    fn get_dispute_pair_keys<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        committee_id: Uuid,
        members: &Vec<MemberData>,
    ) -> Result<Vec<(String, PublicKeyType)>, BitVMXError> {
        let mut keys = Vec::new();
        let prover = members[self.ctx.my_idx].role == ParticipantRole::Prover;

        for member_index in 0..members.len() {
            if self.ctx.my_idx == member_index {
                continue;
            }

            if prover || members[member_index].role == ParticipantRole::Prover {
                let name = get_dispute_pair_key_name(self.ctx.my_idx, member_index);
                let key = context
                    .globals
                    .get_var(&committee_id, &name)?
                    .ok_or_else(|| {
                        BitVMXError::InvalidParameter(format!(
                            "Dispute pair key {} not found",
                            name
                        ))
                    })?
                    .pubkey()?;

                keys.push((name, PublicKeyType::Public(key)));
            }
        }

        Ok(keys)
    }

    fn members_slot_id_keys<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        committee_id: Uuid,
    ) -> Result<Vec<Vec<WinternitzPublicKey>>, BitVMXError> {
        match context
            .globals
            .get_var(&committee_id, MEMBERS_SLOT_ID_KEYS)?
        {
            Some(var) => {
                let members_slot_id_keys: Vec<Vec<WinternitzPublicKey>> =
                    serde_json::from_str(&var.string()?)?;
                Ok(members_slot_id_keys)
            }
            None => Ok(vec![]),
        }
    }

    fn validate_keys<BC: BitcoinCoordinatorApi>(
        &self,
        keys: &Vec<ParticipantKeys>,
        context: &ProgramContext<BC>,
        committee_id: Uuid,
    ) -> Result<(), BitVMXError> {
        // TODO: Add pegout id key validation
        let committee = self.committee(context)?;

        if keys.len() != committee.members.len() {
            return Err(BitVMXError::InvalidParameter(format!(
                "Keys length {} does not match committee members length {}",
                keys.len(),
                committee.members.len()
            )));
        }

        let mut saved_keys = self.members_slot_id_keys(context, committee_id)?;

        // If no keys are saved yet, save the current ones
        if saved_keys.len() == 0 {
            for member_index in 0..committee.members.len() {
                let mut member_keys: Vec<WinternitzPublicKey> = vec![];
                if committee.members[member_index].role == ParticipantRole::Prover {
                    for slot_index in 0..committee.packet_size as usize {
                        info!("Saving key for member {} slot {}", member_index, slot_index);
                        member_keys.push(
                            keys[member_index]
                                .get_winternitz(&indexed_name(SLOT_ID_KEY, slot_index))?
                                .clone(),
                        );
                    }
                }
                saved_keys.push(member_keys);
            }

            context.globals.set_var(
                &committee_id,
                MEMBERS_SLOT_ID_KEYS,
                VariableTypes::String(serde_json::to_string(&saved_keys)?),
            )?;
            return Ok(());
        }

        if saved_keys.len() != committee.members.len() {
            return Err(BitVMXError::InvalidParameter(format!(
                "Saved keys length {} does not match committee members length {}",
                saved_keys.len(),
                committee.members.len()
            )));
        }

        // Validate current keys against saved ones
        for member_index in 0..committee.members.len() {
            if committee.members[member_index].role == ParticipantRole::Prover {
                if saved_keys[member_index].len() != committee.packet_size as usize {
                    return Err(BitVMXError::InvalidParameter(format!(
                        "Saved keys length for member {} does not match committee packet size: {} vs {}",
                        member_index,
                        saved_keys[member_index].len(),
                        committee.packet_size
                    )));
                }

                for slot_index in 0..committee.packet_size as usize {
                    info!(
                        "Comparing key for member {} slot {}",
                        member_index, slot_index
                    );
                    let current_key: &WinternitzPublicKey = keys[member_index]
                        .get_winternitz(&indexed_name(SLOT_ID_KEY, slot_index))?;
                    let saved_key = &saved_keys[member_index][slot_index];
                    if current_key != saved_key {
                        return Err(BitVMXError::InvalidParameter(format!(
                            "Key mismatch for member {} slot {}: current key {} does not match saved key {}",
                            member_index,
                            slot_index,
                            hex::encode(current_key.to_bytes()),
                            hex::encode(saved_key.to_bytes())
                        ))
                    );
                    }
                }
            }
        }

        Ok(())
    }

    fn get_sign_mode(&self, index: usize) -> SignMode {
        if index == self.ctx.my_idx {
            SignMode::Single
        } else {
            SignMode::Skip
        }
    }

    // Set DRP variables for union-verifier.yaml
    fn set_drp_variables<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        committee_id: Uuid,
        committee: &Committee,
        keys: &Vec<ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        // Per input should set:
        // - Prev protocol
        // - Prefix
        // - Pub keys per word

        // # input_4
        // # pegout id
        //   - size: 32
        //     owner: prover_prev

        // # input_5
        // # slot id
        //   - size: 4
        //     owner: prover_prev

        let mut drp_pairs = vec![];
        let data = self.dispute_core_data(context)?;

        if data.member_index == self.ctx.my_idx {
            // So my role is WT
            for (op_index, member) in committee.members.iter().enumerate() {
                if op_index == self.ctx.my_idx {
                    continue;
                }

                if member.role == ParticipantRole::Prover {
                    drp_pairs.push((self.ctx.my_idx, op_index));
                }
            }
        } else {
            if self.is_prover(context)? {
                drp_pairs.push((data.member_index, self.ctx.my_idx));
            }
        }

        for (wt_index, op_index) in drp_pairs {
            let drp_pid = get_dispute_channel_pid(committee_id, op_index, wt_index);

            // input_4: pegout id
            // Set prev protocol
            context.globals.set_var(
                &drp_pid,
                &program_input_prev_protocol(4),
                VariableTypes::Uuid(self.ctx.id),
            )?;

            // Set input prefix
            context.globals.set_var(
                &drp_pid,
                &program_input_prev_prefix(4),
                VariableTypes::String(format!(
                    "{}_",
                    indexed_name(OP_COSIGN_PEGOUT_ID_KEY, op_index)
                )),
            )?;

            // Set pegout id keys
            for word in 0..PEGOUT_ID_KEY_WORDS {
                let key_name = &double_indexed_name(OP_COSIGN_PEGOUT_ID_KEY, op_index, word);

                let key = keys[op_index].get_winternitz(key_name)?;

                context.globals.set_var(
                    &self.ctx.id,
                    key_name,
                    VariableTypes::WinternitzPubKey(key.clone()),
                )?;
            }

            // input_4: slot id
            // Set prev protocol
            context.globals.set_var(
                &drp_pid,
                &program_input_prev_protocol(5),
                VariableTypes::Uuid(self.ctx.id),
            )?;

            // Set input prefix
            context.globals.set_var(
                &drp_pid,
                &program_input_prev_prefix(5),
                VariableTypes::String(format!("{}_", indexed_name(OP_COSIGN_SLOT_KEY, op_index))),
            )?;

            let key = keys[op_index].get_winternitz(OP_COSIGN_SLOT_KEY)?;

            // Set slot id key
            context.globals.set_var(
                &self.ctx.id,
                &double_indexed_name(OP_COSIGN_SLOT_KEY, op_index, 0),
                VariableTypes::WinternitzPubKey(key.clone()),
            )?;
        }

        Ok(())
    }

    fn log_and_dispatch<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
        tx: Transaction,
        speedup: Option<SpeedupData>,
        block_height: Option<u32>,
        program_id: Uuid,
    ) -> Result<(), BitVMXError> {
        let txid = tx.compute_txid();

        // Dispatch the transaction through the bitcoin coordinator
        context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            Context::ProgramId(program_id).to_string()?,
            block_height,
            self.requested_confirmations(context),
        )?;

        info!(
            id = self.ctx.my_idx,
            "{} {} with txid: {}. Block height: {:?}",
            tx_name,
            get_dispatch_action(block_height),
            txid,
            block_height
        );

        Ok(())
    }

    fn get_txid(&self, tx_name: &str, protocol_info: Option<(&str, Uuid)>) -> Option<Txid> {
        let protocol = match protocol_info {
            Some((protocol_type, pid)) => {
                let ptype = match self.load_protocol_by_name(protocol_type, pid) {
                    Ok(ptype) => ptype,
                    Err(e) => {
                        warn!(
                            "Unable to load protocol by name. {}. {:?}",
                            protocol_type, e
                        );
                        return None;
                    }
                };
                ptype.load_protocol()
            }
            None => self.load_protocol(),
        };

        if protocol.is_err() {
            warn!(
                "Unable to get Txid. Tx name: {}. {:?}",
                tx_name,
                protocol.err()
            );
            return None;
        }
        let protocol = protocol.unwrap();
        let result = protocol.transaction_by_name(tx_name);
        let txid = match result {
            Ok(tx) => Some(tx.compute_txid()),
            Err(e) => {
                warn!("Error retrieving transaction for {}: {:?}", tx_name, e);
                None
            }
        };
        txid
    }

    fn cancel_dispatch<BC: BitcoinCoordinatorApi>(
        &self,
        context: &ProgramContext<BC>,
        tx_name: &str,
        protocol_info: Option<(&str, Uuid)>,
    ) {
        let pid = match protocol_info {
            Some((_, pid)) => pid,
            None => self.ctx.id,
        };
        info!("Cancel dispatch of {} for PID {}", tx_name, pid);

        let txid = match self.get_txid(tx_name, protocol_info) {
            Some(txid) => txid,
            None => {
                warn!(
                    "Transaction name {} has no associated txid for cancellation",
                    tx_name
                );
                return;
            }
        };
        info!("Cancelling dispatch of {} for txid {}", tx_name, txid);

        context
            .bitcoin_coordinator
            .cancel(bitcoin_coordinator::TypesToMonitor::Transactions(
                vec![txid],
                String::default(),
                None,
            ))
            .unwrap_or_else(|e| {
                warn!("Failed to cancel monitoring for txid {}: {:?}", txid, e);
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn test_key(byte: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
        PublicKey::new(secret.public_key(&secp))
    }

    /// Guards the hard coded CLAIM_INIT_TX output layout against the order in which
    /// ClaimGate::new appends outputs to its `from` transaction. create_claim_init builds this
    /// exact sequence, and save_wt_utxos then reads the stoppers back by index.
    #[test]
    fn claim_init_output_layout() {
        let claim_init = "CLAIM_INIT";
        let mut protocol = Protocol::new("claim_init_layout");
        protocol.add_transaction(claim_init).unwrap();

        let wt_speedup = test_key(1);
        let op_speedup = test_key(2);
        let aggregated = test_key(3);
        let key_pair = test_key(4);

        let wt_claim_gate = ClaimGate::new(
            &mut protocol,
            claim_init,
            "WT_CLAIM",
            (&wt_speedup, SignMode::Single),
            &aggregated,
            CLAIM_GATE_FEE,
            DUST_VALUE,
            vec![&op_speedup],
            Some(vec![&key_pair]),
            10,
            1,
            vec![],
            true,
            None,
        )
        .unwrap();

        let op_claim_gate = ClaimGate::new(
            &mut protocol,
            claim_init,
            "OP_CLAIM",
            (&op_speedup, SignMode::Single),
            &aggregated,
            CLAIM_GATE_FEE,
            DUST_VALUE,
            vec![&wt_speedup],
            Some(vec![&key_pair]),
            10,
            1,
            vec![],
            false,
            wt_claim_gate.exclusive_success_vout,
        )
        .unwrap();

        let wt_speedup_output = OutputType::segwit_key(SPEEDUP_VALUE, &wt_speedup).unwrap();
        protocol
            .add_transaction_output(claim_init, &wt_speedup_output)
            .unwrap();
        protocol
            .add_transaction_output(
                claim_init,
                &OutputType::segwit_key(SPEEDUP_VALUE, &op_speedup).unwrap(),
            )
            .unwrap();

        assert_eq!(
            wt_claim_gate.vout as u32 + 1,
            CLAIM_INIT_WT_STOPPER_VOUT,
            "WT stopper vout"
        );
        assert_eq!(
            op_claim_gate.vout as u32 + 1,
            CLAIM_INIT_OP_STOPPER_VOUT,
            "OP stopper vout"
        );

        let outputs = &protocol.transaction_by_name(claim_init).unwrap().output;
        assert_eq!(outputs.len(), 7, "CLAIM_INIT_TX output count");
        assert_eq!(
            outputs[outputs.len() - CLAIM_INIT_WT_SPEEDUP_OUTPUT_OFFSET_FROM_END as usize]
                .script_pubkey,
            *wt_speedup_output.get_script_pubkey(),
            "WT speedup is not the last output, the OP speedup follows it"
        );
        assert_eq!(
            outputs[outputs.len() - CLAIM_INIT_OP_SPEEDUP_OUTPUT_OFFSET_FROM_END as usize]
                .script_pubkey,
            *OutputType::segwit_key(SPEEDUP_VALUE, &op_speedup)
                .unwrap()
                .get_script_pubkey(),
            "OP speedup follows the WT speedup"
        );
    }
}
