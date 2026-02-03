use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            claim::{ClaimGate, CLAIM_GATE_START, CLAIM_GATE_STOP, CLAIM_GATE_SUCCESS},
            dispute::{self, action_wins_prefix},
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{
                common::{
                    collect_input_signatures, create_transaction_reference, double_indexed_name,
                    estimate_fee, extract_double_index, extract_index,
                    extract_index_from_claim_gate, get_accept_pegin_pid, get_dispatch_action,
                    get_dispute_channel_pid, get_dispute_core_pid, get_dispute_pair_key_name,
                    get_full_penalization_pid, get_initial_deposit_output_type, get_my_idx,
                    get_stream_setting, indexed_name, load_penalized_member, load_union_settings,
                    set_my_idx, triple_indexed_name, InputSigningInfo, WinternitzData,
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
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use core::result::Result::Ok;
use key_manager::key_type::BitcoinKeyType;
use key_manager::winternitz::{WinternitzPublicKey, WinternitzType};
use protocol_builder::{
    builder::Protocol,
    graph::graph::GraphOptions,
    scripts::{
        op_return, op_return_script, timelock, verify_signature,
        verify_winternitz_signature_timelock, SignMode,
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
const PEGOUT_ID_KEY: &str = "PEGOUT_ID_KEY";
const SECRET_KEY: &str = "SECRET_KEY";
pub const CHALLENGE_KEY: &str = "CHALLENGE_KEY";
const SLOT_ID_KEY: &str = "SLOT_ID_KEY";
const SLOT_ID_KEYS: &str = "SLOT_ID_KEYS";
const MEMBERS_SLOT_ID_KEYS: &str = "MEMBERS_SLOT_ID_KEYS";
const INIT_CHALLENGE_SLOT: &str = "INIT_CHALLENGE_SLOT";

const CLAIM_GATE_FEE: u64 = 335; // TODO: Validate this value

pub const OP_INITIAL_DEPOSIT_TX_DISABLER_LEAF: usize = 1;
pub const WT_START_ENABLER_TX_DISABLER_LEAF: usize = 0;

const REVEAL_INPUT_TX_REVEAL_INDEX: usize = 0;
const REVEAL_INPUT_TX_REVEAL_LEAF: usize = 0;
const REVEAL_INPUT_TX_COMMITTEE_LEAF: usize = 1;

// const WT_INIT_CHALLENGE_TX_COSIGN_LEAF: usize = 0;
const WT_INIT_CHALLENGE_TX_TIMELOCK_LEAF: usize = 1;
pub const WT_INIT_CHALLENGE_TX_COSIGN_DISABLER_LEAF: usize = 2;

const WT_INIT_CHALLENGE_COSIGN_VOUT: u32 = 0;
const WT_INIT_CHALLENGE_WT_STOPPER_VOUT: u32 = 3;
const WT_INIT_CHALLENGE_OP_STOPPER_VOUT: u32 = 5;

const OP_COSIGN_TX_TIMELOCK_LEAF: usize = 0;

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
    RevealInput {
        slot_index: usize,
    },
    InputNotRevealed {
        slot_index: usize,
        block_height: Option<u32>,
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
            DisputeCoreTxType::RevealInput { slot_index } => {
                indexed_name(REVEAL_INPUT_TX, *slot_index)
            }
            DisputeCoreTxType::InputNotRevealed { slot_index, .. } => {
                indexed_name(INPUT_NOT_REVEALED_TX, *slot_index)
            }
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

    fn get_pregenerated_aggregated_keys(
        &self,
        context: &ProgramContext,
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

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let committee = self.committee(program_context)?;
        let packet_size = committee.packet_size;
        let data = self.dispute_core_data(program_context)?;
        let mut keys = vec![];

        let speedup_key = program_context
            .key_chain
            .derive_keypair(BitcoinKeyType::P2tr)?;

        keys.push((
            SPEEDUP_KEY.to_string(),
            PublicKeyType::Public(speedup_key.clone()),
        ));

        program_context.globals.set_var(
            &self.ctx.id,
            SPEEDUP_KEY,
            VariableTypes::PubKey(speedup_key),
        )?;

        let dispute_pair_keys =
            self.get_dispute_pair_keys(&program_context, data.committee_id, &committee.members)?;

        keys.extend(dispute_pair_keys);

        let prover = self.prover(program_context)?;

        let mut slot_id_keys = self.slot_id_keys(&program_context, data.committee_id)?;
        if prover {
            // Load SLOT_ID_KEYS if they were previously generated
            // If not present, generate and store them
            if slot_id_keys.is_empty() {
                for _ in 0..packet_size as usize {
                    slot_id_keys.push(PublicKeyType::Winternitz(
                        program_context.key_chain.derive_winternitz_hash160(2)?, // Sign 2 bytes of u16 slot id.
                    ));
                }

                program_context.globals.set_var(
                    &data.committee_id,
                    SLOT_ID_KEYS,
                    VariableTypes::String(serde_json::to_string(&slot_id_keys)?),
                )?;
            } else if slot_id_keys.len() != packet_size as usize {
                return Err(BitVMXError::InvalidParameter(format!(
                    "Expected {} slot_id_keys but found {}",
                    packet_size,
                    slot_id_keys.len()
                )));
            }
        }

        for i in 0..packet_size as usize {
            if prover {
                keys.push((
                    indexed_name(PEGOUT_ID_KEY, i).to_string(),
                    PublicKeyType::Winternitz(
                        program_context.key_chain.derive_winternitz_hash160(32)?,
                    ),
                ));

                keys.push((
                    indexed_name(SECRET_KEY, i).to_string(),
                    PublicKeyType::Winternitz(
                        program_context.key_chain.derive_winternitz_hash160(1)?,
                    ),
                ));

                keys.push((
                    indexed_name(SLOT_ID_KEY, i).to_string(),
                    slot_id_keys[i].clone(),
                ));
            }

            keys.push((
                indexed_name(CHALLENGE_KEY, i),
                PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(1)?),
            ));
        }

        Ok(ParticipantKeys::new(keys, vec![]))
    }

    fn build(
        &self,
        keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        info!("Building DisputeCoreProtocol for program {}", self.ctx.id);
        set_my_idx(context, self.ctx.id, self.ctx.my_idx)?;
        let dispute_core_data = self.dispute_core_data(context)?;
        self.validate_keys(&keys, context, dispute_core_data.committee_id)?;

        let mut protocol = self.load_or_create_protocol();
        let committee = self.committee(context)?;
        let member = &committee.members[dispute_core_data.member_index];
        let mut reimbursement_outputs = vec![];
        let settings = self.load_stream_setting(context)?;

        self.create_wt_start_enabler_output(
            &mut protocol,
            &dispute_core_data,
            &member.dispute_key,
            &committee.dispute_aggregated_key.clone(),
        )?;

        let (mut init_challenge_outputs, mut disabler_directory_output, mut op_cosign_outputs) =
            self.create_wt_start_enabler(
                &mut protocol,
                &dispute_core_data,
                &committee,
                &keys,
                &settings,
            )?;

        let operator_won_script = timelock(
            settings.op_won_timelock,
            &committee.take_aggregated_key,
            SignMode::Aggregate,
        );

        let mut reveal_output: OutputType = OutputType::taproot(
            AmountType::Auto,
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

                self.create_two_dispute_penalization(
                    &mut protocol,
                    i,
                    &committee.take_aggregated_key,
                )?;
            }
        }

        // Add speedup output
        protocol.add_transaction_output(
            &PROTOCOL_FUNDING_TX,
            &OutputType::segwit_key(
                SPEEDUP_VALUE.into(),
                keys[dispute_core_data.member_index].get_public(SPEEDUP_KEY)?,
            )?,
        )?;

        protocol.compute_minimum_output_values()?;
        self.add_funding_change(&mut protocol, &member.dispute_key, &dispute_core_data)?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
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
            &mut init_challenge_outputs,
            &mut disabler_directory_output,
            &mut op_cosign_outputs,
        )?;

        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!("Getting transaction by name: {}", name);
        if name == PROTOCOL_FUNDING_TX {
            Ok(self.protocol_funding_tx(context)?)
        } else if name == WT_START_ENABLER_TX {
            Ok(self.wt_start_enabler_tx(context)?)
        } else if name == OP_INITIAL_DEPOSIT_TX || name == WT_START_ENABLER_TX {
            Ok(self.sign_aggregated_input(name, context, true)?)
        } else if name.starts_with(REIMBURSEMENT_KICKOFF_TX) {
            Ok(self.reimbursement_kickoff_tx(name, context)?)
        } else if name.starts_with(CHALLENGE_TX) {
            Ok(self.challenge_tx(name, context)?)
        } else if name == WT_SELF_DISABLER_TX || name == OP_SELF_DISABLER_TX {
            Ok(self.sign_aggregated_input(name, context, false)?)
        } else if name.starts_with(WT_INIT_CHALLENGE_TX) {
            Ok(self.wt_init_challenge_tx(name, context)?)
        } else {
            Err(BitVMXError::InvalidTransactionName(name.to_string()))
        }
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        _vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
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

    fn notify_external_news(
        &self,
        tx_id: Txid,
        _vout: Option<u32>,
        _tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
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

        if tx_name.starts_with(&action_wins_prefix(&ParticipantRole::Prover)) {
            self.handle_action_wins(program_context, &tx_name, ParticipantRole::Prover, pid)?;
        } else if tx_name.starts_with(&action_wins_prefix(&ParticipantRole::Verifier)) {
            self.handle_action_wins(program_context, &tx_name, ParticipantRole::Verifier, pid)?;
        }

        Ok(())
    }

    fn setup_complete(&self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
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

    fn create_wt_start_enabler(
        &self,
        protocol: &mut Protocol,
        data: &DisputeCoreData,
        committee: &Committee,
        keys: &Vec<ParticipantKeys>,
        settings: &StreamSettings,
    ) -> Result<
        (
            Vec<Option<WtInitChallengeOutputs>>,
            OutputType,
            Vec<Option<OutputType>>,
        ),
        BitVMXError,
    > {
        let wt_speedup_key = keys[data.member_index].get_public(SPEEDUP_KEY)?;
        let wt_dispute_key = &committee.members[data.member_index].dispute_key;
        let mut wt_init_challenge_outputs: Vec<Option<WtInitChallengeOutputs>> = vec![];
        let mut op_cosign_outputs: Vec<Option<OutputType>> = vec![];
        let challenge_cost = dispute::protocol_cost();

        for (member_index, member) in committee.members.clone().iter().enumerate() {
            let mut scripts = vec![];
            let op_speedup_key = keys[member_index].get_public(SPEEDUP_KEY)?;
            let op_dispute_key = &committee.members[member_index].dispute_key;

            if member.role == ParticipantRole::Prover && data.member_index != member_index {
                for slot in 0..committee.packet_size as usize {
                    let key_name = indexed_name(SLOT_ID_KEY, slot);
                    let slot_id_key = keys[member_index].get_winternitz(&key_name)?;

                    scripts.push(scripts::verify_winternitz(
                        &wt_dispute_key,
                        self.get_sign_mode(data.member_index),
                        &key_name,
                        slot_id_key,
                    )?);
                }
            }

            if member.role == ParticipantRole::Prover && data.member_index != member_index {
                let init_challenge_name =
                    double_indexed_name(WT_INIT_CHALLENGE_TX, data.member_index, member_index);
                let op_cosign_name =
                    double_indexed_name(OP_COSIGN_TX, data.member_index, member_index);
                let op_no_cosign_name =
                    double_indexed_name(OP_NO_COSIGN_TX, data.member_index, member_index);
                let wt_no_challenge_name =
                    double_indexed_name(WT_NO_CHALLENGE_TX, data.member_index, member_index);
                let wt_claim_name =
                    double_indexed_name(WT_CLAIM_GATE, data.member_index, member_index);
                let op_claim_name =
                    double_indexed_name(OP_CLAIM_GATE, data.member_index, member_index);

                protocol.add_connection(
                    "init_challenge",
                    WT_START_ENABLER_TX,
                    OutputType::taproot(AmountType::Auto, &wt_dispute_key, &scripts)?.into(),
                    &init_challenge_name,
                    InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
                    None,
                    None,
                )?;

                // TODO: Review this script, it should validate the slot id.
                let verify_slot_id =
                    verify_signature(&committee.dispute_aggregated_key, SignMode::Aggregate)?;

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
                        // FIXME: Leaf 0 should be cosign script here
                        // This should cosign the challenge input to be able to open the challenge.
                        verify_slot_id,
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

                let key_pair_name = get_dispute_pair_key_name(data.member_index, member_index);
                let key_pair = keys[data.member_index].get_public(&key_pair_name)?;

                // Create WT claim gate
                let wt_claim_gate = ClaimGate::new(
                    protocol,
                    &init_challenge_name,
                    &wt_claim_name,
                    (wt_dispute_key, self.get_sign_mode(data.member_index)),
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
                    &init_challenge_name,
                    &op_claim_name,
                    (op_dispute_key, self.get_sign_mode(member_index)),
                    &committee.dispute_aggregated_key,
                    CLAIM_GATE_FEE,
                    DUST_VALUE,
                    vec![wt_speedup_key],
                    Some(vec![&key_pair]),
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

                wt_init_challenge_outputs.push(Some(WtInitChallengeOutputs {
                    wt_stopper: wt_claim_gate.stoppers[0].clone(),
                    op_stopper: op_claim_gate.stoppers[0].clone(),
                    op_cosign: init_challenge_output.clone(),
                }));

                // FIXME: Review this output. This goes to DisputeChannel. Need 2 scripts by now.
                // NOTE: DRP consumes leaf 1 hardcoded.
                let verify_wt_signature =
                    verify_signature(wt_dispute_key, self.get_sign_mode(data.member_index))?;

                let wt_not_challenge_timelock_script = timelock(
                    settings.wt_no_challenge_timelock,
                    &committee.dispute_aggregated_key,
                    SignMode::Aggregate,
                );

                let op_cosign_output = OutputType::taproot(
                    challenge_cost.into(),
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

                // OP NO COSIGN TX
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

                protocol.add_connection(
                    "op_no_cosign",
                    &init_challenge_name,
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
                    &OutputType::segwit_unspendable(
                        op_return_script(vec![])?.get_script().clone(),
                    )?,
                )?;

                // WT NO CHALLENGE TX
                protocol.add_connection(
                    "wt_no_challenge",
                    &init_challenge_name,
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
                    &OutputType::segwit_unspendable(
                        op_return_script(vec![])?.get_script().clone(),
                    )?,
                )?;

                protocol.add_transaction_output(
                    &init_challenge_name,
                    &OutputType::segwit_key(SPEEDUP_VALUE.into(), &wt_speedup_key)?,
                )?;
            } else {
                protocol.add_transaction_output(
                    WT_START_ENABLER_TX,
                    &OutputType::taproot(AmountType::Auto, wt_dispute_key, &vec![])?,
                )?;

                wt_init_challenge_outputs.push(None);
                op_cosign_outputs.push(None);
            }
        }

        let op_count = committee
            .members
            .iter()
            .filter(|m| m.role == ParticipantRole::Prover)
            .count() as u64;

        let wt_disabler_directory_fee = estimate_fee(2, op_count as usize * 2, 1);

        let disabler_directory_funds_output = OutputType::taproot(
            (DUST_VALUE * op_count * 2 as u64 + wt_disabler_directory_fee).into(),
            &committee.dispute_aggregated_key,
            &[],
        )?;
        protocol.add_transaction_output(&WT_START_ENABLER_TX, &disabler_directory_funds_output)?;

        // Add speedup output
        protocol.add_transaction_output(
            &WT_START_ENABLER_TX,
            &OutputType::segwit_key(SPEEDUP_VALUE.into(), &wt_speedup_key)?,
        )?;

        Ok((
            wt_init_challenge_outputs,
            disabler_directory_funds_output,
            op_cosign_outputs,
        ))
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
        settings: &StreamSettings,
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

    fn create_dispute_core(
        &self,
        protocol: &mut Protocol,
        committee: &Committee,
        dispute_core_data: &DisputeCoreData,
        dispute_core_index: usize,
        keys: &Vec<ParticipantKeys>,
        reimbursement_output: OutputType,
        context: &ProgramContext,
        reveal_output: &OutputType,
        settings: &StreamSettings,
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
            PEGOUT_ID_KEY,
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

        let reveal_script = protocol_builder::scripts::verify_winternitz_signature(
            &operator_dispute_key,
            operator_keys.get_winternitz(&indexed_name(SLOT_ID_KEY, dispute_core_index))?,
            self.get_sign_mode(dispute_core_data.member_index),
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

        // TODO: Should we remove this output? If so, need to update input_not_revealed_tx with correct speedup output index
        protocol.add_transaction_output(
            &input_not_revealed,
            &OutputType::segwit_unspendable(op_return(vec![]))?,
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
        take_aggregated_key: &PublicKey,
    ) -> Result<(), BitVMXError> {
        let last_reveal = indexed_name(REVEAL_INPUT_TX, dispute_core_index);

        if dispute_core_index == 0 {
            // No previous reveal transaction to connect to.
            return Ok(());
        }

        for i in 0..dispute_core_index {
            let prev_reveal = indexed_name(REVEAL_INPUT_TX, i);
            let two_dispute_penalization = format!(
                "{}_{}_{}",
                TWO_DISPUTE_PENALIZATION_TX, i, dispute_core_index
            );

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

            protocol.add_transaction_output(
                &two_dispute_penalization,
                &OutputType::taproot(AmountType::Auto, &take_aggregated_key, &[])?,
            )?;
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
            let disabler_directory_amount =
                committee.packet_size as u64 * DUST_VALUE + SPEEDUP_VALUE + directory_fee;
            protocol.add_transaction_output(
                &OP_INITIAL_DEPOSIT_TX,
                &OutputType::taproot(
                    disabler_directory_amount.into(),
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

        // Add one speedup ouput per committee member to the challenge and input_not_revealed transactions.
        for i in 0..keys.len() {
            let speedup_output =
                OutputType::segwit_key(AmountType::Auto, keys[i].get_public(SPEEDUP_KEY)?)?;
            protocol.add_transaction_output(&challenge, &speedup_output)?;
            protocol.add_transaction_output(&input_not_revealed, &speedup_output)?;
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
                    &OutputType::segwit_key(change.into(), member_change_key)?,
                )
                .map_err(|e| BitVMXError::ProtocolBuilderError(e))?;
        }

        Ok(())
    }

    fn protocol_funding_tx(
        &self,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        let tx_name = PROTOCOL_FUNDING_TX;
        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            tx_name,
            &vec![InputSigningInfo::SignEdcsa {
                input_index: 0,
                key_manager: context.key_chain.key_manager.as_ref(),
            }],
        )?;

        let tx = protocol.transaction_to_send(&tx_name, &args)?;

        let txid = tx.compute_txid();
        let speedup_key = self.my_speedup_key(context)?;
        let speedup_vout = (tx.output.len() - 2) as u32;
        let speedup_utxo = Utxo::new(txid, speedup_vout, SPEEDUP_VALUE, &speedup_key);

        Ok((tx, Some(speedup_utxo.into())))
    }

    fn reimbursement_kickoff_tx(
        &self,
        name: &str,
        context: &ProgramContext,
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
                    key_name: PEGOUT_ID_KEY.to_string(),
                    key_type: WinternitzType::HASH160,
                    key_manager: context.key_chain.key_manager.as_ref(),
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

    fn challenge_tx(
        &self,
        name: &str,
        context: &ProgramContext,
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
                    key_manager: context.key_chain.key_manager.as_ref(),
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

    fn wt_init_challenge_tx(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", name);

        let protocol = self.load_protocol()?;
        let slot_index = self.get_number(context, &self.ctx.id, INIT_CHALLENGE_SLOT)? as usize;

        // Prepare signatures
        let slot_signature = protocol
            .input_taproot_script_spend_signature(name, 0, slot_index)?
            .unwrap();

        // Create input arguments
        let mut input_args = InputArgs::new_taproot_script_args(slot_index);
        let key_name = "value";

        // TODO: should we support this in collect_input_signatures?
        let witness = context
            .witness
            .get_witness(&self.ctx.id, &key_name)?
            .unwrap();
        let winternitz_signature = witness.winternitz()?;
        input_args.push_winternitz_signature(winternitz_signature);
        input_args.push_taproot_signature(slot_signature)?;

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

    fn get_number(
        &self,
        context: &ProgramContext,
        pid: &Uuid,
        var_name: &str,
    ) -> Result<u32, BitVMXError> {
        Ok(context.globals.get_var(pid, var_name)?.unwrap().number()?)
    }

    fn set_number(
        &self,
        context: &ProgramContext,
        pid: &Uuid,
        var_name: &str,
        value: u32,
    ) -> Result<(), BitVMXError> {
        context
            .globals
            .set_var(pid, var_name, VariableTypes::Number(value))
    }

    fn dispute_core_data(&self, context: &ProgramContext) -> Result<DisputeCoreData, BitVMXError> {
        let data = context
            .globals
            .get_var(&self.ctx.id, &DisputeCoreData::name())?
            .unwrap()
            .string()?;

        let data: DisputeCoreData = serde_json::from_str(&data)?;
        Ok(data)
    }

    fn committee(&self, context: &ProgramContext) -> Result<Committee, BitVMXError> {
        let committee_id = self.committee_id(context)?;

        let committee = context
            .globals
            .get_var(&committee_id, &Committee::name())?
            .unwrap()
            .string()?;

        let committee: Committee = serde_json::from_str(&committee)?;
        Ok(committee)
    }

    fn prover(&self, context: &ProgramContext) -> Result<bool, BitVMXError> {
        match self.committee(context)?.members[self.ctx.my_idx].role {
            ParticipantRole::Prover => Ok(true),
            _ => Ok(false),
        }
    }

    fn my_speedup_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        Ok(context
            .globals
            .get_var(&self.ctx.id, SPEEDUP_KEY)?
            .unwrap()
            .pubkey()?)
    }

    fn my_dispute_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        let committee = self.committee(context)?;
        Ok(committee.members[self.ctx.my_idx].dispute_key.clone())
    }

    fn committee_id(&self, context: &ProgramContext) -> Result<Uuid, BitVMXError> {
        Ok(self.dispute_core_data(context)?.committee_id)
    }

    fn monitored_operator_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        let committee = self.committee(context)?;
        let data = self.dispute_core_data(context)?;
        Ok(committee.members[data.member_index].take_key)
    }

    fn get_selected_operator_key(
        &self,
        slot_id: usize,
        program_context: &ProgramContext,
    ) -> Result<Option<PublicKey>, BitVMXError> {
        let committee_id = self.committee_id(program_context)?;
        let selected_operator_key_name = format!("{}_{}", SELECTED_OPERATOR_PUBKEY, slot_id);

        match program_context
            .globals
            .get_var(&committee_id, &selected_operator_key_name)?
        {
            Some(selected_operator_var) => Ok(Some(selected_operator_var.pubkey()?)),
            None => Ok(None),
        }
    }

    fn get_reveal_in_progress(
        &self,
        program_context: &ProgramContext,
    ) -> Result<Option<u32>, BitVMXError> {
        match program_context
            .globals
            .get_var(&self.ctx.id, REVEAL_IN_PROGRESS)?
        {
            Some(var) => Ok(Some(var.number()?)),
            None => Ok(None),
        }
    }

    fn set_reveal_in_progress(
        &self,
        program_context: &ProgramContext,
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

    fn handle_wt_claim_gate_txs(
        &self,
        context: &ProgramContext,
        tx_name: &str,
        tx_status: &TransactionStatus,
    ) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Handling {}", tx_name);

        let (wt_index, op_index) = extract_index_from_claim_gate(tx_name)?;

        if tx_name.ends_with(CLAIM_GATE_START) {
            if self.is_my_dispute_core(context)? {
                let settings = self.load_stream_setting(context)?;
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

    fn handle_action_wins(
        &self,
        program_context: &ProgramContext,
        tx_name: &str,
        role: ParticipantRole,
        pid: Uuid,
    ) -> Result<(), BitVMXError> {
        // Need to load my_idx from storage because self.ctx.my_idx has my index on DRP
        let my_idx = get_my_idx(program_context, self.ctx.id)?;

        info!(
            id = my_idx,
            "Handling wins action {}. PID: {}", tx_name, pid
        );

        let committee_id = self.committee_id(program_context)?;
        let committee = self.committee(program_context)?;
        let wt_index = self.dispute_core_data(program_context)?.member_index;

        // Look for the operator index that matches the DisputeChannel program ID in the context
        let maybe_index = committee
            .members
            .iter()
            .enumerate()
            .find(|(op_index, _)| get_dispute_channel_pid(committee_id, *op_index, wt_index) == pid)
            .map(|(op_index, _)| op_index);

        let drp_op_index = match maybe_index {
            Some(i) => i,
            None => {
                error!(
                    id = my_idx,
                    "Could not find matching DisputeChannel program for PID: {}", pid
                );
                return Ok(());
            }
        };

        info!(
            id = my_idx,
            "DisputeChannel operator index for PID {} is {}", pid, drp_op_index
        );

        if role == ParticipantRole::Prover {
            if my_idx == drp_op_index {
                self.dispatch_claim_gate(
                    program_context,
                    ClaimGateAction::Start,
                    OP_CLAIM_GATE,
                    drp_op_index,
                )?;
            }
        } else if role == ParticipantRole::Verifier {
            if my_idx == wt_index {
                self.dispatch_claim_gate(
                    program_context,
                    ClaimGateAction::Start,
                    WT_CLAIM_GATE,
                    drp_op_index,
                )?;
            }
        }

        Ok(())
    }

    fn handle_op_no_cosign_tx(
        &self,
        context: &ProgramContext,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Handling {}", tx_name);
        let (_, op_index) = extract_double_index(tx_name)?;

        if self.is_my_dispute_core(context)? {
            self.dispatch_claim_gate(context, ClaimGateAction::Start, WT_CLAIM_GATE, op_index)?;
        }

        Ok(())
    }

    fn handle_wt_no_challenge_tx(
        &self,
        context: &ProgramContext,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Handling {}", tx_name);
        let (_, op_index) = extract_double_index(tx_name)?;

        if op_index == self.ctx.my_idx {
            self.dispatch_claim_gate(context, ClaimGateAction::Start, OP_CLAIM_GATE, op_index)?;
        }

        Ok(())
    }

    fn handle_op_claim_gate_txs(
        &self,
        context: &ProgramContext,
        tx_name: &str,
        tx_status: &TransactionStatus,
    ) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Handling {}", tx_name);

        let (wt_index, op_index) = extract_index_from_claim_gate(tx_name)?;

        if tx_name.ends_with(CLAIM_GATE_START) {
            if self.ctx.my_idx == op_index {
                let settings = self.load_stream_setting(context)?;
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

    fn claim_gate_tx(
        &self,
        context: &ProgramContext,
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
                    &self.my_dispute_key(context)?,
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

    fn dispatch_claim_gate(
        &self,
        context: &ProgramContext,
        action: ClaimGateAction,
        prefix: &str,
        op_index: usize,
    ) -> Result<(), BitVMXError> {
        let data = self.dispute_core_data(context)?;
        let base = double_indexed_name(prefix, data.member_index, op_index);
        let tx_name = action.tx_name(&base);
        info!(id = self.ctx.my_idx, "Auto-dispatching {}", tx_name);

        let (tx, speedup) =
            self.claim_gate_tx(context, &tx_name, &action.inputs(), action.with_speedup())?;
        let txid = tx.compute_txid();

        context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            Context::ProgramId(self.ctx.id).to_string()?,
            action.block_height(),
            self.requested_confirmations(context),
        )?;

        info!(
            id = self.ctx.my_idx,
            "{} {} with txid: {}",
            tx_name,
            get_dispatch_action(action.block_height()),
            txid
        );

        Ok(())
    }

    fn load_stream_setting(&self, context: &ProgramContext) -> Result<StreamSettings, BitVMXError> {
        get_stream_setting(
            &load_union_settings(context)?,
            self.committee(context)?.stream_denomination,
        )
    }

    fn handle_op_cosign_tx(
        &self,
        context: &ProgramContext,
        tx_name: &str,
        tx_status: &TransactionStatus,
    ) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Handling {}", tx_name);
        let settings = self.load_stream_setting(context)?;
        let (_, op_index) = extract_double_index(tx_name)?;

        if self.is_my_dispute_core(context)? {
            let drp_pid =
                get_dispute_channel_pid(self.committee_id(context)?, op_index, self.ctx.my_idx);
            let drp_protocol = self.load_protocol_by_name(PROGRAM_TYPE_DRP, drp_pid)?;

            let (tx, speedup) =
                drp_protocol.get_transaction_by_name(&dispute::START_CH.to_string(), context)?;
            let txid = tx.compute_txid();

            context.bitcoin_coordinator.dispatch(
                tx,
                speedup,
                Context::ProgramId(self.ctx.id).to_string()?,
                None,
                self.requested_confirmations(context),
            )?;

            info!(
                id = self.ctx.my_idx,
                "{} dispatched with txid: {}",
                dispute::START_CH.to_string(),
                txid
            );
        } else {
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

    fn handle_wt_init_challenge(
        &self,
        context: &ProgramContext,
        tx_name: &str,
        tx_status: &TransactionStatus,
    ) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Handling {}", tx_name);

        let settings = self.load_stream_setting(context)?;
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
        } else {
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

                    return Ok(());
                }
                None => {}
            }

            if op_index == self.ctx.my_idx {
                self.dispatch(
                    context,
                    DisputeCoreTxType::OperatorCosign {
                        wt_index: data.member_index,
                        op_index,
                    },
                )?;
            } else {
                info!(
                    id = self.ctx.my_idx,
                    "{} not for me (my index: {}), skipping op_cosign dispatch",
                    tx_name,
                    self.ctx.my_idx
                );
            }
        }

        Ok(())
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

    fn op_cosign_tx(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![InputSigningInfo::SignTaproot {
                input_index: 0,
                script_index: None,
                key_manager: context.key_chain.key_manager.as_ref(),
                id: "".to_string(),
            }],
        )?;

        let tx = protocol.transaction_to_send(&name, &args)?;
        info!(id = self.ctx.my_idx, "Signed {}", name);

        Ok((tx, None))
    }

    fn handle_reveal_input_tx(
        &self,
        context: &ProgramContext,
        tx_name: &str,
        tx_status: &TransactionStatus,
    ) -> Result<(), BitVMXError> {
        let slot_index = extract_index(&tx_name, REVEAL_INPUT_TX)?;
        info!(
            id = self.ctx.my_idx,
            "Handling reveal input tx for slot {}", slot_index
        );

        if self.is_my_dispute_core(context)? {
            info!(
                id = self.ctx.my_idx,
                "This is my dispute_core, scheduling OPERATOR_WON_TX for slot {}", slot_index
            );

            let settings = self.load_stream_setting(context)?;
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

        let data = self.dispute_core_data(context)?;

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

                return Ok(());
            }
            None => {}
        }

        let committee = self.committee(context)?;
        let wt_dispute_core_id = get_dispute_core_pid(
            data.committee_id,
            &committee.members[self.ctx.my_idx].take_key,
        );

        // Save data to sign init challenge in wt own dispute core
        self.set_number(
            context,
            &wt_dispute_core_id,
            INIT_CHALLENGE_SLOT,
            slot_index as u32,
        )?;

        let protocol = self.load_protocol()?;

        let script = protocol.get_script_to_spend(
            tx_name,
            REVEAL_INPUT_TX_REVEAL_INDEX as u32,
            REVEAL_INPUT_TX_REVEAL_LEAF as u32,
        )?;

        self.decode_witness_for_tx(
            tx_name,
            REVEAL_INPUT_TX_REVEAL_INDEX as u32,
            context,
            &tx_status.tx,
            Some(REVEAL_INPUT_TX_REVEAL_LEAF as u32),
            Some(protocol),
            Some(vec![script]),
        )?;

        let key_name = "value";
        let witness = context
            .witness
            .get_witness(&self.ctx.id, key_name)?
            .unwrap();

        // Save witness in WT dispute core
        context
            .witness
            .set_witness(&wt_dispute_core_id, key_name, witness)?;

        // Load wt dispute core and dispatch init challenge tx
        let protocol = self.load_protocol_by_name(PROGRAM_TYPE_DISPUTE_CORE, wt_dispute_core_id)?;
        let init_challenge_name =
            double_indexed_name(WT_INIT_CHALLENGE_TX, self.ctx.my_idx, data.member_index);

        let (tx, speedup) = protocol.get_transaction_by_name(&init_challenge_name, context)?;
        let txid = tx.compute_txid();

        context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            Context::ProgramId(self.ctx.id).to_string()?,
            None,
            self.requested_confirmations(context),
        )?;

        info!(
            id = self.ctx.my_idx,
            "{} dispatched for slot: {} with txid: {}", init_challenge_name, slot_index, txid
        );

        Ok(())
    }

    fn handle_challenge_tx(
        &self,
        context: &ProgramContext,
        slot_index: usize,
        tx_status: &TransactionStatus,
    ) -> Result<(), BitVMXError> {
        if self.is_my_dispute_core(context)? {
            info!(
                id = self.ctx.my_idx,
                "This is my dispute_core, checking for operator take dispatch for slot {}",
                slot_index
            );
            self.dispatch(context, DisputeCoreTxType::RevealInput { slot_index })?;
        } else {
            // Schedule input not revealed dispatch transaction
            let settings = self.load_stream_setting(context)?;
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

    fn reveal_input_tx(
        &self,
        name: &str,
        context: &ProgramContext,
        slot_index: usize,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(id = self.ctx.my_idx, "Loading {} for DisputeCore", name);

        let mut protocol = self.load_protocol()?;

        let args = collect_input_signatures(
            &mut protocol,
            name,
            &vec![InputSigningInfo::ScriptSpend {
                input_index: REVEAL_INPUT_TX_REVEAL_INDEX,
                script_index: REVEAL_INPUT_TX_REVEAL_LEAF,
                winternitz_data: Some(WinternitzData {
                    data: (slot_index as u16).to_le_bytes().to_vec(),
                    key_name: "value".to_string(),
                    key_type: WinternitzType::HASH160,
                    key_manager: context.key_chain.key_manager.as_ref(),
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

    fn input_not_revealed_tx(
        &self,
        name: &str,
        context: &ProgramContext,
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

        // Speedup data
        let speedup_utxo = Utxo::new(
            tx.compute_txid(),
            1 + self.ctx.my_idx as u32, //Speedup vout is member index + 1 (1 is because op return output)
            SPEEDUP_VALUE,
            &self.my_speedup_key(context)?,
        );

        Ok((tx, Some(speedup_utxo.into())))
    }

    fn handle_double_reveal(
        &self,
        context: &ProgramContext,
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

        let name = format!(
            "{}_{}_{}",
            TWO_DISPUTE_PENALIZATION_TX, slot_index_prev, slot_index_last
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

    fn handle_reimbursement_kickoff_transaction(
        &self,
        context: &ProgramContext,
        tx_status: &TransactionStatus,
        tx_id: Txid,
        tx_name: &str,
    ) -> Result<(), BitVMXError> {
        info!(
            "Handling reimbursement kickoff txid: {}. Name: {}",
            tx_id, tx_name
        );

        // Extract slot_index from transaction name
        let slot_index = extract_index(tx_name, REIMBURSEMENT_KICKOFF_TX)?;
        info!("Extracted slot index: {}", slot_index);

        let settings = self.load_stream_setting(context)?;

        if self.is_my_dispute_core(context)? {
            info!(
                id = self.ctx.my_idx,
                "This is my dispute_core, checking for operator take dispatch for slot {}",
                slot_index
            );
            // Handle operator take if needed
            if tx_status.confirmations == 1 {
                let block_height =
                    self.get_dispatch_height(tx_status, settings.long_timelock + 1)?;
                self.dispatch(
                    context,
                    DisputeCoreTxType::OperatorTake {
                        op_index: self.ctx.my_idx,
                        slot_index,
                        block_height: Some(block_height),
                    },
                )?;
            } else {
                info!(
                    id = self.ctx.my_idx,
                    "Reimbursement kickoff transaction {} lacks enough confirmations: {}",
                    tx_id,
                    tx_status.confirmations
                );
            }
        } else {
            info!(
                id = self.ctx.my_idx,
                "Not my dispute_core, skipping operator take dispatch for slot {}", slot_index
            );

            let data = self.dispute_core_data(context)?;
            // Check if operator already penalized
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

                    return Ok(());
                }
                None => {}
            }

            // Handle challenge if needed
            match self.get_selected_operator_key(slot_index, context)? {
                Some(selected_operator_key) => {
                    // Get the operator's take key that this dispute core is monitoring
                    let monitored_operator_key = self.monitored_operator_key(context)?;

                    // Compare if the monitored operator is the selected one
                    let is_valid = selected_operator_key == monitored_operator_key;

                    if !is_valid {
                        info!(
                            "Unauthorized operator detected for slot {}, dispatching Challenge Tx",
                            slot_index
                        );
                        self.dispatch(
                            context,
                            DisputeCoreTxType::Challenge {
                                slot_index,
                                block_height: Some(self.get_dispatch_height(
                                    tx_status,
                                    self.load_stream_setting(context)?.short_timelock,
                                )?),
                            },
                        )?;
                    } else {
                        info!("Authorized operator confirmed for slot {}", slot_index);
                        // TODO: here we need to validate that the advancement of funds has actually been made
                    }
                }
                None => {
                    info!("No selected operator key found for slot {}", slot_index);
                    // If no selected operator key is set, it means that someone triggered a reimbursment kickoff transaction but there was no advances of funds
                    self.dispatch(
                        context,
                        DisputeCoreTxType::Challenge {
                            slot_index,
                            block_height: Some(self.get_dispatch_height(
                                tx_status,
                                self.load_stream_setting(context)?.short_timelock,
                            )?),
                        },
                    )?;
                }
            }
        }

        self.send_reimbursement_kickoff_spv(context, tx_id, slot_index)?;

        Ok(())
    }

    fn send_reimbursement_kickoff_spv(
        &self,
        context: &ProgramContext,
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
            .send(&context.components_config.l2, data)?;

        Ok(())
    }

    fn dispatch(
        &self,
        context: &ProgramContext,
        tx_type: DisputeCoreTxType,
    ) -> Result<(), BitVMXError> {
        let tx_name = tx_type.tx_name();
        info!(
            id = self.ctx.my_idx,
            "Dispatch {} from protocol {}", tx_name, self.ctx.id
        );

        let (tx, speedup) = match tx_type {
            DisputeCoreTxType::WtStartEnabler => self.wt_start_enabler_tx(context)?,
            DisputeCoreTxType::ProtocolFunding => self.protocol_funding_tx(context)?,
            DisputeCoreTxType::OperatorDisablerDirectory { .. } => {
                let dispute_core_data: DisputeCoreData = self.dispute_core_data(context)?;
                let protocol = self.load_protocol_by_name(
                    PROGRAM_TYPE_FULL_PENALIZATION,
                    get_full_penalization_pid(dispute_core_data.committee_id),
                )?;
                protocol.get_transaction_by_name(&tx_name, context)?
            }
            DisputeCoreTxType::WatchtowerDisablerDirectory { .. } => {
                let dispute_core_data: DisputeCoreData = self.dispute_core_data(context)?;
                let protocol = self.load_protocol_by_name(
                    PROGRAM_TYPE_FULL_PENALIZATION,
                    get_full_penalization_pid(dispute_core_data.committee_id),
                )?;
                protocol.get_transaction_by_name(&tx_name, context)?
            }
            DisputeCoreTxType::OperatorTake { slot_index, .. }
            | DisputeCoreTxType::OperatorWon { slot_index, .. } => {
                let dispute_core_data: DisputeCoreData = self.dispute_core_data(context)?;
                let accept_pegin_pid =
                    get_accept_pegin_pid(dispute_core_data.committee_id, slot_index);
                let protocol =
                    self.load_protocol_by_name(PROGRAM_TYPE_ACCEPT_PEGIN, accept_pegin_pid)?;

                protocol.get_transaction_by_name(&tx_name, context)?
            }
            DisputeCoreTxType::Challenge { .. } => self.challenge_tx(&tx_name.clone(), context)?,
            DisputeCoreTxType::WatchtowerNoChallenge { .. } => self.wt_no_challenge_tx(&tx_name)?,
            DisputeCoreTxType::OperatorNoCosign { .. } => self.op_no_cosign_tx(&tx_name)?,
            DisputeCoreTxType::OperatorCosign { .. } => self.op_cosign_tx(&tx_name, context)?,
            DisputeCoreTxType::RevealInput { slot_index } => {
                self.reveal_input_tx(&tx_name, context, slot_index)?
            }
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
            DisputeCoreTxType::PenalizationStopOperatorWon { .. }
            | DisputeCoreTxType::PenalizationOperatorLazyDisabler { .. }
            | DisputeCoreTxType::PenalizationWatchtowerDisabler { .. }
            | DisputeCoreTxType::PenalizationWatchtowerCosignDisabler { .. } => {
                let dispute_core_data: DisputeCoreData = self.dispute_core_data(context)?;
                let protocol = self.load_protocol_by_name(
                    PROGRAM_TYPE_FULL_PENALIZATION,
                    get_full_penalization_pid(dispute_core_data.committee_id),
                )?;
                protocol.get_transaction_by_name(&tx_name, context)?
            }
        };

        let txid = tx.compute_txid();

        // Dispatch the transaction through the bitcoin coordinator
        context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            Context::ProgramId(self.ctx.id).to_string()?,
            tx_type.block_height(),
            self.requested_confirmations(context),
        )?;

        info!(
            id = self.ctx.my_idx,
            "{} {} with txid: {}",
            tx_name,
            get_dispatch_action(tx_type.block_height()),
            txid
        );

        Ok(())
    }

    fn wt_start_enabler_tx(
        &self,
        context: &ProgramContext,
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

    fn is_my_dispute_core(&self, program_context: &ProgramContext) -> Result<bool, BitVMXError> {
        let dispute_core_data = self.dispute_core_data(program_context)?;
        Ok(dispute_core_data.member_index == self.ctx.my_idx)
    }

    fn save_op_utxos(
        &self,
        context: &ProgramContext,
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
        }

        // FIXME: Should we save the whole UTXOS as in reimbursement_kickoff_utxos?
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
                output_value.into(),
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

    fn save_wt_utxos(
        &self,
        context: &ProgramContext,
        committee: &Committee,
        data: &DisputeCoreData,
        init_challenge_outputs: &mut Vec<Option<WtInitChallengeOutputs>>,
        disabler_directory_output: &mut OutputType,
        op_cosign_outputs: &mut Vec<Option<OutputType>>,
    ) -> Result<(), BitVMXError> {
        let protocol = self.load_or_create_protocol();

        let wt_start_enabler_tx = protocol.transaction_by_name(WT_START_ENABLER_TX)?;
        let wt_start_enabler_txid = wt_start_enabler_tx.compute_txid();

        let disabler_directory_vout = committee.members.len() as usize;
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

        let mut init_challenge_utxos = vec![];
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

                let wt_init_challenge =
                    double_indexed_name(WT_INIT_CHALLENGE_TX, data.member_index, op_index);
                let wt_init_challenge_tx = protocol.transaction_by_name(&wt_init_challenge)?;
                let wt_init_challenge_txid = wt_init_challenge_tx.compute_txid();

                let mut outputs = init_challenge_outputs[op_index].clone().unwrap();

                let wt_stopper: PartialUtxo = (
                    wt_init_challenge_txid,
                    WT_INIT_CHALLENGE_WT_STOPPER_VOUT,
                    Some(outputs.wt_stopper.get_value_or_err()?.to_sat()),
                    Some(outputs.wt_stopper),
                );

                let op_stopper: PartialUtxo = (
                    wt_init_challenge_txid,
                    WT_INIT_CHALLENGE_OP_STOPPER_VOUT,
                    Some(outputs.op_stopper.get_value_or_err()?.to_sat()),
                    Some(outputs.op_stopper),
                );

                let cosign_output_value =
                    wt_init_challenge_tx.output[WT_INIT_CHALLENGE_COSIGN_VOUT as usize].value;

                outputs.op_cosign.set_value(cosign_output_value);

                let init_challenge_cosign_utxo: PartialUtxo = (
                    wt_init_challenge_txid,
                    WT_INIT_CHALLENGE_COSIGN_VOUT,
                    Some(cosign_output_value.to_sat()),
                    Some(outputs.op_cosign),
                );

                init_challenge_utxos.push(Some(WtInitChallengeUtxos {
                    wt_stopper,
                    op_stopper,
                    op_cosign: init_challenge_cosign_utxo,
                }));

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
            &OP_COSIGN_UTXOS,
            VariableTypes::String(serde_json::to_string(&op_cosign_utxos)?),
        )?;

        Ok(())
    }

    fn pegout_id(
        &self,
        context: &ProgramContext,
        slot_index: usize,
    ) -> Result<Vec<u8>, BitVMXError> {
        context
            .globals
            .get_var(&self.ctx.id, &indexed_name(PEGOUT_ID, slot_index))?
            .unwrap()
            .input()
    }

    fn sign_aggregated_input(
        &self,
        tx_name: &str,
        context: &ProgramContext,
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

    fn slot_id_keys(
        &self,
        context: &ProgramContext,
        committee_id: Uuid,
    ) -> Result<Vec<PublicKeyType>, BitVMXError> {
        match context.globals.get_var(&committee_id, SLOT_ID_KEYS)? {
            Some(var) => {
                let slot_id_keys: Vec<PublicKeyType> = serde_json::from_str(&var.string()?)?;
                Ok(slot_id_keys)
            }
            None => Ok(vec![]),
        }
    }

    fn get_dispute_pair_keys(
        &self,
        context: &ProgramContext,
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

    fn members_slot_id_keys(
        &self,
        context: &ProgramContext,
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

    fn validate_keys(
        &self,
        keys: &Vec<ParticipantKeys>,
        context: &ProgramContext,
        committee_id: Uuid,
    ) -> Result<(), BitVMXError> {
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
}
