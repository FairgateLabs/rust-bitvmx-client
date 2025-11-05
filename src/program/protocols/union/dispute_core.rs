use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{
                common::{
                    create_transaction_reference, estimate_fee, extract_index,
                    get_accept_pegin_pid, get_initial_deposit_output_type, indexed_name,
                },
                scripts,
                types::*,
            },
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::{ProgramContext, PROGRAM_TYPE_ACCEPT_PEGIN},
};
use bitcoin::{Amount, OutPoint, PublicKey, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use core::result::Result::Ok;
use key_manager::winternitz::WinternitzType;
use protocol_builder::{
    builder::Protocol,
    graph::graph::GraphOptions,
    scripts::SignMode,
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::{SpeedupData, AUTO_AMOUNT, RECOVER_AMOUNT},
        InputArgs, OutputType, Utxo,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

pub const PEGOUT_ID: &str = "pegout_id";
const PEGOUT_ID_KEY: &str = "pegout_id_key";
const SECRET_KEY: &str = "secret";
const CHALLENGE_KEY: &str = "challenge_pubkey";
const REVEAL_INPUT_KEY: &str = "reveal_pubkey";
const REVEAL_TAKE_PRIVKEY: &str = "reveal_take_private_key";
const SLOT_ID_KEY: &str = "slot_id_key";

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
        let packet_size = self.committee(program_context)?.packet_size;
        let mut keys = vec![];

        keys.push((
            CHALLENGE_KEY.to_string(),
            PublicKeyType::Public(program_context.key_chain.derive_keypair()?),
        ));

        let speedup_key = program_context.key_chain.derive_keypair()?;

        keys.push((
            SPEEDUP_KEY.to_string(),
            PublicKeyType::Public(speedup_key.clone()),
        ));

        program_context.globals.set_var(
            &self.ctx.id,
            SPEEDUP_KEY,
            VariableTypes::PubKey(speedup_key),
        )?;

        keys.push((
            REVEAL_INPUT_KEY.to_string(),
            PublicKeyType::Public(program_context.key_chain.derive_keypair()?),
        ));
        keys.push((
            REVEAL_TAKE_PRIVKEY.to_string(),
            PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(32)?),
        ));

        if self.prover(program_context)? {
            for i in 0..packet_size as usize {
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
                    indexed_name(SLOT_ID_KEY, i),
                    PublicKeyType::Winternitz(
                        program_context.key_chain.derive_winternitz_hash160(32)?,
                    ),
                ));
            }
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

        let mut protocol = self.load_or_create_protocol();
        let dispute_core_data = self.dispute_core_data(context)?;
        let committee = self.committee(context)?;
        let member = &committee.members[dispute_core_data.member_index];

        let mut reimbursement_output =
            self.create_reimbursement_output(&dispute_core_data, &keys, &committee)?;

        self.create_wt_start_enabler_output(
            &mut protocol,
            &dispute_core_data,
            &member.dispute_key,
            &committee.dispute_aggregated_key.clone(),
        )?;

        let mut wt_start_enabler_outputs =
            self.create_wt_start_enabler(&mut protocol, &dispute_core_data, &committee, &keys)?;

        // If member is an operator create Operator initial deposit and dispute cores
        if member.role == ParticipantRole::Prover {
            self.create_op_initial_deposit(
                &mut protocol,
                &member.dispute_key,
                &committee.dispute_aggregated_key,
            )?;

            for i in 0..committee.packet_size as usize {
                self.create_dispute_core(
                    &mut protocol,
                    &committee,
                    &dispute_core_data,
                    i,
                    &keys,
                    reimbursement_output.clone(),
                    context,
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
                SPEEDUP_VALUE,
                keys[dispute_core_data.member_index].get_public(SPEEDUP_KEY)?,
            )?,
        )?;

        protocol.compute_minimum_output_values()?;
        self.add_funding_change(&mut protocol, &member.dispute_key, &dispute_core_data)?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);

        self.save_protocol(protocol)?;
        self.save_take_utxos(
            context,
            &mut reimbursement_output,
            &committee.dispute_aggregated_key,
            &member.role,
            &mut wt_start_enabler_outputs,
        )?;

        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        if name == PROTOCOL_FUNDING_TX {
            Ok(self.protocol_funding_tx(context)?)
        } else if name == OP_INITIAL_DEPOSIT_TX || name == WT_START_ENABLER_TX {
            Ok(self.sign_aggregated_input(name, context, true)?)
        } else if name.starts_with(REIMBURSEMENT_KICKOFF_TX) {
            Ok(self.reimbursement_kickoff_tx(name, context)?)
        } else if name.starts_with(CHALLENGE_TX) {
            Ok(self.challenge_tx(name, context)?)
        } else if name == WT_SELF_DISABLER_TX || name == OP_SELF_DISABLER_TX {
            Ok(self.sign_aggregated_input(name, context, false)?)
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
        program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        let tx_name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "DisputeCoreProtocol received news of transaction: {}, txid: {} with {} confirmations",
            tx_name, tx_id, tx_status.confirmations
        );

        if tx_name.starts_with(REIMBURSEMENT_KICKOFF_TX) {
            self.handle_reimbursement_kickoff_transaction(
                program_context,
                &tx_status,
                tx_id,
                &tx_name,
            )?;
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
            self.dispatch_protocol_funding_tx(program_context)?;
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
                AUTO_AMOUNT,
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
            &OutputType::segwit_key(RECOVER_AMOUNT, watchtower_dispute_key)?,
        )?;

        return Ok(());
    }

    fn create_wt_start_enabler(
        &self,
        protocol: &mut Protocol,
        data: &DisputeCoreData,
        committee: &Committee,
        keys: &Vec<ParticipantKeys>,
    ) -> Result<Vec<OutputType>, BitVMXError> {
        let wt_speedup_key = keys[data.member_index].get_public(SPEEDUP_KEY)?;
        let wt_dispute_key = &committee.members[data.member_index].dispute_key;
        let validate_dispute_key = protocol_builder::scripts::verify_signature(
            &committee.dispute_aggregated_key,
            SignMode::Aggregate,
        )?;
        let mut outputs = vec![];

        for (member_index, member) in committee.members.clone().iter().enumerate() {
            // NOTE: This introduce a shift between scripts and slots to open a dispute
            let mut scripts = vec![validate_dispute_key.clone()];

            if member.role == ParticipantRole::Prover && data.member_index != member_index {
                for slot in 0..committee.packet_size as usize {
                    let slot_id_key =
                        keys[member_index].get_winternitz(&indexed_name(SLOT_ID_KEY, slot))?;

                    scripts.push(scripts::start_challenge(
                        &wt_dispute_key,
                        SLOT_ID_KEY,
                        slot_id_key,
                    )?);
                }
            }

            let start_enabler_output =
                // OutputType::taproot(AUTO_AMOUNT, &committee.dispute_aggregated_key, &scripts)?;
                OutputType::taproot(50000, &wt_dispute_key, &scripts)?;

            protocol.add_transaction_output(&WT_START_ENABLER_TX, &start_enabler_output)?;

            outputs.push(start_enabler_output);
        }

        let wt_disabler_directory_fee = estimate_fee(2, committee.members.len(), 1);
        let disabler_directory_funds_output = OutputType::taproot(
            DUST_VALUE * committee.members.len() as u64 + wt_disabler_directory_fee,
            &committee.dispute_aggregated_key,
            &[],
        )?;
        protocol.add_transaction_output(&WT_START_ENABLER_TX, &disabler_directory_funds_output)?;
        outputs.push(disabler_directory_funds_output);

        let speedup_output = OutputType::segwit_key(SPEEDUP_VALUE, &wt_speedup_key)?;
        // Add speedup output
        protocol.add_transaction_output(&WT_START_ENABLER_TX, &speedup_output)?;
        outputs.push(speedup_output);

        Ok(outputs)
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
                AUTO_AMOUNT,
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
            &OutputType::segwit_key(RECOVER_AMOUNT, operator_dispute_key)?,
        )?;

        Ok(())
    }

    fn create_reimbursement_output(
        &self,
        dispute_core_data: &DisputeCoreData,
        keys: &Vec<ParticipantKeys>,
        committee: &Committee,
    ) -> Result<OutputType, BitVMXError> {
        let mut timelocks = vec![];
        for i in 0..keys.len() {
            // If this is the operator owning the dispute core, we use a long timelock for the operator take transaction,
            // otherwise a short one for the challenge transaction.
            let blocks = if i == dispute_core_data.member_index {
                DISPUTE_CORE_LONG_TIMELOCK
            } else {
                DISPUTE_CORE_SHORT_TIMELOCK
            };

            let timelock = protocol_builder::scripts::timelock(
                blocks,
                &committee.members[i].dispute_key,
                SignMode::Single,
            );

            timelocks.push(timelock);
        }

        Ok(OutputType::taproot(
            AUTO_AMOUNT,
            &committee.take_aggregated_key,
            timelocks.as_slice(),
        )?)
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
    ) -> Result<(), BitVMXError> {
        // Operator keys
        let operator_keys = keys[dispute_core_data.member_index].clone();
        let operator_dispute_key = &committee.members[dispute_core_data.member_index].dispute_key;

        // Aggregated keys
        let take_aggregated_key = &committee.take_aggregated_key;
        let dispute_aggregated_key = &committee.dispute_aggregated_key;

        // Pegout ID key
        let pegout_id_name = indexed_name(PEGOUT_ID_KEY, dispute_core_index);
        let pegout_id_key = operator_keys.get_winternitz(&pegout_id_name)?;

        // Secret key
        let secret_name = indexed_name(SECRET_KEY, dispute_core_index);
        let secret_key = operator_keys.get_winternitz(&secret_name)?;

        // TX names
        let reimbursement_kickoff = indexed_name(REIMBURSEMENT_KICKOFF_TX, dispute_core_index);
        let challenge = indexed_name(CHALLENGE_TX, dispute_core_index);
        let reveal_input = indexed_name(REVEAL_INPUT_TX, dispute_core_index);
        let input_not_revealed = indexed_name(INPUT_NOT_REVEALED_TX, dispute_core_index);

        let start_reimbursement =
            scripts::start_reimbursement(take_aggregated_key, PEGOUT_ID_KEY, pegout_id_key)?;

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
                AUTO_AMOUNT,
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
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::None),
            Some(DISPUTE_CORE_SHORT_TIMELOCK),
            None,
        )?;

        let secret = protocol_builder::scripts::verify_winternitz_signature(
            operator_keys.get_public(REVEAL_INPUT_KEY)?,
            secret_key,
            SignMode::Skip,
        )?;

        protocol.add_connection(
            "reveal_input",
            &challenge,
            OutputType::taproot(AUTO_AMOUNT, dispute_aggregated_key, &[secret])?.into(),
            &reveal_input,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            None,
        )?;

        // TODO: Add leaves with timelocks for each committee member
        protocol.add_transaction_output(
            &reveal_input,
            &OutputType::taproot(AUTO_AMOUNT, take_aggregated_key, &[])?,
        )?;

        protocol.add_connection(
            "input_not_revealed",
            &challenge,
            OutputSpec::Index(0),
            &input_not_revealed,
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
            &input_not_revealed,
            &OutputType::taproot(AUTO_AMOUNT, take_aggregated_key, &[])?,
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
        let last_reimbursement_kickoff = indexed_name(REIMBURSEMENT_KICKOFF_TX, dispute_core_index);

        if dispute_core_index == 0 {
            // No previous reimbursement kickoff transaction to connect to.
            return Ok(());
        }

        for i in 0..dispute_core_index {
            let prev_reimbursement_kickoff = indexed_name(REIMBURSEMENT_KICKOFF_TX, i);
            let two_dispute_penalization = format!(
                "{}_{}_{}",
                TWO_DISPUTE_PENALIZATION_TX, i, dispute_core_index
            );

            protocol.add_connection(
                "prev_reimbursement_kickoff",
                &prev_reimbursement_kickoff,
                OutputSpec::Index(0),
                &two_dispute_penalization,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::KeyOnly {
                        key_path_sign: SignMode::Aggregate,
                    },
                ),
                Some(DISPUTE_CORE_SHORT_TIMELOCK),
                None,
            )?;

            protocol.add_connection(
                "last_reimbursement_kickoff",
                &last_reimbursement_kickoff,
                OutputSpec::Index(0),
                &two_dispute_penalization,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::KeyOnly {
                        key_path_sign: SignMode::Aggregate,
                    },
                ),
                Some(DISPUTE_CORE_SHORT_TIMELOCK),
                None,
            )?;

            protocol.add_transaction_output(
                &two_dispute_penalization,
                &OutputType::taproot(AUTO_AMOUNT, &take_aggregated_key, &[])?,
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
            let directory_fee = estimate_fee(2, committee.packet_size as usize + 1, 1);
            let disabler_directory_amount =
                committee.packet_size as u64 * DUST_VALUE + SPEEDUP_VALUE + directory_fee;
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
                &OutputType::segwit_key(AUTO_AMOUNT, operator_speedup_key)?,
            )?;
        }

        // Add a speedup output to the reimbursement_kickoff transaction.
        protocol.add_transaction_output(
            &reimbursement_kickoff,
            &OutputType::segwit_key(AUTO_AMOUNT, operator_speedup_key)?,
        )?;

        // Add one speedup ouput per committee member to the challenge and input_not_revealed transactions.
        for i in 0..keys.len() {
            let speedup_output =
                OutputType::segwit_key(AUTO_AMOUNT, keys[i].get_public(SPEEDUP_KEY)?)?;
            protocol.add_transaction_output(&challenge, &speedup_output)?;
            protocol.add_transaction_output(&input_not_revealed, &speedup_output)?;
        }

        // Add a speedup output to the reveal_input transaction.
        protocol.add_transaction_output(
            &reveal_input,
            &OutputType::segwit_key(AUTO_AMOUNT, operator_speedup_key)?,
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

        protocol
            .add_transaction_output(
                &PROTOCOL_FUNDING_TX,
                &OutputType::segwit_key(change, member_change_key)?,
            )
            .map_err(|e| BitVMXError::ProtocolBuilderError(e))?;

        Ok(())
    }

    fn protocol_funding_tx(
        &self,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        let tx_name = PROTOCOL_FUNDING_TX;
        let mut protocol = self.load_protocol()?;

        let signature = protocol.sign_ecdsa_input(&tx_name, 0, &context.key_chain.key_manager)?;

        let mut input_args = InputArgs::new_segwit_args();
        input_args.push_ecdsa_signature(signature)?;

        let tx = protocol.transaction_to_send(&tx_name, &[input_args])?;

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

        let protocol = self.load_protocol()?;

        // Prepare signatures
        let committee_signature = protocol
            .input_taproot_script_spend_signature(name, 0, leaf_index)?
            .unwrap();

        let script = protocol.get_script_to_spend(name, 0, leaf_index as u32)?;
        let pegout_id_key = script.get_key(PEGOUT_ID_KEY).unwrap();

        let pegout_id_signature = context.key_chain.key_manager.sign_winternitz_message(
            self.pegout_id(context, slot_index)?.as_slice(),
            WinternitzType::HASH160,
            pegout_id_key.derivation_index(),
        )?;

        // Create input arguments
        let mut input_args = InputArgs::new_taproot_script_args(leaf_index);
        input_args.push_winternitz_signature(pegout_id_signature);
        input_args.push_taproot_signature(committee_signature)?;

        let tx = protocol.transaction_to_send(&name, &[input_args])?;
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
        let my_index = self.ctx.my_idx;

        let signatures = protocol.sign_taproot_input(
            name,
            0,
            &SpendMode::Script {
                leaf: my_index as usize,
            },
            context.key_chain.key_manager.as_ref(),
            "",
        )?;

        let mut input_args = InputArgs::new_taproot_script_args(my_index);
        input_args.push_taproot_signature(signatures[my_index].unwrap())?;
        let tx = protocol.transaction_to_send(&name, &[input_args])?;

        info!(
            id = my_index,
            "Signed {} with signatures: {:?}", name, signatures
        );

        let txid = tx.compute_txid();
        let speedup_key = self.my_speedup_key(context)?;
        let speedup_vout = 1 + self.ctx.my_idx as u32;
        let speedup_utxo = Utxo::new(txid, speedup_vout, SPEEDUP_VALUE, &speedup_key);

        Ok((tx, Some(speedup_utxo.into())))
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

    fn committee_id(&self, context: &ProgramContext) -> Result<Uuid, BitVMXError> {
        Ok(self.dispute_core_data(context)?.committee_id)
    }

    fn monitored_operator_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        let committee = self.committee(context)?;
        let data = self.dispute_core_data(context)?;
        Ok(committee.members[data.member_index].take_key)
    }

    fn dispatch_challenge_tx(
        &self,
        slot_id: usize,
        program_context: &ProgramContext,
        reimbursement_txid: Txid,
        tx_status: TransactionStatus,
    ) -> Result<(), BitVMXError> {
        let tx_name = indexed_name(CHALLENGE_TX, slot_id);
        info!("Dispatching {}", tx_name);

        let (mut challenge_tx, speedup) = self.challenge_tx(&tx_name, program_context)?;
        let challenge_txid = challenge_tx.compute_txid();

        // Connect the challenge transaction to the reimbursement kickoff transaction
        if !challenge_tx.input.is_empty() {
            challenge_tx.input[0].previous_output = OutPoint {
                txid: reimbursement_txid,
                vout: 0,
            };
        }

        program_context.bitcoin_coordinator.dispatch(
            challenge_tx,
            speedup,
            format!("dispute_core_challenge_{}:{}", self.ctx.id, tx_name), // Context string
            Some(tx_status.block_info.unwrap().height + DISPUTE_CORE_SHORT_TIMELOCK as u32), // Dispatch after short timelock
        )?;

        info!(
            "{} connected to reimbursement tx {} and dispatched with txid: {}",
            tx_name, reimbursement_txid, challenge_txid
        );

        Ok(())
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

    fn get_reimbursement_in_progress(
        &self,
        program_context: &ProgramContext,
    ) -> Result<Option<u32>, BitVMXError> {
        match program_context
            .globals
            .get_var(&self.ctx.id, REIMBURSEMENT_KICKOFF_IN_PROGRESS)?
        {
            Some(var) => Ok(Some(var.number()?)),
            None => Ok(None),
        }
    }

    fn set_reimbursement_in_progress(
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
            REIMBURSEMENT_KICKOFF_IN_PROGRESS,
            VariableTypes::Number(slot_index as u32),
        )
    }

    fn handle_double_reimbursement_kickoff(
        &self,
        context: &ProgramContext,
        tx_status: &TransactionStatus,
        slot_index: usize,
    ) -> Result<bool, BitVMXError> {
        let reimbursement_in_progress = self.get_reimbursement_in_progress(context)?;
        if reimbursement_in_progress.is_none() {
            info!(
                id = self.ctx.my_idx,
                "No reimbursement in progress, setting slot index: {} as in progress", slot_index
            );
            self.set_reimbursement_in_progress(context, slot_index)?;
            return Ok(false);
        } else {
            info!(
                id = self.ctx.my_idx,
                "Reimbursement already in progress for slot index: {}, dispatching double kickoff penalization for slots {} and {}",
                reimbursement_in_progress.unwrap(),
                reimbursement_in_progress.unwrap(),
                slot_index
            );

            let block_height = Some(
                tx_status.block_info.as_ref().unwrap().height
                    + DISPUTE_CORE_SHORT_TIMELOCK as u32
                    + 1,
            );
            self.dispatch_double_kickoff_penalization_tx(
                context,
                reimbursement_in_progress.unwrap() as usize,
                slot_index,
                block_height,
            )?;

            info!(
                id = self.ctx.my_idx,
                "Cleaning REIMBURSEMENT_KICKOFF_IN_PROGRESS"
            );
            // Asumming the penalization tx was dispatched successfully and mined,
            context
                .globals
                .unset_var(&self.ctx.id, REIMBURSEMENT_KICKOFF_IN_PROGRESS)?;

            return Ok(true);
        }
    }

    fn dispatch_double_kickoff_penalization_tx(
        &self,
        context: &ProgramContext,
        slot_index_prev: usize,
        slot_index_last: usize,
        block_height: Option<u32>,
    ) -> Result<(), BitVMXError> {
        // Get the signed transaction
        let (tx, speedup, name) =
            self.double_kickoff_penalization_tx(context, slot_index_prev, slot_index_last)?;
        let txid = tx.compute_txid();

        info!(
            id = self.ctx.my_idx,
            "Auto-dispatching {} txid: {}", name, txid
        );

        // Dispatch the transaction through the bitcoin coordinator
        context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            format!("dispute_core_setup_{}:{}", self.ctx.id, name), // Context string
            block_height,                                           // Dispatch immediately
        )?;

        info!(
            id = self.ctx.my_idx,
            "{} dispatched successfully with txid: {}", name, txid
        );
        Ok(())
    }

    fn double_kickoff_penalization_tx(
        &self,
        context: &ProgramContext,
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

        let leaf_index = self.ctx.my_idx as usize;
        let mut protocol = self.load_protocol()?;

        let signature_0 = protocol.sign_taproot_input(
            &name,
            0,
            &SpendMode::Script { leaf: leaf_index },
            context.key_chain.key_manager.as_ref(),
            "",
        )?;
        let mut input_0 = InputArgs::new_taproot_script_args(leaf_index);
        input_0.push_taproot_signature(signature_0[leaf_index].unwrap())?;

        let signature_1 = protocol.sign_taproot_input(
            &name,
            1,
            &SpendMode::Script { leaf: leaf_index },
            context.key_chain.key_manager.as_ref(),
            "",
        )?;
        let mut input_1 = InputArgs::new_taproot_script_args(leaf_index);
        input_1.push_taproot_signature(signature_1[leaf_index].unwrap())?;

        let tx = protocol.transaction_to_send(&name, &[input_0, input_1])?;

        Ok((tx, None, name))
    }

    fn handle_reimbursement_kickoff_transaction(
        &self,
        program_context: &ProgramContext,
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

        if self.is_my_dispute_core(program_context)? {
            info!(
                id = self.ctx.my_idx,
                "This is my dispute_core, checking for operator take dispatch for slot {}",
                slot_index
            );
            // Handle operator take if needed
            if tx_status.confirmations == 1 {
                let block_height = tx_status.block_info.as_ref().unwrap().height
                    + DISPUTE_CORE_LONG_TIMELOCK as u32
                    + 1;
                self.dispatch_operator_take_tx(program_context, slot_index, block_height)?;
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

            // Handle double reimbursement kick-off penalization if needed
            if self.handle_double_reimbursement_kickoff(program_context, tx_status, slot_index)? {
                return Ok(());
            }

            // Handle challenge if needed
            match self.get_selected_operator_key(slot_index, program_context)? {
                Some(selected_operator_key) => {
                    // Get the operator's take key that this dispute core is monitoring
                    let monitored_operator_key = self.monitored_operator_key(program_context)?;

                    // Compare if the monitored operator is the selected one
                    let is_valid = selected_operator_key == monitored_operator_key;

                    if !is_valid {
                        info!(
                            "Unauthorized operator detected for slot {}, dispatching Challenge Tx",
                            slot_index
                        );
                        self.dispatch_challenge_tx(
                            slot_index,
                            program_context,
                            tx_id,
                            tx_status.clone(),
                        )?;
                    } else {
                        info!("Authorized operator confirmed for slot {}", slot_index);
                        // TODO: here we need to validate that the advancement of funds has actually been made
                    }
                }
                None => {
                    info!("No selected operator key found for slot {}", slot_index);
                    // If no selected operator key is set, it means that someone triggered a reimbursment kickoff transaction but there was no advances of funds
                    self.dispatch_challenge_tx(
                        slot_index,
                        program_context,
                        tx_id,
                        tx_status.clone(),
                    )?;
                }
            }
        }

        Ok(())
    }

    fn dispatch_protocol_funding_tx(
        &self,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let tx_name = PROTOCOL_FUNDING_TX;

        info!(
            id = self.ctx.my_idx,
            "Dispatching {} tx from protocol {}", tx_name, self.ctx.id
        );

        // Get the signed transaction
        let (tx, speedup) = self.protocol_funding_tx(program_context)?;
        let txid = tx.compute_txid();

        info!(
            id = self.ctx.my_idx,
            "Auto-dispatching {} transaction: {}", tx_name, txid
        );

        // Dispatch the transaction through the bitcoin coordinator
        program_context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            format!("dispute_core_setup_{}:{}", self.ctx.id, tx_name), // Context string
            None,                                                      // Dispatch immediately
        )?;

        info!(
            id = self.ctx.my_idx,
            "{} dispatched successfully with txid: {}", tx_name, txid
        );

        Ok(())
    }

    fn is_my_dispute_core(&self, program_context: &ProgramContext) -> Result<bool, BitVMXError> {
        let dispute_core_data = self.dispute_core_data(program_context)?;
        Ok(dispute_core_data.member_index == self.ctx.my_idx)
    }

    fn dispatch_operator_take_tx(
        &self,
        context: &ProgramContext,
        slot_index: usize,
        block_height: u32,
    ) -> Result<(), BitVMXError> {
        let tx_name = indexed_name(OPERATOR_TAKE_TX, self.ctx.my_idx);
        info!(
            id = self.ctx.my_idx,
            "Dispatching {} tx for slot: {}", tx_name, slot_index
        );

        let dispute_core_data: DisputeCoreData = self.dispute_core_data(context)?;
        let accept_pegin_pid = get_accept_pegin_pid(dispute_core_data.committee_id, slot_index);
        self.save_operator_leaf_index(context, accept_pegin_pid)?;
        let protocol = self.load_protocol_by_name(PROGRAM_TYPE_ACCEPT_PEGIN, accept_pegin_pid)?;

        let (tx, speedup) = protocol.get_transaction_by_name(&tx_name, context)?;
        let txid = tx.compute_txid();

        context.bitcoin_coordinator.dispatch(
            tx,
            speedup,
            tx_name.clone(),
            Some(block_height), // Dispatch immediately with input args
        )?;

        info!(
            id = self.ctx.my_idx,
            "{} dispatched for slot: {} with txid: {}", tx_name, slot_index, txid
        );

        Ok(())
    }

    fn save_operator_leaf_index(
        &self,
        context: &ProgramContext,
        accept_pegin_pid: Uuid,
    ) -> Result<(), BitVMXError> {
        let leaf_index = self.ctx.my_idx as u32;
        context.globals.set_var(
            &accept_pegin_pid,
            &OPERATOR_LEAF_INDEX,
            VariableTypes::Number(leaf_index),
        )?;
        Ok(())
    }

    fn save_take_utxos(
        &self,
        context: &ProgramContext,
        reimbursement_output: &mut OutputType,
        dispute_aggregated_key: &PublicKey,
        role: &ParticipantRole,
        wt_start_enabler_outputs: &mut Vec<OutputType>,
    ) -> Result<(), BitVMXError> {
        let committee = self.committee(context)?;
        let protocol = self.load_or_create_protocol();

        // Save REIMBURSEMENT_KICKOFF_UTXO if dispute core owner is a Prover
        if *role == ParticipantRole::Prover {
            for i in 0..committee.packet_size as usize {
                let name = indexed_name(REIMBURSEMENT_KICKOFF_TX, i);
                let reimbursement_kickoff_tx: &Transaction = protocol.transaction_by_name(&name)?;

                let reimbursement_output_index = 0;
                let reimbursement_output_value =
                    reimbursement_kickoff_tx.output[reimbursement_output_index].value;
                reimbursement_output.set_value(reimbursement_output_value.clone());

                let operator_take_utxo = (
                    reimbursement_kickoff_tx.compute_txid(),
                    0,
                    Some(reimbursement_output_value.to_sat()),
                    Some(reimbursement_output.clone()),
                );

                let name = indexed_name(REVEAL_INPUT_TX, i);
                let reveal_tx = protocol.transaction_by_name(&name)?;
                let reveal_output_index = 0;
                let reveal_output_value = reveal_tx.output[reveal_output_index].value;
                // Reusing reimbursement utxo, it's the same output type
                reimbursement_output.set_value(reveal_output_value.clone());

                let operator_won_utxo = (
                    reveal_tx.compute_txid(),
                    0,
                    Some(reveal_output_value.to_sat()),
                    Some(reimbursement_output.clone()),
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
                "Saving initial deposit txid: {} and amount: {}",
                initial_deposit_txid,
                output_value
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
        }

        let wt_start_enabler_tx = protocol.transaction_by_name(WT_START_ENABLER_TX)?;
        let wt_start_enabler_txid = wt_start_enabler_tx.compute_txid();

        // Create WT_START_ENABLER_UTXOs and save them in one array
        let mut wt_start_enabler_utxos: Vec<PartialUtxo> = vec![];
        for i in 0..wt_start_enabler_outputs.len() {
            let output_value = wt_start_enabler_tx.output[i].value.to_sat();

            wt_start_enabler_outputs[i].set_value(Amount::from_sat(output_value));
            wt_start_enabler_utxos.push((
                wt_start_enabler_txid,
                i as u32,
                Some(output_value),
                Some(wt_start_enabler_outputs[i].clone()),
            ));
        }

        context.globals.set_var(
            &self.ctx.id,
            &WT_START_ENABLER_UTXOS,
            VariableTypes::String(serde_json::to_string(&wt_start_enabler_utxos)?),
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

        let protocol = self.load_protocol()?;

        let signature = protocol
            .input_taproot_key_spend_signature(tx_name, 0)?
            .unwrap();

        let mut input_args = InputArgs::new_taproot_key_args();
        input_args.push_taproot_signature(signature)?;

        let tx = protocol.transaction_to_send(&tx_name, &[input_args])?;
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
}
