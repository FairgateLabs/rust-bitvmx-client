use std::collections::HashMap;

use bitcoin::{hashes::Hash, PublicKey, Sequence, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitcoin_script_stack::stack::StackTracker;
use protocol_builder::{
    builder::ProtocolBuilder,
    errors::ProtocolBuilderError,
    scripts::{self, timelock, ProtocolScript, SignMode},
    types::{
        connection::InputSpec,
        input::{SighashType, SpendMode},
        output::SpeedupData,
        InputArgs, OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            claim::ClaimGate,
            dispute::{START_CH, TIMELOCK_BLOCKS},
            protocol_handler::{external_fund_tx, ProtocolContext, ProtocolHandler},
        },
        variables::VariableTypes,
    },
    types::ProgramContext,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct SlotProtocol {
    ctx: ProtocolContext,
}

pub const FUND_SLOT: &str = "FUND_SLOT";
pub const SETUP_TX: &str = "SETUP_TX";
pub const CERT_HASH_TX: &str = "CERT_HASH_TX_";
pub const GID_TX: &str = "GID_TX_";
pub const OP_WINS: &str = "OP_WINS_";

pub fn claim_name(op: usize) -> String {
    format!("{}{}", OP_WINS, op)
}

pub fn cert_hash_tx_op(n: u32) -> String {
    format!("{}{}", CERT_HASH_TX, n)
}
pub fn certificate_hash(n: usize) -> String {
    format!("certificate_hash_{}", n)
}

pub fn group_id(op: usize) -> String {
    format!("group_id_{}", op)
}

pub fn group_id_tx(op: usize, gid: u8) -> String {
    format!("{}{}_{}", GID_TX, op, gid)
}

pub fn group_id_to(op: usize) -> String {
    format!("{}{}_TO", GID_TX, op)
}
pub fn start_challenge_to(op: usize, op_challenger: usize) -> String {
    format!("{}_{}_{}_TO", START_CH, op, op_challenger)
}

impl ProtocolHandler for SlotProtocol {
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
        Ok(vec![(
            "pregenerated".to_string(),
            context
                .globals
                .get_var(&self.ctx.id, "operators_aggregated_pub")?
                .unwrap()
                .pubkey()?,
        )])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let key_chain = &mut program_context.key_chain;
        let mut keys = vec![];

        let cert_hash = key_chain.derive_winternitz_hash160(20)?;
        keys.push((certificate_hash(self.ctx.my_idx), cert_hash.into()));

        let gid = key_chain.derive_winternitz_hash160(1)?;
        keys.push((group_id(self.ctx.my_idx), gid.into()));

        Ok(ParticipantKeys::new(keys, vec![]))
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        program_context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        //TODO: this is hacky. parametrize get_transaction_name
        if name.starts_with("unsigned_") {
            let name = name.strip_prefix("unsigned_").unwrap();
            return Ok((
                self.load_protocol()?.transaction_by_name(name)?.clone(),
                None,
            ));
        }

        if name.starts_with(CERT_HASH_TX) {
            return Ok((
                self.get_signed_tx(program_context, name, 0, 0, false, 0)?,
                None,
            ));
        }

        match name {
            SETUP_TX => Ok((self.setup_tx()?, None)),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        _context: String,
        program_context: &ProgramContext,
        participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        let name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Program {}: Transaction {}:{:?} has been seen on-chain {}",
            self.ctx.id, name, vout, self.ctx.my_idx
        );

        if name.starts_with(CERT_HASH_TX) && vout.is_none() {
            let operator = name
                .strip_prefix(CERT_HASH_TX)
                .unwrap_or("")
                .parse::<u32>()?;

            info!("Operator {} has sent a certificate hash", operator);
            self.decode_witness_for_tx(
                &name,
                0,
                program_context,
                &participant_keys[operator as usize],
                &tx_status.tx,
                Some(0),
                None,
                None,
            )?;

            // after sending the certificate hash, the operator should send the group id
            if self.ctx.my_idx == operator as usize {
                let gid = program_context
                    .globals
                    .get_var(&self.ctx.id, &group_id(operator as usize))?
                    .unwrap()
                    .input()?[0];

                let gid_selection_tx = self.get_signed_tx(
                    program_context,
                    &group_id_tx(operator as usize, gid),
                    0,
                    gid as u32,
                    false,
                    0,
                )?;
                info!(
                    "Operator {} is going to send the group id {}",
                    operator, gid
                );
                program_context.bitcoin_coordinator.dispatch(
                    gid_selection_tx,
                    None,
                    Context::ProgramId(self.ctx.id).to_string()?,
                    None,
                )?;

                let total_operators = program_context
                    .globals
                    .get_var(&self.ctx.id, "operators")?
                    .unwrap()
                    .number()?;

                let txid = tx_status.tx_id;

                //notify when the stops are consumed
                for i in 0..total_operators - 1 {
                    info!("Subscribe to vout {}", i + 2);
                    program_context.bitcoin_coordinator.monitor(
                        bitcoin_coordinator::TypesToMonitor::SpendingUTXOTransaction(
                            txid,
                            i + 2, // the first stop is at pos 2
                            Context::ProgramId(self.ctx.id).to_string()?,
                        ),
                    )?;
                }

                /*
                For now we are sending the to after one challange is completed
                for i in 0..total_operators {
                    if i != operator {
                        program_context.bitcoin_coordinator.dispatch(
                            self.get_signed_tx(
                                program_context,
                                &start_challenge_to(operator as usize, i as usize),
                                0,
                                0,
                                false,
                                0,
                            )?,
                            Context::ProgramId(self.ctx.id).to_string()?,
                            Some(
                                tx_status.block_info.as_ref().unwrap().block_height + 100, // TIMELOCK_BLOCKS as u32,
                            ),
                        )?;
                    }
                }*/
            }
        }

        if name.starts_with(CERT_HASH_TX) && vout.is_some() {
            let operator = name
                .strip_prefix(CERT_HASH_TX)
                .unwrap_or("")
                .parse::<u32>()?;
            if operator != self.ctx.my_idx as u32 {
                return Ok(());
            }

            let total_operators = program_context
                .globals
                .get_var(&self.ctx.id, "operators")?
                .unwrap()
                .number()?;

            let mut stops_consumed = program_context
                .globals
                .get_var(&self.ctx.id, "stops_consumed")?
                .unwrap_or(VariableTypes::Number(0))
                .number()?;

            //this part is to avoid resending. this shoudld be moved to timelock as soon as cert_hash is sent
            if stops_consumed == 0 {
                program_context.globals.set_var(
                    &self.ctx.id,
                    "stops_consumed",
                    VariableTypes::Number(1),
                )?;

                for i in 0..total_operators - 1 {
                    if i != vout.unwrap() - 2 {
                        info!("Sending tx to consume the stop for {}", i);
                        program_context.bitcoin_coordinator.dispatch(
                            self.get_signed_tx(
                                program_context,
                                &start_challenge_to(operator as usize, i as usize),
                                0,
                                0,
                                false,
                                0,
                            )?,
                            None,
                            Context::ProgramId(self.ctx.id).to_string()?,
                            None,
                        )?;
                    } else {
                        info!("The stop for the operator {} has been consumed", i);
                    }
                }
            } else {
                stops_consumed += 1;
                program_context.globals.set_var(
                    &self.ctx.id,
                    "stops_consumed",
                    VariableTypes::Number(stops_consumed),
                )?;

                if stops_consumed == total_operators - 1 {
                    info!("All stops have been consumed");
                    info!("Ready to send claim win start");

                    let tx = self.get_signed_tx(
                        program_context,
                        &ClaimGate::tx_start(&claim_name(operator as usize)),
                        0,
                        0,
                        false,
                        0,
                    )?;

                    info!(
                        "Dispatching: {} {:?}",
                        &ClaimGate::tx_start(&claim_name(operator as usize)),
                        &tx
                    );
                    program_context.bitcoin_coordinator.dispatch(
                        tx,
                        None,
                        Context::ProgramId(self.ctx.id).to_string()?,
                        None,
                    )?;
                }
            }
        }

        if name.starts_with(OP_WINS) && name.ends_with("_START") {
            let operator = name
                .strip_prefix(OP_WINS)
                .unwrap_or("")
                .strip_suffix("_START")
                .unwrap_or("")
                .parse::<u32>()?;
            info!("Operator {} has sent a claim win", operator);
            if operator != self.ctx.my_idx as u32 {
                //TOOD: Others should react sending the stop tx
                return Ok(());
            }

            info!("Prover sending SUCCESS tx");
            program_context.bitcoin_coordinator.dispatch(
                self.get_signed_tx(
                    program_context,
                    &ClaimGate::tx_success(&claim_name(operator as usize)),
                    0,
                    0,
                    false,
                    0,
                )?,
                None,
                Context::ProgramId(self.ctx.id).to_string()?,
                Some(tx_status.block_info.unwrap().height + TIMELOCK_BLOCKS as u32),
            )?;
        }

        if name.starts_with(GID_TX) {
            let op_and_id: Vec<u32> = name
                .strip_prefix(GID_TX)
                .unwrap_or("0_0")
                .split('_')
                .map(|s| s.parse::<u32>().unwrap())
                .collect();

            info!("Operator {} has sent a group id", op_and_id[0]);
            self.decode_witness_for_tx(
                &name,
                0,
                program_context,
                &participant_keys[op_and_id[0] as usize],
                &tx_status.tx,
                Some(op_and_id[1]),
                None,
                None,
            )?;
        }

        Ok(())
    }

    fn build(
        &self,
        keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let fee = context
            .globals
            .get_var(&self.ctx.id, "FEE")?
            .unwrap()
            .number()? as u64;
        let protocol_cost = 200_000;
        let speedup_dust = 500;
        let gid_max = 8;

        context.globals.set_var(
            &self.ctx.id,
            "operators",
            VariableTypes::Number(keys.len() as u32),
        )?;

        let ops_agg_pubkey = context
            .globals
            .get_var(&self.ctx.id, "operators_aggregated_pub")?
            .unwrap()
            .pubkey()?;

        let pair_0_1_aggregated = context
            .globals
            .get_var(&self.ctx.id, "pair_0_1_aggregated")?
            .unwrap()
            .pubkey()?;

        let _unspendable = context
            .globals
            .get_var(&self.ctx.id, "unspendable")?
            .unwrap()
            .pubkey()?;

        let fund_utxo = context
            .globals
            .get_var(&self.ctx.id, "fund_utxo")?
            .unwrap()
            .utxo()?;

        //create the protocol
        let mut protocol = self.load_or_create_protocol();

        let mut amount = fund_utxo.2.unwrap();
        let spending = vec![scripts::check_aggregated_signature(
            &ops_agg_pubkey,
            SignMode::Aggregate,
        )];
        let output_type = external_fund_tx(&ops_agg_pubkey, spending, amount)?;

        protocol.add_external_transaction(FUND_SLOT)?;
        protocol.add_unkwnoun_outputs(FUND_SLOT, fund_utxo.1)?;

        protocol.add_connection(
            &format!("{}__{}", FUND_SLOT, SETUP_TX),
            FUND_SLOT,
            output_type.into(),
            SETUP_TX,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            Some(fund_utxo.0),
        )?;

        amount = self.checked_sub(amount, fee)?;

        let pb = ProtocolBuilder {};

        let amount_for_publish_gid = fee + speedup_dust + speedup_dust;
        let claim_gate_cost = ClaimGate::cost(fee, speedup_dust, keys.len() as u8 - 1, 1);

        let amount_for_sequence = fee
            + speedup_dust
            + amount_for_publish_gid
            + claim_gate_cost
            + keys.len() as u64 * protocol_cost;

        //====================================
        //CREATES THE SLOTS FOR EACH OPERATOR
        //CERT HASH TX:
        // vout0 = gid_publish (leafs 0..=gid_max)
        // vout1 = claim_gate_start
        // vout2..2+operators-1 = stop_gate    [for 3 operators 2,3]
        // (vout2+operators-1).. (vout2+operators-1+operators-1)= start_challenge  [for 3 operators 4,5]
        for (i, key) in keys.iter().enumerate() {
            //====================================
            //EVERY OPERATOR CAN SEND A CERTIFICATE HASH
            //Verify the winternitz signature
            let key_name = certificate_hash(i);
            let winternitz_check = scripts::verify_winternitz_signatures(
                &ops_agg_pubkey,
                &vec![(&key_name, key.get_winternitz(&key_name)?)],
                SignMode::Aggregate,
            )?;

            let output_type = OutputType::taproot(
                amount_for_sequence,
                &ops_agg_pubkey,
                &[winternitz_check.clone()],
            )?;

            let certhashtx = cert_hash_tx_op(i as u32);

            protocol.add_connection(
                &format!("{}__{}", SETUP_TX, certhashtx),
                SETUP_TX,
                output_type.into(),
                &certhashtx,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::All {
                        key_path_sign: SignMode::Aggregate,
                    },
                ),
                None,
                None,
            )?;

            //====================================
            // AFTER SETTING THE CERTIFICATE HASH, THE OPERATOR IS FORCED TO SEND THE GROUP ID
            //create the group id output
            let key_name = group_id(i);
            let mut leaves: Vec<ProtocolScript> = (1..=gid_max)
                .map(|gid| winternitz_equality(key, &ops_agg_pubkey, &key_name, gid).unwrap())
                .collect();
            let timelock_script = timelock(TIMELOCK_BLOCKS, &ops_agg_pubkey, SignMode::Aggregate);
            leaves.insert(0, timelock_script);
            //put timelock as zero so the index matches the gid

            let output_type =
                OutputType::taproot(amount_for_publish_gid, &ops_agg_pubkey, &leaves)?;

            protocol.add_transaction_output(&certhashtx, &output_type)?;

            // create txs that consumes the gid
            for gid in 1..=gid_max {
                let gidtx = group_id_tx(i, gid);
                protocol.add_transaction(&gidtx)?;

                protocol.add_transaction_input(
                    Hash::all_zeros(),
                    0,
                    &gidtx,
                    Sequence::ENABLE_RBF_NO_LOCKTIME,
                    &SpendMode::Script { leaf: gid as usize }, //TODO: test with gid
                    &SighashType::taproot_all(),
                )?;

                let gid_spend =
                    scripts::check_aggregated_signature(&ops_agg_pubkey, SignMode::Aggregate);

                protocol.add_transaction_output(
                    &gidtx,
                    &OutputType::taproot(speedup_dust, &ops_agg_pubkey, &[gid_spend])?,
                )?;

                protocol.add_connection(
                    &format!("{}__{}", certhashtx, gidtx),
                    &certhashtx,
                    0.into(),
                    &gidtx,
                    0.into(),
                    None,
                    None,
                )?;

                // Add one extra non-spendable output to each challenge response transaction to ensure different txids
                let differenciator = scripts::op_return_script(vec![gid as u8])?
                    .get_script()
                    .clone();
                protocol.add_transaction_output(
                    &gidtx,
                    &OutputType::segwit_unspendable(differenciator)?,
                )?;

                pb.add_speedup_output(&mut protocol, &gidtx, speedup_dust, &ops_agg_pubkey)?;
            }

            //====================================
            // IF GROUP ID IS NOT SELECTED THE REST OF THE OPERATORS CAN PENALIZE AFTER TIME OUT
            // create the timeout gid tx
            let gidtotx = group_id_to(i);
            protocol.add_transaction(&gidtotx)?;

            protocol.add_transaction_input(
                Hash::all_zeros(),
                0,
                &gidtotx,
                Sequence::from_height(TIMELOCK_BLOCKS),
                &SpendMode::Script { leaf: 0 },
                &SighashType::taproot_all(),
            )?;

            protocol.add_connection(
                &format!("{}__{}", certhashtx, gidtotx),
                &certhashtx,
                0.into(),
                &gidtotx,
                0.into(),
                None,
                None,
            )?;

            //====================================
            // ADD THE CLAIM GATE THAT THE OPERATOR WINS
            // IF CONTAINS ALSO THE STOP OUTPUTS THAT IF THE OPERATOR WINS CHALLENGE NEEDS TO CONSUME
            //TODO: set the proper pair aggregated for the stop output
            let stop_count = keys.len() as u8 - 1;
            let mut stop_pubkeys = vec![];
            for _ in 0..stop_count {
                stop_pubkeys.push(&pair_0_1_aggregated);
            }
            let claim_gate = ClaimGate::new(
                &mut protocol,
                &certhashtx,
                &claim_name(i),
                &ops_agg_pubkey,
                fee,
                speedup_dust,
                stop_count,
                Some(stop_pubkeys),
                TIMELOCK_BLOCKS,
                vec![&ops_agg_pubkey],
            )?;

            //====================================
            // ADD THE OUTPUTS TO ALLOW EVERY OTHER OPERATOR TO CHALLENGE
            // ALSO THIS OUTPUT CAN BE CONSUME BY TIMEOUT IF HAS NOT BEEN CHALLENGED
            //TODO:here choose the appropiate pair
            //this should be another aggregated to be signed later
            //TODO: define properly the input utxo leafs
            //TODO: in this case we need to use a timelock to restrict the prover the take by timeout the start chhalenge
            let ops_agg_check =
                scripts::timelock(TIMELOCK_BLOCKS, &ops_agg_pubkey, SignMode::Aggregate);
            let pair_agg_check =
                scripts::check_aggregated_signature(&pair_0_1_aggregated, SignMode::Aggregate);
            let start_challenge = OutputType::taproot(
                protocol_cost,
                &ops_agg_pubkey,
                &[ops_agg_check, pair_agg_check],
            )?;

            let mut count = 0;
            for n in 0..keys.len() {
                if n != i {
                    //protocol.add_transaction_output(&certhashtx, &start_challenge.clone())?;
                    let tx_name = start_challenge_to(i, count);

                    protocol.add_connection(
                        &format!("{}__{}_TL", certhashtx, tx_name),
                        &certhashtx,
                        start_challenge.clone().into(),
                        &tx_name,
                        InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
                        Some(TIMELOCK_BLOCKS),
                        None,
                    )?;

                    //add the input that consume the stop output of the claim gate
                    count += 1;
                    let vout = claim_gate.vout + count;
                    protocol.add_transaction_input(
                        Hash::all_zeros(),
                        vout,
                        &tx_name,
                        Sequence::ENABLE_RBF_NO_LOCKTIME,
                        &SpendMode::Script { leaf: 0 },
                        &SighashType::taproot_all(),
                    )?;
                    protocol.add_connection(
                        &format!("{}__{}_STOP", certhashtx, tx_name),
                        &certhashtx,
                        (claim_gate.vout + count).into(),
                        &tx_name,
                        1.into(),
                        None,
                        None,
                    )?;

                    //add an output "speedup" (this is actually tacking the value of the protocol)
                    //needs to be changed once the speedup is working
                    pb.add_speedup_output(
                        &mut protocol,
                        &tx_name,
                        protocol_cost - fee,
                        &ops_agg_pubkey,
                    )?;
                }
            }

            pb.add_speedup_output(&mut protocol, &gidtotx, speedup_dust, &ops_agg_pubkey)?;

            pb.add_speedup_output(&mut protocol, &certhashtx, speedup_dust, &ops_agg_pubkey)?;
            amount = self.checked_sub(amount, amount_for_sequence)?;
        }

        // add one output to test
        pb.add_speedup_output(&mut protocol, SETUP_TX, amount, &ops_agg_pubkey)?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;
        Ok(())
    }

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!("SlotProtocol setup complete for program {}", self.ctx.id);
        Ok(())
    }
}

impl SlotProtocol {
    pub fn new(context: ProtocolContext) -> Self {
        Self { ctx: context }
    }

    pub fn setup_tx(&self) -> Result<Transaction, ProtocolBuilderError> {
        let signature = self
            .load_protocol()?
            .input_taproot_key_spend_signature(SETUP_TX, 0)?
            .unwrap();
        let mut taproot_arg = InputArgs::new_taproot_key_args();
        taproot_arg.push_taproot_signature(signature)?;

        self.load_protocol()?
            .transaction_to_send(SETUP_TX, &[taproot_arg])
    }
}

pub fn winternitz_equality(
    keys: &ParticipantKeys,
    aggregated: &PublicKey,
    key_name: &str,
    equal: u8,
) -> Result<ProtocolScript, BitVMXError> {
    let mut stack = StackTracker::new();
    stack.define(1, "selected-gid-high");
    stack.define(1, "selected-gid-low");
    stack.number(((equal & 0xF0) >> 4) as u32);
    stack.op_equalverify();
    stack.number((equal & 0xF) as u32);
    stack.op_equalverify();

    Ok(scripts::verify_winternitz_signatures_aux(
        &aggregated,
        &vec![(&key_name, keys.get_winternitz(&key_name)?)],
        SignMode::Aggregate,
        true,
        Some(vec![stack.get_script()]),
        //None,
    )?)
}
