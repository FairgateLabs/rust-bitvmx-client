use std::collections::HashMap;

use bitcoin::{hashes::Hash, PublicKey, Sequence, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitcoin_script_stack::stack::StackTracker;
use console::style;
use key_manager::key_type::BitcoinKeyType;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    graph::graph::GraphOptions,
    scripts::{self, timelock, ProtocolScript, SignMode},
    types::{
        connection::InputSpec,
        input::{SighashType, SpendMode},
        output::SpeedupData,
        InputArgs, OutputType, Utxo,
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
            cardinal::{
                slot_config::SlotProtocolConfiguration, OPERATORS, OPERATORS_AGGREGATED_PUB,
                STOPS_CONSUMED,
            },
            claim::ClaimGate,
            dispute::{self, START_CH, TIMELOCK_BLOCKS_KEY},
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

pub fn slot_protocol_dust_cost(participants: u8) -> u64 {
    let dust = OutputType::generic_dust_limit(None).to_sat();
    participants as u64 * (amount_for_operator(participants) + dust) + dust
}

pub fn amount_for_operator(operators: u8) -> u64 {
    let dust = OutputType::generic_dust_limit(None).to_sat();

    let protocol_cost = dispute::protocol_cost();
    let claim_gate_cost = ClaimGate::cost(dust, dust, operators as u8 - 1, 1, false);
    let amount_for_operator = dust
        + dust
        + (dust * 8) // sending the cert hash tx
        + claim_gate_cost
        + (operators -1) as u64 * protocol_cost;
    amount_for_operator
}

pub fn dust_claim_stop() -> u64 {
    let dust = OutputType::generic_dust_limit(None).to_sat();
    2 * dust
}

pub fn claim_name(op: usize) -> String {
    format!("{}{}", OP_WINS, op)
}

pub fn cert_hash_tx_op(n: u32) -> String {
    format!("{}{}", CERT_HASH_TX, n)
}

pub fn certificate_hash(n: usize) -> String {
    format!("certificate_hash_{}", n)
}

pub fn certificate_hash_sub(op: usize, word: u8) -> String {
    format!("certificate_hash_{}_{}", op, word)
}

pub fn certificate_hash_prefix(op: usize) -> String {
    format!("certificate_hash_{}_", op)
}

pub fn group_id(op: usize) -> String {
    format!("group_id_{}_0", op) //add 0 as it only requires one word but the connection with the dispute is made with prefixes
}

pub fn group_id_prefix(op: usize) -> String {
    format!("group_id_{}_", op)
}

/*pub fn group_id_pubkey(op: usize) -> String {
    format!("group_id_pubkey_{}", op)
}*/

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
                .get_var(&self.ctx.id, OPERATORS_AGGREGATED_PUB)?
                .unwrap()
                .pubkey()?,
        )])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let key_chain = &mut program_context.key_chain;

        let speedup = key_chain.derive_keypair(BitcoinKeyType::P2tr)?;

        program_context.globals.set_var(
            &self.ctx.id,
            "speedup",
            VariableTypes::PubKey(speedup.clone()),
        )?;

        let mut keys = vec![("speedup".to_string(), speedup.into())];

        // we need 8*4 = 32 bytes, so we can challenge the word size input
        for i in 0..8 {
            let cert_hash = key_chain.derive_winternitz_hash160(4)?;
            keys.push((certificate_hash_sub(self.ctx.my_idx, i), cert_hash.into()));
        }

        let gid = key_chain.derive_winternitz_hash160(4)?;
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
            let full_hash = program_context
                .globals
                .get_var(&self.ctx.id, &certificate_hash(self.ctx.my_idx))?
                .unwrap()
                .input()?;

            for i in 0..8 {
                let partial_input = full_hash
                    .get((i * 4) as usize..((i + 1) * 4) as usize)
                    .unwrap();
                program_context.globals.set_var(
                    &self.ctx.id,
                    &certificate_hash_sub(self.ctx.my_idx, i),
                    VariableTypes::Input(partial_input.to_vec()),
                )?;
            }
            let tx = self.get_signed_tx(program_context, name, 0, 0, false, 0)?;
            let speedup_utxo = self.get_speedup_data_from_tx(&tx, program_context, None)?;

            return Ok((tx, Some(speedup_utxo.into())));
        }

        match name {
            SETUP_TX => Ok(self.setup_tx(program_context)?),
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
        _participant_keys: Vec<&ParticipantKeys>,
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
                    .input()?;
                let gid = u32::from_le_bytes(
                    gid.try_into()
                        .map_err(|_| BitVMXError::InvalidMessageFormat)?,
                );

                let gid_selection_tx = self.get_signed_tx(
                    program_context,
                    &group_id_tx(operator as usize, gid as u8),
                    0,
                    gid as u32,
                    false,
                    0,
                )?;
                info!(
                    "Operator {} is going to send the group id {}. Txid: {}",
                    operator,
                    gid,
                    style(gid_selection_tx.compute_txid()).green()
                );

                let speedup_data =
                    self.get_speedup_data_from_tx(&gid_selection_tx, program_context, None)?;

                program_context.bitcoin_coordinator.dispatch(
                    gid_selection_tx,
                    Some(speedup_data),
                    Context::ProgramId(self.ctx.id).to_string()?,
                    None,
                    self.requested_confirmations(program_context),
                )?;

                let total_operators = program_context
                    .globals
                    .get_var(&self.ctx.id, OPERATORS)?
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
                            self.requested_confirmations(program_context),
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
                .get_var(&self.ctx.id, OPERATORS)?
                .unwrap()
                .number()?;

            let mut stops_consumed = program_context
                .globals
                .get_var(&self.ctx.id, STOPS_CONSUMED)?
                .unwrap_or(VariableTypes::Number(0))
                .number()?;

            //this part is to avoid resending. this shoudld be moved to timelock as soon as cert_hash is sent
            if stops_consumed == 0 {
                program_context.globals.set_var(
                    &self.ctx.id,
                    STOPS_CONSUMED,
                    VariableTypes::Number(1),
                )?;

                for i in 0..total_operators - 1 {
                    if i != vout.unwrap() - 2 {
                        info!("Sending tx to consume the stop for {}", i);

                        let tx = self.get_signed_tx(
                            program_context,
                            &start_challenge_to(operator as usize, i as usize),
                            0,
                            0,
                            false,
                            0,
                        )?;
                        let speedup_data =
                            self.get_speedup_data_from_tx(&tx, program_context, None)?;
                        program_context.bitcoin_coordinator.dispatch(
                            tx,
                            Some(speedup_data),
                            Context::ProgramId(self.ctx.id).to_string()?,
                            None,
                            self.requested_confirmations(program_context),
                        )?;
                    } else {
                        info!("The stop for the operator {} has been consumed", i);
                    }
                }
            } else {
                stops_consumed += 1;
                program_context.globals.set_var(
                    &self.ctx.id,
                    STOPS_CONSUMED,
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
                    let speedup_data = self.get_speedup_data_from_tx(&tx, program_context, None)?;
                    program_context.bitcoin_coordinator.dispatch(
                        tx,
                        Some(speedup_data),
                        Context::ProgramId(self.ctx.id).to_string()?,
                        None,
                        self.requested_confirmations(program_context),
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

            let timelock_blocks = program_context
                .globals
                .get_var(&self.ctx.id, TIMELOCK_BLOCKS_KEY)?
                .unwrap()
                .number()?;

            info!("Prover sending SUCCESS tx");

            let tx = self.get_signed_tx(
                program_context,
                &ClaimGate::tx_success(&claim_name(operator as usize)),
                0,
                1,
                false,
                0,
            )?;
            let speedup_data = self.get_speedup_data_from_tx(&tx, program_context, None)?;
            program_context.bitcoin_coordinator.dispatch(
                tx,
                Some(speedup_data),
                Context::ProgramId(self.ctx.id).to_string()?,
                Some(tx_status.block_info.unwrap().height + timelock_blocks),
                self.requested_confirmations(program_context),
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
        let dust = OutputType::generic_dust_limit(None).to_sat();

        let SlotProtocolConfiguration {
            operators_aggregated_pub,
            operators_pairs,
            fund_utxo,
            gid_max,
            timelock_blocks,
            operators,
            ..
        } = SlotProtocolConfiguration::new_from_globals(self.ctx.id, &context.globals)?;

        //save participants wots
        for (idx, key) in keys.iter().enumerate() {
            for sub in 0..8 {
                context.globals.set_var(
                    &self.ctx.id,
                    &certificate_hash_sub(idx, sub),
                    VariableTypes::WinternitzPubKey(
                        key.get_winternitz(&certificate_hash_sub(idx, sub))?.clone(),
                    ),
                )?;
            }
            context.globals.set_var(
                &self.ctx.id,
                &group_id(idx),
                VariableTypes::WinternitzPubKey(key.get_winternitz(&group_id(idx))?.clone()),
            )?;
        }

        //create the protocol
        let mut protocol = self.load_or_create_protocol();
        let pb = ProtocolBuilder {};

        //=======================
        // Connect the funding tx with the first tx. SETUP_TX
        let amount = fund_utxo.2.ok_or(BitVMXError::MissingParameter(
            "Funding UTXO amount is required".to_string(),
        ))?;
        let spending = vec![scripts::check_aggregated_signature(
            &operators_aggregated_pub,
            SignMode::Aggregate,
        )];
        let output_type = external_fund_tx(&operators_aggregated_pub, spending, amount)?;

        protocol.add_external_transaction(FUND_SLOT)?;
        protocol.add_unknown_outputs(FUND_SLOT, fund_utxo.1)?;

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

        let speedup_keys = keys
            .iter()
            .map(|k| k.get_public("speedup"))
            .collect::<Result<Vec<_>, _>>()?;

        //====================================
        //CREATES THE SLOTS FOR EACH OPERATOR
        //CERT HASH TX:
        // vout0 = gid_publish (leafs 0..=gid_max)
        // vout1 = claim_gate_start
        // vout2..2+operators-1 = stop_gate    [for 3 operators 2,3]
        // (vout2+operators-1).. (vout2+operators-1+operators-1)= start_challenge  [for 3 operators 4,5]
        for (i, key) in keys.iter().enumerate() {
            //create the certificate hash tx
            info!("Creating certificate hash tx for operator {}", i);
            let certhashtx = self.add_cert_hash_tx(
                i,
                key,
                &operators_aggregated_pub,
                &mut protocol,
                amount_for_operator(operators),
                gid_max,
                timelock_blocks,
            )?;

            //create group id tx that consumes outputs from the certificate hash tx
            self.add_group_id_tx(
                i,
                key,
                &certhashtx,
                &operators_aggregated_pub,
                &mut protocol,
                gid_max,
            )?;

            //====================================
            // IF GROUP ID IS NOT SELECTED THE REST OF THE OPERATORS CAN PENALIZE AFTER TIME OUT
            // create the timeout gid tx
            let gidtotx = group_id_to(i);
            info!("Creating timeout gid tx {}", gidtotx);

            protocol.add_connection(
                &format!("{}__{}", certhashtx, gidtotx),
                &certhashtx,
                0.into(),
                &gidtotx,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::Script { leaf: 0 }, //we put the timelock on the leaf 0
                ),
                Some(timelock_blocks),
                None,
            )?;

            for (n, other_key) in keys.iter().enumerate() {
                if n == i {
                    continue;
                }
                pb.add_speedup_output(
                    &mut protocol,
                    &gidtotx,
                    dust,
                    other_key.get_public("speedup")?,
                )?;
            }

            //====================================
            // ADD THE CLAIM GATE THAT THE OPERATOR WINS
            // IF CONTAINS ALSO THE STOP OUTPUTS THAT IF THE OPERATOR WINS CHALLENGE NEEDS TO CONSUME
            //TODO: set the proper pair aggregated for the stop output
            let mut stopper_keys = speedup_keys.clone();
            let claimer = stopper_keys.remove(i);
            let mut subset_cov = vec![];
            for _ in 0..operators - 1 {
                subset_cov.push(&operators_pairs[0]);
            }
            let claimer_sign = if self.ctx.my_idx == i {
                SignMode::Single
            } else {
                SignMode::Skip
            };
            let claim_gate = ClaimGate::new(
                &mut protocol,
                &certhashtx,
                &claim_name(i),
                (claimer, claimer_sign),
                &operators_aggregated_pub,
                dust,
                dust,
                stopper_keys,
                Some(subset_cov),
                timelock_blocks,
                1,
                vec![],
                false,
                None,
            )?;

            //====================================
            // ADD THE OUTPUTS TO ALLOW EVERY OTHER OPERATOR TO CHALLENGE
            // ALSO THIS OUTPUT CAN BE CONSUME BY TIMEOUT IF HAS NOT BEEN CHALLENGED
            //TODO:here choose the appropiate pair
            //this should be another aggregated to be signed later
            //TODO: define properly the input utxo leafs
            //TODO: in this case we need to use a timelock to restrict the prover the take by timeout the start chhalenge
            let ops_agg_check = scripts::timelock(
                timelock_blocks,
                &operators_aggregated_pub,
                SignMode::Aggregate,
            );
            let pair_agg_check =
                scripts::check_aggregated_signature(&operators_pairs[0], SignMode::Aggregate);
            let start_challenge = OutputType::taproot(
                dispute::protocol_cost().into(),
                &operators_aggregated_pub,
                &[ops_agg_check, pair_agg_check],
            )?;

            // allow the operator to chancel the challenge by timeout
            let mut count = 0;
            for n in 0..keys.len() {
                info!(
                    "Creating start challenge tx for operator {} with key {}",
                    n,
                    key.get_public("speedup")?
                );
                if n != i {
                    let tx_name = start_challenge_to(i, count);

                    protocol.add_connection(
                        &format!("{}__{}_TL", certhashtx, tx_name),
                        &certhashtx,
                        start_challenge.clone().into(),
                        &tx_name,
                        InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
                        Some(timelock_blocks),
                        None,
                    )?;

                    //add the input that consume the stop output of the claim gate
                    count += 1;
                    protocol.add_connection(
                        &format!("{}__{}_STOP", certhashtx, tx_name),
                        &certhashtx,
                        (claim_gate.vout + count).into(),
                        &tx_name,
                        InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
                        None,
                        None,
                    )?;

                    pb.add_speedup_output(
                        &mut protocol,
                        &tx_name,
                        dust,
                        key.get_public("speedup")?,
                    )?;
                }
            }

            pb.add_speedup_output(&mut protocol, &certhashtx, dust, key.get_public("speedup")?)?;
        }

        // Add the speedup output for the SETUP_TX
        for k in keys {
            pb.add_speedup_output(&mut protocol, SETUP_TX, dust, k.get_public("speedup")?)?;
        }
        info!("Going to build");

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize(GraphOptions::EdgeArrows)?);
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

    pub fn setup_tx(
        &self,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        let dust = OutputType::generic_dust_limit(None).to_sat();

        let signature = self
            .load_protocol()?
            .input_taproot_key_spend_signature(SETUP_TX, 0)?
            .unwrap();
        let mut taproot_arg = InputArgs::new_taproot_key_args();
        taproot_arg.push_taproot_signature(signature)?;

        let tx = self
            .load_protocol()?
            .transaction_to_send(SETUP_TX, &[taproot_arg])?;

        let txid = tx.compute_txid();
        let speedup = context
            .globals
            .get_var(&self.ctx.id, "speedup")?
            .unwrap()
            .pubkey()?;

        let operators = context
            .globals
            .get_var(&self.ctx.id, OPERATORS)?
            .unwrap()
            .number()?;
        let speedup_utxo = Utxo::new(txid, operators + self.ctx.my_idx as u32, dust, &speedup);

        //debug!("Transaction to send: {:?}", tx);
        Ok((tx, Some(speedup_utxo.into())))
    }

    fn add_cert_hash_tx(
        &self,
        i: usize,
        key: &ParticipantKeys,
        operators_aggregated_pub: &PublicKey,
        protocol: &mut Protocol,
        amount_for_sequence: u64,
        gid_max: u8,
        timelock_blocks: u16,
    ) -> Result<String, BitVMXError> {
        //====================================
        //EVERY OPERATOR CAN SEND A CERTIFICATE HASH
        //Verify the winternitz signature
        let mut names_and_keys = vec![];
        for sub in 0..8 {
            let key_name = certificate_hash_sub(i, sub);
            names_and_keys.push((key_name.clone(), key.get_winternitz(&key_name)?));
        }
        let winternitz_check = scripts::verify_winternitz_signatures(
            &operators_aggregated_pub,
            &names_and_keys,
            SignMode::Aggregate,
        )?;

        let output_type = OutputType::taproot(
            amount_for_sequence.into(),
            &operators_aggregated_pub,
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
            .map(|gid| winternitz_equality(key, &operators_aggregated_pub, &key_name, gid).unwrap())
            .collect();
        let timelock_script = timelock(
            timelock_blocks,
            &operators_aggregated_pub,
            SignMode::Aggregate,
        );
        leaves.insert(0, timelock_script);
        //put timelock as zero so the index matches the gid

        //3 dust, one for the tx, one for the connection output and one for the speedup output
        let dust = OutputType::generic_dust_limit(None).to_sat();
        let output_type =
            OutputType::taproot((3 * dust).into(), &operators_aggregated_pub, &leaves)?;

        protocol.add_transaction_output(&certhashtx, &output_type)?;

        Ok(certhashtx)
    }

    fn add_group_id_tx(
        &self,
        i: usize,
        key: &ParticipantKeys,
        certhashtx: &str,
        operators_aggregated_pub: &PublicKey,
        protocol: &mut Protocol,
        gid_max: u8,
    ) -> Result<(), BitVMXError> {
        // create txs that consumes the gid
        // it requires 2 dust
        let dust = OutputType::generic_dust_limit(None).to_sat();

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
                scripts::check_aggregated_signature(&operators_aggregated_pub, SignMode::Aggregate);

            protocol.add_transaction_output(
                &gidtx,
                &OutputType::taproot(dust.into(), &operators_aggregated_pub, &[gid_spend])?,
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
            // this output is zero value
            let differenciator = scripts::op_return_script(vec![gid as u8])?
                .get_script()
                .clone();
            protocol
                .add_transaction_output(&gidtx, &OutputType::segwit_unspendable(differenciator)?)?;

            let pb = ProtocolBuilder {};
            pb.add_speedup_output(protocol, &gidtx, dust, key.get_public("speedup")?)?;
        }

        Ok(())
    }
}

pub fn winternitz_equality(
    keys: &ParticipantKeys,
    aggregated: &PublicKey,
    key_name: &str,
    equal: u8,
) -> Result<ProtocolScript, BitVMXError> {
    let mut stack = StackTracker::new();
    let provided = stack.define(8, "provided_gid");
    let real = stack.number_u32(u32::from_be_bytes((equal as u32).to_le_bytes()) as u32);
    stack.reverse_u32(real);
    stack.equals(provided, true, real, true);

    Ok(scripts::verify_winternitz_signatures_aux(
        &aggregated,
        &vec![(&key_name, keys.get_winternitz(&key_name)?)],
        SignMode::Aggregate,
        true,
        Some(vec![stack.get_script()]),
        //None,
    )?)
}
