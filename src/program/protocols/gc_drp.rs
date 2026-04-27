use std::collections::HashMap;

use bitcoin::{script::read_scriptint, PublicKey, ScriptBuf, Transaction, Txid, XOnlyPublicKey};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitcoin_script::script;
use bitcoin_script_stack::stack::StackTracker;
use bitvmx_job_dispatcher_types::garbled_messages::{
    GCJobEvaluationResult, GCJobProveResult, GarbledJobType,
};
use console::style;
use key_manager::{
    errors::LamportError,
    key_type::BitcoinKeyType,
    lamport::{LamportPublicKey, LamportSignature, LamportType},
};
use protocol_builder::{
    builder::ProtocolBuilder,
    graph::graph::GraphOptions,
    scripts::{self, KeyType, ProtocolScript, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::{AmountType, SpeedupData},
        OutputType,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::{
        participant::{
            CommsAddress, ParticipantKeys,
            ParticipantRole::{self, Prover, Verifier},
            PublicKeyType,
        },
        protocols::{
            claim::{auto_claim_start, claim_state_handle, ClaimGate},
            dispute::{self},
            protocol_handler::{
                timeout_input_tx, timeout_tx, ClaimGateConfig, WithClaimGateConfig,
            },
            timeouts::{auto_dispatch_timeout, cancel_timeout, TxOwnershipTable},
        },
        setup::steps::{
            garbler_step::{
                GCConfiguration, GC_INPUT_PK, GC_OUTPUT_PK, GC_PUBLIC_DATA,
                GC_PUBLIC_INPUT_SIGNATURE,
            },
            SetupStepName,
        },
        variables::{Globals, PartialUtxo, VariableTypes, WitnessTypes},
    },
    types::{IncomingBitVMXApiMessages, ParticipantChannel, ProgramContext, PROGRAM_TYPE_GC_DRP},
};

use super::protocol_handler::{ProtocolContext, ProtocolHandler};

pub const SPEEDUP_KEY: &str = "speedup";
pub const AGGREGATED_KEY: &str = "aggregated";

pub const PAIR_0_1_AGGREGATED: &str = "pair_0_1_aggregated";
pub const FUNDING_UTXO: &str = "funding_utxo";
pub const TIMELOCK_BLOCKS: &str = "timelock_blocks";

pub const EXTERNAL_START: &str = dispute::EXTERNAL_START;
pub const START_CH: &str = dispute::START_CH;
pub const INPUT: &str = "INPUT_TX";
pub const VERIFIER_FINAL: &str = dispute::VERIFIER_FINAL;
pub const PROVER_WINS: &str = dispute::PROVER_WINS;
pub const VERIFIER_WINS: &str = dispute::VERIFIER_WINS;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GCDisputeConfiguration {
    pub id: Uuid,
    pub funding_utxo: PartialUtxo,
    pub pair_0_1_aggregated: PublicKey,
    pub prover_actions: Vec<(PartialUtxo, Vec<usize>)>,
    pub prover_enablers: Vec<OutputType>,
    pub verifier_actions: Vec<(PartialUtxo, Vec<usize>)>,
    pub verifier_enablers: Vec<OutputType>,
    pub timelock_blocks: u16,
    pub notify_protocol: Vec<(String, Uuid)>,
}

impl GCDisputeConfiguration {
    pub const NAME: &'static str = "gc_dispute_configuration";

    pub fn new(
        program_id: Uuid,
        funding_utxo: PartialUtxo,
        pair_0_1_aggregated: PublicKey,
        timelock_blocks: u16,
        prover_actions: Vec<(PartialUtxo, Vec<usize>)>,
        prover_enablers: Vec<OutputType>,
        verifier_actions: Vec<(PartialUtxo, Vec<usize>)>,
        verifier_enablers: Vec<OutputType>,
        notify_protocol: Vec<(String, Uuid)>,
    ) -> Self {
        Self {
            id: program_id,
            funding_utxo,
            pair_0_1_aggregated,
            timelock_blocks,
            prover_actions,
            prover_enablers,
            verifier_actions,
            verifier_enablers,
            notify_protocol,
        }
    }

    pub fn load(id: &Uuid, globals: &Globals) -> Result<Self, BitVMXError> {
        let gc_dispute_configuration = globals.get_var_or_err(id, Self::NAME)?.string()?;
        Ok(serde_json::from_str(&gc_dispute_configuration)?)
    }

    fn get_setup_messages(
        &self,
        addresses: Vec<CommsAddress>,
        leader: u16,
    ) -> Result<Vec<String>, BitVMXError> {
        Ok(vec![
            VariableTypes::String(serde_json::to_string(&self)?).set_msg(self.id, Self::NAME)?,
            IncomingBitVMXApiMessages::Setup(
                self.id,
                PROGRAM_TYPE_GC_DRP.to_string(),
                addresses,
                leader,
            )
            .to_string()?,
        ])
    }

    pub fn setup(
        &self,
        id_channel_pairs: &Vec<ParticipantChannel>,
        addresses: Vec<CommsAddress>,
        leader: u16,
    ) -> Result<(), BitVMXError> {
        for id_channel_pair in id_channel_pairs {
            for msg in self.get_setup_messages(addresses.clone(), leader)? {
                id_channel_pair.channel.send(&id_channel_pair.id, msg)?;
            }
        }
        Ok(())
    }
}

impl ClaimGateConfig for GCDisputeConfiguration {
    fn load(id: &Uuid, globals: &Globals) -> Result<Self, BitVMXError> {
        GCDisputeConfiguration::load(id, globals)
    }

    fn get_notify_protocol(&self) -> &Vec<(String, Uuid)> {
        &self.notify_protocol
    }

    fn get_prover_actions(&self) -> &Vec<(PartialUtxo, Vec<usize>)> {
        &self.prover_actions
    }

    fn get_verifier_actions(&self) -> &Vec<(PartialUtxo, Vec<usize>)> {
        &self.verifier_actions
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GCDisputeResolutionProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for GCDisputeResolutionProtocol {
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
        let config = GCDisputeConfiguration::load(&self.ctx.id, &context.globals)?;

        Ok(vec![(
            "pregenerated".to_string(),
            config.pair_0_1_aggregated.clone(),
        )])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let aggregated_1 = program_context
            .key_manager
            .next_keypair(BitcoinKeyType::P2tr)?;

        let speedup = program_context
            .key_manager
            .next_keypair(BitcoinKeyType::P2tr)?;

        program_context.globals.set_var(
            &self.ctx.id,
            SPEEDUP_KEY,
            VariableTypes::PubKey(speedup),
        )?;

        let keys: Vec<(String, PublicKeyType)> = vec![
            (AGGREGATED_KEY.to_string(), aggregated_1.into()),
            (SPEEDUP_KEY.to_string(), speedup.into()),
        ];

        Ok(ParticipantKeys::new(keys, vec![AGGREGATED_KEY.to_string()]))
    }

    fn build(
        &self,
        keys: Vec<ParticipantKeys>,
        computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let dust = OutputType::generic_dust_limit(None).to_sat();
        let speedup_dust = dust;
        let fee = dust;

        let (prover_signs, verifier_signs) = if self.role() == ParticipantRole::Prover {
            (SignMode::Single, SignMode::Skip)
        } else {
            (SignMode::Skip, SignMode::Single)
        };

        let config = GCDisputeConfiguration::load(&self.ctx.id, &context.globals)?;

        let timelock_blocks = config.timelock_blocks;

        let funding_utxo = config.funding_utxo;

        let output_type = funding_utxo.3.ok_or(BitVMXError::MissingParameter(
            "funding UTXO output type is required".to_string(),
        ))?;

        let prover_speedup_pub = keys[0].get_public(SPEEDUP_KEY)?;
        let verifier_speedup_pub = keys[1].get_public(SPEEDUP_KEY)?;
        let aggregated = computed_aggregated
            .get(AGGREGATED_KEY)
            .ok_or_else(|| BitVMXError::NotFound(AGGREGATED_KEY.to_string()))?;

        let mut protocol = self.load_or_create_protocol();

        protocol.add_external_transaction(EXTERNAL_START)?;
        protocol.add_unknown_outputs(EXTERNAL_START, funding_utxo.1)?;
        protocol.add_transaction_output(EXTERNAL_START, &output_type)?;

        protocol.add_connection(
            &format!("{EXTERNAL_START}_{START_CH}"),
            EXTERNAL_START,
            (funding_utxo.1 as usize).into(),
            START_CH,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
            None,
            Some(funding_utxo.0),
        )?;

        let pb = ProtocolBuilder {};
        pb.add_speedup_output(&mut protocol, START_CH, speedup_dust, verifier_speedup_pub)?;

        let claim_prover = ClaimGate::new(
            &mut protocol,
            START_CH,
            PROVER_WINS,
            (prover_speedup_pub, prover_signs),
            aggregated,
            fee,
            speedup_dust,
            vec![verifier_speedup_pub],
            None,
            timelock_blocks,
            config.prover_actions.len() as u64,
            config.prover_enablers,
            true,
            None,
        )?;

        let claim_verifier = ClaimGate::new(
            &mut protocol,
            START_CH,
            VERIFIER_WINS,
            (verifier_speedup_pub, verifier_signs),
            aggregated,
            fee,
            speedup_dust,
            vec![prover_speedup_pub],
            None,
            timelock_blocks,
            config.verifier_actions.len() as u64,
            config.verifier_enablers,
            false,
            claim_prover.exclusive_success_vout,
        )?;

        for (n, (utxo, leaves)) in config.prover_actions.iter().enumerate() {
            self.add_action(
                &mut protocol,
                utxo,
                leaves,
                &prover_speedup_pub,
                &ParticipantRole::Prover,
                PROVER_WINS,
                n as u32 + 1,
            )?;
        }

        for (n, (utxo, leaves)) in config.verifier_actions.iter().enumerate() {
            self.add_action(
                &mut protocol,
                utxo,
                leaves,
                &verifier_speedup_pub,
                &ParticipantRole::Verifier,
                VERIFIER_WINS,
                n as u32 + 1,
            )?;
        }

        let gc_input_pk = context
            .globals
            .get_var_or_err(&self.context().id, GC_INPUT_PK)?
            .lamport_pubkey()?;

        self.add_connection_with_scripts(
            context,
            aggregated,
            &mut protocol,
            timelock_blocks,
            AmountType::Auto,
            speedup_dust,
            START_CH,
            INPUT,
            &claim_verifier,
            vec![scripts::verify_lamport_signatures(
                prover_speedup_pub,
                &vec![("prover_input", &gc_input_pk)],
                SignMode::Single,
                None,
            )?],
            (&prover_speedup_pub, &verifier_speedup_pub),
        )?;

        let gc_output_pk = context
            .globals
            .get_var_or_err(&self.context().id, GC_OUTPUT_PK)?
            .lamport_pubkey()?;

        let mut connection_leaf = scripts::check_signature(aggregated, SignMode::Aggregate);
        connection_leaf.set_assert_leaf_id(0);

        let mut timeout = scripts::timelock(2 * timelock_blocks, &aggregated, SignMode::Aggregate);
        timeout.set_assert_leaf_id(1);

        let mut script = Self::lamport_check_false(
            aggregated,
            SignMode::Aggregate,
            &gc_output_pk,
            "circuit_output",
        )?;
        script.set_assert_leaf_id(2);

        let output_type = OutputType::taproot(
            AmountType::Auto,
            aggregated,
            &vec![connection_leaf, timeout, script],
        )?;

        protocol.add_connection(
            &format!("{}__{}", INPUT, VERIFIER_FINAL),
            INPUT,
            output_type.clone().into(),
            VERIFIER_FINAL,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 2 }),
            None,
            None,
        )?;

        protocol.add_connection(
            &format!("{}_TL_{}_{}_TO", INPUT, 2 * timelock_blocks, VERIFIER_FINAL),
            INPUT,
            OutputSpec::Last,
            &timeout_tx(VERIFIER_FINAL),
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
            Some(2 * timelock_blocks),
            None,
        )?;

        protocol.add_connection(
            &format!("{}__CONNECTOR__INPUT_TO", INPUT),
            INPUT,
            OutputSpec::Last,
            &timeout_input_tx(INPUT),
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
            None,
            None,
        )?;

        pb.add_speedup_output(
            &mut protocol,
            VERIFIER_FINAL,
            speedup_dust,
            &verifier_speedup_pub,
        )?;

        context.globals.set_var(
            &self.context().id,
            &timeout_tx(VERIFIER_FINAL),
            VariableTypes::VecNumber(vec![1, 2 * timelock_blocks as u32]),
        )?;

        pb.add_speedup_output(
            &mut protocol,
            &timeout_tx(VERIFIER_FINAL),
            speedup_dust,
            &prover_speedup_pub,
        )?;

        claim_verifier.add_claimer_win_connection(&mut protocol, VERIFIER_FINAL)?;
        claim_prover.add_claimer_win_connection(&mut protocol, &timeout_tx(VERIFIER_FINAL))?;
        protocol.compute_minimum_output_values()?;
        protocol.build(&context.key_manager, &self.ctx.protocol_name)?;

        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);
        self.save_protocol(protocol)?;

        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        if name == START_CH {
            let tx = self.get_signed(context, START_CH, vec![0.into()])?;
            let speedup = self.get_speedup_data_from_tx(&tx, context, Some(0))?;
            Ok((tx, Some(speedup)))
        } else {
            Err(BitVMXError::InvalidTransactionName(name.to_string()))
        }
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        _context: String,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let name = self.get_transaction_name_by_id(tx_id)?;
        let current_height = tx_status
            .block_info
            .as_ref()
            .ok_or_else(|| {
                BitVMXError::InvalidTransactionStatus(
                    "TransactionStatus missing block_info".to_string(),
                )
            })?
            .height;
        info!(
            "Program {}: Transaction name: {}  id: {}:{:?} has been seen on-chain {}. Height: {}",
            self.context().id,
            style(&name).blue(),
            style(&tx_id).green(),
            style(&vout).yellow(),
            self.role(),
            current_height,
        );

        let config = GCDisputeConfiguration::load(&self.context().id, &program_context.globals)?;

        let ownership_table = Self::create_ownership_table();

        cancel_timeout(self, &name, vout, program_context, &ownership_table)?;

        let timelock_blocks = config.timelock_blocks;

        auto_dispatch_timeout(
            self,
            &name,
            vout,
            program_context,
            current_height,
            &ownership_table,
        )?;

        auto_claim_start(self, &name, vout, program_context, &ownership_table)?;

        claim_state_handle(
            self,
            tx_id,
            &name,
            vout,
            tx_status.clone(),
            program_context,
            current_height,
            timelock_blocks as u32,
        )?;

        match vout {
            None => match (name.as_str(), self.role()) {
                (START_CH, ParticipantRole::Prover) => {
                    let (tx, speedup) = self.get_tx_with_speedup_data(program_context, INPUT)?;
                    self.dispatch(program_context, tx, Some(speedup), None)?;
                }
                (VERIFIER_FINAL, ParticipantRole::Verifier) => {
                    let claim_name = ClaimGate::tx_start(VERIFIER_WINS);
                    let tx = self.get_signed(program_context, &claim_name, vec![0.into()])?;
                    let speedup_data = self.get_speedup_data_from_tx(&tx, program_context, None)?;
                    info!("{claim_name}: {:?}", tx);
                    program_context.bitcoin_coordinator.dispatch(
                        tx,
                        Some(speedup_data),
                        Context::ProgramId(self.ctx.id).to_string()?,
                        None,
                        self.requested_confirmations(program_context),
                    )?;
                }
                _ => {}
            },
            Some(vout) => {
                let transaction = &tx_status.tx;
                let input_index = self.find_prevout(tx_id, vout, transaction)?;
                let witness = transaction.input[input_index as usize].witness.clone();
                let leaf = read_scriptint(
                    witness
                        .third_to_last()
                        .ok_or_else(|| BitVMXError::InvalidWitness(witness.clone()))?,
                )? as u32;

                let params = program_context
                    .globals
                    .get_var_or_err(&self.ctx.id, &timeout_input_tx(&name))?
                    .vec_number()?;

                let timeout_leaf = params[0];

                if leaf == timeout_leaf {
                    warn!("The timeout input for {name} was consumed");
                    return Ok(());
                }

                match (name.as_str(), self.role()) {
                    (INPUT, ParticipantRole::Verifier) => {
                        let prover_circuit_input =
                            self.decode_lamport_for_speedup(tx_id, vout, &name, transaction)?;

                        let protocol_id = &self.ctx.id;
                        let config = GCConfiguration::load(protocol_id, &program_context.globals)?;
                        let output_dir = format!("runs/gc/{}/{}", config.role, protocol_id);

                        let public_input_signature = program_context
                            .globals
                            .get_var_or_err(&self.ctx.id, GC_PUBLIC_INPUT_SIGNATURE)?
                            .input()?;

                        let (public_input_signature, _) = public_input_signature.as_chunks::<32>();

                        let public_input: Vec<([u8; 32], u8)> = public_input_signature
                            .iter()
                            .copied()
                            .zip(config.circuit_public_input.iter().map(|b| *b as u8))
                            .collect();

                        let circuit_input = [public_input, prover_circuit_input].concat();

                        let public_data: GCJobProveResult = serde_json::from_str(
                            &program_context
                                .globals
                                .get_var_or_err(protocol_id, GC_PUBLIC_DATA)?
                                .string()?,
                        )?;

                        self.execute_job(
                            program_context,
                            &program_context.components_config.garbler,
                            GarbledJobType::Evaluate(
                                config.circuit,
                                public_data,
                                circuit_input,
                                output_dir,
                            ),
                            "verifier_evaluate_circuit",
                        )?;
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn setup_steps(&self) -> Option<Vec<SetupStepName>> {
        Some(vec![
            SetupStepName::Garbler,
            SetupStepName::Keys,
            SetupStepName::Nonces,
            SetupStepName::Signatures,
        ])
    }
}

impl WithClaimGateConfig for GCDisputeResolutionProtocol {
    type Config = GCDisputeConfiguration;
    const PROGRAM_TYPE: &'static str = PROGRAM_TYPE_GC_DRP;

    fn role(&self) -> ParticipantRole {
        if self.context().my_idx == 0 {
            ParticipantRole::Prover
        } else {
            ParticipantRole::Verifier
        }
    }
}

impl GCDisputeResolutionProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    pub fn execution_result(
        &self,
        result: Value,
        job_context: &Context,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        // Dedup guard: if this step was already processed, skip it
        let dedup_key = if let Context::ProgramStep(_, ref step) = job_context {
            let key = format!("job_done:{}", step);
            if context.globals.contains_var(&self.ctx.id, &key)? {
                warn!("Duplicate job result for step '{}', skipping", step);
                return Ok(());
            }
            Some(key)
        } else {
            None
        };

        let result: GCJobEvaluationResult = serde_json::from_value(result)?;

        // TODO: don't send if output is correct
        // We assume there is a single output
        let signature = LamportSignature::from_bytes(&result.output[0], 1, LamportType::SHA256)?;
        context.witness.set_witness(
            &self.ctx.id,
            "circuit_output",
            WitnessTypes::Lamport(signature),
        )?;

        let tx = self.get_signed(context, VERIFIER_FINAL, vec![(2, true).into()])?;
        self.dispatch(context, tx, None, None)?;

        // Mark this step as processed to prevent duplicate handling
        if let Some(key) = dedup_key {
            context
                .globals
                .set_var(&self.ctx.id, &key, VariableTypes::Bool(true))?;
        }

        Ok(())
    }

    fn lamport_check_false(
        aggregated: &PublicKey,
        sign_mode: SignMode,
        key: &LamportPublicKey,
        key_name: &str,
    ) -> Result<ProtocolScript, BitVMXError> {
        let script = script!(
            {XOnlyPublicKey::from(*aggregated).serialize().to_vec()}
            OP_CHECKSIGVERIFY
            { Self::ots_check_false_lamport(key) }
            OP_PUSHNUM_1
        )
        .compile();

        let mut lamport_check = ProtocolScript::new(script, aggregated, sign_mode);
        lamport_check.add_key(
            key_name,
            key.derivation_index()
                .ok_or(LamportError::ExtraDataMissing(
                    "derivation_index".to_string(),
                ))?,
            KeyType::lamport(key)?,
            0,
        )?;

        Ok(lamport_check)
    }

    fn ots_check_false_lamport(key: &LamportPublicKey) -> ScriptBuf {
        let mut stack = StackTracker::new();

        for i in 0..key.len() {
            stack.define(1, format!("signature_{}", i).as_str());
        }

        let (zeros, _ones) = key.to_hashes_string();

        const OTS_SIZE: u32 = 32;
        for idx in (0..key.len()).rev() {
            stack.op_size();
            stack.number(OTS_SIZE);
            stack.op_equalverify();

            stack.op_sha256();
            stack.hexstr(&zeros[idx]);
            stack.op_equalverify();
        }

        stack.get_script()
    }

    fn get_tx_with_speedup_data(
        &self,
        context: &ProgramContext,
        name: &str,
    ) -> Result<(Transaction, SpeedupData), BitVMXError> {
        let tx = self.get_signed(context, name, vec![(0, true).into()])?;
        let protocol = self.load_protocol()?;
        let (output_type, scripts) = protocol.get_script_from_output(name, 0)?;
        info!("Scripts length: {}", scripts.len());

        let lamp_sigs = self.get_lamport_signature_for_script(&scripts[0], context)?;
        let speedup_data = SpeedupData::new_with_input(
            self.partial_utxo_from(&tx, 0),
            output_type,
            lamp_sigs,
            0,
            true,
        );

        Ok((tx, speedup_data))
    }

    fn create_ownership_table() -> TxOwnershipTable {
        let mut table = TxOwnershipTable::new();
        table.add_ignored(START_CH.to_string());
        table.add_ignored(VERIFIER_FINAL.to_string());

        table.add(START_CH, Verifier);
        table.add(INPUT, Prover);
        table.add(VERIFIER_FINAL, Verifier);

        table
    }
}
