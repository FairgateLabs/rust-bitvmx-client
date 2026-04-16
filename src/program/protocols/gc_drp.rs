use std::collections::HashMap;

use bitcoin::{script::read_scriptint, PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitcoin_script_stack::stack::StackTracker;
use bitvmx_job_dispatcher_types::garbled_messages::{
    GCJobEvaluationResult, GCJobProveResult, GarbledJobType,
};
use console::style;
use key_manager::{
    key_type::BitcoinKeyType,
    lamport::{LamportSignature, LamportType},
};
use protocol_builder::{
    builder::ProtocolBuilder,
    graph::graph::GraphOptions,
    scripts::{self, ProtocolScript, SignMode},
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
            protocol_handler::{timeout_input_tx, ClaimGateConfig, WithClaimGateConfig},
            timeouts::{auto_dispatch_timeout, cancel_timeout, TxOwnershipTable},
        },
        setup::steps::{
            garbler_step::{GCConfiguration, GC_INPUT_PK, GC_OUTPUT_PK, GC_PUBLIC_DATA},
            SetupStepName,
        },
        variables::{Globals, PartialUtxo, VariableTypes},
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
pub const COMMITMENT: &str = dispute::COMMITMENT;
pub const CHALLENGE: &str = "CHALLENGE_TX";
pub const INPUT: &str = "INPUT_TX";
pub const EQUIVOCATION: &str = "EQUIVOCATION_TX";
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

        self.add_connection_with_scripts(
            context,
            aggregated,
            &mut protocol,
            timelock_blocks,
            AmountType::Auto,
            speedup_dust,
            START_CH,
            COMMITMENT,
            &claim_verifier,
            Self::lamport_check(
                prover_speedup_pub,
                SignMode::Single,
                &keys[0],
                &Vec::<&str>::new(),
                None,
            )?,
            (&prover_speedup_pub, &verifier_speedup_pub),
        )?;

        self.add_connection_with_scripts(
            context,
            aggregated,
            &mut protocol,
            timelock_blocks,
            AmountType::Auto,
            speedup_dust,
            COMMITMENT,
            CHALLENGE,
            &claim_prover,
            Self::lamport_check(
                verifier_speedup_pub,
                SignMode::Single,
                &keys[1],
                &Vec::<&str>::new(),
                None,
            )?,
            (&verifier_speedup_pub, &prover_speedup_pub),
        )?;

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
            CHALLENGE,
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

        self.add_connection_with_scripts(
            context,
            aggregated,
            &mut protocol,
            timelock_blocks,
            AmountType::Auto,
            speedup_dust,
            INPUT,
            EQUIVOCATION,
            &claim_prover,
            vec![scripts::verify_lamport_signatures(
                verifier_speedup_pub,
                &vec![("circuit_output", &gc_output_pk)],
                SignMode::Single,
                Some(vec![Self::get_expects_false_script()]),
            )?],
            (&verifier_speedup_pub, &prover_speedup_pub),
        )?;

        let mut speedup_timeout =
            scripts::check_aggregated_signature(&aggregated, SignMode::Aggregate);
        speedup_timeout.set_assert_leaf_id(0);
        let mut verifier_final =
            scripts::timelock(2 * timelock_blocks, &aggregated, SignMode::Aggregate);
        verifier_final.set_assert_leaf_id(1);

        let output_type = OutputType::taproot(
            AmountType::Auto,
            aggregated,
            &vec![speedup_timeout, verifier_final],
        )?;

        protocol.add_connection(
            &format!(
                "{}_TL_{}_{}",
                EQUIVOCATION,
                2 * timelock_blocks,
                VERIFIER_FINAL
            ),
            EQUIVOCATION,
            output_type.into(),
            VERIFIER_FINAL,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
            Some(2 * timelock_blocks),
            None,
        )?;

        protocol.add_connection(
            &format!("{}__CONNECTOR__INPUT_TO", EQUIVOCATION),
            EQUIVOCATION,
            OutputSpec::Last,
            &timeout_input_tx(EQUIVOCATION),
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

        claim_verifier.add_claimer_win_connection(&mut protocol, VERIFIER_FINAL)?;
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
                    let (tx, speedup) =
                        self.get_tx_with_speedup_data(program_context, COMMITMENT)?;
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
                    (COMMITMENT, ParticipantRole::Verifier) => {
                        let (tx, speedup) =
                            self.get_tx_with_speedup_data(program_context, CHALLENGE)?;
                        self.dispatch(program_context, tx, Some(speedup), None)?;
                    }
                    (CHALLENGE, ParticipantRole::Prover) => {
                        let (tx, speedup) =
                            self.get_tx_with_speedup_data(program_context, INPUT)?;
                        self.dispatch(program_context, tx, Some(speedup), None)?;
                    }
                    (INPUT, ParticipantRole::Verifier) => {
                        let sigs =
                            self.decode_lamport_for_speedup(tx_id, vout, &name, transaction)?;

                        let protocol_id = &self.ctx.id;
                        let config = GCConfiguration::load(protocol_id, &program_context.globals)?;
                        let output_dir = format!("runs/gc/{}/{}", config.role, protocol_id);

                        let public_data: GCJobProveResult = serde_json::from_str(
                            &program_context
                                .globals
                                .get_var_or_err(protocol_id, GC_PUBLIC_DATA)?
                                .string()?,
                        )?;

                        self.execute_job(
                            program_context,
                            &program_context.components_config.garbler,
                            GarbledJobType::Evaluate(config.circuit, public_data, sigs, output_dir),
                            "verifier_evaluate_circuit",
                        )?;
                    }
                    (EQUIVOCATION, ParticipantRole::Verifier) => {
                        let tx = self.get_signed(
                            program_context,
                            &VERIFIER_FINAL,
                            vec![(1, true).into()],
                        )?;
                        let speedup_data =
                            self.get_speedup_data_from_tx(&tx, program_context, None)?;
                        let height = Some(current_height + 2 * timelock_blocks as u32);
                        self.dispatch(program_context, tx, Some(speedup_data), height)?;
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
        let tx = self.get_signed(context, EQUIVOCATION, vec![(0, true).into()])?;
        let protocol = self.load_protocol()?;
        let (output_type, _) = protocol.get_script_from_output(EQUIVOCATION, 0)?;

        let sp = SpeedupData::new_with_input(
            self.partial_utxo_from(&tx, 0),
            output_type,
            vec![signature],
            0,
            true,
        );

        self.dispatch(context, tx, Some(sp), None)?;

        // Mark this step as processed to prevent duplicate handling
        if let Some(key) = dedup_key {
            context
                .globals
                .set_var(&self.ctx.id, &key, VariableTypes::Bool(true))?;
        }

        Ok(())
    }

    fn lamport_check<T: AsRef<str> + std::fmt::Debug>(
        aggregated: &PublicKey,
        sign_mode: SignMode,
        keys: &ParticipantKeys,
        var_names: &Vec<T>,
        extra_check_scripts: Option<Vec<ScriptBuf>>,
    ) -> Result<Vec<ProtocolScript>, BitVMXError> {
        info!("lamport check for variables: {:?}", &var_names);

        let names_and_keys = var_names
            .iter()
            .map(|v| Ok::<_, BitVMXError>((v, keys.get_lamport(v.as_ref())?)))
            .collect::<Result<Vec<_>, _>>()?;

        let lamport_check = scripts::verify_lamport_signatures(
            aggregated,
            &names_and_keys,
            sign_mode,
            extra_check_scripts,
        )?;

        Ok(vec![lamport_check])
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
        table.add(COMMITMENT, Prover);
        table.add(CHALLENGE, Verifier);
        table.add(INPUT, Prover);
        table.add(EQUIVOCATION, Verifier);
        table.add(VERIFIER_FINAL, Verifier);

        table
    }

    fn get_expects_false_script() -> ScriptBuf {
        let mut stack = StackTracker::new();
        stack.define(1, "bit");
        stack.op_not();
        stack.op_verify();

        stack.get_script()
    }
}
