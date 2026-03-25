use std::collections::HashMap;

use bitcoin::{script::read_scriptint, PublicKey, ScriptBuf, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use console::style;
use key_manager::{key_type::BitcoinKeyType, lamport::LamportType};
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
            claim::{ClaimGate, auto_claim_start, claim_state_handle},
            dispute::{self, input_handler::set_inputs},
            protocol_handler::{ClaimGateConfig, WithClaimGateConfig, timeout_input_tx},
            timeouts::{TxOwnershipTable, auto_dispatch_timeout, cancel_timeout, dispatch},
        },
        variables::{Globals, PartialUtxo, VariableTypes},
    },
    types::{IncomingBitVMXApiMessages, PROGRAM_TYPE_GC_DRP, ParticipantChannel, ProgramContext},
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

        let mut keys: Vec<(String, PublicKeyType)> = vec![
            (AGGREGATED_KEY.to_string(), aggregated_1.into()),
            (SPEEDUP_KEY.to_string(), speedup.into()),
        ];

        if self.role() == ParticipantRole::Prover {
            set_inputs(
                &self.ctx.id,
                &program_context,
                vec![("prover_input", 0u8).into()],
            )?;
        } else {
            set_inputs(
                &self.ctx.id,
                &program_context,
                vec![("verifier_preimage", 0u8).into()],
            )?;
        }

        let key_manager = &mut program_context.key_manager;

        // TODO: import them via the job dispatcher(?)
        if self.role() == ParticipantRole::Prover {
            let pub_key = key_manager.next_lamport(8, LamportType::SHA256)?;
            keys.push(("prover_input".to_string(), pub_key.into()));
        } else {
            let pub_key = key_manager.next_lamport(8, LamportType::SHA256)?;

            keys.push(("verifier_preimage".to_string(), pub_key.into()));
        }

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
            Self::lamport_check(
                prover_speedup_pub,
                SignMode::Single,
                &keys[0],
                &vec!["prover_input"],
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
            INPUT,
            EQUIVOCATION,
            &claim_prover,
            Self::lamport_check(
                verifier_speedup_pub,
                SignMode::Single,
                &keys[1],
                &vec!["verifier_preimage"],
                None,
            )?,
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
                    dispatch(program_context, self, tx, Some(speedup), None)?;
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
                        dispatch(program_context, self, tx, Some(speedup), None)?;
                    }
                    (CHALLENGE, ParticipantRole::Prover) => {
                        let (tx, speedup) =
                            self.get_tx_with_speedup_data(program_context, INPUT)?;
                        dispatch(program_context, self, tx, Some(speedup), None)?;
                    }
                    (INPUT, ParticipantRole::Verifier) => {
                        let (tx, speedup) =
                            self.get_tx_with_speedup_data(program_context, EQUIVOCATION)?;

                        let sigs =
                            self.decode_lamport_for_speedup(tx_id, vout, &name, transaction)?;
                        println!("{:?}", sigs);
                        // TODO: evaluate garbled circuit and get output

                        dispatch(program_context, self, tx, Some(speedup), None)?;
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
                        dispatch(program_context, self, tx, Some(speedup_data), height)?;
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
        let mut table = TxOwnershipTable { txs: vec![] };
        table.add(START_CH, Verifier);
        table.add(COMMITMENT, Prover);
        table.add(CHALLENGE, Verifier);
        table.add(INPUT, Prover);
        table.add(EQUIVOCATION, Verifier);
        table.add(VERIFIER_FINAL, Verifier);

        table
    }
}
