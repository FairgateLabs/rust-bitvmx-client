use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use emulator::loader::program_definition::ProgramDefinition;
use key_manager::winternitz::WinternitzType;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    errors::ProtocolBuilderError,
    scripts::{self, SignMode},
    types::{
        input::{LeafSpec, SighashType},
        output::SpendMode,
        InputArgs, OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    keychain::KeyChain,
    program::{participant::ParticipantRole, protocols::slot::external_fund_tx, witness},
    types::ProgramContext,
};

use super::{
    super::participant::ParticipantKeys,
    protocol_handler::{ProtocolContext, ProtocolHandler},
};

pub const START_CH: &str = "pre_kickoff";
pub const INPUT_1: &str = "INPUT_1";
const _KICKOFF: &str = "kickoff";
const _PROTOCOL: &str = "protocol";

#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeResolutionProtocol {
    ctx: ProtocolContext,
}

fn get_role(my_idx: usize) -> ParticipantRole {
    if my_idx == 0 {
        ParticipantRole::Prover
    } else {
        ParticipantRole::Verifier
    }
}

impl ProtocolHandler for DisputeResolutionProtocol {
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
                .get_var(&self.ctx.id, "aggregated")?
                .pubkey()?,
        )])
    }

    fn generate_keys(&self, key_chain: &mut KeyChain) -> Result<ParticipantKeys, BitVMXError> {
        //TODO: define which keys are generated for each role

        //let message_size = 2;
        //let one_time_keys_count = 10;
        //let protocol = self.program_context.key_chain.derive_keypair()?;
        let aggregated_1 = key_chain.derive_keypair()?;

        let speedup = key_chain.derive_keypair()?;
        let timelock = key_chain.derive_keypair()?;

        let mut keys = vec![
            ("aggregated_1".to_string(), aggregated_1.into()),
            ("speedup".to_string(), speedup.into()),
            ("timelock".to_string(), timelock.into()),
        ];

        let program_input_leaf_1 = key_chain.derive_winternitz_hash160(4)?;
        let program_input_leaf_2 = key_chain.derive_winternitz_hash160(4)?;
        if self.role() == ParticipantRole::Prover {
            keys.push((
                "program_input_leaf_1".to_string(),
                program_input_leaf_1.into(),
            ));
            keys.push((
                "program_input_leaf_2".to_string(),
                program_input_leaf_2.into(),
            ));
        }

        Ok(ParticipantKeys::new(keys, vec!["aggregated_1".to_string()]))
    }

    fn get_transaction_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        match name {
            START_CH => Ok(self.prekickoff_transaction()?),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        tx_status: TransactionStatus,
        _context: String,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Program {}: Transaction {} has been seen on-chain {}",
            self.ctx.id,
            name,
            self.role()
        );

        if name == START_CH && self.role() == ParticipantRole::Prover {
            //TODO: inform whoever is needed
            // now act here to test

            info!("Dispatching transaction the input 1 tx");
            let tx_to_dispatch = self.input_1_tx(0x1234_4444, &program_context.key_chain)?;

            let context = Context::ProgramId(self.ctx.id);
            program_context.bitcoin_coordinator.dispatch(
                tx_to_dispatch,
                context.to_string()?,
                None,
            )?;
        }

        if name == INPUT_1 && self.role() == ParticipantRole::Verifier {
            //let wpub = self .get_prover() .keys .as_ref() .unwrap() .get_winternitz("program_input") .unwrap();
            let witness = tx_status.tx.input[0].witness.clone();
            let data = witness::decode_witness(vec![4], WinternitzType::HASH160, witness)?;
            //info!("message bytes {:?}", data[0].message_bytes());
            //from vec<u8> be bytes to u32
            let message = u32::from_be_bytes(data[0].message_bytes().try_into().unwrap());
            warn!(
                "Program {}:{} Witness data decoded: {:0x}",
                self.ctx.id, name, message
            );
        }

        Ok(())
    }

    fn build(
        &self,
        keys: Vec<ParticipantKeys>,
        computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        // TODO get this from config, all values expressed in satoshis
        let fee = 1000;
        const TIMELOCK_BLOCKS: u16 = 10;

        let utxo = context.globals.get_var(&self.ctx.id, "utxo")?.utxo()?;

        let program_definition = context
            .globals
            .get_var(&self.ctx.id, "program_definition")?
            .string()?;
        let _program = ProgramDefinition::from_config(&program_definition)?;

        let external_aggregated = context
            .globals
            .get_var(&self.ctx.id, "aggregated")?
            .pubkey()?;

        let mut protocol = self.load_or_create_protocol();

        let mut amount = utxo.2.unwrap();
        let output_type = external_fund_tx(&external_aggregated, amount)?;

        protocol.add_external_connection(
            utxo.0,
            utxo.1,
            output_type,
            START_CH,
            &SighashType::taproot_all(),
        )?;

        let aggregated = computed_aggregated.get("aggregated_1").unwrap();

        amount -= fee;
        self.add_input_tx(
            aggregated,
            &mut protocol,
            TIMELOCK_BLOCKS,
            &keys,
            amount,
            fee,
        )?;

        //amount -= fee;

        protocol.build(&context.key_chain.key_manager)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;

        Ok(())
    }
}

impl DisputeResolutionProtocol {
    pub fn new(context: ProtocolContext) -> Self {
        Self { ctx: context }
    }

    pub fn role(&self) -> ParticipantRole {
        get_role(self.ctx.my_idx)
    }

    pub fn prekickoff_transaction(&self) -> Result<Transaction, ProtocolBuilderError> {
        let signature = self
            .load_protocol()?
            .input_taproot_key_spend_signature(START_CH, 0)?
            .unwrap();
        let mut taproot_arg = InputArgs::new_taproot_key_args();
        taproot_arg.push_taproot_signature(signature)?;

        self.load_protocol()?
            .transaction_to_send(START_CH, &[taproot_arg])
    }

    pub fn input_1_tx(
        &self,
        data: u32,
        key_chain: &KeyChain,
    ) -> Result<Transaction, ProtocolBuilderError> {
        let protocol = self.load_protocol()?;

        let txname = INPUT_1;

        let signature = protocol
            .input_taproot_script_spend_signature(txname, 0, 0)?
            .unwrap();
        let spend = protocol.get_script_to_spend(txname, 0, 0)?;
        let mut spending_args = InputArgs::new_taproot_script_args(LeafSpec::Index(0));

        //TODO: set value for variable from outside
        let message_to_sign = data.to_be_bytes();
        let winternitz_signature = key_chain.key_manager.sign_winternitz_message(
            &message_to_sign,
            WinternitzType::HASH160,
            spend.get_key("value").unwrap().derivation_index(),
        )?;

        //warn!("bytes: {:?}", message_to_sign);
        //warn!("Sending Winternitz signature: {:?}", winternitz_signature);

        spending_args.push_winternitz_signature(winternitz_signature);
        spending_args.push_taproot_signature(signature)?;

        protocol.transaction_to_send(txname, &[spending_args])
    }

    pub fn add_input_tx(
        &self,
        aggregated: &PublicKey,
        protocol: &mut Protocol,
        timelock_blocks: u16,
        keys: &Vec<ParticipantKeys>,
        amount: u64,
        fee: u64,
    ) -> Result<(), BitVMXError> {
        let input_data_l1 = scripts::verify_winternitz_signature(
            aggregated,
            keys[0].get_winternitz("program_input_leaf_1")?,
            SignMode::Aggregate,
        )?;

        let timeout = scripts::timelock(timelock_blocks, &aggregated, SignMode::Aggregate);

        let output_type = OutputType::taproot(
            amount,
            aggregated,
            &[input_data_l1, timeout],
            &SpendMode::All {
                key_path_sign: SignMode::Aggregate,
            },
            &vec![],
        )?;

        protocol.add_connection(
            "prover_first_input",
            START_CH,
            INPUT_1,
            &output_type,
            &SighashType::taproot_all(),
        )?;

        let pb = ProtocolBuilder {};
        //put the amount here as there is no output yet
        pb.add_speedup_output(protocol, INPUT_1, amount - fee, aggregated)?;

        Ok(())
    }
}
