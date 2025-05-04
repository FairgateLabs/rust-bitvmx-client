use std::{collections::HashMap, rc::Rc};

use bitcoin::{
    key::UntweakedPublicKey, secp256k1, Amount, PublicKey, ScriptBuf, Transaction, TxOut, Txid,
    XOnlyPublicKey,
};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use key_manager::winternitz::WinternitzType;
use protocol_builder::{
    builder::Protocol,
    errors::ProtocolBuilderError,
    scripts,
    types::{
        input::{LeafSpec, SighashType},
        InputArgs, OutputType,
    },
};
use serde::{Deserialize, Serialize};
use storage_backend::storage::Storage;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    bitvmx::Context, errors::BitVMXError, keychain::KeyChain, program::witness,
    types::ProgramContext,
};

use super::{
    participant::{ParticipantKeys, ParticipantRole},
    program::ProtocolParameters,
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
        parameters: &ProtocolParameters,
    ) -> Result<(), BitVMXError> {
        let name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Program {}: Transaction {} has been seen on-chain {}",
            self.ctx.id,
            name,
            parameters.drp().role
        );

        if name == START_CH && parameters.drp().role == ParticipantRole::Prover {
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

        if name == INPUT_1 && parameters.drp().role == ParticipantRole::Verifier {
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
}

impl DisputeResolutionProtocol {
    pub fn new(program_id: Uuid, storage: Rc<Storage>) -> Self {
        let protocol_name = format!("drp_{}", program_id);
        Self {
            ctx: ProtocolContext::new(program_id, protocol_name, storage),
        }
    }

    pub fn generate_keys(
        role: &ParticipantRole,
        key_chain: &mut KeyChain,
    ) -> Result<ParticipantKeys, BitVMXError> {
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
        if role == &ParticipantRole::Prover {
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

    pub fn build(
        &self,
        prover_keys: &ParticipantKeys,
        _verifier_keys: &ParticipantKeys,
        computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        // TODO get this from config, all values expressed in satoshis
        let _p2pkh_dust_threshold: u64 = 546;
        let _p2sh_p2wpkh_dust_threshold: u64 = 540;
        let mut p2wpkh_dust_threshold: u64 = 99_999_000; // 294;
        let _taproot_dust_threshold: u64 = 330;
        let fee = 1000;

        let utxo = context.globals.get_var(&self.ctx.id, "utxo")?.utxo()?;

        let secp = secp256k1::Secp256k1::new();
        let internal_key = context
            .globals
            .get_var(&self.ctx.id, "aggregated")?
            .pubkey()?;
        let untweaked_key: UntweakedPublicKey = XOnlyPublicKey::from(internal_key);

        let spending_scripts = vec![scripts::timelock_renew(&internal_key)];
        let spend_info =
            scripts::build_taproot_spend_info(&secp, &untweaked_key, &spending_scripts)?;

        let script_pubkey = ScriptBuf::new_p2tr(&secp, untweaked_key, spend_info.merkle_root());

        //Description of the output that the START_CH consumes
        let prevout = TxOut {
            value: Amount::from_sat(utxo.2.unwrap()),
            script_pubkey,
        };

        // let output_type = OutputType::TaprootScript {
        //     value: Amount::from_sat(utxo.amount),
        //     internal_key: *internal_key,
        //     script_pubkey,
        //     spending_scripts,
        //     with_key_path: true,
        //     prevouts: vec![prevout],
        // };

        let output_type = OutputType::tr_script(
            utxo.2.unwrap(),
            &internal_key,
            &spending_scripts,
            true,
            vec![prevout],
        )?;

        // let output_type = OutputSpendingType::TaprootUntweakedKey { key: *internal_key, prevouts: vec![prevout] };

        //let mut builder = ProtocolBuilder::new(&self.protocol_name, self.storage.clone().unwrap())?;
        let mut protocol = Protocol::load(
            &self.context().protocol_name,
            self.context().storage.clone().unwrap(),
        )?
        .unwrap_or(Protocol::new(&self.context().protocol_name));

        protocol.add_external_connection(
            utxo.0,
            utxo.1,
            output_type,
            START_CH,
            &SighashType::taproot_all(),
        )?;

        //protocol.add_speedup_output(START_CH, p2wpkh_dust_threshold, verifier_keys.speedup())?;

        // reuse aggregated until we can have multiple aggregated keys
        let aggregated = computed_aggregated.get("aggregated_1").unwrap();

        let input_data_l1 = scripts::verify_winternitz_signature(
            aggregated,
            prover_keys.get_winternitz("program_input_leaf_1")?,
        )?;

        let input_data_l2 = scripts::verify_winternitz_signature(
            aggregated,
            prover_keys.get_winternitz("program_input_leaf_2")?,
        )?;

        // protocol.add_taproot_script_spend_connection(
        //     "prover_first_input",
        //     START_CH,
        //     //taproot_dust_threshold,
        //     p2wpkh_dust_threshold,
        //     //&key_chain.unspendable_key()?,
        //     &XOnlyPublicKey::from(aggregated.clone()), //TOOD: skip this one ?
        //     &[input_data_l1, input_data_l2],
        //     INPUT_1,
        //     &tr_sighash_type,
        // )?;

        let output_type = OutputType::tr_script(
            p2wpkh_dust_threshold,
            &internal_key,
            &[input_data_l1, input_data_l2],
            true,
            vec![],
        )?;
        protocol.add_connection(
            "prover_first_input",
            START_CH,
            INPUT_1,
            output_type,
            &SighashType::taproot_all(),
        )?;

        p2wpkh_dust_threshold -= fee;

        // protocol.add_speedup_output(INPUT_1, p2wpkh_dust_threshold, prover_keys.speedup())?;

        // Speedup output
        let output_type = OutputType::segwit_key(p2wpkh_dust_threshold, prover_keys.speedup())?;
        protocol.add_transaction_output(INPUT_1, output_type)?;

        //protocol.add_taproot_key_spend_output(START_CH, value, internal_key, prevouts)

        // builder.add_taproot_script_spend_connection(
        //     PROTOCOL,
        //     PREKICKOFF,
        //     taproot_dust_threshold,
        //     &XOnlyPublicKey::from(*internal_key),
        //     &[kickoff_spending],
        //     KICKOFF,
        //     &tr_sighash_type,
        // )?;

        // let kickoff_spending = scripts::kickoff(
        //     internal_key,
        //     &prover_keys.program_input_key,
        //     &prover_keys.program_ending_state,
        //     &prover_keys.program_ending_step_number,
        // )?;

        // builder.add_taproot_script_spend_connection(
        //     PROTOCOL,
        //     PREKICKOFF,
        //     taproot_dust_threshold,
        //     &XOnlyPublicKey::from(*internal_key),
        //     &[kickoff_spending],
        //     KICKOFF,
        //     &tr_sighash_type,
        // )?;

        protocol.build(true, &context.key_chain.key_manager)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;

        Ok(())
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
            .input_taproot_script_spend_signature(txname, 0, 1)?
            .unwrap();
        let spend = protocol.get_script_to_spend(txname, 0, 1)?;
        let mut spending_args = InputArgs::new_taproot_script_args(LeafSpec::Index(1));

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
}
