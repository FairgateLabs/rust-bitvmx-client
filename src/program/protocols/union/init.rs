use protocol_builder::builder::Protocol;
use protocol_builder::graph::graph::GraphOptions;
use protocol_builder::scripts::SignMode;
use protocol_builder::types::connection::{InputSpec, OutputSpec};
use protocol_builder::types::input::{SighashType, SpendMode};
use protocol_builder::types::{InputArgs, OutputType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

use crate::errors::BitVMXError;
use crate::program::{
    participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
    protocols::{
        protocol_handler::{ProtocolContext, ProtocolHandler},
        union::{
            common::{create_transaction_reference, indexed_name},
            scripts,
            types::*,
        },
    },
    variables::VariableTypes,
};
use crate::types::ProgramContext;
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::coordinator::BitcoinCoordinatorApi;
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::types::output::{SpeedupData, AUTO_AMOUNT, RECOVER_AMOUNT};
use uuid::Uuid;

const SLOT_ID_KEY: &str = "slot_id_key";
const SECRET_KEY: &str = "secret";
const REVEAL_TAKE_PRIVKEY: &str = "reveal_take_private_key";
const TAKE_KEY: &str = "take_key";
const DISPUTE_KEY: &str = "dispute_key";

#[derive(Clone, Serialize, Deserialize)]
pub struct InitProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for InitProtocol {
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
        Ok(vec![
            (
                TAKE_AGGREGATED_KEY.to_string(),
                self.take_aggregated_key(context)?,
            ),
            (
                DISPUTE_AGGREGATED_KEY.to_string(),
                self.dispute_aggregated_key(context)?,
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
            TAKE_KEY.to_string(),
            PublicKeyType::Public(self.my_take_key(program_context)?),
        ));
        keys.push((
            DISPUTE_KEY.to_string(),
            PublicKeyType::Public(self.my_dispute_key(program_context)?),
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
            REVEAL_TAKE_PRIVKEY.to_string(),
            PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(32)?),
        ));

        for slot in 0..packet_size as usize {
            keys.push((
                indexed_name(SLOT_ID_KEY, slot),
                PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(32)?),
            ));

            keys.push((
                indexed_name(SECRET_KEY, slot),
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
        let mut protocol = self.load_or_create_protocol();
        let init_data = self.init_data(context)?;
        let watchtower_index = init_data.member_index;
        let committee = self.committee(context)?;
        let watchtower_keys = keys[init_data.member_index].clone();

        info!(
            "Setting up init protocol for member {}",
            init_data.member_index,
        );

        self.create_initial_deposit(&mut protocol, &watchtower_keys, &init_data)?;

        // iterate over committee members and create start enablers
        for (member_index, _member) in committee.members.clone().iter().enumerate() {
            let member_keys = keys[member_index].clone();
            self.add_start_enabler_output(
                &mut protocol,
                &committee,
                &member_keys,
                member_index,
                watchtower_index,
            )?;
        }

        // TODO set utxo var here for dispute channels

        // Add change output to setup tx
        protocol.compute_minimum_output_values()?;
        self.add_funding_change(&mut protocol, &watchtower_keys, &init_data)?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        self.save_protocol(protocol.clone())?;

        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);

        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        if name == format!("{}{}", WATCHTOWER, SETUP_TX_SUFFIX) {
            Ok(self.setup_tx(context)?)
        } else if name == format!("{}{}", WATCHTOWER, START_ENABLER_TX_SUFFIX) {
            Ok(self.wt_start_enabler_tx(name, context)?)
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
        _program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        let tx_name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Init protocol received news of transaction: {}, txid: {} with {} confirmations",
            tx_name, tx_id, tx_status.confirmations
        );

        Ok(())
    }

    fn setup_complete(&self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        info!(id = self.ctx.my_idx, "Init {} setup complete", self.ctx.id);
        self.dispatch_setup_tx(program_context)?;

        Ok(())
    }
}

impl InitProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn init_data(&self, context: &ProgramContext) -> Result<InitData, BitVMXError> {
        let data = context
            .globals
            .get_var(&self.ctx.id, &InitData::name())?
            .unwrap()
            .string()?;

        let data: InitData = serde_json::from_str(&data)?;
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

    fn take_aggregated_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        Ok(self.committee(context)?.take_aggregated_key.clone())
    }

    fn dispute_aggregated_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        Ok(self.committee(context)?.dispute_aggregated_key.clone())
    }

    fn my_take_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        let my_index = self.ctx.my_idx;
        let committee = self.committee(context)?;
        Ok(committee.members[my_index].take_key.clone())
    }

    fn my_dispute_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        let my_index = self.ctx.my_idx;
        let committee = self.committee(context)?;
        Ok(committee.members[my_index].dispute_key.clone())
    }

    fn committee_id(&self, context: &ProgramContext) -> Result<Uuid, BitVMXError> {
        Ok(self.init_data(context)?.committee_id)
    }

    fn create_initial_deposit(
        &self,
        protocol: &mut Protocol,
        watchtower_keys: &ParticipantKeys,
        init_data: &InitData,
    ) -> Result<(), BitVMXError> {
        let watchtower_utxo = init_data.watchtower_utxo.clone();
        let watchtower_dispute_key = watchtower_keys.get_public(DISPUTE_KEY)?;
        let reveal_take_private_key = watchtower_keys.get_winternitz(REVEAL_TAKE_PRIVKEY)?.clone();

        // Connect the setup transaction to the watchtower funding transaction.
        let funding = format!("{}{}", WATCHTOWER, FUNDING_TX_SUFFIX);
        let setup = format!("{}{}", WATCHTOWER, SETUP_TX_SUFFIX);
        let start_enabler = format!("{}{}", WATCHTOWER, START_ENABLER_TX_SUFFIX);
        let self_disabler = format!("{}{}", WATCHTOWER, SELF_DISABLER_TX_SUFFIX);

        // Create the funding transaction reference
        create_transaction_reference(protocol, &funding, &mut [watchtower_utxo.clone()].to_vec())?;

        // The watchtower_utxo must be of type P2WPKH
        protocol.add_connection(
            "setup",
            &funding,
            (watchtower_utxo.1 as usize).into(),
            &setup,
            InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::None),
            None,
            Some(watchtower_utxo.0),
        )?;

        // Connect the initial deposit transaction to the setup transaction.
        protocol.add_connection(
            "initial_deposit",
            &setup,
            OutputSpec::Auto(OutputType::taproot(
                AUTO_AMOUNT,
                watchtower_dispute_key,
                &[scripts::reveal_take_private_key(
                    watchtower_dispute_key,
                    &reveal_take_private_key,
                )?],
            )?),
            &start_enabler,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::None),
            None,
            None,
        )?;

        // Connect the self-disabler (recover funds) transaction.
        protocol.add_connection(
            "self_disabler",
            &setup,
            OutputSpec::Index(0),
            &self_disabler,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::None),
            None,
            None,
        )?;

        protocol.add_transaction_output(
            &self_disabler,
            &OutputType::segwit_key(RECOVER_AMOUNT, watchtower_dispute_key)?,
        )?;

        Ok(())
    }

    fn add_start_enabler_output(
        &self,
        protocol: &mut Protocol,
        committee: &Committee,
        member_keys: &ParticipantKeys,
        member_index: usize,
        watchtower_index: usize,
    ) -> Result<(), BitVMXError> {
        let start_enabler = format!("{}{}", WATCHTOWER, START_ENABLER_TX_SUFFIX);
        let mut scripts = vec![];

        if committee.members[member_index].role == ParticipantRole::Verifier
            || watchtower_index == member_index
        {
            scripts = vec![protocol_builder::scripts::op_return_script(
                "skip".as_bytes().to_vec(),
            )?];
        } else {
            for slot in 0..committee.packet_size as usize {
                let slot_id_key = member_keys.get_winternitz(&indexed_name(SLOT_ID_KEY, slot))?;

                // TODO is this correct? should we use aggregated key?
                scripts.push(scripts::start_challenge(
                    &committee.dispute_aggregated_key,
                    SLOT_ID_KEY,
                    slot_id_key,
                )?);
            }
        }

        protocol.add_transaction_output(
            &start_enabler,
            &OutputType::taproot(
                AUTO_AMOUNT,
                &committee.members[watchtower_index].dispute_key,
                &scripts,
            )?,
        )?;

        Ok(())
    }

    fn add_funding_change(
        &self,
        protocol: &mut Protocol,
        watchtower_keys: &ParticipantKeys,
        init_data: &InitData,
    ) -> Result<(), BitVMXError> {
        // Add a change output to the setup transaction
        // This fee assumes 1 sat per byte plus a 10 extra percent as a safety margin.
        // It is computed using the size of the transaction, a 68 vbyte size for the input witness (P2WPKH)
        // and the 3 outputs (setup, change, and speedup output).
        let setup_fees = 246;
        let funding_amount = init_data.watchtower_utxo.2.unwrap();
        let watchtower_dispute_key = watchtower_keys.get_public(DISPUTE_KEY)?;
        let setup = format!("{}{}", WATCHTOWER, SETUP_TX_SUFFIX);

        let setup_amount = protocol.transaction_by_name(&setup)?.output[0]
            .value
            .to_sat();

        protocol
            .add_transaction_output(
                &setup,
                &OutputType::segwit_key(
                    funding_amount - setup_amount - setup_fees - SPEEDUP_VALUE,
                    watchtower_dispute_key,
                )?,
            )
            .map_err(|e| BitVMXError::ProtocolBuilderError(e))?;

        Ok(())
    }

    fn dispatch_setup_tx(&self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        let setup_tx_name = format!("{}{}", WATCHTOWER, SETUP_TX_SUFFIX);
        let init_data = self.init_data(program_context)?;

        if init_data.member_index != self.ctx.my_idx {
            info!(
                id = self.ctx.my_idx,
                "Not my init, skipping dispatch of {} transaction", setup_tx_name
            );
            return Ok(());
        }

        info!(
            id = self.ctx.my_idx,
            "Dispatching {} tx from protocol {}", setup_tx_name, self.ctx.id
        );

        // Get the signed transaction
        let (setup_tx, speedup) = self.setup_tx(program_context)?;
        let setup_txid = setup_tx.compute_txid();

        // Dispatch the transaction through the bitcoin coordinator
        program_context.bitcoin_coordinator.dispatch(
            setup_tx,
            speedup,
            format!("init_setup_{}:{}", self.ctx.id, setup_tx_name), // Context string
            None,                                                    // Dispatch immediately
        )?;

        info!(
            id = self.ctx.my_idx,
            "{} dispatched successfully with txid: {}", setup_tx_name, setup_txid
        );

        Ok(())
    }

    fn setup_tx(
        &self,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        let name = format!("{}{}", WATCHTOWER, SETUP_TX_SUFFIX);

        let mut protocol = self.load_protocol()?;

        let signature = protocol.sign_ecdsa_input(&name, 0, &context.key_chain.key_manager)?;

        let mut input_args = InputArgs::new_segwit_args();
        input_args.push_ecdsa_signature(signature)?;

        let tx = protocol.transaction_to_send(&name, &[input_args])?;

        Ok((tx, None))
    }

    fn wt_start_enabler_tx(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        info!(
            id = self.ctx.my_idx,
            "Loading Start Enabler transaction for Init"
        );

        let mut protocol: Protocol = self.load_protocol()?;

        let signatures = protocol.sign_taproot_input(
            &name,
            0,
            &SpendMode::KeyOnly {
                key_path_sign: SignMode::Single,
            },
            context.key_chain.key_manager.as_ref(),
            "",
        )?;

        let mut input_args = InputArgs::new_taproot_key_args();
        for signature in signatures {
            if signature.is_some() {
                info!(
                    "Adding taproot signature to input args for {}: {:?}",
                    name, signature
                );
                input_args.push_taproot_signature(signature.unwrap())?;
            }
        }

        let tx = protocol.transaction_to_send(&name, &[input_args])?;

        Ok((tx, None))
    }
}
