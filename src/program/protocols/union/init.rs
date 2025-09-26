use protocol_builder::builder::Protocol;
use protocol_builder::graph::graph::GraphOptions;
use protocol_builder::scripts::SignMode;
use protocol_builder::types::connection::{InputSpec, OutputSpec};
use protocol_builder::types::input::{SighashType, SpendMode};
use protocol_builder::types::OutputType;
use serde::{Deserialize, Serialize};
use tracing::info;
use std::collections::HashMap;

use crate::errors::BitVMXError;
use crate::program::participant::{ParticipantKeys, ParticipantRole, PublicKeyType};
use crate::program::protocols::protocol_handler::{ProtocolContext, ProtocolHandler};
use crate::program::protocols::union::common::{create_transaction_reference, indexed_name};
use crate::program::protocols::union::scripts;
use crate::program::protocols::union::types::{
    Committee, InitData, MemberData, DISPUTE_AGGREGATED_KEY, FUNDING_TX_SUFFIX, INITIAL_DEPOSIT_TX_SUFFIX, SELF_DISABLER_TX_SUFFIX, SETUP_TX_SUFFIX, SPEEDUP_KEY, SPEEDUP_VALUE, START_ENABLER_TX_SUFFIX, TAKE_AGGREGATED_KEY, WATCHTOWER
};
use crate::program::variables::VariableTypes;
use crate::types::ProgramContext;
use bitcoin::{PublicKey, Transaction, Txid};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::types::output::{SpeedupData, AUTO_AMOUNT, RECOVER_AMOUNT};
use uuid::Uuid;

pub const PEGOUT_ID: &str = "pegout_id";
const PEGOUT_ID_KEY: &str = "pegout_id_key";
const SLOT_ID_KEY: &str = "slot_id_key";
const SECRET_KEY: &str = "secret";
const CHALLENGE_KEY: &str = "challenge_pubkey";
const REVEAL_INPUT_KEY: &str = "reveal_pubkey";
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

        // keys.push((
        //     CHALLENGE_KEY.to_string(),
        //     PublicKeyType::Public(program_context.key_chain.derive_keypair()?),
        // ));

        // let speedup_key = program_context.key_chain.derive_keypair()?;

        // keys.push((
        //     SPEEDUP_KEY.to_string(),
        //     PublicKeyType::Public(speedup_key.clone()),
        // ));

        // program_context.globals.set_var(
        //     &self.ctx.id,
        //     SPEEDUP_KEY,
        //     VariableTypes::PubKey(speedup_key),
        // )?;

        // keys.push((
        //     REVEAL_INPUT_KEY.to_string(),
        //     PublicKeyType::Public(program_context.key_chain.derive_keypair()?),
        // ));

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
        let committee = self.committee(context)?;
        let watchtower_keys = keys[init_data.member_index].clone();
        
        info!(
            "Setting up init protocol for member {}", init_data.member_index,
        );

        self.create_initial_deposit(&mut protocol, &watchtower_keys, &init_data)?;

        // iterate over committee members and create start enablers
        for (index, member) in committee.members.clone().iter().enumerate() {
            self.create_watchtower_start_enabler(
                &mut protocol,
                &committee.clone(),
                &watchtower_keys,
                &member,
                index
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
        transaction_name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        todo!()
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
        participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        // todo!()
        Ok(())
    }

    fn setup_complete(&self, context: &ProgramContext) -> Result<(), BitVMXError> {
        // todo!()
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
        protocol.add_external_transaction(&funding)?;

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

    fn create_watchtower_start_enabler(
        &self,
        protocol: &mut Protocol,
        committee: &Committee,
        watchtower_keys: &ParticipantKeys,
        member: &MemberData,
        index: usize,
    ) -> Result<(), BitVMXError> {
        if member.role == ParticipantRole::Verifier {
            return Ok(());
        }

        let watchtower_dispute_key = watchtower_keys.get_public(DISPUTE_KEY)?;
        let initial_deposit = format!("{}{}", WATCHTOWER, INITIAL_DEPOSIT_TX_SUFFIX);
        let start_enabler = format!("{}{}", WATCHTOWER, START_ENABLER_TX_SUFFIX);

        let mut scripts = vec![];

        if self.ctx.my_idx == index {
            scripts = vec![protocol_builder::scripts::op_return_script("skip".as_bytes().to_vec())?];
        } else {
            for slot in 0..committee.packet_size as usize {
                let slot_id_key = watchtower_keys.get_winternitz(&indexed_name(SLOT_ID_KEY, slot))?;

                // TODO is this correct? should we use aggregated key?
                scripts.push(scripts::start_challenge
                    (&committee.dispute_aggregated_key,
                        SLOT_ID_KEY,
                        slot_id_key
                    )?);
            }
        }

        protocol.add_transaction_output(
            &start_enabler,
            &OutputType::taproot(AUTO_AMOUNT, &member.dispute_key.clone(), &scripts)?,
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

}
