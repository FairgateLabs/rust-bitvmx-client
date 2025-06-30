use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::events::events::Event,
        },
    },
    types::ProgramContext,
};
use bitcoin::{Amount, PublicKey, ScriptBuf, Transaction, Txid, WScriptHash};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    scripts::{self, SignMode},
    types::{
        connection::InputSpec,
        input::{SighashType, SpendMode},
        OutputType,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

pub const OPERATOR_FUNDING_TX: &str = "OPERATOR_FUNDING_TX";
pub const WATCHTOWER_FUNDING_TX: &str = "WATCHTOWER_FUNDING_TX";
pub const OPERATOR_DISPUTE_OPENER_TX: &str = "OPERATOR_DISPUTE_OPENER_TX";
pub const WATCHTOWER_START_ENABLER_TX: &str = "WATCHTOWER_START_ENABLER_TX";

pub const DISPUTE_OPENER_VALUE: u64 = 1000;
pub const START_ENABLER_VALUE: u64 = 1000;

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
        _context: &ProgramContext,
    ) -> Result<Vec<(String, PublicKey)>, BitVMXError> {
        Ok(vec![])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let members_selected = program_context
            .globals
            .get_var(&self.ctx.id, "members_selected")?
            .unwrap()
            .string()?;

        let members_selected: Event = serde_json::from_str(&members_selected)?;
        let (my_role, my_take_pubkey, my_dispute_pubkey, take_pubkeys, dispute_pubkeys) =
            match members_selected {
                Event::MembersSelected {
                    my_role,
                    my_take_pubkey,
                    my_dispute_pubkey,
                    take_pubkeys,
                    dispute_pubkeys,
                    ..
                } => (
                    my_role,
                    my_take_pubkey,
                    my_dispute_pubkey,
                    take_pubkeys,
                    dispute_pubkeys,
                ),
                _ => return Err(BitVMXError::InvalidMessageFormat),
            };

        let take_aggregated_key = program_context
            .key_chain
            .new_musig2_session(take_pubkeys.clone(), my_take_pubkey.clone())?;

        let dispute_aggregated_key = program_context
            .key_chain
            .new_musig2_session(dispute_pubkeys.clone(), my_dispute_pubkey.clone())?;

        let mut keys = vec![];
        if my_role == ParticipantRole::Prover {
            keys.push((
                "ot_pegout_id".to_string(),
                PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(20)?),
            ));
            keys.push((
                "ot_bit0".to_string(),
                PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(1)?),
            ));
            keys.push((
                "ot_bit1".to_string(),
                PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(1)?),
            ));
        }

        keys.push((
            "take_aggregated_key".to_string(),
            PublicKeyType::Public(take_aggregated_key.clone()),
        ));
        keys.push((
            "dispute_aggregated_key".to_string(),
            PublicKeyType::Public(dispute_aggregated_key.clone()),
        ));

        Ok(ParticipantKeys::new(
            keys,
            vec![
                "take_aggregated_key".to_string(),
                "dispute_aggregated_key".to_string(),
            ],
        ))
    }

    fn build(
        &self,
        keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let members_selected = context
            .globals
            .get_var(&self.ctx.id, "members_selected")?
            .unwrap()
            .string()?;

        let members_selected: Event = serde_json::from_str(&members_selected)?;
        let (my_role, operators_count) = match members_selected {
            Event::MembersSelected {
                my_role,
                operator_count,
                ..
            } => (my_role, operator_count),
            _ => return Err(BitVMXError::InvalidMessageFormat),
        };

        let mut protocol = self.load_or_create_protocol();

        if my_role == ParticipantRole::Prover {
            let op_funding_utxo = context
                .globals
                .get_var(&self.ctx.id, "op_funding_utxo")?
                .unwrap()
                .utxo()?;

            // Declare the external op_funding transaction
            protocol.add_external_transaction(OPERATOR_FUNDING_TX)?;
            protocol.add_transaction_output(OPERATOR_FUNDING_TX, &op_funding_utxo.3.unwrap())?;

            // Connect the operator dispute opener transaction with the op_funding transaction
            protocol.add_connection(
                "initial_op_deposit",
                OPERATOR_FUNDING_TX,
                (op_funding_utxo.1 as usize).into(),
                OPERATOR_DISPUTE_OPENER_TX,
                InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
                None,
                Some(op_funding_utxo.0),
            )?;
        }

        let wt_funding_utxo = context
            .globals
            .get_var(&self.ctx.id, "wt_funding_utxo")?
            .unwrap()
            .utxo()?;

        // Declare the external op_funding transaction
        protocol.add_external_transaction(WATCHTOWER_FUNDING_TX)?;
        protocol.add_transaction_output(WATCHTOWER_FUNDING_TX, &wt_funding_utxo.3.unwrap())?;

        protocol.add_connection(
            "initial_wt_deposit",
            WATCHTOWER_FUNDING_TX,
            (wt_funding_utxo.1 as usize).into(),
            WATCHTOWER_START_ENABLER_TX,
            InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
            None,
            Some(wt_funding_utxo.0),
        )?;

        let mut operators_found = 0;
        for participant in keys.iter() {
            match participant.get_winternitz("ot_pegout_id") {
                Ok(ot_pegout_id) => {
                    let ot_bit0 = participant.get_winternitz("ot_bit0")?;
                    let ot_bit1 = participant.get_winternitz("ot_bit1")?;

                    // let script =
                    //     scripts::reveal_secret(slot_preimage_bytes, &public_key, SignMode::Single);
                    // let script_pubkey =
                    //     ScriptBuf::new_p2wsh(&WScriptHash::from(script.get_script().clone()));

                    // protocol.add_transaction_output(
                    //     WATCHTOWER_START_ENABLER_TX,
                    //     &OutputType::SegwitScript {
                    //         value: Amount::from_sat(START_ENABLER_VALUE),
                    //         script_pubkey,
                    //         script,
                    //     },
                    // )?;

                    operators_found += 1;
                }
                Err(_) => {
                    continue;
                }
            };
        }

        assert!(
            operators_found == operators_count,
            "Expected {} operators, found {}",
            operators_count,
            operators_found
        );

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;

        Ok(())
    }

    fn get_transaction_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        Err(BitVMXError::InvalidTransactionName(name.to_string()))
    }

    fn notify_news(
        &self,
        _tx_id: Txid,
        _vout: Option<u32>,
        _tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        // TODO
        Ok(())
    }
}

impl InitProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }
}
