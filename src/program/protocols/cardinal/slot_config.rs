use bitcoin::{PublicKey, Txid};
use bitvmx_broker::channel::channel::DualChannel;
use protocol_builder::{
    scripts::{self, SignMode},
    types::{OutputType, Utxo},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        protocols::{
            cardinal::{
                slot::{certificate_hash_prefix, dust_claim_stop, group_id_prefix},
                FUND_UTXO, OPERATORS, OPERATORS_AGGREGATED_PUB, PAIR_0_1_AGGREGATED,
            },
            dispute::{
                program_input_prev_prefix, program_input_prev_protocol, protocol_cost,
                TIMELOCK_BLOCKS, TIMELOCK_BLOCKS_KEY,
            },
            protocol_handler::external_fund_tx,
        },
        variables::{Globals, PartialUtxo, VariableTypes},
    },
    types::{IncomingBitVMXApiMessages, BITVMX_ID, PROGRAM_TYPE_SLOT},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotProtocolConfiguration {
    pub id: Uuid,
    pub gid_max: u8,
    pub operators: u8,
    pub operators_aggregated_pub: PublicKey,
    pub operators_pairs: Vec<PublicKey>,
    pub fund_utxo: PartialUtxo,
    pub timelock_blocks: u16,
}

impl SlotProtocolConfiguration {
    pub fn new(
        program_id: Uuid,
        operators: u8,
        operators_aggregated_pub: PublicKey,
        operators_pairs: Vec<PublicKey>,
        fund_utxo: PartialUtxo,
        timelock_blocks: u16,
    ) -> Self {
        Self {
            id: program_id,
            gid_max: 2_u32.pow(operators as u32) as u8,
            operators,
            operators_aggregated_pub,
            operators_pairs,
            fund_utxo,
            timelock_blocks,
        }
    }

    pub fn new_from_globals(id: Uuid, globals: &Globals) -> Result<Self, BitVMXError> {
        let operators = globals.get_var(&id, OPERATORS)?.unwrap().number()? as u8;

        let ops_agg_pubkey = globals
            .get_var(&id, OPERATORS_AGGREGATED_PUB)?
            .unwrap()
            .pubkey()?;

        let pair_0_1_aggregated = globals
            .get_var(&id, PAIR_0_1_AGGREGATED)?
            .unwrap()
            .pubkey()?;

        let fund_utxo = globals.get_var(&id, FUND_UTXO)?.unwrap().utxo()?;

        let timelock_blocks = globals
            .get_var(&id, TIMELOCK_BLOCKS_KEY)?
            .unwrap()
            .number()? as u16;

        Ok(Self::new(
            id,
            operators,
            ops_agg_pubkey,
            vec![pair_0_1_aggregated],
            fund_utxo,
            timelock_blocks,
        ))
    }

    pub fn get_setup_messages(
        &self,
        addresses: Vec<crate::program::participant::P2PAddress>,
        leader: u16,
    ) -> Result<Vec<String>, BitVMXError> {
        Ok(vec![
            VariableTypes::Number(self.operators as u32).set_msg(self.id, OPERATORS)?,
            VariableTypes::PubKey(self.operators_aggregated_pub.clone())
                .set_msg(self.id, OPERATORS_AGGREGATED_PUB)?,
            VariableTypes::PubKey(self.operators_pairs[0].clone())
                .set_msg(self.id, PAIR_0_1_AGGREGATED)?,
            VariableTypes::Utxo(self.fund_utxo.clone()).set_msg(self.id, FUND_UTXO)?,
            VariableTypes::Number(self.timelock_blocks as u32)
                .set_msg(self.id, TIMELOCK_BLOCKS_KEY)?,
            IncomingBitVMXApiMessages::Setup(
                self.id,
                PROGRAM_TYPE_SLOT.to_string(),
                addresses,
                leader,
            )
            .to_string()?,
        ])
    }

    pub fn setup(
        &self,
        channel: &DualChannel,
        addresses: Vec<crate::program::participant::P2PAddress>,
        leader: u16,
    ) -> Result<(), BitVMXError> {
        for msg in self.get_setup_messages(addresses, leader)? {
            channel.send(BITVMX_ID, msg)?;
        }
        Ok(())
    }

    pub fn dispute_connection(
        &self,
        txid: Txid,
        _prover: usize,
        _verifier: usize,
    ) -> Result<(Utxo, OutputType, Utxo, OutputType, &PublicKey), BitVMXError> {
        //TODO: Compute proper vouts from prover and verifier
        let pair_aggregated_pub_key = &self.operators_pairs[0];
        let initial_utxo = Utxo::new(txid, 4, protocol_cost(), pair_aggregated_pub_key);
        let prover_win_utxo_value = dust_claim_stop() as u64;
        let prover_win_utxo = Utxo::new(txid, 2, prover_win_utxo_value, pair_aggregated_pub_key);

        let initial_spending_condition = vec![
            scripts::timelock(
                TIMELOCK_BLOCKS,
                &self.operators_aggregated_pub,
                SignMode::Aggregate,
            ),
            scripts::check_aggregated_signature(&pair_aggregated_pub_key, SignMode::Aggregate),
        ];
        let initial_output_type = external_fund_tx(
            &self.operators_aggregated_pub,
            initial_spending_condition,
            protocol_cost(),
        )?;

        let prover_win_spending_condition = vec![
            scripts::check_aggregated_signature(
                &self.operators_aggregated_pub,
                SignMode::Aggregate,
            ),
            scripts::check_aggregated_signature(&pair_aggregated_pub_key, SignMode::Aggregate),
        ];
        let prover_win_output_type = external_fund_tx(
            &self.operators_aggregated_pub,
            prover_win_spending_condition,
            prover_win_utxo_value,
        )?;
        Ok((
            initial_utxo,
            initial_output_type,
            prover_win_utxo,
            prover_win_output_type,
            pair_aggregated_pub_key,
        ))
    }

    pub fn program_input_connection(
        &self,
        dispute_id: &Uuid,
        prover_id: usize,
    ) -> Result<Vec<String>, BitVMXError> {
        let input_idx_cert_hash = 1;
        let input_idx_group_id = 2;
        let msgs = vec![
            VariableTypes::Uuid(self.id).set_msg(
                *dispute_id,
                &program_input_prev_protocol(input_idx_cert_hash),
            )?,
            VariableTypes::String(certificate_hash_prefix(prover_id))
                .set_msg(*dispute_id, &program_input_prev_prefix(input_idx_cert_hash))?,
            VariableTypes::Uuid(self.id).set_msg(
                *dispute_id,
                &program_input_prev_protocol(input_idx_group_id),
            )?,
            VariableTypes::String(group_id_prefix(prover_id))
                .set_msg(*dispute_id, &program_input_prev_prefix(input_idx_group_id))?,
        ];
        Ok(msgs)
    }
}
