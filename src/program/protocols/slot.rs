use std::collections::HashMap;

use bitcoin::{hashes::Hash, PublicKey, Sequence, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use bitcoin_script_stack::stack::StackTracker;
use protocol_builder::{
    builder::ProtocolBuilder,
    errors::ProtocolBuilderError,
    scripts::{self, timelock, ProtocolScript, SignMode},
    types::{
        input::{InputSpec, LeafSpec, SighashType},
        output::SpendMode,
        InputArgs, OutputType,
    },
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    bitvmx::Context,
    errors::BitVMXError,
    program::protocols::{
        claim::ClaimGate, dispute::TIMELOCK_BLOCKS, protocol_handler::external_fund_tx,
    },
    types::ProgramContext,
};

use super::{
    super::participant::ParticipantKeys,
    protocol_handler::{ProtocolContext, ProtocolHandler},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct SlotProtocol {
    ctx: ProtocolContext,
}

pub const SETUP_TX: &str = "SETUP_TX";
pub const CERT_HASH_TX: &str = "CERT_HASH_TX_";
pub const GID_TX: &str = "GID_TX_";

pub fn cert_hash_tx_op(n: u32) -> String {
    format!("{}{}", CERT_HASH_TX, n)
}
pub fn certificate_hash(n: usize) -> String {
    format!("certificate_hash_{}", n)
}

pub fn group_id(n: usize) -> String {
    format!("group_id_{}", n)
}

pub fn group_id_tx(op: usize, gid: u8) -> String {
    format!("{}{}_{}", GID_TX, op, gid)
}

pub fn group_id_to(op: usize) -> String {
    format!("{}{}_TO", GID_TX, op)
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
                .get_var(&self.ctx.id, "operators_aggregated_pub")?
                .pubkey()?,
        )])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let key_chain = &mut program_context.key_chain;
        let mut keys = vec![];

        let cert_hash = key_chain.derive_winternitz_hash160(20)?;
        keys.push((certificate_hash(self.ctx.my_idx), cert_hash.into()));

        let gid = key_chain.derive_winternitz_hash160(1)?;
        keys.push((group_id(self.ctx.my_idx), gid.into()));

        Ok(ParticipantKeys::new(keys, vec![]))
    }

    fn get_transaction_name(
        &self,
        name: &str,
        program_context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        //TODO: this is hacky. parametrize get_transaction_name
        if name.starts_with("unsigned_") {
            let name = name.strip_prefix("unsigned_").unwrap();
            return Ok(self.load_protocol()?.transaction_by_name(name)?.clone());
        }

        if name.starts_with(CERT_HASH_TX) {
            return Ok(self.get_signed_tx(program_context, name, 0, 0, false)?);
        }

        match name {
            SETUP_TX => Ok(self.setup_tx()?),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        tx_status: TransactionStatus,
        _context: String,
        program_context: &ProgramContext,
        participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        let name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Program {}: Transaction {} has been seen on-chain {}",
            self.ctx.id, name, self.ctx.my_idx
        );

        if name.starts_with(CERT_HASH_TX) {
            let operator = name
                .strip_prefix(CERT_HASH_TX)
                .unwrap_or("0")
                .parse::<u32>()
                .unwrap();

            info!("Operator {} has sent a certificate hash", operator);
            self.decode_witness_for_tx(
                &name,
                0,
                program_context,
                &participant_keys[operator as usize],
                &tx_status.tx,
                Some(0),
            )?;

            // after sending the certificate hash, the operator should send the group id
            if self.ctx.my_idx == operator as usize {
                let gid = program_context
                    .globals
                    .get_var(&self.ctx.id, &group_id(operator as usize))?
                    .input()?[0];

                let gid_selection_tx = self.get_signed_tx(
                    program_context,
                    &group_id_tx(operator as usize, gid),
                    0,
                    gid as u32,
                    false,
                )?;
                info!(
                    "Operator {} is going to send the group id {}",
                    operator, gid
                );
                program_context.bitcoin_coordinator.dispatch(
                    gid_selection_tx,
                    Context::ProgramId(self.ctx.id).to_string()?,
                    None,
                )?;
            }
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
                &participant_keys[op_and_id[0] as usize],
                &tx_status.tx,
                Some(op_and_id[1]),
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
        let fee = context.globals.get_var(&self.ctx.id, "FEE")?.number()? as u64;
        let protocol_cost = 200_000;
        let speedup_dust = 500;
        let gid_max = 8;

        let ops_agg_pubkey = context
            .globals
            .get_var(&self.ctx.id, "operators_aggregated_pub")?
            .pubkey()?;

        let _unspendable = context
            .globals
            .get_var(&self.ctx.id, "unspendable")?
            .pubkey()?;

        let fund_utxo = context.globals.get_var(&self.ctx.id, "fund_utxo")?.utxo()?;

        //create the protocol
        let mut protocol = self.load_or_create_protocol();

        let mut amount = fund_utxo.2.unwrap();
        let output_type = external_fund_tx(&ops_agg_pubkey, amount)?;

        protocol.add_external_connection(
            fund_utxo.0,
            fund_utxo.1,
            output_type,
            SETUP_TX,
            &SighashType::taproot_all(),
        )?;
        amount -= fee;

        let pb = ProtocolBuilder {};

        let amount_for_publish_gid = fee + speedup_dust;
        let claim_gate_cost = ClaimGate::cost(fee, speedup_dust, keys.len() as u8 - 1, 1);

        //ClaimGate::new(&mut protocol, from, claim_name, aggregated, amount_fee, amount_dust, stop_count, timelock_blocks, actions)
        let amount_for_sequence =
            fee + speedup_dust + amount_for_publish_gid + claim_gate_cost + 3 * protocol_cost;

        for (i, key) in keys.iter().enumerate() {
            //Verify the winternitz signature
            let key_name = certificate_hash(i);
            let winternitz_check = scripts::verify_winternitz_signatures(
                &ops_agg_pubkey,
                &vec![(&key_name, key.get_winternitz(&key_name)?)],
                SignMode::Aggregate,
            )?;

            let output_type = OutputType::taproot(
                amount_for_sequence,
                &ops_agg_pubkey,
                &[winternitz_check.clone()],
                &SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
                &vec![],
            )?;

            let certhashtx = cert_hash_tx_op(i as u32);

            protocol.add_connection(
                &format!("{}__{}", SETUP_TX, certhashtx),
                SETUP_TX,
                &certhashtx,
                &output_type,
                &SighashType::taproot_all(),
            )?;

            //create the group id output
            let key_name = group_id(i);
            let mut leaves: Vec<ProtocolScript> = (1..=gid_max)
                .map(|gid| winternitz_equality(key, &ops_agg_pubkey, &key_name, gid).unwrap())
                .collect();
            let timelock_script = timelock(TIMELOCK_BLOCKS, &ops_agg_pubkey, SignMode::Aggregate);
            leaves.insert(0, timelock_script);
            //put timelock as zero so the index matches the gid

            let output_type = OutputType::taproot(
                amount_for_publish_gid,
                &ops_agg_pubkey,
                &leaves,
                //TODO: this should be moved to the input part
                /*&SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },*/
                &SpendMode::Script {
                    leaf: LeafSpec::Index(4),
                },
                &vec![],
            )?;

            protocol.add_transaction_output(&certhashtx, &output_type)?;

            // create txs that consumes the gid
            for gid in 1..=gid_max {
                let gidtx = group_id_tx(i, gid);
                protocol.add_transaction(&gidtx)?;

                protocol.add_transaction_input(
                    Hash::all_zeros(),
                    0,
                    &gidtx,
                    Sequence::ENABLE_RBF_NO_LOCKTIME,
                    &SighashType::taproot_all(),
                )?;

                protocol.connect(
                    &format!("{}__{}", certhashtx, gidtx),
                    &certhashtx,
                    0,
                    &gidtx,
                    InputSpec::Index(0),
                )?;

                // Add one extra non-spendable output to each challenge response transaction to ensure different txids
                let differenciator = scripts::op_return_script(vec![gid as u8])?
                    .get_script()
                    .clone();
                protocol.add_transaction_output(
                    &gidtx,
                    &OutputType::segwit_unspendable(differenciator)?,
                )?;

                pb.add_speedup_output(&mut protocol, &gidtx, speedup_dust, &ops_agg_pubkey)?;
            }

            // create the timeout gid tx
            let gidtotx = group_id_to(i);
            protocol.add_transaction(&gidtotx)?;

            protocol.add_transaction_input(
                Hash::all_zeros(),
                0,
                &gidtotx,
                Sequence::from_height(TIMELOCK_BLOCKS),
                &SighashType::taproot_all(),
            )?;

            protocol.connect(
                &format!("{}__{}", certhashtx, gidtotx),
                &certhashtx,
                0,
                &gidtotx,
                InputSpec::Index(0),
            )?;

            //add the claimgate
            let _claim_gate = ClaimGate::new(
                &mut protocol,
                &certhashtx,
                &format!("OP_WINS_{}", i),
                &ops_agg_pubkey,
                fee,
                speedup_dust,
                keys.len() as u8 - 1,
                TIMELOCK_BLOCKS,
                vec![],
            )?;

            let start_challenge = OutputType::taproot(
                protocol_cost,
                &ops_agg_pubkey,
                &[winternitz_check],
                &SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
                &vec![],
            )?;

            for n in 0..keys.len() {
                if n != i {
                    protocol.add_transaction_output(&certhashtx, &start_challenge)?;
                }
            }

            pb.add_speedup_output(&mut protocol, &gidtotx, speedup_dust, &ops_agg_pubkey)?;

            pb.add_speedup_output(&mut protocol, &certhashtx, speedup_dust, &ops_agg_pubkey)?;
            amount -= amount_for_sequence;
        }

        // add one output to test
        pb.add_speedup_output(&mut protocol, SETUP_TX, amount, &ops_agg_pubkey)?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;
        Ok(())
    }
}

impl SlotProtocol {
    pub fn new(context: ProtocolContext) -> Self {
        Self { ctx: context }
    }

    pub fn setup_tx(&self) -> Result<Transaction, ProtocolBuilderError> {
        let signature = self
            .load_protocol()?
            .input_taproot_key_spend_signature(SETUP_TX, 0)?
            .unwrap();
        let mut taproot_arg = InputArgs::new_taproot_key_args();
        taproot_arg.push_taproot_signature(signature)?;

        self.load_protocol()?
            .transaction_to_send(SETUP_TX, &[taproot_arg])
    }
}

pub fn winternitz_equality(
    keys: &ParticipantKeys,
    aggregated: &PublicKey,
    key_name: &str,
    equal: u8,
) -> Result<ProtocolScript, BitVMXError> {
    let mut stack = StackTracker::new();
    stack.define(1, "selected-gid-high");
    stack.define(1, "selected-gid-low");
    stack.number(((equal & 0xF0) >> 4) as u32);
    stack.op_equalverify();
    stack.number((equal & 0xF) as u32);
    stack.op_equalverify();

    Ok(scripts::verify_winternitz_signatures_aux(
        &aggregated,
        &vec![(&key_name, keys.get_winternitz(&key_name)?)],
        SignMode::Aggregate,
        true,
        Some(vec![stack.get_script()]),
        //None,
    )?)
}
