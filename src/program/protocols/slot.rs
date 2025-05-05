use std::collections::HashMap;

use bitcoin::{
    key::UntweakedPublicKey, secp256k1, Amount, PublicKey, ScriptBuf, Transaction, TxOut, Txid,
    XOnlyPublicKey,
};
use bitcoin_coordinator::TransactionStatus;
use protocol_builder::{
    builder::ProtocolBuilder,
    errors::ProtocolBuilderError,
    scripts,
    types::{input::SighashType, InputArgs, OutputType},
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{errors::BitVMXError, keychain::KeyChain, types::ProgramContext};

use super::{
    super::participant::ParticipantKeys,
    protocol_handler::{ProtocolContext, ProtocolHandler},
};

#[derive(Clone, Serialize, Deserialize)]
pub struct SlotProtocol {
    ctx: ProtocolContext,
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
        _my_idx: usize,
        _key_chain: &mut KeyChain,
    ) -> Result<ParticipantKeys, BitVMXError> {
        Ok(ParticipantKeys::new(vec![], vec![]))
    }

    fn get_transaction_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        match name {
            SETUP_TX => Ok(self.setup_tx()?),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
        }
    }
    fn notify_news(
        &self,
        _tx_id: Txid,
        _tx_status: TransactionStatus,
        _context: String,
        _program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        Ok(())
    }

    fn build(
        &self,
        _keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let fee = 1000;
        let speedup_dust = 500;

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

        let amount = fund_utxo.2.unwrap();
        let output_type = external_fund_tx(&ops_agg_pubkey, amount)?;

        protocol.add_external_connection(
            fund_utxo.0,
            fund_utxo.1,
            output_type,
            SETUP_TX,
            &SighashType::taproot_all(),
        )?;

        // add one output to test
        let pb = ProtocolBuilder {};
        pb.add_speedup_output(
            &mut protocol,
            SETUP_TX,
            amount - fee - speedup_dust,
            &ops_agg_pubkey,
        )?;

        protocol.build(true, &context.key_chain.key_manager)?;
        info!("{}", protocol.visualize()?);
        self.save_protocol(protocol)?;
        Ok(())
    }
}

pub const SETUP_TX: &str = "setup_tx";

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

fn external_fund_tx(aggregated: &PublicKey, amount: u64) -> Result<OutputType, BitVMXError> {
    let secp = secp256k1::Secp256k1::new();
    let untweaked_key: UntweakedPublicKey = XOnlyPublicKey::from(*aggregated);

    let spending_scripts = vec![scripts::timelock_renew(&aggregated)];
    let spend_info = scripts::build_taproot_spend_info(&secp, &untweaked_key, &spending_scripts)?;

    let script_pubkey = ScriptBuf::new_p2tr(&secp, untweaked_key, spend_info.merkle_root());

    //Description of the output that the SETUP_TX consumes
    let prevout = TxOut {
        value: Amount::from_sat(amount),
        script_pubkey,
    };

    Ok(OutputType::tr_script(
        amount,
        aggregated,
        &spending_scripts,
        true,
        vec![prevout],
    )?)
}
