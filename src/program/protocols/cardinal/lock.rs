use std::collections::HashMap;

use bitcoin::{PublicKey, Transaction, Txid, XOnlyPublicKey};
use bitcoin_coordinator::TransactionStatus;
use bitvmx_broker::channel::channel::DualChannel;
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    graph::graph::GraphOptions,
    scripts::{self, reveal_secret, timelock, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::SpeedupData,
        InputArgs, OutputType, Utxo,
    },
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantKeys,
        protocols::{
            cardinal::EOL_TIMELOCK_DURATION,
            protocol_handler::{ProtocolContext, ProtocolHandler},
        },
        variables::{Globals, PartialUtxo, VariableTypes},
    },
    types::{IncomingBitVMXApiMessages, ProgramContext, BITVMX_ID, PROGRAM_TYPE_LOCK},
};

pub const LOCK_REQ_TX: &str = "lock_req_tx";
pub const LOCK_TX: &str = "lock_tx";
pub const HAPPY_PATH_TX: &str = "happy_path_tx";

#[derive(Clone, Serialize, Deserialize)]
pub struct LockProtocol {
    ctx: ProtocolContext,
}

pub struct LockProtocolConfiguration {
    pub operators_aggregated_pub: PublicKey,
    pub operators_aggregated_pub_happy_path: PublicKey,
    pub unspendable: PublicKey,
    pub user_pubkey: PublicKey,
    pub secret: Vec<u8>,
    pub ordinal_utxo: PartialUtxo,
    pub protocol_utxo: PartialUtxo,
    pub timelock_blocks: u16,       //lock request timelock in blocks
    pub eol_timelock_duration: u16, //end of life timelock duration in blocks
}

pub const MIN_RELAY_FEE: u64 = 2;
pub const LOCK_PROTOCOL_DUST_COST: u64 = 3500 * MIN_RELAY_FEE;
pub const DUST: u64 = 500 * MIN_RELAY_FEE;

impl LockProtocolConfiguration {
    pub fn new(
        operators_aggregated_pub: PublicKey,
        operators_aggregated_pub_happy_path: PublicKey,
        unspendable: PublicKey,
        user_pubkey: PublicKey,
        secret: Vec<u8>,
        ordinal_utxo: PartialUtxo,
        protocol_utxo: PartialUtxo,
        timelock_blocks: u16,
        eol_timelock_duration: u16,
    ) -> Self {
        Self {
            operators_aggregated_pub,
            operators_aggregated_pub_happy_path,
            unspendable,
            user_pubkey,
            secret,
            ordinal_utxo,
            protocol_utxo,
            timelock_blocks,
            eol_timelock_duration,
        }
    }

    pub fn new_from_globals(id: Uuid, globals: &Globals) -> Result<Self, BitVMXError> {
        let operators_aggregated_pub = globals
            .get_var(&id, "operators_aggregated_pub")?
            .unwrap()
            .pubkey()?;
        let ops_agg_happy_path = globals
            .get_var(&id, "operators_aggregated_happy_path")?
            .unwrap()
            .pubkey()?;
        let unspendable = globals.get_var(&id, "unspendable")?.unwrap().pubkey()?;
        let user_pubkey = globals.get_var(&id, "user_pubkey")?.unwrap().pubkey()?;
        let secret = globals.get_var(&id, "secret")?.unwrap().secret()?;
        let ordinal_utxo = globals.get_var(&id, "ordinal_utxo")?.unwrap().utxo()?;
        let protocol_utxo = globals.get_var(&id, "protocol_utxo")?.unwrap().utxo()?;
        let timelock_blocks = globals.get_var(&id, "timelock_blocks")?.unwrap().number()? as u16;
        let eol_timelock_duration = globals
            .get_var(&id, EOL_TIMELOCK_DURATION)?
            .unwrap()
            .number()? as u16;

        Ok(Self::new(
            operators_aggregated_pub,
            ops_agg_happy_path,
            unspendable,
            user_pubkey,
            secret,
            ordinal_utxo,
            protocol_utxo,
            timelock_blocks,
            eol_timelock_duration,
        ))
    }

    pub fn send(&self, program_id: Uuid, channel: &DualChannel) -> Result<(), BitVMXError> {
        channel.send(
            BITVMX_ID,
            VariableTypes::PubKey(self.operators_aggregated_pub.clone())
                .set_msg(program_id, "operators_aggregated_pub")?,
        )?;
        channel.send(
            BITVMX_ID,
            VariableTypes::PubKey(self.operators_aggregated_pub_happy_path.clone())
                .set_msg(program_id, "operators_aggregated_happy_path")?,
        )?;
        channel.send(
            BITVMX_ID,
            VariableTypes::PubKey(self.unspendable.clone()).set_msg(program_id, "unspendable")?,
        )?;
        channel.send(
            BITVMX_ID,
            VariableTypes::PubKey(self.user_pubkey.clone()).set_msg(program_id, "user_pubkey")?,
        )?;
        channel.send(
            BITVMX_ID,
            VariableTypes::Secret(self.secret.clone()).set_msg(program_id, "secret")?,
        )?;
        channel.send(
            BITVMX_ID,
            VariableTypes::Utxo(self.ordinal_utxo.clone()).set_msg(program_id, "ordinal_utxo")?,
        )?;
        channel.send(
            BITVMX_ID,
            VariableTypes::Utxo(self.protocol_utxo.clone()).set_msg(program_id, "protocol_utxo")?,
        )?;
        channel.send(
            BITVMX_ID,
            VariableTypes::Number(self.timelock_blocks as u32)
                .set_msg(program_id, "timelock_blocks")?,
        )?;
        channel.send(
            BITVMX_ID,
            VariableTypes::Number(self.eol_timelock_duration as u32)
                .set_msg(program_id, EOL_TIMELOCK_DURATION)?,
        )?;

        Ok(())
    }

    pub fn setup(
        &self,
        program_id: Uuid,
        channel: &DualChannel,
        addresses: Vec<crate::program::participant::P2PAddress>,
        leader: u16,
    ) -> Result<(), BitVMXError> {
        self.send(program_id, channel)?;

        let setup_msg = IncomingBitVMXApiMessages::Setup(
            program_id,
            PROGRAM_TYPE_LOCK.to_string(),
            addresses,
            leader,
        )
        .to_string()?;
        channel.send(BITVMX_ID, setup_msg)?;
        Ok(())
    }
}

impl ProtocolHandler for LockProtocol {
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
                .unwrap()
                .pubkey()?,
        )])
    }

    fn generate_keys(
        &self,
        program_context: &mut ProgramContext,
    ) -> Result<ParticipantKeys, BitVMXError> {
        let speedup = program_context.key_chain.derive_keypair()?;

        program_context.globals.set_var(
            &self.ctx.id,
            "speedup",
            VariableTypes::PubKey(speedup.clone()),
        )?;

        let mut keys = vec![("speedup".to_string(), speedup.into())];

        //TODO: get from a variable the number of bytes required to encode the too_id
        let start_id = program_context.key_chain.derive_winternitz_hash160(1)?;
        keys.push((format!("too_id_{}", self.ctx.my_idx), start_id.into()));

        if self.ctx.my_idx == 0 {
            let start_id = program_context.key_chain.derive_winternitz_hash160(128)?;
            keys.push(("zkp".to_string(), start_id.into()));
        }

        Ok(ParticipantKeys::new(keys, vec![]))
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        match name {
            LOCK_TX => Ok((self.accept_tx(context))?),
            HAPPY_PATH_TX => Ok((self.happy_path()?, None)),
            _ => Err(BitVMXError::InvalidTransactionName(name.to_string())),
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
        let name = self.get_transaction_name_by_id(tx_id)?;
        if tx_status.confirmations == 1 {
            info!(
                "Program {}: Transaction {} has been seen on-chain",
                self.ctx.id, name
            );
        }
        if name == LOCK_TX && tx_status.confirmations == 1 {
            let witness = tx_status.tx.input[0].witness.clone();
            info!(
                "secret witness {:?}",
                String::from_utf8(witness[1].to_vec())
                    .map_err(|_| BitVMXError::InvalidMessageFormat)?
            );
        }
        Ok(())
    }

    fn build(
        &self,
        keys: Vec<ParticipantKeys>,
        _computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let LockProtocolConfiguration {
            operators_aggregated_pub,
            operators_aggregated_pub_happy_path,
            unspendable,
            user_pubkey,
            secret,
            ordinal_utxo,
            protocol_utxo,
            timelock_blocks,
            eol_timelock_duration,
        } = LockProtocolConfiguration::new_from_globals(self.ctx.id, &context.globals)?;

        warn!(
            "Setup with: {:?} {:?} {:?}",
            ordinal_utxo, protocol_utxo, user_pubkey
        );

        warn!(
            "======== Ops_agg_key: {:?} Unspendable: {:?} User_pubkey{:?}",
            XOnlyPublicKey::from(operators_aggregated_pub).to_string(),
            XOnlyPublicKey::from(unspendable).to_string(),
            XOnlyPublicKey::from(user_pubkey).to_string()
        );

        //THIS SECTION DEFINES THE OUTPUTS OF THE LOCK_REQ_TX
        //THAT WILL BE SPENT BY THE LOCK_TX

        // Mark this script as unsigned script, so the protocol builder wont try to sign it
        let timelock_script = timelock(timelock_blocks, &user_pubkey, SignMode::Skip);

        let reveal_secret_script = reveal_secret(
            secret.to_vec(),
            &operators_aggregated_pub,
            SignMode::Aggregate,
        );
        let leaves = vec![timelock_script.clone(), reveal_secret_script.clone()];

        let output_type_ordinal =
            OutputType::taproot(ordinal_utxo.2.unwrap(), &unspendable, &leaves)?;

        let output_type_protocol =
            OutputType::taproot(protocol_utxo.2.unwrap(), &unspendable, &leaves)?;

        let mut protocol = self.load_or_create_protocol();
        protocol.add_external_transaction(LOCK_REQ_TX)?;

        protocol.add_transaction_output(LOCK_REQ_TX, &output_type_ordinal)?;
        protocol.add_transaction_output(LOCK_REQ_TX, &output_type_protocol)?;

        assert_eq!(ordinal_utxo.0, protocol_utxo.0);

        protocol.add_connection(
            "LOCK_REQ_TX__LOCK_TX_ORDINAL",
            LOCK_REQ_TX,
            OutputSpec::Index(0),
            LOCK_TX,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            Some(ordinal_utxo.0),
        )?;

        protocol.add_connection(
            "LOCK_REQ_TX__LOCK_TX_PROTOCOL",
            LOCK_REQ_TX,
            OutputSpec::Index(1),
            LOCK_TX,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            Some(protocol_utxo.0),
        )?;

        // START DEFINING THE OUTPUTS OF THE LOCK_TX

        // The following script is the output that user timeout could use as input
        let taproot_script_eol_timelock_expired_tx_lock =
            scripts::timelock(eol_timelock_duration, &user_pubkey, SignMode::Skip);

        //this should be another aggregated to be signed later
        let taproot_script_all_sign_tx_lock =
            scripts::check_aggregated_signature(&operators_aggregated_pub, SignMode::Aggregate);

        protocol.add_transaction_output(
            LOCK_TX,
            &OutputType::taproot(
                ordinal_utxo.2.unwrap(),
                &unspendable,
                &[
                    taproot_script_eol_timelock_expired_tx_lock.clone(),
                    taproot_script_all_sign_tx_lock.clone(),
                ],
            )?, // We do not need prevouts cause the tx is in the graph,
        )?;

        //this could be even a different one, but we will use the same for now
        let taproot_script_protocol_fee_addres_signature_in_tx_lock =
            scripts::check_aggregated_signature(&operators_aggregated_pub, SignMode::Aggregate);

        let amount = self.checked_sub(protocol_utxo.2.unwrap(), DUST * (keys.len() as u64 + 1))?;
        // [Protocol fees taproot output]
        // taproot output sending the fee (incentive to bridge) to the fee address
        protocol.add_transaction_output(
            LOCK_TX,
            &OutputType::taproot(
                amount,
                &unspendable,
                &[taproot_script_protocol_fee_addres_signature_in_tx_lock],
            )?,
        )?;

        self.add_happy_path(
            &mut protocol,
            &operators_aggregated_pub_happy_path,
            &unspendable,
            ordinal_utxo.2.unwrap(),
            self.checked_sub(amount, DUST)?,
        )?;

        let pb = ProtocolBuilder {};
        for k in keys {
            pb.add_speedup_output(&mut protocol, LOCK_TX, DUST, k.get_public("speedup")?)?;
        }

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("{}", protocol.visualize(GraphOptions::Default)?);
        self.save_protocol(protocol)?;

        Ok(())
    }

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!("LockProtocol setup complete for program {}", self.ctx.id);
        Ok(())
    }
}

impl LockProtocol {
    pub fn new(context: ProtocolContext) -> Self {
        Self { ctx: context }
    }

    pub fn add_happy_path(
        &self,
        protocol: &mut Protocol,
        ops_agg_happy_path: &PublicKey,
        unspendable: &PublicKey,
        amount_ordinal: u64,
        amount_protocol: u64,
    ) -> Result<(), BitVMXError> {
        // START DEFINING THE HAPPY_PATH_TX

        let happy_path_check =
            scripts::check_aggregated_signature(&ops_agg_happy_path, SignMode::Skip);

        protocol.add_connection(
            "spend_hp_1",
            LOCK_TX,
            0.into(),
            HAPPY_PATH_TX,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            None,
        )?;

        protocol.add_connection(
            "spend_hp_2",
            LOCK_TX,
            1.into(),
            HAPPY_PATH_TX,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            None,
        )?;

        protocol.add_transaction_output(
            HAPPY_PATH_TX,
            &OutputType::taproot(amount_ordinal, &unspendable, &[happy_path_check.clone()])?,
        )?;
        protocol.add_transaction_output(
            HAPPY_PATH_TX,
            &OutputType::taproot(amount_protocol, &unspendable, &[happy_path_check.clone()])?,
        )?;

        Ok(())
    }

    pub fn accept_tx(
        &self,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        //Gets the
        let secret = context
            .witness
            .get_witness(&self.ctx.id, "secret")?
            .unwrap()
            .secret()?;

        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(LOCK_TX, 0, 1)?
            .unwrap();
        let mut taproot_arg_0 = InputArgs::new_taproot_script_args(1);
        taproot_arg_0.push_taproot_signature(signature)?;
        //info!("signature =====>: {:?}", signature);
        taproot_arg_0.push_slice(&secret);

        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(LOCK_TX, 1, 1)?
            .unwrap();
        let mut taproot_arg_1 = InputArgs::new_taproot_script_args(1);
        taproot_arg_1.push_taproot_signature(signature)?;
        taproot_arg_1.push_slice(&secret);

        let tx = self
            .load_protocol()?
            .transaction_to_send(LOCK_TX, &[taproot_arg_0, taproot_arg_1])?;

        let txid = tx.compute_txid();
        let speedup = context
            .globals
            .get_var(&self.ctx.id, "speedup")?
            .unwrap()
            .pubkey()?;
        let speedup_utxo = Utxo::new(txid, 2 + self.ctx.my_idx as u32, DUST, &speedup);

        info!("Transaction to send: {:?}", tx);
        Ok((tx, Some(speedup_utxo.into())))
    }

    pub fn happy_path(&self) -> Result<Transaction, BitVMXError> {
        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(HAPPY_PATH_TX, 0, 1)?
            .unwrap();
        let mut taproot_arg_0 = InputArgs::new_taproot_script_args(1);
        taproot_arg_0.push_taproot_signature(signature)?;

        let signature = self
            .load_protocol()?
            .input_taproot_script_spend_signature(HAPPY_PATH_TX, 1, 0)?
            .unwrap();
        let mut taproot_arg_1 = InputArgs::new_taproot_script_args(0);
        taproot_arg_1.push_taproot_signature(signature)?;

        let tx = self
            .load_protocol()?
            .transaction_to_send(HAPPY_PATH_TX, &[taproot_arg_0, taproot_arg_1])?;

        info!("Transaction to send: {:?}", tx);
        Ok(tx)
    }

    pub fn add_winternitz_check(
        &self,
        aggregated: &PublicKey,
        protocol: &mut Protocol,
        keys: &ParticipantKeys,
        amount: u64,
        amount_speedup: u64,
        var_names: &Vec<&str>,
        from: &str,
        to: &str,
    ) -> Result<(), BitVMXError> {
        info!("Adding winternitz check for {} to {}", from, to);
        info!("Amount: {}", amount);
        info!("Speedup: {}", amount_speedup);
        let names_and_keys = var_names
            .iter()
            .map(|v| (*v, keys.get_winternitz(v).unwrap()))
            .collect();

        let winternitz_check = scripts::verify_winternitz_signatures(
            aggregated,
            &names_and_keys,
            SignMode::Aggregate,
        )?;

        let leaves = [winternitz_check];

        let output_type = OutputType::taproot(amount, aggregated, &leaves)?;

        protocol.add_connection(
            &format!("{}__{}", from, to),
            from,
            output_type.into(),
            to,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        let pb = ProtocolBuilder {};
        //put the amount here as there is no output yet
        pb.add_speedup_output(protocol, to, amount_speedup, aggregated)?;

        Ok(())
    }
}
