use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{self, types::*},
        },
        variables::VariableTypes,
    },
    types::ProgramContext,
};

use bitcoin::{OutPoint, PublicKey, Transaction, Txid};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use uuid::{timestamp::context, Uuid};
use protocol_builder::{
    builder::Protocol,
    graph::graph::GraphOptions,
    scripts::{self, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::SpeedupData,
        OutputType,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

const PEGOUT_ID_KEY: &str = "pegout_id";
const SECRET_KEY: &str = "secret";
const CHALLENGE_KEY: &str = "challenge_pubkey";
const REVEAL_INPUT_KEY: &str = "reveal_pubkey";
const REVEAL_TAKE_PRIVKEY: &str = "reveal_take_private_key";
const TAKE_KEY: &str = "take_key";
const DISPUTE_KEY: &str = "dispute_key";

#[derive(Clone, Serialize, Deserialize)]
pub struct DisputeCoreProtocol {
    ctx: ProtocolContext,
}

impl ProtocolHandler for DisputeCoreProtocol {
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
        keys.push((
            CHALLENGE_KEY.to_string(),
            PublicKeyType::Public(program_context.key_chain.derive_keypair()?),
        ));

        if self.prover(program_context)? {
            keys.push((
                REVEAL_INPUT_KEY.to_string(),
                PublicKeyType::Public(program_context.key_chain.derive_keypair()?),
            ));
            keys.push((
                REVEAL_TAKE_PRIVKEY.to_string(),
                PublicKeyType::Winternitz(program_context.key_chain.derive_winternitz_hash160(32)?),
            ));

            for i in 0..packet_size as usize {
                keys.push((
                    indexed_name(PEGOUT_ID_KEY, i).to_string(),
                    PublicKeyType::Winternitz(
                        program_context.key_chain.derive_winternitz_hash160(20)?,
                    ),
                ));

                keys.push((
                    indexed_name(SECRET_KEY, i).to_string(),
                    PublicKeyType::Winternitz(
                        program_context.key_chain.derive_winternitz_hash160(1)?,
                    ),
                ));
            }
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
        let dispute_core_data = self.dispute_core_data(context)?;
        let committee = self.committee(context)?;
        let operator_keys = keys[dispute_core_data.operator_index].clone();

        self.create_initial_deposit(&mut protocol, &operator_keys, &dispute_core_data)?;

        for i in 0..committee.packet_size as usize {
            self.create_dispute_core(
                &mut protocol,
                &committee,
                &dispute_core_data,
                i,
                &keys,
                context,
            )?;
        }

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);

        self.save_protocol(protocol)?;
        self.save_take_utxos(context)?;

        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        _context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        Ok((
            self.load_protocol()?.transaction_by_name(name)?.clone(),
            None,
        ))
    }

    fn notify_news(
        &self,
        tx_id: Txid,
        _vout: Option<u32>,
        tx_status: TransactionStatus,
        context: String,
        program_context: &ProgramContext,
        _participant_keys: Vec<&ParticipantKeys>,
    ) -> Result<(), BitVMXError> {
        let transaction_name = self.get_transaction_name_by_id(tx_id)?;
        // Route to appropriate handler based on transaction type
        if transaction_name.starts_with(REIMBURSEMENT_KICKOFF_TX) {
            self.handle_reimbursement_kickoff_transaction(
                tx_id,
                &tx_status,
                &context,
                program_context,
            )?;
        }
        // TODO: Add more transaction type handlers here as needed

        // let a = AckNews::Monitor(AckMonitorNews::RskPeginTransaction(txid));
        // _program_context.bitcoin_coordinator.ack_news(a);

        Ok(())
    }

    fn setup_complete(&self, _program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            id = self.ctx.my_idx,
            "DisputeCore {} setup complete", self.ctx.id
        );

        Ok(())
    }
}

impl DisputeCoreProtocol {
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }

    fn create_initial_deposit(
        &self,
        protocol: &mut Protocol,
        operator_keys: &ParticipantKeys,
        dispute_core_data: &DisputeCoreData,
    ) -> Result<(), BitVMXError> {
        let operator_utxo = dispute_core_data.operator_utxo.clone();
        let operator_dispute_key = operator_keys.get_public(DISPUTE_KEY)?;
        let reveal_take_private_key = operator_keys.get_winternitz(REVEAL_TAKE_PRIVKEY)?.clone();

        // Connect the setup transaction to the operator funding transaction.
        let funding = format!("{}{}", OPERATOR, FUNDING_TX_SUFFIX);
        let setup = format!("{}{}", OPERATOR, SETUP_TX_SUFFIX);
        let initial_deposit = format!("{}{}", OPERATOR, INITIAL_DEPOSIT_TX_SUFFIX);
        let self_disabler = format!("{}{}", OPERATOR, SELF_DISABLER_TX_SUFFIX);

        protocol.add_external_transaction(&funding)?;
        protocol.add_transaction_output(&funding, &operator_utxo.3.unwrap())?;

        // The operator_utxo must be of type P2WPKH
        protocol.add_connection(
            "setup",
            &funding,
            (operator_utxo.1 as usize).into(),
            &setup,
            InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::None),
            None,
            Some(operator_utxo.0),
        )?;

        // Connect the initial deposit transaction to the setup transaction.
        protocol.add_connection(
            "initial_deposit",
            &setup,
            OutputSpec::Auto(OutputType::taproot(
                operator_utxo.2.unwrap(),
                operator_dispute_key,
                &[union::scripts::reveal_take_private_key(
                    operator_dispute_key,
                    &reveal_take_private_key,
                )?],
            )?),
            &initial_deposit,
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

        Ok(())
    }

    fn create_dispute_core(
        &self,
        protocol: &mut Protocol,
        committee: &Committee,
        dispute_core_data: &DisputeCoreData,
        dispute_core_index: usize,
        keys: &Vec<ParticipantKeys>,
        context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        let pegout_id_name = indexed_name(PEGOUT_ID_KEY, dispute_core_index);
        let secret_name = indexed_name(SECRET_KEY, dispute_core_index);

        let operator_keys = keys[dispute_core_data.operator_index].clone();

        let operator_dispute_key = operator_keys.get_public(DISPUTE_KEY)?;
        let take_aggregated_key = self.take_aggregated_key(context)?;
        let dispute_aggregated_key = &self.dispute_aggregated_key(context)?;
        let pegout_id_key = operator_keys.get_winternitz(&pegout_id_name)?;
        let secret_key = operator_keys.get_winternitz(&secret_name)?;

        let initial_deposit = format!("{}{}", OPERATOR, INITIAL_DEPOSIT_TX_SUFFIX);
        let reimbursement_kickoff = indexed_name(REIMBURSEMENT_KICKOFF_TX, dispute_core_index);
        let challenge = indexed_name(CHALLENGE_TX, dispute_core_index);
        let reveal_input = indexed_name(REVEAL_INPUT_TX, dispute_core_index);
        let input_not_revealed = indexed_name(INPUT_NOT_REVEALED_TX, dispute_core_index);

        let start_reimbursement = union::scripts::start_reimbursement(
            &take_aggregated_key,
            operator_dispute_key,
            pegout_id_key,
        )?;

        // We use the operator's dispute key as internal key to use the key spend path for self disablement.
        protocol.add_connection(
            "start_dispute_core",
            &initial_deposit,
            OutputType::taproot(
                DISPUTE_OPENER_VALUE,
                &operator_dispute_key,
                &[start_reimbursement],
            )?
            .into(),
            &reimbursement_kickoff,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            None,
        )?;

        let mut challenge_requests = vec![];
        for i in 0..keys.len() {
            // If this is my dispute_core I need to disable me from performing a challenge request to myself.
            if i == dispute_core_data.operator_index {
                challenge_requests.push(scripts::op_return_script("skip".as_bytes().to_vec())?);
            }

            challenge_requests.push(scripts::verify_signature(
                keys[i].get_public(CHALLENGE_KEY)?,
                SignMode::Single,
            )?);
        }

        protocol.add_connection(
            "challenge",
            &reimbursement_kickoff,
            OutputType::taproot(
                DISPUTE_OPENER_VALUE,
                &take_aggregated_key,
                challenge_requests.as_slice(),
            )?
            .into(),
            &challenge,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::None),
            Some(DISPUTE_CORE_LONG_TIMELOCK),
            None,
        )?;

        let secret = scripts::verify_winternitz_signature(
            operator_keys.get_public(REVEAL_INPUT_KEY)?,
            secret_key,
            SignMode::Skip,
        )?;

        protocol.add_connection(
            "reveal_input",
            &challenge,
            OutputType::taproot(DISPUTE_OPENER_VALUE, &dispute_aggregated_key, &[secret])?.into(),
            &reveal_input,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            None,
        )?;

        protocol.add_transaction_output(
            &reveal_input,
            &OutputType::taproot(DUST_VALUE, &take_aggregated_key, &[])?,
        )?;

        protocol.add_connection(
            "input_not_revealed",
            &challenge,
            OutputSpec::Index(0),
            &input_not_revealed,
            InputSpec::Auto(
                SighashType::taproot_all(),
                SpendMode::KeyOnly {
                    key_path_sign: SignMode::Aggregate,
                },
            ),
            None,
            None,
        )?;

        protocol.add_transaction_output(
            &input_not_revealed,
            &OutputType::taproot(DUST_VALUE, &take_aggregated_key, &[])?,
        )?;

        self.add_speedup_outputs(
            protocol,
            keys,
            dispute_core_index,
            &operator_dispute_key,
            committee.packet_size as usize,
        )?;

        Ok(())
    }

    fn add_speedup_outputs(
        &self,
        protocol: &mut Protocol,
        keys: &Vec<ParticipantKeys>,
        dispute_core_index: usize,
        operator_dispute_key: &PublicKey,
        packet_size: usize,
    ) -> Result<(), BitVMXError> {
        let initial_deposit = format!("{}{}", OPERATOR, INITIAL_DEPOSIT_TX_SUFFIX);
        let reimbursement_kickoff = indexed_name(REIMBURSEMENT_KICKOFF_TX, dispute_core_index);
        let challenge = indexed_name(CHALLENGE_TX, dispute_core_index);
        let reveal_input = indexed_name(REVEAL_INPUT_TX, dispute_core_index);
        let input_not_revealed = indexed_name(INPUT_NOT_REVEALED_TX, dispute_core_index);

        // Add a speedup output to the initial_deposit transaction after the last reimbursement output.
        if dispute_core_index == packet_size - 1 {
            protocol.add_transaction_output(
                &initial_deposit,
                &OutputType::segwit_key(SPEED_UP_VALUE, operator_dispute_key)?,
            )?;
        }

        // Add a speedup output to the reimbursement_kickoff transaction.
        protocol.add_transaction_output(
            &reimbursement_kickoff,
            &OutputType::segwit_key(SPEED_UP_VALUE, operator_dispute_key)?,
        )?;

        // Add one speedup ouput per committee member to the challenge and input_not_revealed transactions.
        for i in 0..keys.len() {
            let speedup_output =
                OutputType::segwit_key(SPEED_UP_VALUE, keys[i].get_public(DISPUTE_KEY)?)?;
            protocol.add_transaction_output(&challenge, &speedup_output)?;
            protocol.add_transaction_output(&input_not_revealed, &speedup_output)?;
        }

        // Add a speedup output to the reveal_input transaction.
        protocol.add_transaction_output(
            &reveal_input,
            &OutputType::segwit_key(SPEED_UP_VALUE, operator_dispute_key)?,
        )?;

        Ok(())
    }

    fn dispute_core_data(&self, context: &ProgramContext) -> Result<DisputeCoreData, BitVMXError> {
        let data = context
            .globals
            .get_var(&self.ctx.id, &DisputeCoreData::name())?
            .unwrap()
            .string()?;

        let data: DisputeCoreData = serde_json::from_str(&data)?;
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

    fn prover(&self, context: &ProgramContext) -> Result<bool, BitVMXError> {
        match self.committee(context)?.members[self.ctx.my_idx].role {
            ParticipantRole::Prover => Ok(true),
            _ => Ok(false),
        }
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
        Ok(self.dispute_core_data(context)?.committee_id)
    }

    fn get_monitored_operator_key(&self, context: &ProgramContext) -> Result<PublicKey, BitVMXError> {
        match context.globals.get_var(&self.ctx.id, MONITORED_OPERATOR_KEY)? {
            Some(key_var) => Ok(key_var.pubkey()?),
            None => Err(BitVMXError::VariableNotFound(self.ctx.id, MONITORED_OPERATOR_KEY.to_string())),
        }
    }

    fn get_selected_operator_key(
        &self,
        slot_id: usize,
        program_context: &ProgramContext,
    ) -> Result<Option<PublicKey>, BitVMXError> {
        let committee_id = self.committee_id(program_context)?;
        let selected_operator_key_name = format!("{}_{}", SELECTED_OPERATOR_PUBKEY, slot_id);

        match program_context
            .globals
            .get_var(&committee_id, &selected_operator_key_name)?
        {
            Some(selected_operator_var) => Ok(Some(selected_operator_var.pubkey()?)),
            None => Ok(None),
        }
    }

    fn dispatch_challenge_tx(
        &self,
        slot_id: usize,
        context: &str,
        program_context: &ProgramContext,
        reimbursement_tx_id: Txid,
    ) -> Result<(), BitVMXError> {
        info!("Dispatching Challenge Tx for slot_id: {}", slot_id);

        // Build the challenge transaction name
        let challenge_tx_name = indexed_name(CHALLENGE_TX, slot_id);

        let member_index = self.committee(program_context)?.member_index;

        info!("Challenge tx will use member {} leaf in taptree", member_index);

        // Get the signed transaction using the member's taptree leaf
        let mut challenge_tx = self.get_signed_tx(
            program_context,
            &challenge_tx_name,
            0,
            member_index as u32,
            false,
            0,
        )?;

        // Connect the signed challenge transaction to the reimbursement kickoff transaction
        if !challenge_tx.input.is_empty() {
            challenge_tx.input[0].previous_output = OutPoint {
                txid: reimbursement_tx_id,
                vout: 0, // Challenge tx consumes output 0 from reimbursement kickoff
            };
        }

        program_context.bitcoin_coordinator.dispatch(challenge_tx, None, context.to_string(), None);

        info!("Challenge transaction {} connected to reimbursement tx {} and dispatched", challenge_tx_name, reimbursement_tx_id);

        Ok(())
    }

    fn handle_reimbursement_kickoff_transaction(
        &self,
        tx_id: Txid,
        _tx_status: &TransactionStatus,
        context: &str,
        program_context: &ProgramContext,
    ) -> Result<(), BitVMXError> {
        info!(
            "Detected reimbursement kickoff transaction: {} with context: {}",
            tx_id, context
        );

        // Extract slot_id from transaction name
        let transaction_name = self.get_transaction_name_by_id(tx_id)?;
        let slot_id = transaction_name
            .strip_prefix(&format!("{}_", REIMBURSEMENT_KICKOFF_TX))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| BitVMXError::InvalidTransactionName(transaction_name))?;

        // Get the selected operator's key for this slot
        match self.get_selected_operator_key(slot_id, program_context)? {
            Some(selected_operator_key) => {
                // Get the operator's take key that this dispute core is monitoring
                let monitored_operator_key = self.get_monitored_operator_key(program_context)?;

                // Compare if the monitored operator is the selected one
                let is_valid = selected_operator_key == monitored_operator_key;

                if !is_valid {
                    info!("Unauthorized operator detected for slot {}, dispatching Challenge Tx", slot_id);
                    self.dispatch_challenge_tx(slot_id, context, program_context, tx_id)?;
                } else {
                    info!("Authorized operator confirmed for slot {}", slot_id);
                    // TODO: here we need to validate that the advancement of funds has actually been made
                }
            }
            None => {
                info!("No selected operator key found for slot {}", slot_id);
                // If no selected operator key is set, it means that someone triggered a reimbursment kickoff transaction but there was no advances of funds
                self.dispatch_challenge_tx(slot_id, context, program_context, tx_id)?;
            }
        }

        Ok(())
    }

    fn save_take_utxos(&self, context: &ProgramContext) -> Result<(), BitVMXError> {
        let committee = self.committee(context)?;
        let take_key = &self.take_aggregated_key(context)?;
        let protocol = self.load_or_create_protocol();

        for i in 0..committee.packet_size as usize {
            let name = indexed_name(REIMBURSEMENT_KICKOFF_TX, i);
            let reimbursement_kickoff_tx = protocol.transaction_by_name(&name)?;
            let operator_take_output = OutputType::taproot(DUST_VALUE, &take_key, &[])?;

            let operator_take_utxo = (
                reimbursement_kickoff_tx.compute_txid(),
                0,
                Some(DUST_VALUE),
                Some(operator_take_output),
            );

            let name = indexed_name(REVEAL_INPUT_TX, i);
            let reveal_input_tx = protocol.transaction_by_name(&name)?;
            let operator_won_output = OutputType::taproot(DUST_VALUE, &take_key, &[])?;

            let operator_won_utxo = (
                reveal_input_tx.compute_txid(),
                0,
                Some(DUST_VALUE),
                Some(operator_won_output),
            );

            context.globals.set_var(
                &self.ctx.id,
                &indexed_name(OPERATOR_TAKE_ENABLER, i),
                VariableTypes::Utxo(operator_take_utxo.clone()),
            )?;

            context.globals.set_var(
                &self.ctx.id,
                &indexed_name(OPERATOR_WON_ENABLER, i),
                VariableTypes::Utxo(operator_won_utxo.clone()),
            )?;
        }

        Ok(())
    }
}

fn indexed_name(prefix: &str, index: usize) -> String {
    format!("{}_{}", prefix, index)
}
