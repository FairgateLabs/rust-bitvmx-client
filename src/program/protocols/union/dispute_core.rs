use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeys, ParticipantRole, PublicKeyType},
        protocols::{
            protocol_handler::{ProtocolContext, ProtocolHandler},
            union::{
                self,
                common::{create_transaction_reference, indexed_name},
                types::*,
            },
        },
        variables::VariableTypes,
    },
    types::ProgramContext,
};

use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::Message,
    EcdsaSighashType, PublicKey, Transaction, Txid,
};
use bitcoin_coordinator::{coordinator::BitcoinCoordinatorApi, TransactionStatus};
use core::result::Result::Ok;
use protocol_builder::{
    builder::Protocol,
    errors::ProtocolBuilderError,
    graph::graph::GraphOptions,
    scripts::{self, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::{SpeedupData, AUTO_AMOUNT, RECOVER_AMOUNT},
        InputArgs, OutputType,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

pub const PEGOUT_ID: &str = "pegout_id";
const PEGOUT_ID_KEY: &str = "pegout_id_key";
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

        self.add_funding_change(&mut protocol, &operator_keys, &dispute_core_data)?;

        protocol.build(&context.key_chain.key_manager, &self.ctx.protocol_name)?;
        info!("\n{}", protocol.visualize(GraphOptions::EdgeArrows)?);

        self.save_protocol(protocol)?;
        self.save_take_utxos(context)?;

        Ok(())
    }

    fn get_transaction_by_name(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<(Transaction, Option<SpeedupData>), BitVMXError> {
        if name == format!("{}{}", OPERATOR, INITIAL_DEPOSIT_TX_SUFFIX) {
            Ok((self.op_initial_deposit_tx(name, context)?, None))
        } else if name == format!("{}{}", OPERATOR, SETUP_TX_SUFFIX) {
            Ok((self.setup_tx(context)?, None))
        } else if name.starts_with(REIMBURSEMENT_KICKOFF_TX) {
            Ok((self.reimbursement_kickoff_tx(name, context)?, None))
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
        let transaction_name = self.get_transaction_name_by_id(tx_id)?;
        info!(
            "Dispute core protocol received news of transaction: {}, txid: {} with status {:#?}",
            transaction_name, tx_id, tx_status
        );

        // match transaction_name.as_str() {
        //     t if t.starts_with(REIMBURSEMENT_KICKOFF_TX) => {
        //         self.handle_reimbursement_kickoff_transaction(
        //             tx_id,
        //             &tx_status,
        //             &context,
        //             program_context,
        //         )?;
        //     }
        //     _ => {
        //         // Optional: handle default / unknown transaction types here
        //     }
        // }

        // TODO: Add more transaction type handlers here as needed
        Ok(())
    }

    fn setup_complete(&self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        // This is called after the protocol is built and ready to be used
        info!(
            id = self.ctx.my_idx,
            "DisputeCore {} setup complete", self.ctx.id
        );

        // Automatically get and dispatch the OP_SETUP_TX transaction
        self.dispatch_setup_tx(program_context)?;

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

        // Create the funding transaction reference
        create_transaction_reference(protocol, &funding, &mut [operator_utxo.clone()].to_vec())?;

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
                AUTO_AMOUNT,
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

        protocol.add_transaction_output(
            &self_disabler,
            &OutputType::segwit_key(RECOVER_AMOUNT, operator_dispute_key)?,
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

        // If this is my dispute_core I need to store the pegout_id_key in the globals for later use in the reimbursement kickoff dispatch
        if dispute_core_data.operator_index == self.ctx.my_idx {
            let pegout_id_name = indexed_name(PEGOUT_ID_KEY, dispute_core_index);
            let pegout_id_key = operator_keys.get_winternitz(&pegout_id_name)?;
            let data = VariableTypes::WinternitzPubKey(pegout_id_key.clone());
            let _ = context.globals.set_var(&self.ctx.id, &pegout_id_name, data);
        }

        let start_reimbursement = union::scripts::start_reimbursement(
            &take_aggregated_key,
            operator_dispute_key,
            pegout_id_key,
        )?;

        // We use the operator's dispute key as internal key to use the key spend path for self disablement.
        protocol.add_connection(
            "start_dispute_core",
            &initial_deposit,
            OutputType::taproot(AUTO_AMOUNT, &operator_dispute_key, &[start_reimbursement])?.into(),
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
                AUTO_AMOUNT,
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
            OutputType::taproot(AUTO_AMOUNT, &dispute_aggregated_key, &[secret])?.into(),
            &reveal_input,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::ScriptsOnly),
            None,
            None,
        )?;

        protocol.add_transaction_output(
            &reveal_input,
            &OutputType::taproot(AUTO_AMOUNT, &take_aggregated_key, &[])?,
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
            &OutputType::taproot(AUTO_AMOUNT, &take_aggregated_key, &[])?,
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
                &OutputType::segwit_key(AUTO_AMOUNT, operator_dispute_key)?,
            )?;
        }

        // Add a speedup output to the reimbursement_kickoff transaction.
        protocol.add_transaction_output(
            &reimbursement_kickoff,
            &OutputType::segwit_key(AUTO_AMOUNT, operator_dispute_key)?,
        )?;

        // Add one speedup ouput per committee member to the challenge and input_not_revealed transactions.
        for i in 0..keys.len() {
            let speedup_output =
                OutputType::segwit_key(AUTO_AMOUNT, keys[i].get_public(DISPUTE_KEY)?)?;
            protocol.add_transaction_output(&challenge, &speedup_output)?;
            protocol.add_transaction_output(&input_not_revealed, &speedup_output)?;
        }

        // Add a speedup output to the reveal_input transaction.
        protocol.add_transaction_output(
            &reveal_input,
            &OutputType::segwit_key(AUTO_AMOUNT, operator_dispute_key)?,
        )?;

        Ok(())
    }

    fn add_funding_change(
        &self,
        protocol: &mut Protocol,
        operator_keys: &ParticipantKeys,
        dispute_core_data: &DisputeCoreData,
    ) -> Result<(), BitVMXError> {
        // Add a change output to the setup transaction
        protocol.compute_minimum_output_values()?;

        let funding_amount = dispute_core_data.operator_utxo.2.unwrap();
        let setup_fees = 1000; //TODO: replace with actual fee calculation or make it configurable
        let operator_dispute_key = operator_keys.get_public(DISPUTE_KEY)?;
        let setup = format!("{}{}", OPERATOR, SETUP_TX_SUFFIX);

        let setup_amount = protocol.transaction_by_name(&setup)?.output[0]
            .value
            .to_sat();

        protocol
            .add_transaction_output(
                &setup,
                &OutputType::segwit_key(
                    funding_amount - setup_amount - setup_fees,
                    operator_dispute_key,
                )?,
            )
            .map_err(|e| BitVMXError::ProtocolBuilderError(e))?;
        Ok(())
    }

    fn setup_tx(&self, context: &ProgramContext) -> Result<Transaction, BitVMXError> {
        let setup_tx_name = format!("{}{}", OPERATOR, SETUP_TX_SUFFIX);

        let mut protocol = self.load_protocol()?;

        let signature =
            protocol.sign_ecdsa_input(&setup_tx_name, 0, &context.key_chain.key_manager)?;

        let mut input_args = InputArgs::new_segwit_args();
        input_args.push_ecdsa_signature(signature)?;

        let setup_tx = protocol.transaction_to_send(&setup_tx_name, &[input_args])?;
        Ok(setup_tx)
    }

    fn reimbursement_kickoff_tx(
        &self,
        name: &str,
        context: &ProgramContext,
    ) -> Result<Transaction, BitVMXError> {
        let slot_index = self.extract_slot_index(name, REIMBURSEMENT_KICKOFF_TX)?;
        let pegout_id_key = self.pegout_id_key(context, slot_index)?;
        let dispute_key = self.my_dispute_key(&context)?;

        let protocol = self.load_protocol()?;

        // Prepare signatures
        let slot_index_digest = sha256::Hash::hash(slot_index.to_be_bytes().as_slice());
        let slot_index_message = Message::from_digest(slot_index_digest.to_byte_array());

        let committee_signature = protocol
            .input_taproot_script_spend_signature(name, slot_index, 0)?
            .unwrap();

        let slot_index_signature = bitcoin::ecdsa::Signature {
            signature: context
                .key_chain
                .key_manager
                .sign_ecdsa_message(&slot_index_message, &dispute_key)?,
            sighash_type: EcdsaSighashType::All,
        };

        let pegout_id_signature = context.key_chain.key_manager.sign_winternitz_message(
            self.pegout_id(context, slot_index)?.as_slice(),
            pegout_id_key.key_type(),
            pegout_id_key.derivation_index()?,
        )?;

        // Create input arguments
        let mut input_args = InputArgs::new_taproot_script_args(0);

        // input_args.push_winternitz_signature(pegout_id_signature);
        input_args.push_taproot_signature(committee_signature)?;

        // NOTE: (in ProtocolBuilder) Allowed TaprootScript inputs to have ECDSA signatures
        // input_args.push_ecdsa_signature(slot_index_signature)?;

        let reimbursement_tx = protocol.transaction_to_send(&name, &[input_args])?;

        info!(
            "Reimbursement kickoff transaction for slot {}: {:#?}",
            slot_index, reimbursement_tx
        );
        Ok(reimbursement_tx)
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

    // fn extract_slot_index_from_context(&self, context: &str) -> Result<usize, BitVMXError> {
    //     let prefix = format!("{}_", REIMBURSEMENT_KICKOFF_TX);
    //     if let Some(suffix) = context.strip_prefix(&prefix) {
    //         suffix
    //             .parse::<usize>()
    //             .map_err(|_| BitVMXError::InvalidTransactionName(context.to_string()))
    //     } else {
    //         Err(BitVMXError::InvalidTransactionName(context.to_string()))
    //     }
    // }

    fn extract_slot_index(&self, tx_name: &str, tx_prefix: &str) -> Result<usize, BitVMXError> {
        let prefix = format!("{}_", tx_prefix);
        let slot_index = tx_name
            .strip_prefix(&prefix)
            .ok_or_else(|| {
                BitVMXError::InvalidTransactionName(format!(
                    "Transaction name '{}' does not match expected format '{}{}'",
                    tx_name, prefix, "{slot_index}"
                ))
            })?
            .parse::<usize>()
            .map_err(|_| {
                BitVMXError::InvalidTransactionName(format!(
                    "Could not parse slot_index from transaction name: {}",
                    tx_name
                ))
            })?;

        info!(
            "Extracted slot_index {} from transaction name: {}",
            slot_index, tx_name
        );
        Ok(slot_index)
    }

    // fn get_selected_operator_key(
    //     &self,
    //     slot_index: usize,
    //     program_context: &ProgramContext,
    // ) -> Result<Option<PublicKey>, BitVMXError> {
    //     let committee_id = self.committee_id(program_context)?;
    //     let selected_operator_key_name = format!("{}_{}", SELECTED_OPERATOR_PUBKEY, slot_index);

    //     match program_context
    //         .globals
    //         .get_var(&committee_id, &selected_operator_key_name)?
    //     {
    //         Some(selected_operator_var) => Ok(Some(selected_operator_var.pubkey()?)),
    //         None => Ok(None),
    //     }
    // }

    // fn validate_transaction_signature(
    //     &self,
    //     _tx_id: Txid,
    //     _tx_status: &TransactionStatus,
    //     _expected_pubkey: PublicKey,
    // ) -> Result<bool, BitVMXError> {
    //     // TODO: Implement actual signature validation
    //     // For now, return true as placeholder
    //     // In real implementation, this would:
    //     // 1. Extract the transaction from tx_status
    //     // 2. Verify the signature against expected_pubkey
    //     // 3. Return true if signature is valid, false otherwise
    //     info!("Validating transaction signature - placeholder implementation");
    //     Ok(true)
    // }

    fn dispatch_setup_tx(&self, program_context: &ProgramContext) -> Result<(), BitVMXError> {
        let setup_tx_name = format!("{}{}", OPERATOR, SETUP_TX_SUFFIX);

        if self.dispute_core_data(program_context)?.operator_index != self.ctx.my_idx {
            info!(
                id = self.ctx.my_idx,
                "Not my dispute_core, skipping dispatch of {} transaction", setup_tx_name
            );
            return Ok(());
        }

        info!(
            id = self.ctx.my_idx,
            "Dispatching {} transaction from protocol {}", setup_tx_name, self.ctx.id
        );

        // Get the signed transaction
        let setup_tx = self.setup_tx(program_context)?;
        let setup_txid = setup_tx.compute_txid();

        info!(
            id = self.ctx.my_idx,
            "Auto-dispatching OP_SETUP_TX transaction: {}", setup_txid
        );

        // Dispatch the transaction through the bitcoin coordinator
        program_context.bitcoin_coordinator.dispatch(
            setup_tx,
            None,                                          // No speedup data
            format!("dispute_core_setup_{}", self.ctx.id), // Context string
            None,                                          // Dispatch immediately
        )?;

        info!(
            id = self.ctx.my_idx,
            "OP_SETUP_TX dispatched successfully with txid: {}", setup_txid
        );

        Ok(())
    }

    // fn dispatch_op_disabler_tx(
    //     &self,
    //     slot_index: usize,
    //     _context: &ProgramContext,
    // ) -> Result<(), BitVMXError> {
    //     // TODO: Implement OP Disabler transaction dispatch
    //     info!("Dispatching OP Disabler Tx for slot_index: {}", slot_index);
    //     // In real implementation, this would:
    //     // 1. Create the OP Disabler transaction
    //     // 2. Submit it to the Bitcoin network
    //     // 3. Handle any necessary coordination
    //     Ok(())
    // }

    // fn handle_reimbursement_kickoff_transaction(
    //     &self,
    //     tx_id: Txid,
    //     _tx_status: &TransactionStatus,
    //     context: &str,
    //     _context: &ProgramContext,
    // ) -> Result<(), BitVMXError> {
    //     info!(
    //         "Detected reimbursement kickoff transaction: {} with context: {}",
    //         tx_id, context
    //     );

    // Extract slot_index from the context
    // let slot_index = self.extract_slot_index_from_context(context)?;

    // // Get the selected operator's key for this slot
    // match self.get_selected_operator_key(slot_index, program_context)? {
    //     Some(selected_operator_key) => {
    //         // Validate transaction signature against selected operator's key
    //         let is_valid =
    //             self.validate_transaction_signature(tx_id, tx_status, selected_operator_key)?;

    //         if !is_valid {
    //             info!(
    //                 "Invalid signature detected for slot {}, dispatching OP Disabler Tx",
    //                 slot_index
    //             );
    //             self.dispatch_op_disabler_tx(slot_index, program_context)?;
    //         } else {
    //             info!("Valid signature confirmed for slot {}", slot_index);
    //         }
    //     }
    //     None => {
    //         info!("No selected operator key found for slot {}", slot_index);
    //         // If no selected operator key is set, it means that someone triggered a reimbursment kickoff transaction but there was no advances of funds
    //         self.dispatch_op_disabler_tx(slot_index, program_context)?;
    //     }
    // }

    //     Ok(())
    // }

    fn save_take_utxos(&self, context: &ProgramContext) -> Result<(), BitVMXError> {
        let committee = self.committee(context)?;
        let take_key = &self.take_aggregated_key(context)?;
        let protocol = self.load_or_create_protocol();

        for i in 0..committee.packet_size as usize {
            let name = indexed_name(REIMBURSEMENT_KICKOFF_TX, i);
            let reimbursement_kickoff_tx = protocol.transaction_by_name(&name)?;
            let operator_take_output = OutputType::taproot(AUTO_AMOUNT, &take_key, &[])?;

            let operator_take_utxo = (
                reimbursement_kickoff_tx.compute_txid(),
                0,
                Some(AUTO_AMOUNT),
                Some(operator_take_output),
            );

            let name = indexed_name(REVEAL_INPUT_TX, i);
            let reveal_input_tx = protocol.transaction_by_name(&name)?;
            let operator_won_output = OutputType::taproot(AUTO_AMOUNT, &take_key, &[])?;

            let operator_won_utxo = (
                reveal_input_tx.compute_txid(),
                0,
                Some(AUTO_AMOUNT),
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

    pub fn op_initial_deposit_tx(
        &self,
        tx_name: &str,
        context: &ProgramContext,
    ) -> Result<Transaction, ProtocolBuilderError> {
        info!(
            id = self.ctx.my_idx,
            "Loading OP Initial Deposit transaction for DisputeCore"
        );

        let dispute_core_data: DisputeCoreData = self
            .dispute_core_data(context)
            .map_err(|_e| ProtocolBuilderError::MissingSignature)?;

        if dispute_core_data.operator_index != self.ctx.my_idx {
            info!(
                id = self.ctx.my_idx,
                "Not my dispute_core, skipping dispatch of {} transaction", tx_name
            );
            return Err(ProtocolBuilderError::MissingSignature);
        }

        let mut protocol: Protocol = self.load_protocol()?;
        let signatures = protocol.sign_taproot_input(
            tx_name,
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
                    tx_name, signature
                );
                input_args.push_taproot_signature(signature.unwrap())?;
            }
        }

        info!("Op initial deposit tx signatures: {:?}", input_args);

        protocol.transaction_to_send(&tx_name, &[input_args])
    }

    fn pegout_id_key(
        &self,
        context: &ProgramContext,
        slot_index: usize,
    ) -> Result<key_manager::winternitz::WinternitzPublicKey, BitVMXError> {
        let pegout_id_name = indexed_name(PEGOUT_ID_KEY, slot_index);
        context
            .globals
            .get_var(&self.ctx.id, &pegout_id_name)?
            .ok_or_else(|| BitVMXError::VariableNotFound(self.ctx.id, pegout_id_name.clone()))?
            .wots_pubkey()
    }

    fn pegout_id(
        &self,
        context: &ProgramContext,
        slot_index: usize,
    ) -> Result<Vec<u8>, BitVMXError> {
        context
            .globals
            .get_var(&self.ctx.id, &indexed_name(PEGOUT_ID, slot_index))?
            .unwrap()
            .input()
    }
}
