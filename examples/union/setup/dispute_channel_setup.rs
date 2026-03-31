use anyhow::Result;
use bitcoin::PublicKey;
use emulator::decision::challenge::{ForceChallenge, ForceCondition};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

use key_manager::winternitz::{
    self, checksum_length, to_checksummed_message, WinternitzPublicKey, WinternitzSignature,
    WinternitzType,
};

use crate::{participants::common::set_program_input, wait_until_msg};
use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{CommsAddress, ParticipantRole},
        protocols::{
            dispute::{
                config::{ConfigResult, DisputeConfiguration, ForceFailConfiguration},
                program_input_prev_prefix, program_input_prev_protocol,
                TIMELOCK_BLOCKS as DRP_TIMELOCK_BLOCKS,
            },
            union::{
                common::{get_dispute_channel_pid, get_dispute_core_pid},
                types::{
                    MemberData, WtInitChallengeUtxos, OP_COSIGN_UTXOS, WT_INIT_CHALLENGE_UTXOS,
                },
            },
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::{OutgoingBitVMXApiMessages, PROGRAM_TYPE_DISPUTE_CORE, PROGRAM_TYPE_DRP},
};

#[allow(dead_code)]
#[derive(Debug)]
pub enum DRPVerifier {
    Demo,
    Generic,
    Union,
}

pub const VERIFIER: DRPVerifier = DRPVerifier::Generic;

pub struct DisputeChannelSetup;

impl DisputeChannelSetup {
    pub fn setup(
        my_index: usize,
        pairwise_keys: &HashMap<CommsAddress, PublicKey>,
        bitvmx: &BitVMXClient,
        members: &Vec<MemberData>,
        committee_id: Uuid,
        addresses: &Vec<CommsAddress>,
    ) -> Result<usize> {
        let drp_program_definition = match VERIFIER {
            DRPVerifier::Demo => "../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world.yaml",
            DRPVerifier::Generic => "../rust-bitvmx-client/verifiers/generic-verifier.yaml", // This should be accessible from client and from job dispatcher
            DRPVerifier::Union => "../rust-bitvmx-client/verifiers/union-verifier.yaml", // This should be accessible from client and from job dispatcher
        };

        let mut total_setups = 0;
        let my_address = addresses[my_index].clone();
        let prover = members[my_index].role == ParticipantRole::Prover;
        let my_dispute_core_pid = get_dispute_core_pid(committee_id, &members[my_index].take_key);

        let my_op_cosign_utxos = Self::op_cosign_utxos(my_dispute_core_pid, bitvmx)?;
        let my_claim_gate_stoppers = Self::wt_init_challenge_utxos(my_dispute_core_pid, &bitvmx)?;

        // Iterate over partners
        for partner_index in 0..members.len() {
            if partner_index == my_index
                || (!prover && members[partner_index].role != ParticipantRole::Prover)
            {
                // Skip myself and verifiers pair
                continue;
            }

            // Set partner address and key pair
            let partner_address = &addresses[partner_index];
            let pair_key = pairwise_keys
                .get(&partner_address)
                .cloned()
                .expect("pairwise key should be present");

            // If I'm an operator, set up DisputeChannel where I'm the operator and my partner is the watchtower
            if prover {
                Self::print_setup_info(my_index, my_index, partner_index);

                let partner_dispute_core_pid =
                    get_dispute_core_pid(committee_id, &members[partner_index].take_key);

                let partner_claim_gate_stoppers =
                    Self::wt_init_challenge_utxos(partner_dispute_core_pid, &bitvmx)?;

                let partner_op_cosign_utxos =
                    Self::op_cosign_utxos(partner_dispute_core_pid, &bitvmx)?;

                let partner_stoppers = partner_claim_gate_stoppers[my_index].clone().unwrap();
                let wt_takekey = &members[partner_index].take_key;

                Self::setup_one(
                    committee_id,
                    my_index,
                    partner_index,
                    &my_address,
                    partner_address,
                    &bitvmx,
                    pair_key,
                    partner_stoppers.wt_stopper,
                    partner_stoppers.op_stopper,
                    partner_op_cosign_utxos[my_index].clone().unwrap(),
                    wt_takekey,
                    drp_program_definition,
                )?;

                total_setups += 1;
            }

            // If my partner is an operator, set up DisputeChannel where they are the operator and I'm the watchtower
            if members[partner_index].role == ParticipantRole::Prover {
                Self::print_setup_info(my_index, partner_index, my_index);

                let my_stoppers = my_claim_gate_stoppers[partner_index].clone().unwrap();
                let wt_takekey = &members[my_index].take_key;

                Self::setup_one(
                    committee_id,
                    partner_index,
                    my_index,
                    &partner_address,
                    &my_address,
                    &bitvmx,
                    pair_key,
                    my_stoppers.wt_stopper,
                    my_stoppers.op_stopper,
                    my_op_cosign_utxos[partner_index].clone().unwrap(),
                    wt_takekey,
                    drp_program_definition,
                )?;

                total_setups += 1;
            }
        }

        info!("DisputeChannel ({} setups)", total_setups);
        Ok(total_setups)
    }

    fn wt_init_challenge_utxos(
        dispute_core_pid: Uuid,
        bitvmx: &BitVMXClient,
    ) -> Result<Vec<Option<WtInitChallengeUtxos>>> {
        bitvmx.get_var(dispute_core_pid, WT_INIT_CHALLENGE_UTXOS.to_string())?;
        std::thread::sleep(std::time::Duration::from_secs(1)); // wait a bit for the message to be processed

        let variable =
            wait_until_msg!(&bitvmx, OutgoingBitVMXApiMessages::Variable(_, _, _var) => _var);

        let data = variable.string()?;
        let claim_stoppers: Vec<Option<WtInitChallengeUtxos>> = serde_json::from_str(&data)?;
        Ok(claim_stoppers)
    }

    fn op_cosign_utxos(
        dispute_core_pid: Uuid,
        bitvmx: &BitVMXClient,
    ) -> Result<Vec<Option<PartialUtxo>>> {
        bitvmx.get_var(dispute_core_pid, OP_COSIGN_UTXOS.to_string())?;
        std::thread::sleep(std::time::Duration::from_secs(1)); // wait a bit for the message to be processed

        let variable =
            wait_until_msg!(&bitvmx, OutgoingBitVMXApiMessages::Variable(_, _, _var) => _var);

        let data = variable.string()?;
        let op_cosign_utxos: Vec<Option<PartialUtxo>> = serde_json::from_str(&data)?;
        Ok(op_cosign_utxos)
    }

    fn setup_one(
        committee_id: Uuid,
        op_index: usize,
        wt_index: usize,
        operator: &CommsAddress,
        watchtower: &CommsAddress,
        bitvmx: &BitVMXClient,
        pair_key: PublicKey,
        wt_stopper: PartialUtxo,
        op_stopper: PartialUtxo,
        op_cosign: PartialUtxo,
        wt_takekey: &PublicKey,
        drp_program_definition: &str,
    ) -> Result<()> {
        let drp_id = get_dispute_channel_pid(committee_id, op_index, wt_index);
        let dispute_core_pid = get_dispute_core_pid(committee_id, wt_takekey);
        let participants: Vec<CommsAddress> = vec![operator.clone(), watchtower.clone()];

        info!(
            "Setting up {} PID {} between OP {} and WT {}",
            PROGRAM_TYPE_DRP, drp_id, op_index, wt_index,
        );

        let dispute_config = ForceFailConfiguration {
            prover_force_second_nary: false,
            fail_input_tx: None,
            main: ConfigResult {
                fail_config_prover: None,
                fail_config_verifier: None,
                force_challenge: ForceChallenge::No,
                force_condition: ForceCondition::Always,
            },
            read: ConfigResult::default(),
        };

        // First transaction that it should dispatch automatically.
        let auto_dispatch = match VERIFIER {
            DRPVerifier::Demo => Some(0),
            DRPVerifier::Generic => Some(2),
            DRPVerifier::Union => Some(2),
        };

        let timelock_blocks = match VERIFIER {
            DRPVerifier::Demo => DRP_TIMELOCK_BLOCKS,
            DRPVerifier::Generic => DRP_TIMELOCK_BLOCKS * 4,
            DRPVerifier::Union => DRP_TIMELOCK_BLOCKS * 4, // Finetune this value. It also depend on the block's minning frequency (on regtest)
        };

        let dispute_configuration = DisputeConfiguration::new(
            drp_id,
            pair_key,
            (op_cosign, 1),              // Consume leaf 1
            vec![(op_stopper, vec![1])], // Consume leaf 1
            vec![],
            vec![(wt_stopper, vec![1])], // Consume leaf 1
            vec![],
            timelock_blocks,
            drp_program_definition.to_string(),
            Some(dispute_config), // FIXME: Remove this setting for production, use 'None' instead.
            vec![(PROGRAM_TYPE_DISPUTE_CORE.to_string(), dispute_core_pid)],
            auto_dispatch,
        );

        match VERIFIER {
            DRPVerifier::Union => {
                let journal_size: u32 = 76 / 4;
                let journal_size_input = journal_size.to_le_bytes().to_vec();
                info!("journal_size_input: {:?}", journal_size_input);

                let elf_id = "589837bb0123b9d5854e0807a8b3ed2b15a848c19e2287ac585a31ec93d711b5"; // Placeholder for the actual ELF ID of the verifier
                let elf_id_input = hex::decode(elf_id).unwrap();

                // Set DRP constants
                set_program_input(&bitvmx, drp_id, 0, journal_size_input.clone())?;
                set_program_input(&bitvmx, drp_id, 1, elf_id_input.clone())?;
            }
            DRPVerifier::Generic => {
                let journal_size: u32 = 1;
                let journal_size_input = journal_size.to_le_bytes().to_vec();
                info!("journal_size_input: {:?}", journal_size_input);

                let elf_id = "311021d9b7a1a876e7fa25caabaa0ebc9c944782d530521059113caefa0b81d1"; // Placeholder for the actual ELF ID of the verifier
                let elf_id_input = hex::decode(elf_id).unwrap();

                // Fake data generation. DO NOT USE IN PRODUCTION.
                let pub_key = derive_winternitz(4, 0);

                // name the variables in a way that can be indexed by word
                bitvmx.set_var(
                    dispute_core_pid,
                    &"previous_input_0".to_string(),
                    VariableTypes::WinternitzPubKey(pub_key),
                )?;

                //configure the dispute so is able to retrive the data from previous protocols
                bitvmx.set_var(
                    drp_id,
                    &program_input_prev_protocol(3),
                    VariableTypes::Uuid(dispute_core_pid),
                )?;

                bitvmx.set_var(
                    drp_id,
                    &program_input_prev_prefix(3),
                    VariableTypes::String("previous_input_".to_string()),
                )?;

                // Set DRP constants
                set_program_input(&bitvmx, drp_id, 0, journal_size_input.clone())?;
                set_program_input(&bitvmx, drp_id, 1, elf_id_input.clone())?;
            }
            DRPVerifier::Demo => {
                // No specific input needed for the demo verifier
            }
        }

        bitvmx.set_var(
            drp_id,
            "dispute_configuration",
            VariableTypes::String(serde_json::to_string(&dispute_configuration)?),
        )?;

        bitvmx.setup(drp_id, PROGRAM_TYPE_DRP.to_string(), participants, 0)?;

        Ok(())
    }

    fn print_setup_info(member_index: usize, op_index: usize, wt_index: usize) {
        info!(
            index = member_index,
            "Setting up DisputeChannel between OP {} and WT {}", op_index, wt_index
        );
    }
}

// Just for testing purposes, DO NOT USE THIS IN PRODUCTION.
pub fn derive_winternitz(message_size_in_bytes: usize, index: u32) -> WinternitzPublicKey {
    let message_digits_length = winternitz::message_digits_length(message_size_in_bytes);
    let checksum_size = checksum_length(message_digits_length);

    let winternitz = winternitz::Winternitz::new();
    let master_secret = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    let public_key = winternitz
        .generate_public_key(
            &master_secret,
            WinternitzType::HASH160,
            message_digits_length,
            checksum_size,
            index,
        )
        .unwrap();

    public_key
}

// Just for testing purposes, DO NOT USE THIS IN PRODUCTION.
pub fn sign_winternitz_message(message_bytes: &[u8], index: u32) -> WinternitzSignature {
    let message_digits_length = winternitz::message_digits_length(message_bytes.len());
    let checksummed_message = to_checksummed_message(message_bytes);
    let checksum_size = checksum_length(message_digits_length);
    let message_size = checksummed_message.len() - checksum_size;

    assert!(message_size == message_digits_length);

    let master_secret = vec![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let winternitz = winternitz::Winternitz::new();
    let private_key = winternitz
        .generate_private_key(
            &master_secret,
            WinternitzType::HASH160,
            message_size,
            checksum_size,
            index,
        )
        .unwrap();

    let signature =
        winternitz.sign_message(message_digits_length, &checksummed_message, &private_key);

    signature
}
