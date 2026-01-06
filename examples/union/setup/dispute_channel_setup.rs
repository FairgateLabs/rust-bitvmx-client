use anyhow::Result;
use bitcoin::PublicKey;
use emulator::decision::challenge::{ForceChallenge, ForceCondition};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

use crate::wait_until_msg;
use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{CommsAddress, ParticipantRole},
        protocols::{
            dispute::{
                config::{ConfigResult, ForceFailConfiguration, DisputeConfiguration},
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

const DRP_PROGRAM_DEFINITION: &str = "../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world.yaml"; // TODO move to config?

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

        let dispute_configuration = DisputeConfiguration::new(
            drp_id,
            pair_key,
            (op_cosign, vec![]),
            vec![(op_stopper, vec![1])], // Consume leaf 1
            vec![],
            vec![(wt_stopper, vec![1])], // Consume leaf 1
            vec![],
            DRP_TIMELOCK_BLOCKS,
            DRP_PROGRAM_DEFINITION.to_string(),
            Some(dispute_config), // FIXME: Remove this setting for production, use 'None' instead.
            vec![(PROGRAM_TYPE_DISPUTE_CORE.to_string(), dispute_core_pid)],
            Some(0),
        );

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
