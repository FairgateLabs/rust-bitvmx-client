use anyhow::Result;
use bitcoin::PublicKey;
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{CommsAddress, ParticipantRole},
        protocols::union::{common::get_dispute_channel_pid, types::MemberData},
        variables::VariableTypes,
    },
    types::PROGRAM_TYPE_DRP,
};

// const FUNDING_UTXO_SUFFIX: &str = "_FUNDING_UTXO";

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
                Self::setup_one(
                    committee_id,
                    my_index,
                    partner_index,
                    &my_address,
                    partner_address,
                    &bitvmx,
                    pair_key,
                )?;

                total_setups += 1;
            }

            // If my partner is an operator, set up DisputeChannel where they are the operator and I'm the watchtower
            if members[partner_index].role == ParticipantRole::Prover {
                Self::print_setup_info(my_index, partner_index, my_index);
                Self::setup_one(
                    committee_id,
                    partner_index,
                    my_index,
                    &partner_address,
                    &my_address,
                    &bitvmx,
                    pair_key,
                )?;

                total_setups += 1;
            }
        }

        info!("DisputeChannel setup complete ({} setups)", total_setups);
        // TODO: Return total setups when dispute channels are re-enabled
        Ok(0)
        // Ok(total_setups)
    }

    fn setup_one(
        committee_id: Uuid,
        op_index: usize,
        wt_index: usize,
        operator: &CommsAddress,
        watchtower: &CommsAddress,
        bitvmx: &BitVMXClient,
        pair_key: PublicKey,
    ) -> Result<()> {
        let drp_id = get_dispute_channel_pid(committee_id, op_index, wt_index);
        let _participants: Vec<CommsAddress> = vec![operator.clone(), watchtower.clone()];

        // Program vars
        let program_path = "../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world.yaml";
        bitvmx.set_var(
            drp_id,
            "program_definition",
            VariableTypes::String(program_path.to_string()),
        )?;
        bitvmx.set_var(drp_id, "aggregated", VariableTypes::PubKey(pair_key))?;

        // TODO: This should be loaded from WT_START_ENABLER_TX and both should set them consistently?
        // We should request that TX to bitvmx with the proper protocol id using `get_dispute_core_pid()`
        // If I'm a watchtower, provide funding hint
        // if matches!(my_role, ParticipantRole::Verifier) {
        //     if let Some(my_utxo) = wt_funding_utxos_per_member.get(my_take_pubkey) {
        //         let wt_key = format!("{}{}", WATCHTOWER, FUNDING_UTXO_SUFFIX);
        //         bitvmx.set_var(drp_id, &wt_key, VariableTypes::Utxo(my_utxo.clone()))?;
        //         bitvmx.set_var(drp_id, "TIMELOCK_BLOCKS", VariableTypes::Number(1))?;
        //     }
        // }

        info!(
            "Setting up {} PID {} between OP {} and WT {}",
            PROGRAM_TYPE_DRP, drp_id, op_index, wt_index,
        );

        // TODO: re-enable dispute channels once protocol is finalized:
        // blocked by https://trello.com/c/eDA2ltcT/42-dispute-channel
        // bitvmx.setup(drp_id, PROGRAM_TYPE_DRP.to_string(), participants, 0)?;

        Ok(())
    }

    fn print_setup_info(member_index: usize, op_index: usize, wt_index: usize) {
        info!(
            index = member_index,
            "Setting up DisputeChannel between OP {} and WT {}", op_index, wt_index
        );
    }
}
