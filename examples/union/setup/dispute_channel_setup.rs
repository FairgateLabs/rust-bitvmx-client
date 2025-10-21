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
        // wt_funding_utxos_per_member: &HashMap<PublicKey, PartialUtxo>,
        addresses: &Vec<CommsAddress>,
    ) -> Result<usize> {
        let mut total_setups = 0;
        let my_address = addresses[my_index].clone();

        // If I'm an operator, set up dispute channels to all watchtowers
        if members[my_index].role == ParticipantRole::Verifier {
            for wt_index in 0..members.len() {
                if wt_index == my_index {
                    // Skip myself
                    continue;
                }

                let pair_key = pairwise_keys
                    .get(&addresses[wt_index])
                    .cloned()
                    .expect("pairwise key should be present");

                info!(
                    id = my_index,
                    "Setting up DisputeChannel between operator index {} and watchtower index {}",
                    my_index,
                    wt_index
                );

                Self::setup_one(
                    committee_id,
                    my_index,
                    wt_index,
                    &my_address,
                    &addresses[wt_index],
                    &bitvmx,
                    pair_key,
                )?;

                total_setups += 1;
            }
        }

        // Now act as watchtower for other operators
        for member_index in 0..members.len() {
            if members[member_index].role == ParticipantRole::Verifier || member_index == my_index {
                // Skip myself and other watchtowers
                continue;
            }

            let pair_key = pairwise_keys
                .get(&addresses[member_index])
                .cloned()
                .expect("pairwise key should be present");

            info!(
                id = my_index,
                "Setting up DisputeChannel between operator index {} and watchtower index {}",
                member_index,
                my_index
            );

            Self::setup_one(
                committee_id,
                member_index,
                my_index,
                &addresses[member_index],
                &my_address,
                &bitvmx,
                pair_key,
            )?;

            total_setups += 1;
        }

        Ok(total_setups)
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
        let participants: Vec<CommsAddress> = vec![operator.clone(), watchtower.clone()];

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
            "Setting up DisputeChannel PID {} between OP {} and WT {}",
            drp_id, op_index, wt_index,
        );

        bitvmx.setup(drp_id, PROGRAM_TYPE_DRP.to_string(), participants, 0)?;

        Ok(())
    }
}
