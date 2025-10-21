use anyhow::Result;
use bitcoin::PublicKey;
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{CommsAddress, ParticipantRole},
        protocols::union::{
            common::get_dispute_channel_pid,
            types::{MemberData, WATCHTOWER},
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::PROGRAM_TYPE_DRP,
};

const FUNDING_UTXO_SUFFIX: &str = "_FUNDING_UTXO";

pub struct DisputeChannelSetup;

impl DisputeChannelSetup {
    pub fn setup(
        my_id: &str,
        my_address: &CommsAddress,
        my_role: &ParticipantRole,
        my_take_pubkey: &PublicKey,
        pairwise_keys: &HashMap<CommsAddress, PublicKey>,
        bitvmx: &BitVMXClient,
        members: &Vec<MemberData>,
        committee_id: Uuid,
        wt_funding_utxos_per_member: &HashMap<PublicKey, PartialUtxo>,
        addresses: &Vec<CommsAddress>,
    ) -> Result<()> {
        let my_addr = my_address.clone();

        for i in 0..addresses.len() {
            for j in (i + 1)..addresses.len() {
                let r1 = &members[i].role;
                let r2 = &members[j].role;
                let a1 = &addresses[i];
                let a2 = &addresses[j];

                // Skip if I'm not part of the pair
                if my_addr != *a1 && my_addr != *a2 {
                    continue;
                }

                // Helper to setup one directional DRP
                let setup_one = |from_idx: usize,
                                 to_idx: usize,
                                 first: &CommsAddress,
                                 second: &CommsAddress|
                 -> Result<()> {
                    let drp_id = get_dispute_channel_pid(committee_id, from_idx, to_idx);
                    let participants: Vec<CommsAddress> = vec![first.clone(), second.clone()];
                    let my_idx = if my_addr == *first { 0 } else { 1 };

                    // Aggregated pairwise key
                    let counterparty = if my_addr == *first { second } else { first };
                    let pair_key = pairwise_keys
                        .get(counterparty)
                        .cloned()
                        .expect("pairwise key should be present");

                    // Program vars
                    let program_path =
                        "../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world.yaml";
                    bitvmx.set_var(
                        drp_id,
                        "program_definition",
                        VariableTypes::String(program_path.to_string()),
                    )?;
                    bitvmx.set_var(drp_id, "aggregated", VariableTypes::PubKey(pair_key))?;

                    // If I'm a watchtower, provide funding hint
                    if matches!(my_role, ParticipantRole::Verifier) {
                        if let Some(my_utxo) = wt_funding_utxos_per_member.get(my_take_pubkey) {
                            let wt_key = format!("{}{}", WATCHTOWER, FUNDING_UTXO_SUFFIX);
                            bitvmx.set_var(
                                drp_id,
                                &wt_key,
                                VariableTypes::Utxo(my_utxo.clone()),
                            )?;
                            bitvmx.set_var(drp_id, "TIMELOCK_BLOCKS", VariableTypes::Number(1))?;
                        }
                    }

                    bitvmx.setup(drp_id, PROGRAM_TYPE_DRP.to_string(), participants, 0)?;
                    info!(id = my_id, drp = ?drp_id, dir = %format!("{}->{}", first.address, second.address), my_idx = my_idx, "Setup Dispute Channel");
                    Ok(())
                };

                match (r1, r2) {
                    // Two operators → two DRPs (both directions)
                    (ParticipantRole::Prover, ParticipantRole::Prover) => {
                        setup_one(i, j, a1, a2)?;
                        setup_one(j, i, a2, a1)?;
                    }
                    // Operator + Watchtower → one DRP: Operator -> Watchtower
                    (ParticipantRole::Prover, ParticipantRole::Verifier) => {
                        setup_one(i, j, a1, a2)?;
                    }
                    (ParticipantRole::Verifier, ParticipantRole::Prover) => {
                        setup_one(j, i, a2, a1)?;
                    }
                    // Two watchtowers → skip
                    (ParticipantRole::Verifier, ParticipantRole::Verifier) => {}
                }
            }
        }

        Ok(())
    }
}
