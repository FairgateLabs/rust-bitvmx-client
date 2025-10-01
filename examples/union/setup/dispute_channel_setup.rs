use anyhow::Result;
use bitcoin::PublicKey;
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

use bitvmx_client::{
    program::participant::{CommsAddress, ParticipantRole},
    program::protocols::union::{
        common::get_dispute_channel_pid,
        types::{FUNDING_UTXO_SUFFIX, WATCHTOWER},
    },
    program::variables::{PartialUtxo, VariableTypes},
    types::PROGRAM_TYPE_DRP,
};

use crate::participants::member::Member;

pub struct DisputeChannelSetup;

impl DisputeChannelSetup {
    pub fn setup(
        member: &mut Member,
        members: &Vec<Member>,
        committee_id: Uuid,
        wt_funding_utxos_per_member: &HashMap<PublicKey, PartialUtxo>,
    ) -> Result<()> {
        let my_addr = member
            .address
            .as_ref()
            .expect("member address not set")
            .clone();

        // Stable ordering by member id
        let mut sorted = members.clone();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));

        for i in 0..sorted.len() {
            for j in (i + 1)..sorted.len() {
                let m1 = &sorted[i];
                let m2 = &sorted[j];
                let a1 = m1.address.as_ref().expect("member address not set");
                let a2 = m2.address.as_ref().expect("member address not set");
                let r1 = &m1.role;
                let r2 = &m2.role;

                // Skip if I'm not part of the pair
                if my_addr != *a1 && my_addr != *a2 { continue; }

                // Helper to setup one directional DRP
                let setup_one = |from_idx: usize, to_idx: usize, first: &CommsAddress, second: &CommsAddress| -> Result<()> {
                    let drp_id = get_dispute_channel_pid(committee_id, from_idx, to_idx);
                    let participants: Vec<CommsAddress> = vec![first.clone(), second.clone()];
                    let my_idx = if my_addr == *first { 0 } else { 1 };

                    // Aggregated pairwise key
                    let counterparty = if my_addr == *first { second } else { first };
                    let pair_key = member
                        .keyring
                        .pairwise_keys
                        .get(counterparty)
                        .cloned()
                        .expect("pairwise key should be present");

                    // Program vars
                    let program_path = "../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world.yaml";
                    member.bitvmx.set_var(drp_id, "program_definition", VariableTypes::String(program_path.to_string()))?;
                    member.bitvmx.set_var(drp_id, "aggregated", VariableTypes::PubKey(pair_key))?;

                    // If I'm a watchtower, provide funding hint
                    if matches!(member.role, ParticipantRole::Verifier) {
                        if let Some(my_take) = member.keyring.take_pubkey.as_ref() {
                            if let Some(my_utxo) = wt_funding_utxos_per_member.get(my_take) {
                                let wt_key = format!("{}{}", WATCHTOWER, FUNDING_UTXO_SUFFIX);
                                member.bitvmx.set_var(drp_id, &wt_key, VariableTypes::Utxo(my_utxo.clone()))?;
                                member.bitvmx.set_var(drp_id, "TIMELOCK_BLOCKS", VariableTypes::Number(1))?;
                            }
                        }
                    }

                    member.bitvmx.setup(drp_id, PROGRAM_TYPE_DRP.to_string(), participants, 0)?;
                    info!(id = member.id, drp = ?drp_id, dir = %format!("{}->{}", m1.id, m2.id), my_idx = my_idx, "Setup Dispute Channel");
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
