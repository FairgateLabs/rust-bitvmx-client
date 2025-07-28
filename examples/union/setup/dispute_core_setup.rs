use anyhow::Result;
use bitcoin::PublicKey;
use std::collections::HashMap;

use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::{common::get_dispute_core_id, types::Committee},
        variables::{PartialUtxo, VariableTypes},
    },
    types::PROGRAM_TYPE_DISPUTE_CORE,
};
use tracing::info;
use uuid::Uuid;

use crate::participants::member::{Keyring, Member};

pub struct DisputeCoreSetup {}

impl DisputeCoreSetup {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        committee_id: Uuid,
        my_id: &str,
        my_role: &ParticipantRole,
        members: &[Member],
        keyring: &Keyring,
        bitvmx: &BitVMXClient,
        funding_utxos_per_member: &HashMap<PublicKey, Vec<PartialUtxo>>,
    ) -> Result<()> {
        let mut committee = Committee {
            my_role: my_role.clone(),
            take_aggregated_key: keyring.take_aggregated_key.unwrap(),
            dispute_aggregated_key: keyring.dispute_aggregated_key.unwrap(),
            operator_count: Self::operator_count(members)?,
            watchtower_count: Self::watchtower_count(members)?,
            packet_size: 10,
            member_index: 0,
        };

        for (member_index, member) in members.iter().enumerate() {
            if member.role == ParticipantRole::Prover {
                let pubkey = member.keyring.take_pubkey.unwrap();
                let protocol_id = get_dispute_core_id(committee_id, &pubkey);
                let funding_utxos = funding_utxos_per_member[&pubkey].clone();

                info!(
                    id = my_id,
                    "Setting up the DisputeCore protocol handler {} for {}", protocol_id, my_id
                );

                committee.member_index = member_index;

                bitvmx.set_var(
                    protocol_id,
                    &Committee::name(),
                    VariableTypes::String(serde_json::to_string(&committee)?),
                )?;

                let funding_names = ["WT_FUNDING_UTXO", "OP_FUNDING_UTXO"];
                for (i, funding) in funding_utxos.iter().enumerate() {
                    let funding_name = funding_names.get(i).unwrap();
                    bitvmx.set_var(
                        protocol_id,
                        funding_name,
                        VariableTypes::Utxo(funding.clone()),
                    )?;
                }

                bitvmx.setup(
                    protocol_id,
                    PROGRAM_TYPE_DISPUTE_CORE.to_string(),
                    Self::get_addresses(members),
                    0,
                )?;
            }
        }

        Ok(())
    }

    fn operator_count(members: &[Member]) -> Result<u32> {
        Ok(members
            .iter()
            .filter(|m| m.role == ParticipantRole::Prover)
            .count() as u32)
    }

    fn watchtower_count(members: &[Member]) -> Result<u32> {
        Ok(members
            .iter()
            .filter(|m| m.role == ParticipantRole::Verifier)
            .count() as u32)
    }

    /// Get all addresses from a list of members
    fn get_addresses(members: &[Member]) -> Vec<P2PAddress> {
        members.iter().filter_map(|m| m.address.clone()).collect()
    }
}
