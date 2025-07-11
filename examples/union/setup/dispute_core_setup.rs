use anyhow::Result;
use std::collections::HashMap;

use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::types::NewCommittee,
        variables::{PartialUtxo, VariableTypes},
    },
    types::PROGRAM_TYPE_DISPUTE_CORE,
};
use tracing::info;
use uuid::Uuid;

use crate::member::{Keyring, Member};

pub struct DisputeCoreSetup {
    pub _covenant_id: Uuid,
    pub _my_member_id: String,
    pub _my_role: ParticipantRole,
    pub _committee: Vec<Member>,
}

impl DisputeCoreSetup {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        covenant_id: Uuid,
        member_index: usize,
        my_id: &str,
        my_role: &ParticipantRole,
        committee: &[Member],
        funding_utxos: &[PartialUtxo],
        keyring: &Keyring,
        bitvmx: &BitVMXClient,
    ) -> Result<DisputeCoreSetup> {
        info!(
            id = my_id,
            "Setting up the DisputeCore protocol handler {} for {}", covenant_id, my_id
        );

        // gather all operator addresses
        // in a real scenario, operators should get this from the chain
        let addresses = Self::get_addresses(committee);

        // build a map of communication pubkeys to addresses
        let mut comms = HashMap::new();
        for member in committee {
            comms.insert(
                member.keyring.communication_pubkey.unwrap(),
                member.address.clone().unwrap(),
            );
        }

        let committe = NewCommittee {
            member_index,
            my_role: my_role.clone(),
            take_aggregated_key: keyring.take_aggregated_key.unwrap(),
            dispute_aggregated_key: keyring.dispute_aggregated_key.unwrap(),
            addresses: comms,
            operator_count: Self::operator_count(committee)?,
            watchtower_count: Self::watchtower_count(committee)?,
            packet_size: 10,
        };

        bitvmx.set_var(
            covenant_id,
            &NewCommittee::name(),
            VariableTypes::String(serde_json::to_string(&committe)?),
        )?;

        let funding_names = ["WT_FUNDING_UTXO", "OP_FUNDING_UTXO"];
        for (i, funding) in funding_utxos.iter().enumerate() {
            let funding_name = funding_names.get(i).unwrap();

            bitvmx.set_var(
                covenant_id,
                funding_name,
                VariableTypes::Utxo(funding.clone()),
            )?;
        }

        bitvmx.setup(
            covenant_id,
            PROGRAM_TYPE_DISPUTE_CORE.to_string(),
            addresses,
            0,
        )?;

        Ok(DisputeCoreSetup {
            _covenant_id: covenant_id,
            _my_member_id: my_id.to_string(),
            _my_role: my_role.clone(),
            _committee: committee.to_vec(),
        })
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
