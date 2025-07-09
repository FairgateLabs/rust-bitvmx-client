use anyhow::Result;
use std::collections::HashMap;

use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::types::CommitteeCreated,
        variables::{PartialUtxo, VariableTypes},
    },
    types::PROGRAM_TYPE_DISPUTE_CORE,
};
use tracing::info;
use uuid::Uuid;

use crate::member::{Keyring, Member};

pub struct DisputeCore {
    pub _covenant_id: Uuid,
    pub _my_member_id: String,
    pub _my_role: ParticipantRole,
    pub _committee: Vec<Member>,
}

impl DisputeCore {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        covenant_id: Uuid,
        my_id: &str,
        my_role: &ParticipantRole,
        committee: &[Member],
        op_funding_utxos: &HashMap<String, PartialUtxo>,
        wt_funding_utxos: &HashMap<String, PartialUtxo>,
        keyring: &Keyring,
        bitvmx: &BitVMXClient,
    ) -> Result<DisputeCore> {
        let addresses = Self::get_addresses(committee);

        info!(
            id = my_id,
            "Preparing Dispute Core covenant {} for {}", covenant_id, my_id
        );

        // build a map of communication pubkeys to addresses
        let mut comms = HashMap::new();
        for member in committee {
            comms.insert(
                member.keyring.communication_pubkey.unwrap(),
                member.address.clone().unwrap(),
            );
        }

        let committee_created = CommitteeCreated {
            my_role: my_role.clone(),
            my_take_pubkey: keyring.take_pubkey.unwrap(),
            my_dispute_pubkey: keyring.dispute_pubkey.unwrap(),
            take_aggregated_key: keyring.take_aggregated_key.unwrap(),
            dispute_aggregated_key: keyring.dispute_aggregated_key.unwrap(),
            addresses: comms,
            operator_count: Self::operator_count(committee)?,
            watchtower_count: Self::watchtower_count(committee)?,
        };

        bitvmx.set_var(
            covenant_id,
            &CommitteeCreated::name(),
            VariableTypes::String(serde_json::to_string(&committee_created)?),
        )?;

        if *my_role == ParticipantRole::Prover {
            bitvmx.set_var(
                covenant_id,
                "OP_FUNDING_UTXO",
                VariableTypes::Utxo(op_funding_utxos.get(&my_id.to_string()).unwrap().clone()),
            )?;
        }

        bitvmx.set_var(
            covenant_id,
            "WT_FUNDING_UTXO",
            VariableTypes::Utxo(wt_funding_utxos.get(&my_id.to_string()).unwrap().clone()),
        )?;

        bitvmx.setup(
            covenant_id,
            PROGRAM_TYPE_DISPUTE_CORE.to_string(),
            addresses,
            0,
        )?;

        Ok(DisputeCore {
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
