use anyhow::Result;
use std::collections::HashMap;

use bitcoin::PublicKey;
use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::events::CommitteeCreated,
        variables::{PartialUtxo, VariableTypes},
    },
    types::PROGRAM_TYPE_DISPUTE_CORE,
};
use tracing::info;
use uuid::Uuid;

use crate::member::{Keyring, Member};

pub struct DisputeCore {
    pub covenant_id: Uuid,
    pub my_member_id: String,
    pub my_role: ParticipantRole,
    pub members: Vec<Member>,
}

impl DisputeCore {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        covenant_id: Uuid,
        member_id: &str,
        role: &ParticipantRole,
        members: &[Member],
        members_take_pubkeys: &[PublicKey],
        members_dispute_pubkeys: &[PublicKey],
        op_funding_utxos: &HashMap<String, PartialUtxo>,
        wt_funding_utxos: &HashMap<String, PartialUtxo>,
        keyring: &Keyring,
        bitvmx: BitVMXClient,
    ) -> Result<DisputeCore> {
        let addresses = Self::get_addresses(members);

        info!(
            id = member_id,
            "Preparing Dispute Core covenant {} for {}", covenant_id, member_id
        );

        // build a map of communication pubkeys to addresses
        let mut comms = HashMap::new();
        for member in members {
            comms.insert(
                member.keyring.communication_pubkey.unwrap(),
                member.address.clone().unwrap(),
            );
        }

        let committee_created = CommitteeCreated {
            my_role: role.clone(),
            my_take_pubkey: keyring.take_pubkey.unwrap(),
            my_dispute_pubkey: keyring.dispute_pubkey.unwrap(),
            take_pubkeys: members_take_pubkeys.to_vec(),
            dispute_pubkeys: members_dispute_pubkeys.to_vec(),
            addresses: comms,
            operator_count: Self::operator_count(members)?,
            watchtower_count: Self::watchtower_count(members)?,
        };

        bitvmx.set_var(
            covenant_id,
            &CommitteeCreated::name(),
            VariableTypes::String(serde_json::to_string(&committee_created)?),
        )?;

        if *role == ParticipantRole::Prover {
            bitvmx.set_var(
                covenant_id,
                "OP_FUNDING_UTXO",
                VariableTypes::Utxo(
                    op_funding_utxos
                        .get(&member_id.to_string())
                        .unwrap()
                        .clone(),
                ),
            )?;
        }

        bitvmx.set_var(
            covenant_id,
            "WT_FUNDING_UTXO",
            VariableTypes::Utxo(
                wt_funding_utxos
                    .get(&member_id.to_string())
                    .unwrap()
                    .clone(),
            ),
        )?;

        bitvmx.set_var(
            covenant_id,
            "take_aggregated_key",
            VariableTypes::PubKey(keyring.take_aggregated_key.clone().unwrap()),
        )?;

        bitvmx.set_var(
            covenant_id,
            "dispute_aggregated_key",
            VariableTypes::PubKey(keyring.dispute_aggregated_key.clone().unwrap()),
        )?;

        bitvmx.setup(
            covenant_id,
            PROGRAM_TYPE_DISPUTE_CORE.to_string(),
            addresses,
            0,
        )?;

        Ok(DisputeCore {
            covenant_id,
            my_member_id: member_id.to_string(),
            my_role: role.clone(),
            members: members.to_vec(),
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
