use anyhow::Result;
use bitcoin::PublicKey;
use std::collections::HashMap;

use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::{
            common::get_dispute_core_pid,
            types::{Committee, DisputeCoreData, MemberData, MONITORED_OPERATOR_KEY},
        },
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
        members: &[Member],
        keyring: &Keyring,
        bitvmx: &BitVMXClient,
        funding_utxos_per_member: &HashMap<PublicKey, PartialUtxo>,
    ) -> Result<()> {
        let committee = Committee {
            members: members
                .iter()
                .map(|m| MemberData {
                    role: m.role.clone(),
                    take_key: m.keyring.take_pubkey.unwrap(),
                    dispute_key: m.keyring.dispute_pubkey.unwrap(),
                })
                .collect(),
            take_aggregated_key: keyring.take_aggregated_key.unwrap(),
            dispute_aggregated_key: keyring.dispute_aggregated_key.unwrap(),
            operator_count: Self::operator_count(members)?,
            packet_size: 10,
        };

        bitvmx.set_var(
            committee_id,
            &Committee::name(),
            VariableTypes::String(serde_json::to_string(&committee)?),
        )?;

        for (operator_index, member) in members.iter().enumerate() {
            if member.role == ParticipantRole::Prover {
                let pubkey = member.keyring.take_pubkey.unwrap();
                let protocol_id = get_dispute_core_pid(committee_id, &pubkey);
                let operator_utxo = funding_utxos_per_member[&pubkey].clone();
                info!(
                    id = my_id,
                    "Setting up the DisputeCore protocol handler {} for {}", protocol_id, my_id
                );

                bitvmx.set_var(
                    protocol_id,
                    &DisputeCoreData::name(),
                    VariableTypes::String(serde_json::to_string(&DisputeCoreData {
                        committee_id,
                        operator_index,
                        operator_utxo: operator_utxo,
                        operator_take_pubkey: pubkey,
                    })?),
                )?;

                // Save the monitored operator's take key
                bitvmx.set_var(
                    protocol_id,
                    MONITORED_OPERATOR_KEY,
                    VariableTypes::PubKey(pubkey),
                )?;

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

    /// Get all addresses from a list of members
    fn get_addresses(members: &[Member]) -> Vec<P2PAddress> {
        members.iter().filter_map(|m| m.address.clone()).collect()
    }
}
