use anyhow::Result;
use bitcoin::PublicKey;
use protocol_builder::types::Utxo;
use std::collections::HashMap;

use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{CommsAddress, ParticipantRole},
        protocols::union::{
            common::get_dispute_core_pid,
            types::{Committee, DisputeCoreData, MemberData, MONITORED_OPERATOR_KEY},
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::{IncomingBitVMXApiMessages, PROGRAM_TYPE_DISPUTE_CORE},
};
use tracing::info;
use uuid::Uuid;

use crate::participants::committee::PACKET_SIZE;

pub struct DisputeCoreSetup {}

impl DisputeCoreSetup {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        committee_id: Uuid,
        my_id: &str,
        members: &Vec<MemberData>,
        take_aggregated_key: PublicKey,
        dispute_aggregated_key: PublicKey,
        bitvmx: &BitVMXClient,
        members_protocol_funding: &HashMap<PublicKey, PartialUtxo>,
        my_speedup_funding: &Utxo,
        addresses: &Vec<CommsAddress>,
    ) -> Result<()> {
        let committee = Committee {
            members: members.clone(),
            take_aggregated_key,
            dispute_aggregated_key,
            packet_size: PACKET_SIZE,
        };

        bitvmx.send_message(IncomingBitVMXApiMessages::SetFundingUtxo(
            my_speedup_funding.clone(),
        ))?;

        bitvmx.set_var(
            committee_id,
            &Committee::name(),
            VariableTypes::String(serde_json::to_string(&committee)?),
        )?;

        for (member_index, member) in members.iter().enumerate() {
            let pubkey = member.take_key;
            let protocol_id = get_dispute_core_pid(committee_id, &pubkey);
            let funding_utxo = members_protocol_funding[&pubkey].clone();
            info!(
                id = my_id,
                "Setting up the DisputeCore protocol handler {} for {}", protocol_id, my_id
            );

            bitvmx.set_var(
                protocol_id,
                &DisputeCoreData::name(),
                VariableTypes::String(serde_json::to_string(&DisputeCoreData {
                    committee_id,
                    member_index,
                    funding_utxo,
                })?),
            )?;

            // FIXME: Should this be removed? Where is it used?
            // Save the monitored operator's take key
            bitvmx.set_var(
                protocol_id,
                MONITORED_OPERATOR_KEY,
                VariableTypes::PubKey(pubkey),
            )?;

            bitvmx.setup(
                protocol_id,
                PROGRAM_TYPE_DISPUTE_CORE.to_string(),
                addresses.clone(),
                0,
            )?;
        }

        Ok(())
    }

    fn operator_count(members: &Vec<MemberData>) -> Result<u32> {
        Ok(members
            .iter()
            .filter(|m| m.role == ParticipantRole::Prover)
            .count() as u32)
    }
}
