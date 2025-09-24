use anyhow::Result;
use bitcoin::PublicKey;
use protocol_builder::types::Utxo;
use std::collections::HashMap;

use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::{
            common::get_init_pid,
            types::{Committee, DisputeCoreData, InitData, MemberData, MONITORED_WATCHTOWER_KEY},
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::{IncomingBitVMXApiMessages, PROGRAM_TYPE_INIT},
};
use tracing::info;
use uuid::Uuid;

pub struct InitSetup {}

impl InitSetup {
    pub fn setup(
        committee_id: Uuid,
        my_id: &str,
        members: &Vec<MemberData>,
        take_aggregated_key: PublicKey,
        dispute_aggregated_key: PublicKey,
        bitvmx: &BitVMXClient,
        watchtower_protocol_funding: &HashMap<PublicKey, PartialUtxo>,
        addresses: &Vec<P2PAddress>,
    ) -> Result<()> {
        for (member_index, member) in members.iter().enumerate() {
            let pubkey = member.take_key;
            let protocol_id = get_init_pid(committee_id, &pubkey);
            let watchtower_utxo = watchtower_protocol_funding[&pubkey].clone();
            info!(
                id = my_id,
                "Setting up the Init protocol handler {} for {}", protocol_id, my_id
            );

            // could this data go inside init data?
            let committee = Committee {
                members: members.clone(),
                take_aggregated_key,
                dispute_aggregated_key,
                operator_count: Self::operator_count(&members.clone())?,
                packet_size: 10,
            };

            bitvmx.set_var(
                committee_id,
                &Committee::name(),
                VariableTypes::String(serde_json::to_string(&committee)?),
            )?;
    
            bitvmx.set_var(
                protocol_id,
                &InitData::name(),
                VariableTypes::String(serde_json::to_string(&InitData {
                    committee_id,
                    member_index,
                    watchtower_utxo: watchtower_utxo,
                })?),
            )?;

            // Save the monitored watchtower's take key
            bitvmx.set_var(
                protocol_id,
                MONITORED_WATCHTOWER_KEY,
                VariableTypes::PubKey(pubkey),
            )?;

            bitvmx.setup(
                protocol_id,
                PROGRAM_TYPE_INIT.to_string(),
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
