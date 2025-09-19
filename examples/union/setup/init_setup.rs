use anyhow::Result;
use bitcoin::PublicKey;
use protocol_builder::types::Utxo;
use std::collections::HashMap;

use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::{
            // common::get_init_pid,
            types::{Committee, DisputeCoreData, MemberData, MONITORED_OPERATOR_KEY},
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
        operator_protocol_funding: &HashMap<PublicKey, PartialUtxo>,
        addresses: &Vec<P2PAddress>,
    ) -> Result<()> {
        Ok(())
    }
}
