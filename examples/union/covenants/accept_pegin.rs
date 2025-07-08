use std::collections::HashMap;

use anyhow::Result;
use bitcoin::Txid;
use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::types::PegInRequest,
        variables::VariableTypes,
    },
    types::PROGRAM_TYPE_ACCEPT_PEG_IN,
};
use tracing::info;
use uuid::Uuid;

use crate::member::{Keyring, Member};

pub struct AcceptPegIn {
    pub covenant_id: Uuid,
    pub my_member_id: String,
    pub my_role: ParticipantRole,
    pub committee: Vec<Member>,
}

impl AcceptPegIn {
    pub fn setup(
        covenant_id: Uuid,
        my_id: &str,
        my_role: &ParticipantRole,
        committee: &[Member],
        request_peg_in_txid: Txid,
        request_peg_in_amount: u64,
        keyring: &Keyring,
        bitvmx: &BitVMXClient,
    ) -> Result<AcceptPegIn> {
        let addresses = Self::get_addresses(committee);

        info!(
            id = my_id,
            "Preparing Accept Peg In covenant {} for {}", covenant_id, my_id
        );

        // build a map of communication pubkeys to addresses
        let mut comms = HashMap::new();
        for member in committee {
            comms.insert(
                member.keyring.communication_pubkey.unwrap(),
                member.address.clone().unwrap(),
            );
        }

        let peg_in_request = PegInRequest {
            my_role: my_role.clone(),
            txid: request_peg_in_txid,
            amount: request_peg_in_amount,
            take_aggregated_key: keyring.take_aggregated_key.clone().unwrap(),
            addresses: comms,
        };

        bitvmx.set_var(
            covenant_id,
            &PegInRequest::name(),
            VariableTypes::String(serde_json::to_string(&peg_in_request)?),
        )?;

        bitvmx.setup(
            covenant_id,
            PROGRAM_TYPE_ACCEPT_PEG_IN.to_string(),
            addresses,
            0,
        )?;

        Ok(AcceptPegIn {
            covenant_id,
            my_member_id: my_id.to_string(),
            my_role: my_role.clone(),
            committee: committee.to_vec(),
        })
    }

    fn get_addresses(committee: &[Member]) -> Vec<P2PAddress> {
        committee
            .iter()
            .map(|m| m.address.clone().unwrap())
            .collect()
    }
}
