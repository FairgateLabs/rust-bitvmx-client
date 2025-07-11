use std::collections::HashMap;

use anyhow::Result;
use bitcoin::Txid;
use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::types::{PegInRequest, OPERATOR_TAKE_KEYS, REIMBURSEMENT_KICKOFF_TXID},
        variables::VariableTypes,
    },
    types::PROGRAM_TYPE_ACCEPT_PEGIN,
};
use tracing::info;
use uuid::Uuid;

use crate::member::{Keyring, Member};

pub struct AcceptPegInSetup {
    pub _covenant_id: Uuid,
    pub _my_member_id: String,
    pub _my_role: ParticipantRole,
    pub _committee: Vec<Member>,
}

impl AcceptPegInSetup {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        covenant_id: Uuid,
        my_id: &str,
        my_role: &ParticipantRole,
        committee: &[Member],
        request_pegin_txid: Txid,
        request_pegin_amount: u64,
        accept_pegin_sighash: &[u8],
        keyring: &Keyring,
        bitvmx: &BitVMXClient,
        reimbursement_kickoff_txid: Txid,
    ) -> Result<AcceptPegInSetup> {
        let addresses = Self::get_addresses(committee);

        info!(
            id = my_id,
            "Setting up the AcceptPegIn protocol handler {} for {}", covenant_id, my_id
        );

        // build a map of communication pubkeys to addresses
        let mut comms = HashMap::new();
        for member in committee {
            comms.insert(
                member.keyring.communication_pubkey.unwrap(),
                member.address.clone().unwrap(),
            );
        }

        let mut take_keys = Vec::new();
        for member in committee {
            if member.role == ParticipantRole::Prover {
                take_keys.push(member.keyring.take_pubkey.unwrap());
            }
        }

        let pegin_request = PegInRequest {
            my_role: my_role.clone(),
            txid: request_pegin_txid,
            amount: request_pegin_amount,
            accept_pegin_sighash: accept_pegin_sighash.to_vec(),
            take_aggregated_key: keyring.take_aggregated_key.unwrap(),
            addresses: comms,
        };

        bitvmx.set_var(
            covenant_id,
            &PegInRequest::name(),
            VariableTypes::String(serde_json::to_string(&pegin_request)?),
        )?;

        bitvmx.set_var(
            covenant_id,
            OPERATOR_TAKE_KEYS,
            VariableTypes::String(serde_json::to_string(&take_keys)?),
        )?;

        bitvmx.set_var(
            covenant_id,
            REIMBURSEMENT_KICKOFF_TXID,
            VariableTypes::String(reimbursement_kickoff_txid.to_string()),
        )?;

        bitvmx.setup(
            covenant_id,
            PROGRAM_TYPE_ACCEPT_PEGIN.to_string(),
            addresses,
            0,
        )?;

        Ok(AcceptPegInSetup {
            _covenant_id: covenant_id,
            _my_member_id: my_id.to_string(),
            _my_role: my_role.clone(),
            _committee: committee.to_vec(),
        })
    }

    fn get_addresses(committee: &[Member]) -> Vec<P2PAddress> {
        committee
            .iter()
            .map(|m| m.address.clone().unwrap())
            .collect()
    }
}
