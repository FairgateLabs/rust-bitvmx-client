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
    types::PROGRAM_TYPE_ACCEPT_PEGIN,
};
use tracing::info;
use uuid::Uuid;

use crate::participants::member::{Keyring, Member};
pub struct AcceptPegInSetup {
    pub _covenant_id: Uuid,
    pub _my_member_id: String,
    pub _my_role: ParticipantRole,
    pub _committee: Vec<Member>,
}

impl AcceptPegInSetup {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        protocol_id: Uuid,
        my_id: &str,
        my_role: &ParticipantRole,
        committee: &[Member],
        request_pegin_txid: Txid,
        request_pegin_amount: u64,
        accept_pegin_sighash: &[u8],
        keyring: &Keyring,
        bitvmx: &BitVMXClient,
        committee_id: Uuid,
        slot_index: u32,
    ) -> Result<AcceptPegInSetup> {
        let addresses = Self::get_addresses(committee);

        info!(
            id = my_id,
            "Setting up the AcceptPegIn protocol handler {} for {}", protocol_id, my_id
        );

        // build a map of communication pubkeys to addresses
        let mut comms = HashMap::new();
        for member in committee {
            comms.insert(
                member.keyring.communication_pubkey.unwrap(),
                member.address.clone().unwrap(),
            );
        }

        let mut operators_take_key = Vec::new();
        for member in committee {
            if member.role == ParticipantRole::Prover {
                operators_take_key.push(member.keyring.take_pubkey.unwrap());
            }
        }

        let pegin_request = PegInRequest {
            my_role: my_role.clone(),
            txid: request_pegin_txid,
            amount: request_pegin_amount,
            accept_pegin_sighash: accept_pegin_sighash.to_vec(),
            take_aggregated_key: keyring.take_aggregated_key.unwrap(),
            addresses: comms,
            operators_take_key,
            slot_index: slot_index,
            committee_id: committee_id,
        };

        bitvmx.set_var(
            protocol_id,
            &PegInRequest::name(),
            VariableTypes::String(serde_json::to_string(&pegin_request)?),
        )?;

        bitvmx.setup(
            protocol_id,
            PROGRAM_TYPE_ACCEPT_PEGIN.to_string(),
            addresses,
            0,
        )?;

        // FIXME: This code will be uncommented soon to broadcast the accept peg-in transaction.
        // let program_id = expect_msg!(bitvmx, SetupCompleted(program_id) => program_id)?;
        // info!(id = "AcceptPegInSetup", program_id = ?program_id, "Dispute core setup completed");

        // bitvmx.get_transaction_by_name(covenant_id, ACCEPT_PEGIN_TX.to_string())?;
        // let tx = expect_msg!(bitvmx, TransactionInfo(_, _, tx) => tx)?;

        // bitvmx.dispatch_transaction(covenant_id, tx)?;
        // let status = expect_msg!(bitvmx, Transaction(_, status, _) => status)?;

        // info!(
        //     "AcceptPegIn protocol handler {} for {} send accept pegin transaction with status: {:?}",
        //     covenant_id, my_id, status
        // );

        Ok(AcceptPegInSetup {
            _covenant_id: protocol_id,
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
