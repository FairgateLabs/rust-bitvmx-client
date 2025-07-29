use crate::{
    macros::wait_for_message_blocking,
    participants::member::{Keyring, Member},
    wait_until_msg,
};
use anyhow::Result;
use bitcoin::{PublicKey, Txid};
use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::types::PegInRequest,
        variables::VariableTypes,
    },
    types::{OutgoingBitVMXApiMessages::SetupCompleted, PROGRAM_TYPE_ACCEPT_PEGIN},
};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

pub struct AcceptPegInSetup {}

impl AcceptPegInSetup {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        protocol_id: Uuid,
        my_id: &str,
        _my_role: &ParticipantRole,
        committee: &[Member],
        request_pegin_txid: Txid,
        request_pegin_amount: u64,
        accept_pegin_sighash: &[u8],
        keyring: &Keyring,
        bitvmx: &BitVMXClient,
        committee_id: Uuid,
        slot_index: u32,
        rootstock_address: String,
        reimbursement_pubkey: PublicKey,
    ) -> Result<()> {
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
            txid: request_pegin_txid,
            amount: request_pegin_amount,
            accept_pegin_sighash: accept_pegin_sighash.to_vec(),
            take_aggregated_key: keyring.take_aggregated_key.unwrap(),
            operators_take_key,
            slot_index: slot_index,
            committee_id: committee_id,
            rootstock_address,
            reimbursement_pubkey,
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

        let program_id = wait_until_msg!(bitvmx, SetupCompleted(_program_id) => _program_id);
        info!(id = "AcceptPegInSetup", program_id = ?program_id, "Accept pegin setup completed (from setup)");

        Ok(())
    }

    fn get_addresses(committee: &[Member]) -> Vec<P2PAddress> {
        committee
            .iter()
            .map(|m| m.address.clone().unwrap())
            .collect()
    }
}
