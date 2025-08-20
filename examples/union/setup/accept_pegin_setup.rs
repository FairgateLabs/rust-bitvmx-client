use crate::participants::member::{Keyring, Member};
use anyhow::Result;
use bitcoin::{PublicKey, Txid};
use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::{common::get_accept_pegin_pid, types::PegInRequest},
        variables::VariableTypes,
    },
    types::PROGRAM_TYPE_ACCEPT_PEGIN,
};
use tracing::info;
use uuid::Uuid;

pub struct AcceptPegInSetup {}

impl AcceptPegInSetup {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        my_id: &str,
        _my_role: &ParticipantRole,
        committee: &[Member],
        request_pegin_txid: Txid,
        request_pegin_amount: u64,
        accept_pegin_sighash: &[u8],
        keyring: &Keyring,
        bitvmx: &BitVMXClient,
        committee_id: Uuid,
        slot_index: usize,
        rootstock_address: String,
        reimbursement_pubkey: PublicKey,
    ) -> Result<()> {
        let addresses = Self::get_addresses(committee);
        let protocol_id = get_accept_pegin_pid(committee_id, slot_index);

        info!(
            id = my_id,
            "Setting up the AcceptPegIn protocol handler {} for {}", protocol_id, my_id
        );

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

        Ok(())
    }

    fn get_addresses(committee: &[Member]) -> Vec<P2PAddress> {
        committee
            .iter()
            .map(|m| m.address.clone().unwrap())
            .collect()
    }
}
