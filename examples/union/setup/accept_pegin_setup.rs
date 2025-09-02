use anyhow::Result;
use bitcoin::{PublicKey, Txid};
use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::{
            common::get_accept_pegin_pid,
            types::{MemberData, PegInRequest},
        },
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
        members: &Vec<MemberData>,
        request_pegin_txid: Txid,
        request_pegin_amount: u64,
        accept_pegin_sighash: &[u8],
        take_aggregated_key: PublicKey,
        bitvmx: &BitVMXClient,
        committee_id: Uuid,
        slot_index: usize,
        rootstock_address: String,
        reimbursement_pubkey: PublicKey,
        addresses: &Vec<P2PAddress>,
    ) -> Result<()> {
        let protocol_id = get_accept_pegin_pid(committee_id, slot_index);

        info!(
            id = my_id,
            "Setting up the AcceptPegIn protocol handler {} for {}", protocol_id, my_id
        );

        let mut operator_indexes = Vec::new();
        for (index, member) in members.iter().enumerate() {
            if member.role == ParticipantRole::Prover {
                operator_indexes.push(index);
            }
        }

        let pegin_request = PegInRequest {
            txid: request_pegin_txid,
            amount: request_pegin_amount,
            accept_pegin_sighash: accept_pegin_sighash.to_vec(),
            take_aggregated_key,
            operator_indexes,
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
            addresses.to_vec(),
            0,
        )?;

        Ok(())
    }
}
