use anyhow::Result;
use bitcoin::PublicKey;
use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::CommsAddress,
        protocols::union::{common::get_user_take_pid, types::PegOutRequest},
        variables::VariableTypes,
    },
    types::PROGRAM_TYPE_USER_TAKE,
};
use tracing::info;
use uuid::Uuid;

pub struct UserTakeSetup {}

impl UserTakeSetup {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        committee_id: Uuid,
        stream_id: u64,
        packet_number: u64,
        slot_index: usize,
        amount: u64,
        pegout_id: Vec<u8>,
        pegout_signature_hash: Vec<u8>,
        pegout_signature_message: Vec<u8>,
        user_pubkey: PublicKey,
        take_aggregated_key: PublicKey,
        my_id: &str,
        bitvmx: &BitVMXClient,
        addresses: &Vec<CommsAddress>,
    ) -> Result<()> {
        let protocol_id = get_user_take_pid(committee_id, slot_index);
        info!(
            id = my_id,
            "Setting up the UserTakeSetup protocol handler {} for {}", protocol_id, my_id
        );

        let pegout_request = PegOutRequest {
            committee_id,
            stream_id,
            packet_number,
            slot_index,
            amount,
            pegout_id,
            pegout_signature_hash,
            pegout_signature_message,
            user_pubkey: user_pubkey.clone(),
            take_aggregated_key,
        };

        bitvmx.set_var(
            protocol_id,
            &PegOutRequest::name(),
            VariableTypes::String(serde_json::to_string(&pegout_request)?),
        )?;

        bitvmx.setup(
            protocol_id,
            PROGRAM_TYPE_USER_TAKE.to_string(),
            addresses.to_vec(),
            0,
        )?;

        Ok(())
    }
}
