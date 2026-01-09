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
        slot_index: usize,
        amount: u64,
        pegout_id: Vec<u8>,
        user_pubkey: PublicKey,
        user_take_sighash: &[u8],
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
            slot_index,
            amount,
            pegout_id,
            user_pubkey: user_pubkey.clone(),
            pegout_sighash: user_take_sighash.to_vec(),
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
