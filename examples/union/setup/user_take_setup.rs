use anyhow::Result;
use bitcoin::PublicKey;
use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::P2PAddress, protocols::union::types::PegOutRequest, variables::VariableTypes,
    },
    types::PROGRAM_TYPE_USER_TAKE,
};
use tracing::info;
use uuid::Uuid;

use crate::participants::member::Member;

pub struct UserTakeSetup {}

impl UserTakeSetup {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        protocol_id: Uuid,
        committee_id: Uuid,
        my_id: &str,
        members: &[Member],
        user_pubkey: PublicKey,
        slot_id: u32,
        fee: u64,
        bitvmx: &BitVMXClient,
        take_aggregated_key: PublicKey,
    ) -> Result<()> {
        info!(
            id = my_id,
            "Setting up the UserTakeSetup protocol handler {} for {}", protocol_id, my_id
        );

        let pegout_request = PegOutRequest {
            committee_id,
            slot_id,
            fee,
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
            Self::get_addresses(members),
            0,
        )?;

        Ok(())
    }

    fn get_addresses(members: &[Member]) -> Vec<P2PAddress> {
        members.iter().map(|m| m.address.clone().unwrap()).collect()
    }
}
