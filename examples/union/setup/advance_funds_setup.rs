use anyhow::Result;
use bitcoin::PublicKey;
use bitvmx_client::{
    client::BitVMXClient,
    program::{
        protocols::union::{
            common::indexed_name,
            types::{AdvanceFundsRequest, SELECTED_OPERATOR_PUBKEY},
        },
        variables::VariableTypes,
    },
};
use bitvmx_client::{program::participant::P2PAddress, types::PROGRAM_TYPE_ADVANCE_FUNDS};
use tracing::info;
use uuid::Uuid;

pub struct AdvanceFunds {}

impl AdvanceFunds {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        bitvmx: &BitVMXClient,
        protocol_id: Uuid,
        committee_id: Uuid,
        slot_index: usize,
        user_pubkey: PublicKey,
        operator_pubkey: PublicKey,
        my_take_pubkey: PublicKey,
        pegout_id: Vec<u8>,
        my_address: P2PAddress,
        fee: u64,
    ) -> Result<()> {
        // All members should set up the operator pubkey that should advance the funds
        bitvmx.set_var(
            committee_id,
            &indexed_name(SELECTED_OPERATOR_PUBKEY, slot_index),
            VariableTypes::PubKey(operator_pubkey),
        )?;

        if operator_pubkey != my_take_pubkey {
            info!(
                "Skipping advance funds setup. Operator pubkey: {}, my take pubkey: {}",
                operator_pubkey, my_take_pubkey
            );
            return Ok(());
        }

        // Only the selected operator will set up the advance funds protocol
        let request = AdvanceFundsRequest {
            committee_id,
            slot_index,
            pegout_id,
            fee, // This will be set later
            user_pubkey,
            my_take_pubkey,
        };

        bitvmx.set_var(
            protocol_id,
            &AdvanceFundsRequest::name(),
            VariableTypes::String(serde_json::to_string(&request)?),
        )?;

        info!(
            "Advance funds setup for member {} with address {:?}",
            my_take_pubkey, my_address
        );

        bitvmx.setup(
            protocol_id,
            PROGRAM_TYPE_ADVANCE_FUNDS.to_string(),
            vec![my_address],
            0,
        )?;

        Ok(())
    }
}
