use anyhow::Result;
use bitvmx_client::program::participant::CommsAddress;
use bitvmx_client::program::protocols::union::types::RejectPeginData;
use bitvmx_client::types::PROGRAM_TYPE_REJECT_PEGIN;
use bitvmx_client::{client::BitVMXClient, program::variables::VariableTypes};
use tracing::info;
use uuid::Uuid;

pub struct RejectPegin {}

impl RejectPegin {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        bitvmx: &BitVMXClient,
        protocol_id: Uuid,
        committee_id: Uuid,
        member_index: usize,
        request_pegin_txid: bitcoin::Txid,
        my_address: CommsAddress,
    ) -> Result<()> {
        // Only the selected operator will set up the advance funds protocol
        let request = RejectPeginData {
            committee_id,
            member_index,
            txid: request_pegin_txid,
        };

        bitvmx.set_var(
            protocol_id,
            &RejectPeginData::name(),
            VariableTypes::String(serde_json::to_string(&request)?),
        )?;

        info!(
            "Reject Pegin setup for member {} with address {:?}",
            member_index, my_address
        );

        bitvmx.setup(
            protocol_id,
            PROGRAM_TYPE_REJECT_PEGIN.to_string(),
            vec![my_address],
            0,
        )?;

        Ok(())
    }
}
