use anyhow::Result;
use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::CommsAddress,
        protocols::union::{common::get_full_penalization_pid, types::FullPenalizationData},
        variables::VariableTypes,
    },
    types::PROGRAM_TYPE_FULL_PENALIZATION,
};
use tracing::info;
use uuid::Uuid;

pub struct FullPenalizationSetup {}

impl FullPenalizationSetup {
    #[allow(clippy::too_many_arguments)]
    pub fn setup(
        my_id: &str,
        bitvmx: &BitVMXClient,
        committee_id: Uuid,
        addresses: &Vec<CommsAddress>,
    ) -> Result<()> {
        let protocol_id = get_full_penalization_pid(committee_id);

        info!(
            id = my_id,
            "Setting up the FullPenalization protocol handler {} for {}", protocol_id, my_id
        );

        let data = FullPenalizationData {
            committee_id: committee_id,
        };

        bitvmx.set_var(
            protocol_id,
            &FullPenalizationData::name(),
            VariableTypes::String(serde_json::to_string(&data)?),
        )?;

        bitvmx.setup(
            protocol_id,
            PROGRAM_TYPE_FULL_PENALIZATION.to_string(),
            addresses.to_vec(),
            0,
        )?;

        Ok(())
    }
}
