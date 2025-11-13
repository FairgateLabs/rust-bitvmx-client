use anyhow::Result;
use bitcoin::PublicKey;
use protocol_builder::types::{
    connection::InputSpec,
    input::{SighashType, SpendMode},
    OutputType,
};
use std::collections::HashMap;
use tracing::info;
use uuid::Uuid;

use bitvmx_client::{
    client::BitVMXClient,
    program::{
        participant::{CommsAddress, ParticipantRole},
        protocols::{
            dispute::config::DisputeConfiguration,
            union::{
                common::{get_dispute_channel_pid, get_dispute_core_pid},
                types::{MemberData, WT_START_ENABLER_UTXOS},
            },
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::{OutgoingBitVMXApiMessages, PROGRAM_TYPE_DRP},
};

use crate::wait_until_msg;

use bitvmx_client::program::protocols::dispute::DUST as DRP_DUST_VALUE;

const DRP_TIMELOCK_BLOCKS: u16 = 15; // TODO review if this is the right value
const DRP_PROGRAM_DEFINITION: &str = "../BitVMX-CPU/docker-riscv32/riscv32/build/hello-world.yaml"; // TODO move to config?

pub struct DisputeChannelSetup;

impl DisputeChannelSetup {
    pub fn setup(
        my_index: usize,
        pairwise_keys: &HashMap<CommsAddress, PublicKey>,
        bitvmx: &BitVMXClient,
        members: &Vec<MemberData>,
        committee_id: Uuid,
        addresses: &Vec<CommsAddress>,
    ) -> Result<usize> {
        let mut total_setups = 0;
        let my_address = addresses[my_index].clone();
        let prover = members[my_index].role == ParticipantRole::Prover;

        // Iterate over partners
        for partner_index in 0..members.len() {
            if partner_index == my_index
                || (!prover && members[partner_index].role != ParticipantRole::Prover)
            {
                // Skip myself and verifiers pair
                continue;
            }

            // Set partner address and key pair
            let partner_address = &addresses[partner_index];
            let pair_key = pairwise_keys
                .get(&partner_address)
                .cloned()
                .expect("pairwise key should be present");

            // If I'm an operator, set up DisputeChannel where I'm the operator and my partner is the watchtower
            if prover {
                // get wt start enabler utxos
                let wt_start_enablers = Self::get_wt_start_enabler_utxos(
                    committee_id,
                    &bitvmx,
                    partner_index,
                    members,
                )?;

                Self::print_setup_info(my_index, my_index, partner_index);
                Self::setup_one(
                    committee_id,
                    my_index,
                    partner_index,
                    &my_address,
                    partner_address,
                    &bitvmx,
                    pair_key,
                    &wt_start_enablers,
                )?;

                total_setups += 1;
            }

            // If my partner is an operator, set up DisputeChannel where they are the operator and I'm the watchtower
            if members[partner_index].role == ParticipantRole::Prover {
                // get wt start enabler utxos
                let wt_start_enablers =
                    Self::get_wt_start_enabler_utxos(committee_id, &bitvmx, my_index, members)?;

                Self::print_setup_info(my_index, partner_index, my_index);
                Self::setup_one(
                    committee_id,
                    partner_index,
                    my_index,
                    &partner_address,
                    &my_address,
                    &bitvmx,
                    pair_key,
                    &wt_start_enablers,
                )?;

                total_setups += 1;
            }
        }

        info!("DisputeChannel setup complete ({} setups)", total_setups);
        Ok(total_setups)
    }

    fn get_wt_start_enabler_utxos(
        committee_id: Uuid,
        bitvmx: &BitVMXClient,
        wt_index: usize,
        members: &Vec<MemberData>,
    ) -> Result<Vec<PartialUtxo>> {
        let dispute_core_pid = get_dispute_core_pid(committee_id, &members[wt_index].take_key);
        bitvmx.get_var(dispute_core_pid, WT_START_ENABLER_UTXOS.to_string())?;
        std::thread::sleep(std::time::Duration::from_secs(1)); // wait a bit for the message to be processed

        let variable =
            wait_until_msg!(&bitvmx, OutgoingBitVMXApiMessages::Variable(_, _, _var) => _var);

        let data = variable.string()?;
        let wt_start_enabler_utxos: Vec<PartialUtxo> = serde_json::from_str(&data)?;

        Ok(wt_start_enabler_utxos)
    }

    fn setup_one(
        committee_id: Uuid,
        op_index: usize,
        wt_index: usize,
        operator: &CommsAddress,
        watchtower: &CommsAddress,
        bitvmx: &BitVMXClient,
        pair_key: PublicKey,
        wt_start_enablers: &Vec<PartialUtxo>,
    ) -> Result<()> {
        let drp_id = get_dispute_channel_pid(committee_id, op_index, wt_index);
        let participants: Vec<CommsAddress> = vec![operator.clone(), watchtower.clone()];

        info!(
            "Setting up {} PID {} between OP {} and WT {}",
            PROGRAM_TYPE_DRP, drp_id, op_index, wt_index,
        );

        let dispute_configuration = DisputeConfiguration::new(
            drp_id,
            pair_key,
            (
                wt_start_enablers[op_index].clone(),
                vec![], // TODO: this vec<usize> is not used by the protocol builder. what is it there for?
                Some(InputSpec::Auto(SighashType::taproot_all(), SpendMode::None)),
            ),
            vec![], // empty prover actions
            vec![OutputType::taproot(DRP_DUST_VALUE, &pair_key, &[])?],
            vec![], // empty verifier actions
            vec![OutputType::taproot(
                DRP_DUST_VALUE,
                &pair_key, // Use pairwise key for 2-party dispute channel
                &[],
            )?],
            DRP_TIMELOCK_BLOCKS,
            DRP_PROGRAM_DEFINITION.to_string(),
            None, // TODO review if this is the right fail force config
        );

        bitvmx.set_var(
            drp_id,
            "dispute_configuration",
            VariableTypes::String(serde_json::to_string(&dispute_configuration)?),
        )?;

        bitvmx.setup(drp_id, PROGRAM_TYPE_DRP.to_string(), participants, 0)?;

        Ok(())
    }

    fn print_setup_info(member_index: usize, op_index: usize, wt_index: usize) {
        info!(
            index = member_index,
            "Setting up DisputeChannel between OP {} and WT {}", op_index, wt_index
        );
    }
}
