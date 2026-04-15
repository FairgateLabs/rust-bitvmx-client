#![cfg(test)]
use anyhow::Result;
use bitcoin::Network;
use bitvmx_client::{
    program::{
        participant::{CommsAddress, ParticipantRole},
        setup::steps::garbler_step::GCConfiguration,
    },
    types::{IncomingBitVMXApiMessages, PROGRAM_TYPE_GC_GENERATION},
};
use tracing::info;
use uuid::Uuid;

use crate::common::{check_gnova_built, config_trace, helper::TestHelper};

mod common;

#[ignore]
#[test]
pub fn test_gc_generation() -> Result<()> {
    let network = Network::Regtest;

    check_gnova_built()?;

    config_trace();

    let mut helper = TestHelper::new(network, false, None)?;

    // Obtain communication addresses from all participants
    let command = IncomingBitVMXApiMessages::GetCommInfo(Uuid::new_v4());
    helper.send_all(command)?;

    let addresses: Vec<CommsAddress> = helper
        .wait_all_msg()?
        .iter()
        .map(|msg| msg.comm_info().unwrap().1)
        .collect::<Vec<_>>();

    // Now configure the protocol itself

    let pair_0_1 = vec![addresses[0].clone(), addresses[1].clone()];
    let pair_0_1_channels = vec![
        helper.id_channel_pairs[0].clone(),
        helper.id_channel_pairs[1].clone(),
    ];

    let prog_id = Uuid::new_v4();

    const TEST_CIRCUIT_PATH: &str = "../rust-bitvmx-gc/test-circuits/simple.circuit";
    let gc_config_prover = GCConfiguration::new(
        prog_id,
        ParticipantRole::Prover,
        TEST_CIRCUIT_PATH.to_string(),
    );
    let gc_config_verifier = GCConfiguration::new(
        prog_id,
        ParticipantRole::Verifier,
        TEST_CIRCUIT_PATH.to_string(),
    );

    info!("Setup start");
    pair_0_1_channels[0].channel.send(
        &pair_0_1_channels[0].id,
        gc_config_prover.get_setup_message()?,
    )?;
    pair_0_1_channels[1].channel.send(
        &pair_0_1_channels[1].id,
        gc_config_verifier.get_setup_message()?,
    )?;

    for chan in pair_0_1_channels.iter() {
        let setup_msg = IncomingBitVMXApiMessages::Setup(
            prog_id,
            PROGRAM_TYPE_GC_GENERATION.to_string(),
            pair_0_1.clone(),
            1,
        );
        chan.channel.send(&chan.id, setup_msg.to_string()?)?;
    }

    let msg = helper.wait_msg(0)?;
    info!("Setup generation done: {:?}", msg);
    let msg = helper.wait_msg(1)?;
    info!("Setup generation done: {:?}", msg);

    helper.stop()?;

    Ok(())
}
