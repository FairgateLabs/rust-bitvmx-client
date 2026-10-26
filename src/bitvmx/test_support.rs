//! Helpers shared by the `BitVMX` unit tests, which live next to the code they exercise.

use super::*;
use crate::{
    comms_helper::serialize_msg, message_queue::QueuedMessage, program::participant::CommsAddress,
    test_utils::TestBitVMXEnv, types::PROGRAM_TYPE_AGGREGATED_KEY,
};

pub(super) fn test_l2_messages(
    env: &TestBitVMXEnv,
) -> Result<Vec<OutgoingBitVMXApiMessages>, BitVMXError> {
    env.bitvmx.program_context.broker_channel.tick()?;
    let l2 = env
        .bitvmx
        .program_context
        .broker_channel
        .create_local_channel(env.bitvmx.program_context.components_config.l2.clone())?;
    l2.get_all()?
        .into_iter()
        .map(|message| OutgoingBitVMXApiMessages::from_string(&message.msg))
        .collect()
}

pub(super) fn self_address(env: &TestBitVMXEnv) -> CommsAddress {
    CommsAddress::new(
        env.bitvmx.program_context.comms.get_address(),
        env.bitvmx.program_context.comms.get_pubk_hash(),
        env.bitvmx.program_context.rsa_public_key.clone(),
    )
}

/// The leader is the first participant.
pub(super) fn create_program(
    env: &mut TestBitVMXEnv,
    program_id: Uuid,
    participants: Vec<CommsAddress>,
) -> Rc<Storage> {
    let store = env.bitvmx.get_store();
    Program::new(
        program_id,
        PROGRAM_TYPE_AGGREGATED_KEY,
        participants,
        0,
        None,
        &mut env.bitvmx.program_context,
        store.clone(),
    )
    .unwrap();
    store
}

pub(super) fn create_single_participant_program(
    env: &mut TestBitVMXEnv,
    program_id: Uuid,
) -> Rc<Storage> {
    let participants = vec![self_address(env)];
    create_program(env, program_id, participants)
}

/// A peer message with an unverifiable signature, as sent by `sender`.
pub(super) fn peer_message(
    sender: &str,
    msg_type: CommsMessageType,
    program_id: &Uuid,
    payload: serde_json::Value,
) -> QueuedMessage {
    let data = serialize_msg("1.0", msg_type, program_id, payload, 0, vec![1]).unwrap();
    QueuedMessage::new(Identifier::new(sender.to_string(), 0), data).unwrap()
}
