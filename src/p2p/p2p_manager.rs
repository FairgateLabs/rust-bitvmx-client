use crate::p2p::p2p_parser::{parse_msg, P2PMessageKind};
use p2p_handler::{P2pHandler, PeerId};
use tracing::info;
use uuid::Uuid;

use crate::{errors::BitVMXError, program::participant};

pub fn exchange_keys(
    comms: &mut P2pHandler,
    participant: &participant::Participant,
    program_id: &Uuid,
    peer_id: PeerId,
    addr: Option<String>,
) -> Result<(), BitVMXError> {
    let keys = participant.keys();
    let keys = match keys {
        Some(keys) => keys.get_keys(),
        None => return Err(BitVMXError::KeysNotFound(*program_id)),
    };

    info!("Sending keys: {:?}", keys.clone());
    let msg = parse_msg("1.0", P2PMessageKind::Key, program_id, keys)?;
    match addr {
        Some(addr) => {
            // Prover
            comms.request(peer_id, addr, msg)?;
        }
        None => {
            // Verifier
            comms.response(peer_id, msg)?;
        }
    }
    Ok(())
}

pub fn exchange_nonces(
    comms: &mut P2pHandler,
    _participant: &participant::Participant,
    program_id: &Uuid,
    peer_id: PeerId,
    addr: Option<String>,
) -> Result<(), BitVMXError> {
    let nonces = vec![0, 1, 2, 3]; //TODO:

    info!("Sending nonces: {:?}", nonces.clone());
    let msg = parse_msg("1.0", P2PMessageKind::Nonce, program_id, nonces)?;

    match addr {
        Some(addr) => {
            // Prover
            comms.request(peer_id, addr, msg)?;
        }
        None => {
            // Verifier
            comms.response(peer_id, msg)?;
        }
    }
    Ok(())
}

pub fn exchange_signatures(
    comms: &mut P2pHandler,
    _participant: &participant::Participant,
    program_id: &Uuid,
    peer_id: PeerId,
    addr: Option<String>,
) -> Result<(), BitVMXError> {
    let sigs = vec![10, 9, 8, 7]; //TODO:

    info!("Sending signature: {:?}", sigs.clone());
    let msg = parse_msg("1.0", P2PMessageKind::Signature, program_id, sigs)?;

    match addr {
        Some(addr) => {
            // Prover
            comms.request(peer_id, addr, msg)?;
        }
        None => {
            // Verifier
            comms.response(peer_id, msg)?;
        }
    }
    Ok(())
}
