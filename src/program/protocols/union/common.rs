use bitcoin::PublicKey;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        protocols::union::types::{OPERATOR_TAKE_TX, OPERATOR_WON_TX},
        variables::PartialUtxo,
    },
};

pub fn get_dispute_core_pid(committee_id: Uuid, pubkey: &PublicKey) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update(pubkey.to_bytes());
    hasher.update("dispute_core");

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn get_accept_pegin_pid(committee_id: Uuid, slot_index: usize) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update(&slot_index.to_be_bytes());
    hasher.update("accept_pegin");

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn get_user_take_pid(committee_id: Uuid, slot_index: usize) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update(&slot_index.to_be_bytes());
    hasher.update("user_take");

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn create_transaction_reference(
    protocol: &mut protocol_builder::builder::Protocol,
    tx_name: &str,
    utxos: &mut Vec<PartialUtxo>,
) -> Result<(), BitVMXError> {
    // Create transaction
    protocol.add_external_transaction(tx_name)?;

    // Sort UTXOs by index
    utxos.sort_by_key(|utxo| utxo.1);
    let mut last_index = 0;

    for utxo in utxos {
        // If there is a gap in the indices, add unknown outputs
        if utxo.1 > last_index + 1 || (utxo.1 == 1 && last_index == 0) {
            protocol.add_unknown_outputs(tx_name, utxo.1 - last_index)?;
        }

        // Add the UTXO as an output
        protocol.add_transaction_output(tx_name, &utxo.clone().3.unwrap())?;
        last_index = utxo.1;
    }

    Ok(())
}

pub fn indexed_name(prefix: &str, index: usize) -> String {
    format!("{}_{}", prefix, index)
}

pub fn postfix_name(prefix: &str, suffix: &str) -> String {
    format!("{}_{}", prefix, suffix)
}

pub fn get_operator_take_tx_name(pubkey: &PublicKey) -> String {
    postfix_name(
        OPERATOR_TAKE_TX,
        &pubkey.wpubkey_hash().unwrap().to_string(),
    )
}

pub fn get_operator_won_tx_name(pubkey: &PublicKey) -> String {
    postfix_name(OPERATOR_WON_TX, &pubkey.wpubkey_hash().unwrap().to_string())
}
