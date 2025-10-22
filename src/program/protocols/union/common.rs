use bitcoin::{Amount, PublicKey, ScriptBuf};
use protocol_builder::{scripts::ProtocolScript, types::OutputType};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{errors::BitVMXError, program::variables::PartialUtxo};

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

pub fn get_take_aggreated_key_pid(committee_id: Uuid) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update("take_aggregated_key");

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn get_dispute_aggregated_key_pid(committee_id: Uuid) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update("dispute_aggregated_key");

    // Get the result as a byte array
    let hash = hasher.finalize();
    return Uuid::from_bytes(hash[0..16].try_into().unwrap());
}

pub fn get_dispute_pair_aggregated_key_pid(committee_id: Uuid, idx_a: usize, idx_b: usize) -> Uuid {
    let mut hasher = Sha256::new();
    // Ensure canonical ordering (min, max) so both parties derive the same id.
    let (min_i, max_i) = if idx_a <= idx_b {
        (idx_a, idx_b)
    } else {
        (idx_b, idx_a)
    };

    hasher.update(committee_id.as_bytes());
    hasher.update(&min_i.to_be_bytes());
    hasher.update(&max_i.to_be_bytes());
    hasher.update("pairwise_aggregated_key");

    let hash = hasher.finalize();
    Uuid::from_bytes(hash[0..16].try_into().unwrap())
}

// Deterministic id for a dispute-channel instance (directional): from_idx -> to_idx
pub fn get_dispute_channel_pid(committee_id: Uuid, op_index: usize, wt_index: usize) -> Uuid {
    let mut hasher = Sha256::new();

    hasher.update(committee_id.as_bytes());
    hasher.update(&op_index.to_be_bytes());
    hasher.update(&wt_index.to_be_bytes());
    hasher.update("dispute_channel");

    let hash = hasher.finalize();
    Uuid::from_bytes(hash[0..16].try_into().unwrap())
}

pub fn get_full_penalization_pid(committee_id: Uuid) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(committee_id.as_bytes());
    hasher.update("full_penalization");

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
    let mut add_initial_outputs = utxos[0].1 > 0;

    for utxo in utxos {
        // If there is a gap in the indices, add unknown outputs
        if utxo.1 - last_index > 1 || add_initial_outputs {
            protocol.add_unknown_outputs(tx_name, utxo.1 - last_index)?;
            add_initial_outputs = false;
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

pub fn double_indexed_name(prefix: &str, index_1: usize, index_2: usize) -> String {
    format!("{}_{}_{}", prefix, index_1, index_2)
}

pub fn triple_indexed_name(prefix: &str, index_1: usize, index_2: usize, index_3: usize) -> String {
    format!("{}_{}_{}_{}", prefix, index_1, index_2, index_3)
}

pub fn extract_index(full_name: &str, tx_name: &str) -> Result<usize, BitVMXError> {
    let prefix = format!("{}_", tx_name);
    let slot_index = full_name
        .strip_prefix(&prefix)
        .ok_or_else(|| {
            BitVMXError::InvalidTransactionName(format!(
                "'{}' does not match expected format '{}{{slot_index}}'",
                full_name, prefix
            ))
        })?
        .parse::<usize>()
        .map_err(|_| {
            BitVMXError::InvalidTransactionName(format!(
                "Could not parse slot_index from: {}",
                full_name
            ))
        })?;

    Ok(slot_index)
}

pub fn get_operator_output_type(
    dispute_key: &PublicKey,
    amount: u64,
) -> Result<OutputType, BitVMXError> {
    let wpkh = dispute_key.wpubkey_hash().expect("key is compressed");
    let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

    Ok(OutputType::SegwitPublicKey {
        value: Amount::from_sat(amount),
        script_pubkey,
        public_key: *dispute_key,
    })
}

pub fn get_initial_deposit_output_type(
    amount: u64,
    operator_key: &PublicKey,
    script: &[ProtocolScript],
) -> Result<OutputType, BitVMXError> {
    Ok(OutputType::taproot(amount, &operator_key, script)?)
}

//Rough estimate of fee for P2WPKH outputs
pub fn estimate_fee(input_quantity: usize, output_quantity: usize, fee_rate: u64) -> u64 {
    (46 + input_quantity as u64 * 68 + output_quantity as u64 * 34) * fee_rate // rough estimate
}
