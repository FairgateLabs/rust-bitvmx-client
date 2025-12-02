use anyhow::Error;
use bitcoin::{Amount, PublicKey, ScriptBuf};
use protocol_builder::{scripts::ProtocolScript, types::OutputType};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        protocols::union::types::{
            StreamSettings, UnionSettings, GLOBAL_SETTINGS_UUID, OP_CLAIM_GATE,
            PAIRWISE_DISPUTE_KEY, WT_CLAIM_GATE,
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::ProgramContext,
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

pub fn get_dispute_pair_key_name(idx_a: usize, idx_b: usize) -> String {
    // Ensure canonical ordering (min, max) so both parties derive the same name.
    let (min_i, max_i) = if idx_a <= idx_b {
        (idx_a, idx_b)
    } else {
        (idx_b, idx_a)
    };

    double_indexed_name(PAIRWISE_DISPUTE_KEY, min_i, max_i)
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

pub fn extract_double_index(input: &str) -> Result<(usize, usize), BitVMXError> {
    let parts: Vec<&str> = input.split('_').collect();
    if parts.len() < 2 {
        return Err(BitVMXError::InvalidParameter(format!(
            "Input '{}' does not contain two indices separated by '_'",
            input
        )));
    }
    let len = parts.len();

    let index2 = parts[len - 2].parse::<usize>().map_err(|_| {
        BitVMXError::InvalidParameter(format!(
            "Could not parse second index from part: '{}'",
            parts[0]
        ))
    })?;

    let index1 = parts[len - 1].parse::<usize>().map_err(|_| {
        BitVMXError::InvalidParameter(format!(
            "Could not parse first index from part: '{}'",
            parts[1]
        ))
    })?;

    Ok((index2, index1))
}

pub fn extract_index_from_claim_gate(input: &str) -> Result<(usize, usize), BitVMXError> {
    let prefix = if input.starts_with(WT_CLAIM_GATE) {
        WT_CLAIM_GATE
    } else if input.starts_with(OP_CLAIM_GATE) {
        OP_CLAIM_GATE
    } else {
        return Err(BitVMXError::InvalidParameter(format!(
            "Input '{}' does not start with expected prefixes",
            input
        )));
    };

    let prefix = &format!("{}_", prefix);
    let rest = input.strip_prefix(prefix).unwrap();
    let parts: Vec<&str> = rest.split('_').collect();
    let a: usize = parts[0].parse().unwrap();
    let b: usize = parts[1].parse().unwrap();
    Ok((a, b))
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

pub fn load_union_settings(context: &ProgramContext) -> Result<UnionSettings, BitVMXError> {
    let var = context
        .globals
        .get_var(&GLOBAL_SETTINGS_UUID, &UnionSettings::name().to_string())?
        .ok_or_else(|| {
            BitVMXError::InvalidParameter(format!(
                "Union settings '{}' not found in UUID: {}",
                UnionSettings::name(),
                GLOBAL_SETTINGS_UUID
            ))
        })?;

    let var_str = var.string().map_err(|_| {
        BitVMXError::InvalidParameter(format!(
            "Union settings '{}' in UUID: {} is not a string",
            UnionSettings::name(),
            GLOBAL_SETTINGS_UUID
        ))
    })?;

    Ok(serde_json::from_str(&var_str)?)
}

pub fn save_union_settings(
    context: &ProgramContext,
    settings: &UnionSettings,
) -> Result<(), Error> {
    context.globals.set_var(
        &GLOBAL_SETTINGS_UUID,
        &UnionSettings::name(),
        VariableTypes::String(serde_json::to_string(settings)?),
    )?;
    Ok(())
}

pub fn get_stream_setting(
    settings: &UnionSettings,
    stream_denomination: u64,
) -> Result<StreamSettings, BitVMXError> {
    if !settings.settings.contains_key(&stream_denomination) {
        return Err(BitVMXError::InvalidParameter(format!(
            "Stream settings not found for denomination: {}",
            stream_denomination
        )));
    }

    Ok(settings.settings.get(&stream_denomination).unwrap().clone())
}

pub fn get_dispatch_action(block_height: Option<u32>) -> String {
    if block_height.is_some() {
        "scheduled".to_string()
    } else {
        "dispatched".to_string()
    }
}
