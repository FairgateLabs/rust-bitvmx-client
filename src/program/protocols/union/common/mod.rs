mod shared;
pub use shared::*;

use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use anyhow::Error;
use bitcoin::{PublicKey, ScriptBuf};
use key_manager::{key_manager::KeyManager, winternitz};
use protocol_builder::{
    builder::Protocol,
    errors::ProtocolBuilderError,
    scripts::{ProtocolScript, SignMode},
    types::{input::SpendMode, output::AmountType, InputArgs, OutputType},
};
use tracing::info;
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        participant::ParticipantRole,
        protocols::union::types::{
            Committee, PenalizedMember, StreamSettings, UnionSettings, GLOBAL_SETTINGS_UUID,
            MY_IDX, OP_CLAIM_GATE, SPEEDUP_VALUE, WT_CLAIM_GATE,
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::ProgramContext,
};

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

    for (i, utxo) in utxos.iter().enumerate() {
        let index = utxo.1;

        // Handle missing outputs BEFORE the first UTXO
        if i == 0 && index > 0 {
            protocol.add_unknown_outputs(tx_name, index)?;
        } else if index > last_index + 1 {
            let gap = index - last_index - 1;
            protocol.add_unknown_outputs(tx_name, gap)?;
        }

        // Add the UTXO
        protocol.add_transaction_output(tx_name, &utxo.3.clone().unwrap())?;

        last_index = index;
    }

    Ok(())
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
    let rest = input.strip_prefix(prefix).ok_or_else(|| {
        BitVMXError::InvalidParameter(format!(
            "Input '{}' does not match expected format '{}{{a}}_{{b}}'",
            input, prefix
        ))
    })?;
    let parts: Vec<&str> = rest.split('_').collect();
    let a: usize = parts[0].parse().map_err(|_| {
        BitVMXError::InvalidParameter(format!(
            "Could not parse first index from part: '{}'",
            parts[0]
        ))
    })?;
    let b: usize = parts[1].parse().map_err(|_| {
        BitVMXError::InvalidParameter(format!(
            "Could not parse second index from part: '{}'",
            parts[1]
        ))
    })?;
    Ok((a, b))
}

pub fn get_operator_output_type(
    dispute_key: &PublicKey,
    amount: u64,
) -> Result<OutputType, BitVMXError> {
    let wpkh = dispute_key.wpubkey_hash().expect("key is compressed");
    let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

    Ok(OutputType::SegwitPublicKey {
        value: amount.into(),
        script_pubkey,
        public_key: *dispute_key,
    })
}

pub fn get_initial_deposit_output_type(
    amount: AmountType,
    operator_key: &PublicKey,
    script: &[ProtocolScript],
) -> Result<OutputType, BitVMXError> {
    Ok(OutputType::taproot(amount, &operator_key, script)?)
}

//Rough estimate of fee for P2WPKH outputs
pub fn estimate_fee(input_quantity: usize, output_quantity: usize, fee_rate: u64) -> u64 {
    (46 + input_quantity as u64 * 68 + output_quantity as u64 * 34) * fee_rate // rough estimate
}

pub fn load_union_settings<BC: BitcoinCoordinatorApi>(
    context: &ProgramContext<BC>,
) -> Result<UnionSettings, BitVMXError> {
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

pub fn save_union_settings<BC: BitcoinCoordinatorApi>(
    context: &ProgramContext<BC>,
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

pub struct WinternitzData<'a> {
    pub data: Vec<u8>,
    pub key_type: winternitz::WinternitzType,
    pub key_name: String,
    pub key_manager: &'a KeyManager,
}

pub enum InputSigningInfo<'a> {
    // Used to retrieve input's signatures that have been signed in build process
    KeySpend {
        input_index: usize,
    },
    ScriptSpend {
        input_index: usize,
        script_index: usize,
        winternitz_data: Option<WinternitzData<'a>>,
    },
    Edcsa {
        input_index: usize,
    },
    // Used to sign inputs at the moment
    SignTaproot {
        input_index: usize,
        script_index: Option<usize>,
        key_manager: &'a KeyManager,
        id: String,
    },
    SignEdcsa {
        input_index: usize,
        key_manager: &'a KeyManager,
    },
}

impl<'a> InputSigningInfo<'a> {
    pub fn get_input_signature(
        &self,
        name: &str,
        protocol: &mut Protocol,
    ) -> Result<InputArgs, BitVMXError> {
        match self {
            InputSigningInfo::KeySpend { input_index } => {
                self.get_key_spend_signature(name, *input_index, protocol)
            }
            InputSigningInfo::ScriptSpend {
                input_index,
                script_index,
                winternitz_data,
            } => self.get_script_spend_signature(
                name,
                *input_index,
                *script_index,
                winternitz_data,
                protocol,
            ),
            InputSigningInfo::Edcsa { input_index } => {
                self.get_ecdsa_signature(name, *input_index, protocol)
            }
            InputSigningInfo::SignTaproot {
                input_index,
                script_index,
                key_manager,
                id,
            } => self.sign_taproot(name, *input_index, *script_index, key_manager, id, protocol),
            InputSigningInfo::SignEdcsa {
                input_index,
                key_manager,
            } => self.sign_ecdsa(name, *input_index, key_manager, protocol),
        }
    }

    pub fn get_key_spend_signature(
        &self,
        name: &str,
        input_index: usize,
        protocol: &mut Protocol,
    ) -> Result<InputArgs, BitVMXError> {
        let signature = protocol
            .input_taproot_key_spend_signature(name, input_index)?
            .ok_or_else(|| BitVMXError::MissingInputSignature {
                tx_name: name.to_string(),
                input_index,
                script_index: None,
            })?;

        let mut args = InputArgs::new_taproot_key_args();
        args.push_taproot_signature(signature)?;

        Ok(args)
    }

    pub fn get_script_spend_signature(
        &self,
        name: &str,
        input_index: usize,
        script_index: usize,
        winternitz_data: &Option<WinternitzData>,
        protocol: &mut Protocol,
    ) -> Result<InputArgs, BitVMXError> {
        let signature = protocol
            .input_taproot_script_spend_signature(name, input_index, script_index)?
            .ok_or_else(|| BitVMXError::MissingInputSignature {
                tx_name: name.to_string(),
                input_index,
                script_index: Some(script_index),
            })?;

        let mut args = InputArgs::new_taproot_script_args(script_index);

        if let Some(wt_data) = winternitz_data {
            let script =
                protocol.get_script_to_spend(name, input_index as u32, script_index as u32)?;

            // TODO: Should we use get_keys() instead and iterate over them to sign all?
            // In that case data should be a vector of data to sign.
            let key = script.get_key(&wt_data.key_name).ok_or_else(|| {
                        BitVMXError::InvalidParameter(format!(
                            "Winternitz key '{}' not found in script. Tx name: {}. Input index: {}. Script index: {}",
                            wt_data.key_name, name, input_index, script_index
                        ))
                    })?;

            let wt_signature = wt_data.key_manager.sign_winternitz_message_by_index(
                wt_data.data.as_slice(),
                wt_data.key_type,
                key.derivation_index(),
            )?;
            args.push_winternitz_signature(wt_signature);
        }

        args.push_taproot_signature(signature)?;
        Ok(args)
    }

    pub fn get_ecdsa_signature(
        &self,
        name: &str,
        input_index: usize,
        protocol: &mut Protocol,
    ) -> Result<InputArgs, BitVMXError> {
        let signature = protocol
            .input_ecdsa_signature(name, input_index)?
            .ok_or_else(|| BitVMXError::MissingInputSignature {
                tx_name: name.to_string(),
                input_index,
                script_index: None,
            })?;
        let mut args = InputArgs::new_segwit_args();
        args.push_ecdsa_signature(signature)?;
        Ok(args)
    }

    pub fn sign_taproot(
        &self,
        name: &str,
        input_index: usize,
        script_index: Option<usize>,
        key_manager: &KeyManager,
        id: &str,
        protocol: &mut Protocol,
    ) -> Result<InputArgs, BitVMXError> {
        let spend_mode = if script_index.is_some() {
            SpendMode::Script {
                leaf: script_index.unwrap(),
            }
        } else {
            SpendMode::KeyOnly {
                key_path_sign: SignMode::Single,
            }
        };

        let signatures = protocol
            .sign_taproot_input(name, input_index, &spend_mode, key_manager, &id)
            .map_err(|e| BitVMXError::ErrorSigningInput {
                tx_name: name.to_string(),
                input_index,
                script_index: None,
                source: e,
            })?;

        let (sig_index, mut args) = if let Some(script_idx) = script_index {
            (script_idx, InputArgs::new_taproot_script_args(script_idx))
        } else {
            (signatures.len() - 1, InputArgs::new_taproot_key_args())
        };
        let signature = signatures[sig_index].ok_or_else(|| BitVMXError::ErrorSigningInput {
            tx_name: name.to_string(),
            input_index,
            script_index,
            source: ProtocolBuilderError::MissingSignature,
        })?;

        args.push_taproot_signature(signature)?;
        Ok(args)
    }

    pub fn sign_ecdsa(
        &self,
        name: &str,
        input_index: usize,
        key_manager: &KeyManager,
        protocol: &mut Protocol,
    ) -> Result<InputArgs, BitVMXError> {
        let signature = protocol
            .sign_ecdsa_input(name, input_index, key_manager)
            .map_err(|e| BitVMXError::ErrorSigningInput {
                tx_name: name.to_string(),
                input_index,
                script_index: None,
                source: e,
            })?;
        let mut args = InputArgs::new_segwit_args();
        args.push_ecdsa_signature(signature)?;
        Ok(args)
    }
}

pub fn collect_input_signatures(
    protocol: &mut Protocol,
    name: &str,
    signing_infos: &Vec<InputSigningInfo>,
) -> Result<Vec<InputArgs>, BitVMXError> {
    let mut input_args = Vec::new();

    for info in signing_infos {
        input_args.push(info.get_input_signature(name, protocol)?);
    }

    Ok(input_args)
}

pub fn save_penalized_member<BC: BitcoinCoordinatorApi>(
    context: &ProgramContext<BC>,
    committee_id: Uuid,
    data: &PenalizedMember,
) -> Result<(), BitVMXError> {
    let name = data.storage_name();
    info!(
        "Updating penalized member data in storage: {}. Data: {:?}",
        name, data
    );

    context.globals.set_var(
        &committee_id,
        &name,
        VariableTypes::String(serde_json::to_string(data)?),
    )?;
    Ok(())
}

pub fn load_penalized_member<BC: BitcoinCoordinatorApi>(
    context: &ProgramContext<BC>,
    committee_id: Uuid,
    member_index: usize,
    role: ParticipantRole,
) -> Result<Option<PenalizedMember>, BitVMXError> {
    let storage_name = PenalizedMember::name(member_index, &role);
    let var = match context.globals.get_var(&committee_id, &storage_name)? {
        Some(v) => v,
        None => return Ok(None),
    };

    let data: PenalizedMember = serde_json::from_str(&var.string()?)?;
    Ok(Some(data))
}

pub fn set_my_idx<BC: BitcoinCoordinatorApi>(
    context: &ProgramContext<BC>,
    pid: Uuid,
    my_idx: usize,
) -> Result<(), BitVMXError> {
    context
        .globals
        .set_var(&pid, MY_IDX, VariableTypes::Number(my_idx as u32))?;
    Ok(())
}

pub fn get_my_idx<BC: BitcoinCoordinatorApi>(
    context: &ProgramContext<BC>,
    pid: Uuid,
) -> Result<usize, BitVMXError> {
    match context.globals.get_var(&pid, MY_IDX)? {
        Some(var) => Ok(var.number()? as usize),
        None => Err(BitVMXError::InvalidParameter(format!(
            "My index not found for protocol {}",
            pid
        ))),
    }
}

pub fn add_speedups(
    protocol: &mut protocol_builder::builder::Protocol,
    tx_name: &str,
    committee: &Committee,
) -> Result<(), BitVMXError> {
    for member in &committee.members {
        protocol.add_transaction_output(
            tx_name,
            &OutputType::segwit_key(SPEEDUP_VALUE, &member.dispute_key)?,
        )?;
    }
    Ok(())
}

pub fn get_reveal_output_value(members_count: usize) -> u64 {
    let two_dispute_penalization_fee = estimate_fee(2, members_count, 1); // All speed up outputs
    let reveal_output_value =
        (SPEEDUP_VALUE * members_count as u64 + two_dispute_penalization_fee) / 2;
    // With two reveal outputs should be able to cover the fees of the TWO_DISPUTE_PENALIZATION_TX and its speed up outputs
    reveal_output_value
}

pub fn get_op_disabler_directory_output_value(members_count: usize) -> u64 {
    (SPEEDUP_VALUE * members_count as u64 + estimate_fee(2, members_count, 1)) / 2
}

/// Magic prefix identifying a request peg-in OP_RETURN payload.
pub const REQUEST_PEGIN_OP_RETURN_MAGIC: &[u8; 9] = b"RSK_PEGIN";

/// Total length in bytes of a request peg-in OP_RETURN payload:
/// magic (9) + packet_number (8) + rootstock_address (20) + compressed pubkey (33).
pub const REQUEST_PEGIN_OP_RETURN_LEN: usize = 70;

/// Builds the request peg-in OP_RETURN payload, preserving the reimbursement key's parity.
///
/// Layout (70 bytes total):
/// - `[0..9]`   magic `"RSK_PEGIN"`
/// - `[9..17]`  packet_number, big endian u64
/// - `[17..37]` rootstock_address
/// - `[37..70]` reimbursement_pubkey, compressed secp256k1 (parity byte + X coordinate)
///
/// Takes a full `PublicKey` rather than an `XOnlyPublicKey` so truncation to x-only is a
/// compile error: P2WPKH destinations built from this key require the parity bit, since the
/// even and odd twins of an X coordinate hash to different destinations.
///
/// This is length 70, not the legacy 69 (x-only key, no parity byte). Consumers must reject
/// the legacy 69-byte payload outright: there is no accept-as-even fallback, because the
/// discarded parity bit cannot be recovered from stored x-only data.
pub fn request_pegin_op_return_data(
    packet_number: u64,
    rootstock_address: [u8; 20],
    reimbursement_pubkey: &PublicKey,
) -> Result<Vec<u8>, BitVMXError> {
    if !reimbursement_pubkey.compressed {
        return Err(BitVMXError::InvalidConversion(format!(
            "reimbursement public key must be compressed, got {} bytes",
            reimbursement_pubkey.to_bytes().len()
        )));
    }

    let payload = [
        REQUEST_PEGIN_OP_RETURN_MAGIC.as_slice(),
        &packet_number.to_be_bytes(),
        &rootstock_address,
        &reimbursement_pubkey.to_bytes(),
    ]
    .concat();

    assert_eq!(payload.len(), REQUEST_PEGIN_OP_RETURN_LEN);

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // Even parity (0x02).
    const EVEN_PUBKEY_HEX: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    // Odd parity (0x03).
    const ODD_PUBKEY_HEX: &str =
        "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";

    fn packet_number() -> u64 {
        42
    }

    fn rootstock_address() -> [u8; 20] {
        [7u8; 20]
    }

    /// Hardcoded expected payload: magic "RSK_PEGIN", packet number 42 big endian,
    /// rootstock address of twenty 0x07 bytes, then the compressed key.
    fn expected_payload_hex(pubkey_hex: &str) -> String {
        format!(
            "{}{}{}{}",
            "52534b5f504547494e",
            "000000000000002a",
            "07".repeat(20),
            pubkey_hex
        )
    }

    #[test]
    fn even_parity_key_produces_expected_payload() {
        let pubkey = PublicKey::from_str(EVEN_PUBKEY_HEX).unwrap();
        let payload =
            request_pegin_op_return_data(packet_number(), rootstock_address(), &pubkey).unwrap();

        assert_eq!(payload.len(), REQUEST_PEGIN_OP_RETURN_LEN);
        assert_eq!(hex::encode(&payload), expected_payload_hex(EVEN_PUBKEY_HEX));
        assert_eq!(payload[37], 0x02);

        let round_tripped = PublicKey::from_slice(&payload[37..70]).unwrap();
        assert_eq!(round_tripped, pubkey);
    }

    #[test]
    fn uncompressed_key_is_rejected() {
        let mut pubkey = PublicKey::from_str(EVEN_PUBKEY_HEX).unwrap();
        pubkey.compressed = false;

        assert!(
            request_pegin_op_return_data(packet_number(), rootstock_address(), &pubkey).is_err()
        );
    }

    #[test]
    fn odd_parity_key_produces_expected_payload() {
        let pubkey = PublicKey::from_str(ODD_PUBKEY_HEX).unwrap();
        let payload =
            request_pegin_op_return_data(packet_number(), rootstock_address(), &pubkey).unwrap();

        assert_eq!(payload.len(), REQUEST_PEGIN_OP_RETURN_LEN);
        assert_eq!(hex::encode(&payload), expected_payload_hex(ODD_PUBKEY_HEX));
        assert_eq!(payload[37], 0x03);

        let round_tripped = PublicKey::from_slice(&payload[37..70]).unwrap();
        assert_eq!(round_tripped, pubkey);
    }
}
