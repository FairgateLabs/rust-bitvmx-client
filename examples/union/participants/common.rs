use std::collections::HashMap;

use bitcoin::{
    absolute::{self},
    hashes::Hash,
    hex::DisplayHex,
    sighash::{Prevouts, SighashCache, TaprootError},
    transaction, Amount, PublicKey, ScriptBuf, Sequence, TapSighash, TapSighashType, Transaction,
    TxOut, Txid, Witness,
};
use bitvmx_client::program::protocols::union::types::{
    StreamSettings, UnionSettings, P2TR_FEE, SPEEDUP_VALUE, USER_TAKE_FEE,
};
pub const PEGIN_CONFIRMATIONS: u16 = 6; // This value should be get from the contract
pub const PEGOUT_CONFIRMATIONS: u16 = 6; // This value should be get from the contract

/// Format a Bitcoin transaction in Solidity syntax for cross-system verification
pub fn format_transaction_solidity(tx: &Transaction) -> String {
    let mut output = String::new();

    // Declare inputs array
    output.push_str(&format!(
        "        BtcTxIn[] memory inputs = new BtcTxIn[]({});\n",
        tx.input.len()
    ));

    // Assign each input
    for (i, input) in tx.input.iter().enumerate() {
        output.push_str(&format!("        inputs[{}] = BtcTxIn({{\n", i));
        output.push_str(&format!(
            "            txId: 0x{},\n",
            input.previous_output.txid
        ));
        output.push_str(&format!(
            "            vout: {},\n",
            input.previous_output.vout
        ));
        output.push_str(&format!(
            "            scriptSig: hex\"{}\",\n",
            input.script_sig.as_bytes().to_lower_hex_string()
        ));
        output.push_str(&format!("            sequence: {}\n", input.sequence.0));
        output.push_str("        });\n");
        if i < tx.input.len() - 1 {
            output.push_str("\n");
        }
    }

    output.push_str("\n");

    // Declare outputs array
    output.push_str(&format!(
        "        BtcTxOut[] memory outputs = new BtcTxOut[]({});\n",
        tx.output.len()
    ));

    // Assign each output
    for (i, out) in tx.output.iter().enumerate() {
        let amount = out.value.to_sat();
        let script_hex = out.script_pubkey.as_bytes().to_lower_hex_string();
        let single = format!(
            "        outputs[{}] = BtcTxOut({{amount: {}, scriptPubKey: hex\"{}\"}});\n",
            i, amount, script_hex
        );
        if single.len() - 1 <= 120 {
            output.push_str(&single);
        } else {
            output.push_str(&format!("        outputs[{}] = BtcTxOut({{\n", i));
            output.push_str(&format!("            amount: {},\n", amount));
            output.push_str(&format!("            scriptPubKey: hex\"{}\"\n", script_hex));
            output.push_str("        });\n");
        }
        if i < tx.output.len() - 1 {
            output.push_str("\n");
        }
    }

    output.push_str("\n");

    // Return statement
    output.push_str(&format!(
        "        return BtcTransaction({{version: {}, inputs: inputs, outputs: outputs, locktime: {}}});",
        tx.version.0,
        tx.lock_time
    ));

    output
}

fn tx_name_to_const_name(tx_name: &str) -> String {
    let base = if let Some(pos) = tx_name.find("_TX") {
        &tx_name[..pos]
    } else {
        tx_name
    };
    format!("EXPECTED_{}_TXID", base)
}

fn tx_name_to_fn_name(tx_name: &str) -> String {
    let base = if let Some(pos) = tx_name.find("_TX") {
        &tx_name[..pos]
    } else {
        tx_name
    };

    let pascal: String = base
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => {
                    first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                }
            }
        })
        .collect();

    format!("_getBitVMX{}Tx", pascal)
}

fn format_bytes_constant(name: &str, value: &str) -> String {
    let single = format!("    bytes constant {} = {};", name, value);
    if single.len() <= 120 {
        format!("{}\n", single)
    } else {
        format!("    bytes constant {} =\n        {};\n", name, value)
    }
}

fn format_bytes32_constant(name: &str, value: &str) -> String {
    let single = format!("    bytes32 constant {} = {};", name, value);
    if single.len() <= 120 {
        format!("{}\n", single)
    } else {
        format!("    bytes32 constant {} =\n        {};\n", name, value)
    }
}

pub fn format_solidity_data_file(
    committee_agg_key: &PublicKey,
    dispute_keys: &[PublicKey],
    user_pubkey: &PublicKey,
    pegout_id: &[u8; 32],
    op_index: usize,
    operator_count: usize,
    watchtower_count: usize,
    named_transactions: &[(&str, Transaction)],
    export_txids: &[&str],
) -> String {
    let mut s = String::new();

    s.push_str("// SPDX-License-Identifier: Unlicense\n");
    s.push_str("pragma solidity ^0.8.20;\n");
    s.push_str("\n");
    s.push_str("// GENERATED FILE - do not edit manually.\n");
    s.push_str("// Run: ./examples/union/scripts/run-example.sh solidity_txs\n");
    s.push_str("// from the rust-bitvmx-client directory.\n");
    s.push_str("\n");
    s.push_str(
        "import {BtcTransaction, BtcTxIn, BtcTxOut} from \"src/interfaces/IBitcoinManager.sol\";\n",
    );
    s.push_str("import {CompactPubKey} from \"src/interfaces/IMemberRegistry.sol\";\n");
    s.push_str("\n");
    s.push_str("contract BitVMXCompatibilityData {\n");
    s.push_str("    // All transactions below correspond to slot index 0 and operator index 1.\n");
    s.push_str("    // These are fixed for testing purposes.\n");
    s.push_str("\n");

    let key_hex = committee_agg_key
        .to_bytes()
        .as_slice()
        .to_lower_hex_string();
    s.push_str(&format_bytes_constant("COMMITTEE_AGGREGATED_KEY", &format!("hex\"{}\"", key_hex)));
    s.push_str("\n");

    let user_key_hex = user_pubkey.to_bytes().as_slice().to_lower_hex_string();
    s.push_str(&format_bytes_constant("USER_COMPRESSED_PUBKEY", &format!("hex\"{}\"", user_key_hex)));
    s.push_str("\n");

    s.push_str(&format_bytes32_constant("PEGOUT_ID", &format!("0x{}", pegout_id.as_slice().to_lower_hex_string())));
    s.push_str("\n");

    s.push_str(&format!("    uint256 constant OPERATOR_INDEX = {};\n", op_index));
    s.push_str(&format!("    uint8 constant OPERATOR_COUNT = {};\n", operator_count));
    s.push_str(&format!("    uint8 constant WATCHTOWER_COUNT = {};\n", watchtower_count));
    s.push_str("\n");

    for (name, tx) in named_transactions {
        if export_txids.contains(name) {
            let const_name = tx_name_to_const_name(name);
            s.push_str(&format_bytes32_constant(&const_name, &format!("0x{}", tx.compute_txid())));
            s.push_str("\n");
        }
    }

    s.push_str(
        "    function _getBitVMXDisputeKeys() internal pure returns (CompactPubKey[] memory keys) {\n",
    );
    s.push_str(&format!(
        "        keys = new CompactPubKey[]({});\n",
        dispute_keys.len()
    ));
    for (i, key) in dispute_keys.iter().enumerate() {
        let bytes = key.to_bytes();
        let parity = bytes[0];
        let x_only = &bytes[1..];
        s.push_str(&format!(
            "        keys[{}] =\n            CompactPubKey({{parity: 0x{:02x}, xOnly: 0x{}}});\n",
            i,
            parity,
            x_only.to_lower_hex_string()
        ));
    }
    s.push_str("    }\n");
    s.push_str("\n");

    for (i, (name, tx)) in named_transactions.iter().enumerate() {
        let fn_name = tx_name_to_fn_name(name);
        s.push_str(&format!(
            "    function {}() internal pure returns (BtcTransaction memory) {{\n",
            fn_name
        ));
        s.push_str(&format_transaction_solidity(tx));
        s.push_str("\n    }\n");
        if i < named_transactions.len() - 1 {
            s.push_str("\n");
        }
    }

    s.push_str("}\n");
    s
}

pub fn prefixed_name(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        return name.to_string();
    }
    format!("{}_{}", prefix, name)
}

pub fn get_user_take_tx(
    stream_value: u64,
    accept_pegin_txid: Txid,
    user_pubkey: PublicKey,
) -> Transaction {
    let txin_0 = bitcoin::TxIn {
        previous_output: bitcoin::OutPoint {
            txid: accept_pegin_txid,
            vout: 0,
        },
        script_sig: ScriptBuf::default(), // For a p2wpkh script_sig is empty.
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // we want to be able to replace this transaction
        witness: Witness::default(),                // Filled in after, at signing time.
    };

    let txin_1 = bitcoin::TxIn {
        previous_output: bitcoin::OutPoint {
            txid: accept_pegin_txid,
            vout: 1,
        },
        script_sig: ScriptBuf::default(), // For a p2wpkh script_sig is empty.
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // we want to be able to replace this transaction
        witness: Witness::default(),                // Filled in after, at signing time.
    };

    let accept_pegin_input = stream_value - P2TR_FEE - SPEEDUP_VALUE;
    let user_take_output_value = accept_pegin_input - SPEEDUP_VALUE - USER_TAKE_FEE;

    // Build two P2WPKH outputs paying to the user's public key (1000 sats each)
    let wpkh = user_pubkey.wpubkey_hash().expect("key is compressed");
    let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

    let tx_out0 = TxOut {
        value: Amount::from_sat(user_take_output_value),
        script_pubkey: script_pubkey.clone().into(),
    };

    let tx_out1 = TxOut {
        value: Amount::from_sat(SPEEDUP_VALUE),
        script_pubkey: script_pubkey.into(),
    };

    Transaction {
        version: transaction::Version::TWO,  // Post BIP-68.
        lock_time: absolute::LockTime::ZERO, // Ignore the transaction lvl absolute locktime.
        input: vec![txin_0, txin_1],
        output: vec![tx_out0, tx_out1],
    }
}

pub fn calculate_taproot_key_path_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32], TaprootError> {
    let mut sighash_cache = SighashCache::new(tx);
    let prevouts = Prevouts::All(prevouts);

    let sighash: TapSighash = sighash_cache.taproot_key_spend_signature_hash(
        input_index,
        &prevouts,
        TapSighashType::All,
    )?;

    Ok(sighash.to_raw_hash().as_byte_array().clone())
}

pub fn get_default_union_settings() -> UnionSettings {
    let mut settings = UnionSettings {
        settings: HashMap::new(),
    };

    settings.settings.insert(
        30000,
        StreamSettings {
            short_timelock: PEGIN_CONFIRMATIONS,
            long_timelock: PEGIN_CONFIRMATIONS + 6,
            op_won_timelock: 150,
            claim_gate_timelock: 6,
            input_not_revealed_timelock: 8,
            op_no_cosign_timelock: 12,
            wt_no_challenge_timelock: 12,
            request_pegin_timelock: 12,
        },
    );

    settings.settings.insert(
        100000,
        StreamSettings {
            short_timelock: PEGIN_CONFIRMATIONS,
            long_timelock: PEGIN_CONFIRMATIONS + 6,
            op_won_timelock: 150,
            claim_gate_timelock: 6,
            input_not_revealed_timelock: 8,
            op_no_cosign_timelock: 12,
            wt_no_challenge_timelock: 12,
            request_pegin_timelock: 12,
        },
    );

    settings.settings.insert(
        1000000,
        StreamSettings {
            short_timelock: PEGIN_CONFIRMATIONS,
            long_timelock: PEGIN_CONFIRMATIONS + 6,
            op_won_timelock: 150,
            claim_gate_timelock: 6,
            input_not_revealed_timelock: 8,
            op_no_cosign_timelock: 12,
            wt_no_challenge_timelock: 12,
            request_pegin_timelock: 12,
        },
    );

    settings
}
