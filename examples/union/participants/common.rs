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
use tracing::info;

pub const DEBUG_TX: bool = false;
pub const PEGIN_CONFIRMATIONS: u16 = 6; // This value should be get from the contract
pub const PEGOUT_CONFIRMATIONS: u16 = 6; // This value should be get from the contract

/// Generic transaction debug printer that can be used for any transaction type
pub fn db_print_transaction<F>(title: &str, tx: &Transaction, print_params: F)
where
    F: FnOnce(),
{
    if !DEBUG_TX {
        return;
    }

    info!("=== {} ===", title);

    // Print transaction-specific parameters using the closure
    print_params();

    info!("Transaction Structure:");
    info!("  - Version: {}", tx.version.0);
    info!("  - Number of Inputs: {}", tx.input.len());
    info!("  - Number of Outputs: {}", tx.output.len());
    info!("  - Locktime: {}", tx.lock_time);
    info!("");
    info!("Transaction Details:");
    info!("  - TxId: 0x{}", tx.compute_txid());
    info!("");

    // Log each input
    for (i, input) in tx.input.iter().enumerate() {
        info!("Input {}:", i);
        info!("  - Previous TxId: 0x{}", input.previous_output.txid);
        info!("  - Previous Vout: {}", input.previous_output.vout);
        info!(
            "  - ScriptSig: {}",
            input.script_sig.as_bytes().to_lower_hex_string()
        );
        info!(
            "  - Sequence: 0x{:08X} ({})",
            input.sequence.0, input.sequence.0
        );
        info!("  - Witness items: {}", input.witness.len());
        for (j, witness_item) in input.witness.iter().enumerate() {
            info!("    Witness {}: {}", j, witness_item.to_lower_hex_string());
        }
    }
    info!("");

    // Log each output
    for (i, output) in tx.output.iter().enumerate() {
        info!("Output {}:", i);
        info!("  - Value: {} satoshis", output.value.to_sat());
        info!(
            "  - ScriptPubKey: {}",
            output.script_pubkey.as_bytes().to_lower_hex_string()
        );
    }
    info!("");

    info!("Solidity Transaction Format:");
    info!("{}", format_transaction_solidity(tx));
    info!("==========================================");
    info!("");
}

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
        output.push_str(&format!("        outputs[{}] = BtcTxOut({{\n", i));
        output.push_str(&format!("            amount: {},\n", out.value.to_sat()));
        output.push_str(&format!(
            "            scriptPubKey: hex\"{}\"\n",
            out.script_pubkey.as_bytes().to_lower_hex_string()
        ));
        output.push_str("        });\n");
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

pub fn format_solidity_data_file(
    committee_agg_key: &PublicKey,
    dispute_keys: &[PublicKey],
    user_pubkey: &PublicKey,
    pegout_id: &[u8; 32],
    named_transactions: &[(&str, Transaction)],
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
    s.push_str("    bytes constant COMMITTEE_AGGREGATED_KEY =\n");
    s.push_str(&format!("        hex\"{}\";\n", key_hex));
    s.push_str("\n");

    let user_key_hex = user_pubkey.to_bytes().as_slice().to_lower_hex_string();
    s.push_str("    bytes constant USER_COMPRESSED_PUBKEY =\n");
    s.push_str(&format!("        hex\"{}\";\n", user_key_hex));
    s.push_str("\n");

    s.push_str("    bytes32 constant PEGOUT_ID =\n");
    s.push_str(&format!(
        "        0x{};\n",
        pegout_id.as_slice().to_lower_hex_string()
    ));
    s.push_str("\n");

    for (name, tx) in named_transactions {
        let const_name = tx_name_to_const_name(name);
        s.push_str(&format!("    bytes32 constant {} =\n", const_name));
        s.push_str(&format!("        0x{};\n", tx.compute_txid()));
        s.push_str("\n");
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
            "        keys[{}] = CompactPubKey({{parity: 0x{:02x}, xOnly: 0x{}}});\n",
            i,
            parity,
            x_only.to_lower_hex_string()
        ));
    }
    s.push_str("    }\n");
    s.push_str("\n");

    for (name, tx) in named_transactions {
        let fn_name = tx_name_to_fn_name(name);
        s.push_str(&format!(
            "    function {}() internal pure returns (BtcTransaction memory) {{\n",
            fn_name
        ));
        s.push_str(&format_transaction_solidity(tx));
        s.push_str("\n    }\n");
        s.push_str("\n");
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
    info!("TX: {:?}", tx);
    info!("Prevouts: {:?}", prevouts);

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
