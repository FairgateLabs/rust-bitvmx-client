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
        info!("  - ScriptSig: {}", input.script_sig.as_bytes().to_lower_hex_string());
        info!("  - Sequence: 0x{:08X} ({})", input.sequence.0, input.sequence.0);
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
        info!("  - ScriptPubKey: {}", output.script_pubkey.as_bytes().to_lower_hex_string());
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
    output.push_str(&format!("        BtcTxIn[] memory inputs = new BtcTxIn[]({});\n", tx.input.len()));

    // Assign each input
    for (i, input) in tx.input.iter().enumerate() {
        output.push_str(&format!("        inputs[{}] = BtcTxIn({{\n", i));
        output.push_str(&format!("            txId: 0x{},\n", input.previous_output.txid));
        output.push_str(&format!("            vout: {},\n", input.previous_output.vout));
        output.push_str(&format!("            scriptSig: hex\"{}\",\n", input.script_sig.as_bytes().to_lower_hex_string()));
        output.push_str(&format!("            sequence: {}\n", input.sequence.0));
        output.push_str("        });\n");
        if i < tx.input.len() - 1 {
            output.push_str("\n");
        }
    }

    output.push_str("\n");

    // Declare outputs array
    output.push_str(&format!("        BtcTxOut[] memory outputs = new BtcTxOut[]({});\n", tx.output.len()));

    // Assign each output
    for (i, out) in tx.output.iter().enumerate() {
        output.push_str(&format!("        outputs[{}] = BtcTxOut({{\n", i));
        output.push_str(&format!("            amount: {},\n", out.value.to_sat()));
        output.push_str(&format!("            scriptPubKey: hex\"{}\"\n", out.script_pubkey.as_bytes().to_lower_hex_string()));
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
            short_timelock: 6,
            long_timelock: 12,
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
            short_timelock: 6,
            long_timelock: 12,
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
            short_timelock: 6,
            long_timelock: 12,
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
