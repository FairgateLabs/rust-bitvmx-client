use std::collections::HashMap;

use bitcoin::{
    absolute::{self},
    hashes::Hash,
    sighash::{Prevouts, SighashCache, TaprootError},
    transaction, Amount, PublicKey, ScriptBuf, Sequence, TapSighash, TapSighashType, Transaction,
    TxOut, Txid, Witness,
};
use bitvmx_client::program::protocols::union::types::{
    StreamSettings, UnionSettings, P2TR_FEE, SPEEDUP_VALUE, USER_TAKE_FEE,
};
use tracing::info;

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
    let txin = bitcoin::TxIn {
        previous_output: bitcoin::OutPoint {
            txid: accept_pegin_txid,
            vout: 0,
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

    let tx_out1 = TxOut {
        value: Amount::from_sat(user_take_output_value),
        script_pubkey: script_pubkey.clone().into(),
    };

    let tx_out2 = TxOut {
        value: Amount::from_sat(SPEEDUP_VALUE),
        script_pubkey: script_pubkey.into(),
    };

    Transaction {
        version: transaction::Version::TWO,  // Post BIP-68.
        lock_time: absolute::LockTime::ZERO, // Ignore the transaction lvl absolute locktime.
        input: vec![txin],
        output: vec![tx_out1, tx_out2],
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
            op_won_timelock: 18,
        },
    );

    settings.settings.insert(
        100000,
        StreamSettings {
            short_timelock: 6,
            long_timelock: 12,
            op_won_timelock: 18,
        },
    );

    settings.settings.insert(
        1000000,
        StreamSettings {
            short_timelock: 6,
            long_timelock: 12,
            op_won_timelock: 18,
        },
    );

    settings
}
