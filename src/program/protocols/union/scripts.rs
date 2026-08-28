use bitcoin::{PublicKey, ScriptBuf, XOnlyPublicKey};
use bitcoin_script_stack::stack::StackTracker;
use key_manager::winternitz::WinternitzPublicKey;
use protocol_builder::{
    errors::ScriptError,
    scripts::{
        ots_checksig, verify_winternitz_signatures_aux, KeyType, ProtocolScript, SignMode,
        StackItem,
    },
};

use bitcoin_scriptexec::treepp::*;

use crate::program::protocols::union::{
    common::{double_indexed_name, indexed_name},
    dispute_core::{
        OP_COSIGN_PEGOUT_ID_KEY, OP_COSIGN_SLOT_KEY, PEGOUT_ID_KEY, PEGOUT_ID_KEY_WORDS,
        SLOT_ID_KEY, WT_COSIGN_PEGOUT_ID_KEY, WT_COSIGN_SLOT_KEY,
    },
};

pub fn verify_winternitz(
    pubkey: &PublicKey,
    sign_mode: SignMode,
    winternitz_name: &str,
    winternitz_pubkey: &WinternitzPublicKey,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(pubkey.clone()).serialize().to_vec() }
        OP_CHECKSIGVERIFY

        { ots_checksig(winternitz_pubkey, false)? }
        OP_PUSHNUM_1
    )
    .compile();

    let mut protocol_script = ProtocolScript::new(script, &pubkey, sign_mode);

    protocol_script.add_key(
        winternitz_name,
        winternitz_pubkey.derivation_index()?,
        KeyType::winternitz(winternitz_pubkey)?,
        0,
    )?;

    protocol_script.add_stack_item(StackItem::new_schnorr_sig(true));
    protocol_script.add_stack_item(StackItem::new_winternitz_sig(&winternitz_pubkey));

    Ok(protocol_script)
}

pub fn init_challenge_script(
    wt_dispute_key: &PublicKey,
    sign_mode: SignMode,
    slot_id: u32,
    op_index: usize,
    op_slot_id_pubkey: &WinternitzPublicKey,
    op_pegout_id_pubkey: &WinternitzPublicKey,
    wt_cosign_slot_id_pubkey: &WinternitzPublicKey,
    wt_cosign_pegout_id_keys: &Vec<&WinternitzPublicKey>,
) -> Result<ProtocolScript, ScriptError> {
    // Create validation script
    let mut stack = StackTracker::new();
    let op_value = stack.define(2 * 2, "op_signed_value"); // each number is 2 bytes, each byte is 2 nibbles
    let wt_value = stack.define(4 * 2, "wt_signed_value"); // each number is 4 bytes, each byte is 2 nibbles
    let number = stack.number_u32(slot_id); // Push expected slot id value to stack
    stack.reverse_u32(number);
    stack.equals(wt_value, true, number, true); // Compare expected slot id with WT signed value
    stack.drop(op_value); // Drop OP signed value as we don't need it after validation
    let validate_slot_id = stack.get_script();
    let validate_pegout_id = get_stack_equality_script(PEGOUT_ID_KEY_WORDS as u32);

    let mut keys = vec![
        (
            indexed_name(WT_COSIGN_SLOT_KEY, op_index),
            wt_cosign_slot_id_pubkey,
        ),
        (indexed_name(SLOT_ID_KEY, op_index), op_slot_id_pubkey),
        (indexed_name(PEGOUT_ID_KEY, op_index), op_pegout_id_pubkey),
    ];

    for (i, key) in wt_cosign_pegout_id_keys.iter().enumerate() {
        keys.push((
            double_indexed_name(WT_COSIGN_PEGOUT_ID_KEY, op_index, i),
            key,
        ));
    }

    verify_winternitz_signatures_aux::<String>(
        wt_dispute_key,
        &keys.to_vec(),
        sign_mode,
        true,
        Some(vec![validate_slot_id, validate_pegout_id]),
    )
}

pub fn cosign_script(
    op_dispute_key: &PublicKey,
    sign_mode: SignMode,
    op_index: usize,
    op_cosign_slot_id_pubkey: &WinternitzPublicKey,
    wt_cosign_slot_id_pubkey: &WinternitzPublicKey,
    op_cosign_pegout_id_keys: &Vec<&WinternitzPublicKey>,
    wt_cosign_pegout_id_keys: &Vec<&WinternitzPublicKey>,
) -> Result<ProtocolScript, ScriptError> {
    let mut validate_cosign = vec![get_stack_equality_script(1)]; // Validate slot id

    for _ in 0..PEGOUT_ID_KEY_WORDS {
        // Validate pegout id words
        validate_cosign.push(get_stack_equality_script(1));
    }

    let mut keys = vec![
        (
            indexed_name(OP_COSIGN_SLOT_KEY, op_index),
            op_cosign_slot_id_pubkey,
        ),
        (
            indexed_name(WT_COSIGN_SLOT_KEY, op_index),
            wt_cosign_slot_id_pubkey,
        ),
    ];

    assert_eq!(
        op_cosign_pegout_id_keys.len(),
        wt_cosign_pegout_id_keys.len()
    );

    for i in 0..wt_cosign_pegout_id_keys.len() {
        keys.push((
            double_indexed_name(OP_COSIGN_PEGOUT_ID_KEY, op_index, i),
            op_cosign_pegout_id_keys[i],
        ));

        keys.push((
            double_indexed_name(WT_COSIGN_PEGOUT_ID_KEY, op_index, i),
            wt_cosign_pegout_id_keys[i],
        ));
    }

    verify_winternitz_signatures_aux::<String>(
        op_dispute_key,
        &keys,
        sign_mode,
        true,
        Some(validate_cosign),
    )
}

fn get_stack_equality_script(words: u32) -> ScriptBuf {
    let word_size = 4;
    let mut stack = StackTracker::new();
    let value_1 = stack.define(word_size * 2 * words, "value_1");
    let value_2 = stack.define(word_size * 2 * words, "value_2"); // each word is 4 bytes, each byte is 2 nibbles
    stack.equals(value_1, true, value_2, true);
    stack.get_script()
}

pub fn operator_pegout_id(
    public_key: &PublicKey,
    pegout_id_key: &WinternitzPublicKey,
    secret_key: &WinternitzPublicKey,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(public_key.clone()).serialize().to_vec() }
        OP_CHECKSIGVERIFY

        { ots_checksig(pegout_id_key, false)? }
        { ots_checksig(secret_key, false)? }
        OP_PUSHNUM_1
    )
    .compile();

    let mut protocol_script = ProtocolScript::new(script, &public_key, SignMode::Aggregate);
    protocol_script.add_key(
        "pegout_id",
        pegout_id_key.derivation_index()?,
        KeyType::winternitz(pegout_id_key)?,
        0,
    )?;

    protocol_script.add_key(
        "secret_key",
        secret_key.derivation_index()?,
        KeyType::winternitz(secret_key)?,
        1,
    )?;

    protocol_script.add_stack_item(StackItem::SchnorrSig {
        non_default_sighash: true,
    });

    let extra_data = pegout_id_key.extra_data().unwrap();
    protocol_script.add_stack_item(StackItem::WinternitzSig {
        size: extra_data.message_size() + extra_data.checksum_size(),
    });

    let extra_data = secret_key.extra_data().unwrap();
    protocol_script.add_stack_item(StackItem::WinternitzSig {
        size: extra_data.message_size() + extra_data.checksum_size(),
    });

    Ok(protocol_script)
}
