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
    );

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

// In order to init a challenge, script should:
// 1. Verify WT dispute key.
// 2. Verify WT slot id winternitz signature and keep signed value in stack for later validation.
// 3. Verify OP slot id key signature (This is the one that OP will reveal in REVEAL_TX witness) (Discard this value from stack)
// 4. Verify previous signed value against expected slot id value.
pub fn init_challenge_script(
    wt_dispute_key: &PublicKey,
    sign_mode: SignMode,
    slot_id_key_name: &str,
    slot_id_pubkey: &WinternitzPublicKey,
    slot_id: u32,
    wt_key_name: &str,
    wt_winternitz_pubkey: &WinternitzPublicKey,
) -> Result<ProtocolScript, ScriptError> {
    // Create validation script
    let mut stack = StackTracker::new();
    let wt_value = stack.define(4 * 2, "wt_signed_value"); // each number is 4 bytes, each byte is 2 nibbles
    let op_value = stack.define(2 * 2, "op_signed_value"); // each number is 2 bytes, each byte is 2 nibbles
    stack.drop(op_value); // Drop OP signed value as we don't need it after validation
    let number = stack.number_u32(slot_id); // Push expected slot id value to stack
    stack.equals(number, true, wt_value, true); // Compare expected slot id with WT signed value
    let validate_slot_id = stack.get_script();

    let protocol_script = verify_winternitz_signatures_aux::<&str>(
        wt_dispute_key,
        &vec![
            (wt_key_name, wt_winternitz_pubkey),
            (slot_id_key_name, slot_id_pubkey),
        ],
        sign_mode,
        true,
        Some(vec![validate_slot_id]),
    )?;

    Ok(protocol_script)
}

// In order to cosign a challenge, script should:
// 1. Verify OP dispute key.
// 3. Verify OP winternitz signature and keep signed value in stack for later validation.
// 2. Verify WT winternitz signature and keep signed value in stack (This is the one that WT will reveal in INIT_CHALLENGE_TX witness)
// 4. Verify both values in stack are equal
pub fn cosign_script(
    op_dispute_key: &PublicKey,
    sign_mode: SignMode,
    wt_key_name: &str,
    wt_winternitz_pubkey: &WinternitzPublicKey,
    op_key_name: &str,
    op_winternitz_pubkey: &WinternitzPublicKey,
) -> Result<ProtocolScript, ScriptError> {
    let validate_cosign = get_stack_equality_script(1);

    let protocol_script = verify_winternitz_signatures_aux::<&str>(
        op_dispute_key,
        &vec![
            (op_key_name, op_winternitz_pubkey),
            (wt_key_name, wt_winternitz_pubkey),
        ],
        sign_mode,
        true,
        Some(vec![validate_cosign]),
    )?;

    Ok(protocol_script)
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
    );

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

// Unused currently
// pub fn reveal_take_private_key(
//     public_key: &PublicKey,
//     take_private_key: &WinternitzPublicKey,
// ) -> Result<ProtocolScript, ScriptError> {
//     let script = script!(
//         { XOnlyPublicKey::from(public_key.clone()).serialize().to_vec() }
//         OP_CHECKSIGVERIFY

//         { ots_checksig(take_private_key, false)? }
//         OP_PUSHNUM_1
//     );

//     let mut protocol_script = ProtocolScript::new(script, public_key, SignMode::Aggregate);
//     protocol_script.add_key(
//         "pegout_id",
//         take_private_key.derivation_index()?,
//         KeyType::winternitz(take_private_key)?,
//         0,
//     )?;

//     protocol_script.add_stack_item(StackItem::SchnorrSig {
//         non_default_sighash: true,
//     });

//     let extra_data = take_private_key.extra_data().unwrap();
//     protocol_script.add_stack_item(StackItem::WinternitzSig {
//         size: extra_data.message_size() + extra_data.checksum_size(),
//     });

//     Ok(protocol_script)
// }
