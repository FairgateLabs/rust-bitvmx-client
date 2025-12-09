use bitcoin::{PublicKey, XOnlyPublicKey};
use key_manager::winternitz::WinternitzPublicKey;
use protocol_builder::{
    errors::ScriptError,
    scripts::{ots_checksig, KeyType, ProtocolScript, SignMode, StackItem},
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
