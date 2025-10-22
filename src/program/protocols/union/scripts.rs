use bitcoin::{PublicKey, XOnlyPublicKey};
use key_manager::winternitz::WinternitzPublicKey;
use protocol_builder::{
    errors::ScriptError,
    scripts::{ots_checksig, KeyType, ProtocolScript, SignMode, StackItem},
};

use bitcoin_scriptexec::treepp::*;

pub fn start_reimbursement(
    committee_key: &PublicKey,
    pegout_id_pubkey_name: &str,
    pegout_id_pubkey: &WinternitzPublicKey,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(committee_key.clone()).serialize().to_vec() }
        OP_CHECKSIGVERIFY

        { ots_checksig(pegout_id_pubkey, false)? }
        OP_PUSHNUM_1
    );

    let mut protocol_script = ProtocolScript::new(script, &committee_key, SignMode::Aggregate);

    protocol_script.add_key(
        pegout_id_pubkey_name,
        pegout_id_pubkey.derivation_index()?,
        KeyType::winternitz(pegout_id_pubkey)?,
        0,
    )?;

    protocol_script.add_stack_item(StackItem::new_schnorr_sig(true));
    protocol_script.add_stack_item(StackItem::new_winternitz_sig(&pegout_id_pubkey));

    Ok(protocol_script)
}

// TODO: this is almost the same as start_reimbursement. DRY this up.
pub fn start_challenge(
    committee_key: &PublicKey,
    slot_id_pubkey_name: &str,
    slot_id_pubkey: &WinternitzPublicKey,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(committee_key.clone()).serialize().to_vec() }
        OP_CHECKSIGVERIFY

        { ots_checksig(slot_id_pubkey, false)? }
        OP_PUSHNUM_1
    );

    let mut protocol_script = ProtocolScript::new(script, &committee_key, SignMode::Aggregate);

    protocol_script.add_key(
        slot_id_pubkey_name,
        slot_id_pubkey.derivation_index()?,
        KeyType::winternitz(slot_id_pubkey)?,
        0,
    )?;

    protocol_script.add_stack_item(StackItem::new_schnorr_sig(true));
    protocol_script.add_stack_item(StackItem::new_winternitz_sig(&slot_id_pubkey));

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

pub fn reveal_take_private_key(
    public_key: &PublicKey,
    take_private_key: &WinternitzPublicKey,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(public_key.clone()).serialize().to_vec() }
        OP_CHECKSIGVERIFY

        { ots_checksig(take_private_key, false)? }
        OP_PUSHNUM_1
    );

    let mut protocol_script = ProtocolScript::new(script, public_key, SignMode::Aggregate);
    protocol_script.add_key(
        "pegout_id",
        take_private_key.derivation_index()?,
        KeyType::winternitz(take_private_key)?,
        0,
    )?;

    protocol_script.add_stack_item(StackItem::SchnorrSig {
        non_default_sighash: true,
    });

    let extra_data = take_private_key.extra_data().unwrap();
    protocol_script.add_stack_item(StackItem::WinternitzSig {
        size: extra_data.message_size() + extra_data.checksum_size(),
    });

    Ok(protocol_script)
}
