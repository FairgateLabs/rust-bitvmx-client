use bitcoin::{PublicKey, XOnlyPublicKey};
use key_manager::winternitz::WinternitzPublicKey;
use protocol_builder::{
    errors::ScriptError,
    scripts::{ots_checksig, KeyType, ProtocolScript, SignMode, StackItem},
};

use bitcoin_scriptexec::treepp::*;

pub fn start_reimbursement(
    committee_key: &PublicKey,
    operator_key: &PublicKey,
    pegout_id_pubkey: &WinternitzPublicKey,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(committee_key.clone()).serialize().to_vec() }
        OP_CHECKSIGVERIFY

        // { XOnlyPublicKey::from(operator_key.clone()).serialize().to_vec() }
        // OP_CHECKSIGVERIFY

        { ots_checksig(pegout_id_pubkey, false)? }
        OP_PUSHNUM_1
    );

    let mut protocol_script = ProtocolScript::new(script, &committee_key, SignMode::Aggregate);

    //TODO: bogus derivation index 0, the only pks that need derivation index are the winternitz keys. Consider making the derivation index optional.
    // protocol_script.add_key("operator_key", 0, KeyType::XOnlyKey, 0)?;

    protocol_script.add_key(
        "pegout_id",
        pegout_id_pubkey.derivation_index()?,
        KeyType::WinternitzKey(pegout_id_pubkey.key_type()),
        1,
    )?;

    protocol_script.add_stack_item(StackItem::SchnorrSig {
        non_default_sighash: true,
    });

    protocol_script.add_stack_item(StackItem::SchnorrSig {
        non_default_sighash: true,
    });

    let extra_data = pegout_id_pubkey.extra_data().unwrap();
    protocol_script.add_stack_item(StackItem::WinternitzSig {
        // FIXME: signature size estimation
        size: (extra_data.message_size() + extra_data.checksum_size()) * 20,
    });

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
        KeyType::WinternitzKey(pegout_id_key.key_type()),
        0,
    )?;

    protocol_script.add_key(
        "secret_key",
        secret_key.derivation_index()?,
        KeyType::WinternitzKey(secret_key.key_type()),
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
        KeyType::WinternitzKey(take_private_key.key_type()),
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
