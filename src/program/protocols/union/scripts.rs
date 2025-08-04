use bitcoin::{PublicKey, XOnlyPublicKey};
use key_manager::winternitz::WinternitzPublicKey;
use protocol_builder::{
    errors::ScriptError,
    scripts::{ots_checksig, KeyType, ProtocolScript, SignMode},
};

use bitcoin_scriptexec::treepp::*;

pub fn start_reimbursement(
    public_key: PublicKey,
    pegout_id_pubkey: &WinternitzPublicKey,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(public_key).serialize().to_vec() }
        OP_CHECKSIGVERIFY

        { ots_checksig(pegout_id_pubkey, false)? }
    );

    let mut protocol_script = ProtocolScript::new(script, &public_key, SignMode::Aggregate);
    protocol_script.add_key(
        "pegout_id",
        pegout_id_pubkey.derivation_index()?,
        KeyType::WinternitzKey(pegout_id_pubkey.key_type()),
        0,
    )?;

    Ok(protocol_script)
}

pub fn operator_pegout_id(
    public_key: PublicKey,
    pegout_id_key: &WinternitzPublicKey,
    secret_key: &WinternitzPublicKey,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(public_key).serialize().to_vec() }
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

    Ok(protocol_script)
}
