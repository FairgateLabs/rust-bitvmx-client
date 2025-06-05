use anyhow::Result;
use common::config_trace;
use fixtures::hardcoded_unspendable;
use std::rc::Rc;
use tracing::info;

use key_manager::{key_manager::KeyManager, key_store::KeyStore, winternitz};
use protocol_builder::{
    builder::Protocol,
    scripts,
    types::{InputArgs, OutputType},
};
use storage_backend::{storage::Storage, storage_config::StorageConfig};
pub mod common;
pub mod fixtures;

#[test]
pub fn test_winternitz() -> Result<()> {
    config_trace();
    let mut protocol = Protocol::new("winternitz");

    let storage_config = StorageConfig::new("/tmp/test_db_1".to_string(), None);
    let storage_config_2 = StorageConfig::new("/tmp/test_db_2".to_string(), None);
    let key_storage = KeyStore::new(Rc::new(Storage::new(&storage_config_2)?));

    let key_manager = Rc::new(KeyManager::new(
        bitcoin::Network::Regtest,
        "m/101/1/0/0/",
        None,
        None,
        key_storage,
        Rc::new(Storage::new(&storage_config)?),
    )?);

    let unspendable = hardcoded_unspendable().into();
    let key = key_manager.derive_keypair(0)?;
    let winternitz_key_1 =
        key_manager.derive_winternitz(2, winternitz::WinternitzType::HASH160, 0)?;
    let _winternitz_key_2 =
        key_manager.derive_winternitz(2, winternitz::WinternitzType::HASH160, 0)?;

    protocol.add_external_transaction("test_tx")?;

    let leaf =
        scripts::verify_winternitz_signature(&key, &winternitz_key_1, scripts::SignMode::Single)?;
    let output = OutputType::taproot(500, &unspendable, &[leaf])?;
    protocol.add_transaction_output("test_tx", &output)?;

    protocol.build(&key_manager, "test")?;
    protocol.sign(&key_manager, "test")?;

    let args = InputArgs::new_taproot_script_args(0);
    info!("Input Args: {:?}", args);

    let tx = protocol.transaction_to_send("test_tx", &vec![args])?;
    info!("Transaction: {:?}", tx);

    Ok(())
}
