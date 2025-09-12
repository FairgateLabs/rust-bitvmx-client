use anyhow::Result;
use bitcoin::{Address, CompressedPublicKey, Network};
use key_manager::{key_manager::KeyManager, key_store::KeyStore};
use storage_backend::storage::Storage;
use tracing::info;

pub fn wallet_info(network: Network) -> Result<()> {
    info!("Generating master wallet info for network {}...", network);

    let mut config = bitvmx_client::config::Config::new(Some("config/op_1.yaml".to_string()))?;
    config.key_storage.path = "/tmp/master_wallet/keys.db".to_string();
    config.storage.path = "/tmp/master_wallet/storage.db".to_string();

    let key_derivation_seed: [u8; 32] = *b"1337beafdeadbeafdeadbeafdeadbeaf";

    let key_manager = KeyManager::new(
        network,
        "m/84/0/0/0/",
        Some(key_derivation_seed),
        None,
        KeyStore::new(std::rc::Rc::new(Storage::new(&config.key_storage)?)),
        std::rc::Rc::new(Storage::new(&config.storage)?),
    )?;

    let pubkey = key_manager.derive_keypair(0)?;
    let privkey = key_manager.export_secret(&pubkey)?;
    let change_pubkey = key_manager.derive_keypair(1)?;
    let change_privkey = key_manager.export_secret(&change_pubkey)?;
    let compressed = CompressedPublicKey::try_from(pubkey).unwrap();
    let address = Address::p2wpkh(&compressed, network);

    let result = std::fs::remove_dir_all("/tmp/master_wallet");
    info!("Master wallet temporary data removed: {:?}\n", result);

    info!("Master wallet info:");
    info!("  Pubkey: {}", pubkey);
    info!("  Privkey: {}", privkey);
    info!("  Address: {}", address);
    info!("");
    info!("  Change Privkey: {}", change_privkey);

    Ok(())
}
