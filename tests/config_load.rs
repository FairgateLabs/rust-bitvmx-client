//! Every config file this repo ships must actually deserialize.
//!
//! `Config` uses `#[serde(deny_unknown_fields)]`, so a stray or misspelled key is a
//! hard error rather than a silently ignored line. These tests need no Bitcoin node.
#![cfg(test)]

use anyhow::Result;
use bitcoin::Network;
use bitvmx_bitcoin_rpc::rpc_config::NetworkFlavor;
use bitvmx_client::config::Config;
use key_manager::{create_key_manager_from_config, key_type::BitcoinKeyType};
use storage_backend::storage_config::StorageConfig;

fn load_op(stem: &str) -> Result<Config> {
    Ok(Config::new(Some(format!("config/{stem}.yaml")))?)
}

fn load_wallet(network_flavor: NetworkFlavor) -> Result<bitvmx_wallet::wallet::config::Config> {
    Ok(bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::wallet::config::Config,
    >(Some(network_flavor.wallet_config()))?)
}

/// Run targets this repo actually ships config files for.
fn configured() -> impl Iterator<Item = NetworkFlavor> {
    NetworkFlavor::ALL.into_iter().filter(|f| f.has_configs())
}

#[test]
fn every_operator_config_parses() -> Result<()> {
    for network_flavor in configured() {
        for stem in network_flavor.op_configs() {
            load_op(&stem).map_err(|e| anyhow::anyhow!("config/{stem}.yaml: {e}"))?;
        }
    }
    Ok(())
}

#[test]
fn every_wallet_config_parses() -> Result<()> {
    for network_flavor in configured() {
        load_wallet(network_flavor)
            .map_err(|e| anyhow::anyhow!("{}: {e}", network_flavor.wallet_config()))?;
    }
    Ok(())
}

#[test]
fn config_network_matches_the_run_target() -> Result<()> {
    for network_flavor in configured() {
        let wallet = load_wallet(network_flavor)?;
        assert_eq!(
            wallet.bitcoin.network_flavor, network_flavor,
            "{network_flavor} wallet network"
        );

        for stem in network_flavor.op_configs() {
            let config = load_op(&stem)?;
            assert_eq!(
                config.bitcoin.network_flavor, network_flavor,
                "{stem} network"
            );
        }
    }
    Ok(())
}

#[test]
fn simchain_configs_report_live_network_capabilities() -> Result<()> {
    // The point of the merged type: regtest encoding, live-network behavior, from a
    // single `network: simchain` field that cannot contradict itself.
    for stem in NetworkFlavor::Simchain.op_configs() {
        let config = load_op(&stem)?;
        assert_eq!(
            config.bitcoin.network_flavor,
            NetworkFlavor::Simchain,
            "{stem}"
        );
        assert_eq!(config.bitcoin.network(), Network::Regtest, "{stem}");
        assert!(config.bitcoin.is_simchain(), "{stem}");
        assert!(!config.bitcoin.can_mine_on_demand(), "{stem}");
        assert!(!config.bitcoin.has_node_wallet(), "{stem}");
        assert!(config.bitcoin.needs_prefunded_wallet(), "{stem}");
    }

    let wallet = load_wallet(NetworkFlavor::Simchain)?;
    assert!(!wallet.bitcoin.can_mine_on_demand());
    assert_eq!(wallet.bitcoin.network(), Network::Regtest);
    Ok(())
}

#[test]
fn regtest_configs_are_untouched_by_the_merge() -> Result<()> {
    // Regression gate: widening the `network` field must not change how the existing
    // files behave. `network: regtest` still means a chain we own outright.
    for stem in NetworkFlavor::Regtest.op_configs() {
        let config = load_op(&stem)?;
        assert_eq!(
            config.bitcoin.network_flavor,
            NetworkFlavor::Regtest,
            "{stem}"
        );
        assert_eq!(config.bitcoin.network(), Network::Regtest, "{stem}");
        assert!(config.bitcoin.can_mine_on_demand(), "{stem}");
        assert!(config.bitcoin.has_node_wallet(), "{stem}");
    }

    let wallet = load_wallet(NetworkFlavor::Regtest)?;
    assert!(wallet.bitcoin.can_mine_on_demand());
    assert!(wallet.bitcoin.has_node_wallet());
    Ok(())
}

#[test]
fn simchain_fee_floor_clears_the_spammer() -> Result<()> {
    // Simchain's stock .env holds the mempool at 15 sat/vB. A coordinator configured
    // below that would broadcast transactions that can never be mined.
    for stem in NetworkFlavor::Simchain.op_configs() {
        let config = load_op(&stem)?;
        let fee = &config
            .coordinator_settings
            .as_ref()
            .unwrap_or_else(|| panic!("{stem} must set coordinator_settings"))
            .fee;
        assert!(
            fee.min_safe_fee_rate > 15,
            "{stem}: min_safe_fee_rate {} does not clear the simchain spam floor",
            fee.min_safe_fee_rate
        );
        assert!(fee.min_safe_fee_rate <= fee.max_feerate_sat_vb, "{stem}");
    }
    Ok(())
}

#[test]
fn simchain_operators_do_not_share_ports_or_paths() -> Result<()> {
    let mut broker_ports = vec![];
    let mut comms = vec![];
    let mut storage = vec![];
    for stem in NetworkFlavor::Simchain.op_configs() {
        let config = load_op(&stem)?;
        broker_ports.push(config.broker.port);
        comms.push(config.comms.address);
        storage.push(config.storage.path.clone());
    }

    for (label, mut values) in [
        (
            "broker ports",
            broker_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>(),
        ),
        (
            "comms addresses",
            comms.iter().map(|a| a.to_string()).collect(),
        ),
        ("storage paths", storage),
    ] {
        let total = values.len();
        values.sort();
        values.dedup();
        assert_eq!(values.len(), total, "simchain operators share {label}");
    }
    Ok(())
}

#[test]
fn simchain_paths_do_not_collide_with_regtest() -> Result<()> {
    // Sharing a database directory would let one run target corrupt the other's state.
    for (simchain, regtest) in NetworkFlavor::Simchain
        .op_configs()
        .iter()
        .zip(NetworkFlavor::Regtest.op_configs().iter())
    {
        let s = load_op(simchain)?;
        let r = load_op(regtest)?;
        assert_ne!(s.storage.path, r.storage.path);
        assert_ne!(s.key_storage.path, r.key_storage.path);
        assert_ne!(s.wallet.db_path, r.wallet.db_path);
        assert_ne!(s.comms.storage_path, r.comms.storage_path);
    }

    let s = load_wallet(NetworkFlavor::Simchain)?;
    let r = load_wallet(NetworkFlavor::Regtest)?;
    assert_ne!(s.wallet.db_path, r.wallet.db_path);
    assert_ne!(s.storage.path, r.storage.path);
    assert_ne!(s.key_storage.path, r.key_storage.path);
    Ok(())
}

/// Each operator must have its own key material.
///
/// The four regtest operators carry four different `mnemonic_sentence` values, so they
/// derive four different keys and MuSig2 can aggregate them. A generator that copied
/// `op_1`'s mnemonic into all four simchain configs made every operator identical, and
/// the suite failed deep inside a tick with `Musig2SignerError(InvalidPublicKey)` —
/// nowhere near the actual mistake. This pins the real invariant rather than the text
/// of the config, so any future cause of duplicate keys is caught too.
#[test]
fn every_operator_derives_a_distinct_key() -> Result<()> {
    for network_flavor in configured() {
        let mut keys = vec![];
        for (i, stem) in network_flavor.op_configs().iter().enumerate() {
            let config = load_op(stem)?;
            // Scratch storage so this never touches a real operator's key database.
            let storage = StorageConfig::new(
                format!("/tmp/config_load_test/{network_flavor}/{i}/keys.db"),
                None,
            );
            let _ = std::fs::remove_dir_all(&storage.path);
            let km = create_key_manager_from_config(&config.key_manager, &storage)
                .map_err(|e| anyhow::anyhow!("{stem}: {e}"))?;
            keys.push((stem.clone(), km.derive_keypair(BitcoinKeyType::P2tr, 0)?));
        }

        for (a_name, a_key) in &keys {
            for (b_name, b_key) in &keys {
                if a_name != b_name {
                    assert_ne!(
                        a_key, b_key,
                        "{a_name} and {b_name} derive the same key — check their \
                         key_manager.mnemonic_sentence values differ"
                    );
                }
            }
        }
    }
    Ok(())
}
