//! Prints the master wallet's receive address for a run target.
//!
//! Needs no Bitcoin node: the address is derived from the WIF in the wallet config.
//!
//! Used to fill in simchain's `USER_ADDRESS`, which is what the simnet bootstrap funds:
//!
//! ```text
//! cargo test --release --test print_env_address -- --nocapture
//! ```
#![cfg(test)]

use anyhow::Result;
use bitvmx_bitcoin_rpc::rpc_config::NetworkFlavor;
use bitvmx_wallet::wallet::Wallet;

fn receive_address(network_flavor: NetworkFlavor) -> Result<String> {
    let config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::wallet::config::Config,
    >(Some(network_flavor.wallet_config().to_string()))?;
    let mut wallet = Wallet::from_config(config.bitcoin, config.wallet)?;
    Ok(wallet.receive_address()?.to_string())
}

#[test]
fn print_simchain_address() -> Result<()> {
    let address = receive_address(NetworkFlavor::Simchain)?;
    println!("\nsimchain master wallet receive address:\n  {address}\n");
    println!("Set this as USER_ADDRESS in simchain's .env, then bring the chain up fresh:");
    println!("  ./scripts/fresh-chain.sh\n");

    // The address is committed in a comment in config/wallet_simchain.yaml and in
    // simchain's .env. If the key ever changes, this fails loudly rather than
    // leaving the bootstrap funding a silently dead address.
    assert_eq!(
        address, "bcrt1qmj09uwj7rulcf7cc899t627wl2gq4ujt5vpxkg",
        "simchain receive address changed; update config/wallet_simchain.yaml \
         and USER_ADDRESS in simchain's .env"
    );
    Ok(())
}

#[test]
fn simchain_and_regtest_wallets_use_distinct_keys() -> Result<()> {
    // A shared key would let a regtest run spend simchain coins and vice versa.
    assert_ne!(
        receive_address(NetworkFlavor::Simchain)?,
        receive_address(NetworkFlavor::Regtest)?
    );
    Ok(())
}
