use core::time::Duration;
use std::thread;

use anyhow::Result;
use bitcoin::{Address, Transaction};
use bitvmx_bitcoin_rpc::rpc_config::NetworkFlavor;
use bitvmx_settings::settings::load_config_file;
use bitvmx_wallet::{
    wallet::config::Config,
    wallet::{Destination, RegtestWallet, Wallet},
};
use tracing::info;

/// Master wallet for funding Bitcoin addresses using bitvmx wallet
pub struct MasterWallet {
    pub wallet: Wallet,
    network_flavor: NetworkFlavor,
}

impl MasterWallet {
    pub fn new(
        network_flavor: NetworkFlavor,
        private_key: Option<String>,
        change_key: Option<String>,
    ) -> Result<Self> {
        // Only the live networks keep their keys outside the repo. Regtest and
        // simchain both carry theirs in the checked-in wallet config.
        if !network_flavor.is_local_chain() && (private_key.is_none() || change_key.is_none()) {
            return Err(anyhow::anyhow!(
                "Private and change key required for the {network_flavor} network"
            ));
        };

        let mut config =
            load_config_file::<Config>(Some(network_flavor.wallet_config().to_string()))?;
        // Override database path and private key in config
        config.wallet.db_path = format!("/tmp/{}/master_wallet.db", network_flavor);

        if private_key.is_some() {
            config.wallet.receive_key = private_key.clone();
        }
        if change_key.is_some() {
            config.wallet.change_key = change_key.clone();
        }

        // Create wallet using config
        let mut wallet = Wallet::from_config(config.bitcoin, config.wallet)?;

        // Sync the wallet
        info!("Syncing master wallet...");
        wallet.sync_wallet()?;
        info!("Master wallet synced.");

        let mut master_wallet = Self {
            wallet,
            network_flavor,
        };
        master_wallet.fund_if_we_can_mine()?;

        Ok(master_wallet)
    }

    /// Mint funds for the wallet, where minting is something we are allowed to do.
    ///
    /// Not on simchain: it is regtest, but its blocks come from the simnet's own
    /// miners and its coins from the bootstrap, so the wallet must already be funded.
    fn fund_if_we_can_mine(&mut self) -> Result<()> {
        if !self.network_flavor.can_mine_on_demand() {
            return Ok(());
        }

        match self.wallet.fund() {
            Ok(_) => {
                info!("Master wallet funded with 150 BTC on regtest");
            }
            Err(e) => {
                info!("Warning: Failed to fund master wallet on regtest: {}", e);
                info!("Make sure Bitcoin Core is running and accessible");
                // Don't fail the whole initialization, just warn
            }
        }

        info!("Waiting for regtest wallet to sync...");
        thread::sleep(Duration::from_secs(25)); // wait for the wallet to update the 100 blocks. It only happens in regtest
        Ok(())
    }

    /// Fund a Bitcoin address directly using send_to_address
    pub fn _fund_address(&mut self, address: &Address, amount_sats: u64) -> Result<Transaction> {
        self.fund_address_with_fee(address, amount_sats, None)
    }

    /// Fund a Bitcoin address with custom fee rate using send_to_address
    pub fn fund_address_with_fee(
        &mut self,
        address: &Address,
        amount_sats: u64,
        fee_rate: Option<u64>,
    ) -> Result<Transaction> {
        let address_str = address.to_string();

        let transaction = self
            .wallet
            .send_funds(Destination::Address(address_str, amount_sats), fee_rate)
            .map_err(|e| anyhow::anyhow!("Failed to fund address: {}", e))?;

        Ok(transaction)
    }

    /// Get wallet balance
    pub fn _get_balance(&mut self) -> Result<u64> {
        let balance = self.wallet.balance();
        Ok(balance.total().to_sat())
    }

    /// The run target this wallet belongs to, including simnets.
    pub fn network_flavor(&self) -> NetworkFlavor {
        self.network_flavor
    }

    /// Address encoding identity. `network()` means `bitcoin::Network` everywhere.
    pub fn network(&self) -> bitcoin::Network {
        self.network_flavor.bitcoin_network()
    }

    /// Sync wallet with the blockchain
    pub fn _sync(&mut self) -> Result<()> {
        self.wallet
            .sync_wallet()
            .map_err(|e| anyhow::anyhow!("Failed to sync wallet: {}", e))?;

        Ok(())
    }

    // Generate a new receive address
    // pub fn receive_address(&mut self) -> Result<Address> {
    //     self.wallet
    //         .receive_address()
    //         .map_err(|e| anyhow::anyhow!("Failed to generate receive address: {}", e))
    // }
}
