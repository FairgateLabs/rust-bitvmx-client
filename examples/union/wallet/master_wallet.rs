use anyhow::Result;
use bitcoin::{Address, Network, Transaction};
use bitvmx_settings::settings::load_config_file;
use bitvmx_wallet::{
    config::Config,
    wallet::{RegtestWallet, Wallet},
};
use tracing::info;

/// Master wallet for funding Bitcoin addresses using bitvmx wallet
pub struct MasterWallet {
    pub wallet: Wallet,
    network: Network,
}

impl MasterWallet {
    pub fn new(network: Network, private_key: Option<String>) -> Result<Self> {
        if network != Network::Regtest && private_key.is_none() {
            return Err(anyhow::anyhow!(
                "Private key required for non-regtest networks"
            ));
        };

        // Load configuration from appropriate config file
        let config_path = match network {
            Network::Regtest => "config/wallet_regtest.yaml",
            Network::Testnet4 => "config/wallet_testnet.yaml",
            _ => return Err(anyhow::anyhow!("Unsupported network: {}", network)),
        };

        let mut config = load_config_file::<Config>(Some(config_path.to_string()))?;
        // Override database path and private key in config
        config.wallet.db_path = format!(
            "/tmp/{}/master_wallet.db",
            network.to_string().to_lowercase()
        );

        if private_key.is_some() {
            config.wallet.receive_key = private_key;
        }

        // Create wallet using config
        let mut wallet = Wallet::from_config(config.bitcoin, config.wallet)?;

        // Sync the wallet
        wallet.sync_wallet()?;

        let mut master_wallet = Self { wallet, network };
        master_wallet.fund_if_regtest()?;

        Ok(master_wallet)
    }

    /// Auto-fund wallet if on regtest network
    fn fund_if_regtest(&mut self) -> Result<()> {
        if self.network == Network::Regtest {
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
        }
        Ok(())
    }

    /// Fund a Bitcoin address directly using send_to_address
    pub fn fund_address(&mut self, address: &Address, amount_sats: u64) -> Result<Transaction> {
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
            .send_to_address(&address_str, amount_sats, fee_rate)
            .map_err(|e| anyhow::anyhow!("Failed to fund address: {}", e))?;

        Ok(transaction)
    }

    /// Get wallet balance
    pub fn get_balance(&mut self) -> Result<u64> {
        let balance = self.wallet.balance();
        Ok(balance.total().to_sat())
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Sync wallet with the blockchain
    pub fn sync(&mut self) -> Result<()> {
        self.wallet
            .sync_wallet()
            .map_err(|e| anyhow::anyhow!("Failed to sync wallet: {}", e))?;

        Ok(())
    }

    // uncomment for testnet example
    // /// Generate a new receive address
    // pub fn receive_address(&mut self) -> Result<Address> {
    //     self.wallet
    //         .receive_address()
    //         .map_err(|e| anyhow::anyhow!("Failed to generate receive address: {}", e))
    // }
}
