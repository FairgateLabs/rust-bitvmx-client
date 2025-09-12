
use anyhow::Result;
use bitcoin::{Address, Network, PrivateKey, Txid};
use bitvmx_settings::settings::load_config_file;
use bitvmx_wallet::{config::{WalletConfig, Config}, wallet::{Wallet, RegtestWallet}};
use tracing::info;


/// Master wallet for funding Bitcoin addresses using bitvmx wallet
pub struct MasterWallet {
    wallet: Wallet,
    network: Network,
}

impl MasterWallet {
    pub fn new(
        network: Option<Network>,
        private_key: Option<PrivateKey>
    ) -> Result<Self> {
        let network = network.unwrap_or(Network::Regtest);

        // Load configuration from appropriate config file
        let config_path = match network {
            Network::Regtest => "config/wallet_regtest.yaml",
            Network::Testnet => "config/wallet_testnet.yaml",
            _ => return Err(anyhow::anyhow!("Unsupported network: {}", network)),
        };

        let config = load_config_file::<Config>(Some(config_path.to_string()))?;
        let bitcoin_config = config.bitcoin;

        // Generate private key if not provided (regtest only)
        let private_key = if let Some(pk) = private_key {
            pk
        } else if network == Network::Regtest {
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let mut rng = bitcoin::secp256k1::rand::thread_rng();
            let (secret_key, _) = secp.generate_keypair(&mut rng);
            PrivateKey::new(secret_key, network)
        } else {
            return Err(anyhow::anyhow!("Private key required for non-regtest networks"));
        };

        // Create wallet config with the private key
        let wallet_config = WalletConfig {
            db_path: format!("/tmp/{}/master_wallet.db", network.to_string().to_lowercase()),
            start_height: Some(0), // TODO: Check where we can start from
            receive_key: Some(private_key.to_string()),
            change_key: None, // TODO: Check if we need a change key or a single descriptor wallet is sufficient
        };

        // Create wallet using config
        let mut wallet = Wallet::from_config(bitcoin_config, wallet_config)?;

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
                },
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
    pub fn fund_address(&mut self, address: &Address, amount_sats: u64) -> Result<Txid> {
        self.fund_address_with_fee(address, amount_sats, None)
    }

    /// Fund a Bitcoin address with custom fee rate using send_to_address
    pub fn fund_address_with_fee(&mut self, address: &Address, amount_sats: u64, fee_rate: Option<u64>) -> Result<Txid> {
        let address_str = address.to_string();

        let transaction = self.wallet
            .send_to_address(&address_str, amount_sats, fee_rate)
            .map_err(|e| anyhow::anyhow!("Failed to fund address: {}", e))?;

        Ok(transaction.compute_txid())
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