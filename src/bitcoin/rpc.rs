use bitcoin::{consensus, Address, Amount, CompressedPublicKey, Network, PublicKey, Transaction, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use crate::errors::BitcoinClientError;

pub struct BitcoinClient {
    network: Network,
    client: Client,
    wallet_address: Address,
}

impl BitcoinClient {
    pub fn new(network: Network, url: &str, user: &str, pass: &str, wallet_name: &str) -> Result<Self, BitcoinClientError> {
        let client = Client::new(
            url,
            Auth::UserPass(
                user.to_string(),
                pass.to_string(),
            ),
        ).map_err(|e| BitcoinClientError::FailedToCreateClient{ error: e.to_string() })?;

        let wallet_address = Self::init_wallet(network, wallet_name, &client)?;

        Ok(Self {
            network,
            client,
            wallet_address,
        })
    }   

    pub fn fund_address(&self, address: &Address, amount: Amount) -> Result<(Transaction, u32), BitcoinClientError> {
        // send BTC to address
        let txid = self.client.send_to_address(
            address,
            amount,
            None,
            None,
            None,
            None,
            None,
            None,
        ).map_err(|e| BitcoinClientError::FailedToFundAddress{ error: e.to_string() })?;
    
        // mine a block to confirm transaction
        self.mine_blocks(1)?;
    
        // get transaction details
        let tx_info = self.client.get_transaction(&txid, Some(true))
            .map_err(|e| BitcoinClientError::FailedToGetTransactionDetails{ error: e.to_string() })?;

        let tx = tx_info.transaction()
            .map_err(|e| BitcoinClientError::FailedToGetTransactionDetails{ error: e.to_string() })?;

        let vout = tx_info
        .details
        .first()
        .expect("No details found for transaction")
        .vout;

        Ok((tx, vout))
    }

    pub fn send_transaction(&self, tx: Transaction) -> Result<Txid, BitcoinClientError> {
        let serialized_tx = consensus::encode::serialize_hex(&tx);

        let result = self.client.send_raw_transaction(serialized_tx);
        if let Err(e) = result {
            println!("Error: {:?}", e);
            return Err(BitcoinClientError::FailedToSendTransaction{ error: e.to_string() });
        }

        let txid = result.unwrap();

        // mine a block to confirm transaction
        self.mine_blocks(1)?;

        Ok(txid)
    }

    pub fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, BitcoinClientError> {
        let tx = self.client.get_raw_transaction(txid, None).ok();
        Ok(tx)
    }

    pub fn mine_blocks(&self, blocks: u64) -> Result<(), BitcoinClientError> {
        // mine a block to confirm transaction
        self.client.generate_to_address(blocks, &self.wallet_address)
            .map_err(|e| BitcoinClientError::FailedToMineBlocks{ error: e.to_string() })?;

        Ok(())
    }

    pub fn get_new_address(&self, pk: PublicKey) -> Address {
        let compressed = CompressedPublicKey::try_from(pk).unwrap();
        let address = Address::p2wpkh(&compressed, self.network).as_unchecked().clone();
        address.clone().require_network(self.network).unwrap()
    }

    pub fn get_blockchain_info(&self) -> Result<bitcoincore_rpc::json::GetBlockchainInfoResult, BitcoinClientError> {
        self.client.get_blockchain_info()
            .map_err(|e| BitcoinClientError::FailedToGetTransactionDetails{ error: e.to_string() })
    }

    fn init_wallet(network: Network, wallet_name: &str, rpc: &Client) -> Result<Address, BitcoinClientError> {
        let wallets = rpc.list_wallets().map_err(|e| BitcoinClientError::FailedToListWallets{ error: e.to_string() })?;
        if !wallets.contains(&wallet_name.to_string()) {
            match rpc.create_wallet(wallet_name, None, None, None, None) {
                Ok(r) => r,
                Err(e) => {
                    return Err(BitcoinClientError::FailedToCreateWallet{ error: e.to_string() })
                },
            };
        }

        let wallet = rpc
            .get_new_address(None, None)
            .map_err(|e| BitcoinClientError::FailedToGetNewAddress{ error: e.to_string() })?
            .require_network(network)
            .map_err(|e| BitcoinClientError::FailedToGetNewAddress{ error: e.to_string() })?;
    
        rpc.generate_to_address(105, &wallet)
            .map_err(|e| BitcoinClientError::FailedToMineBlocks{ error: e.to_string() })?;
    
        Ok(wallet)
    }
}
