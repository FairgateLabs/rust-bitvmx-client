use anyhow::Result;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_bitcoin_rpc::rpc_config::NetworkFlavor;
use bitvmx_client::config::Config;

pub fn get_bitcoin_client() -> Result<BitcoinClient> {
    let network_flavor = NetworkFlavor::from_env();
    let config = Config::new(Some(format!("config/{}.yaml", network_flavor.op_config(1))))?;

    // Built from the config so the client carries its network_flavor and the simchain guard
    // rails are armed.
    let bitcoin_client = BitcoinClient::new_from_config(&config.bitcoin)?;

    Ok(bitcoin_client)
}
