use anyhow::Result;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_broker::{channel::channel::DualChannel, identification::identifier::Identifier};
use bitvmx_client::config::Config;

#[derive(Clone)]
pub struct ParticipantChannel {
    pub id: Identifier,
    pub channel: DualChannel,
}

pub fn get_bitcoin_client() -> Result<BitcoinClient> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    Ok(bitcoin_client)
}
