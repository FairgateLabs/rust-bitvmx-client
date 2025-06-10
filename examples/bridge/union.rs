use anyhow::Result;
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};


struct UnionClient {
    channel: DualChannel,
}

impl UnionClient {
    pub fn new() -> Self {
        Self { channel: DualChannel::new(&BrokerConfig::new(54321, None), 2) }
    }

    pub fn setup(&self) -> Result<()> {
        // TODO
        Ok(())
    }

    pub fn get_temporary_peg_in_address(&self) -> Result<()> {
        // TODO
        Ok(())
    }

    pub fn request_peg_in(&self) -> Result<()> {
        // TODO
        Ok(())
    }
}
