use anyhow::Result;
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use std::{thread, time::Duration};
use tracing::info;
use crate::types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages};

pub struct BitVMXClient {
    channel: DualChannel,
    client_id: u32,
}

impl BitVMXClient {
    pub fn new(broker_port: u16, client_id: u32) -> Self {
        let config = BrokerConfig::new(broker_port, None);
        let channel = DualChannel::new(&config, client_id);
        Self { channel, client_id }
    }

    pub fn send_message(&self, msg: IncomingBitVMXApiMessages) -> Result<()> {
        // BitVMX instance uses ID 1 by convention
        let bitvmx_id = 1;
        let serialized = serde_json::to_string(&msg)?;
        info!("Sending message to {}: {:?}", bitvmx_id, serialized);
        self.channel.send(bitvmx_id, serialized)?;
        Ok(())
    }

    pub fn subscribe<F>(&self, mut callback: F)
    where
        F: FnMut(OutgoingBitVMXApiMessages),
    {
        loop {
            if let Ok(Some((msg, from))) = self.channel.recv() {
                match serde_json::from_str(&msg) {
                    Ok(decoded_msg) => callback(decoded_msg),
                    Err(e) => println!("Failed to decode message from {}: {}", from, e),
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn get_message(&self) -> Option<(String, u32)> {
        if let Ok(Some((msg, from))) = self.channel.recv() {
            Some((msg, from))
        } else {
            None
        }
    }
}
