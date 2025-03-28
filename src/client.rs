use anyhow::Result;
use bitcoin::Transaction;
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use uuid::Uuid;
use std::{thread, time::Duration};
use tracing::info;
use crate::{program::{dispute::Funding, participant::{P2PAddress, ParticipantRole}}, types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages}};

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

    pub fn ping(&self) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::Ping())
    }

    pub fn setup(&self, id: Uuid, role: ParticipantRole, address: P2PAddress, funding: Funding) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::SetupProgram(id, role, address, funding))
    }

    pub fn dispatch_transaction(&self, id: Uuid, tx: Transaction) -> Result<()> {
        self.send_message(IncomingBitVMXApiMessages::DispatchTransaction(id, tx))
    }

    pub fn send_message(&self, msg: IncomingBitVMXApiMessages) -> Result<()> {
        // BitVMX instance uses ID 1 by convention
        let bitvmx_id = 1;
        let serialized = serde_json::to_string(&msg)?;
        info!("Sending message to {}: {:?}", bitvmx_id, serialized);
        self.channel.send(bitvmx_id, serialized)?;
        Ok(())
    }

    /// Busy wait for a message from the broker
    pub fn wait_message(&self) -> Result<OutgoingBitVMXApiMessages> {
        // TODO: add timeout
        // TODO: add sleep
        let (msg, from) = loop {
            if let Some(message) = self.get_message()? { break message; }
        };
        Ok(msg)
    }

    // pub fn subscribe<F>(&self, mut callback: F)
    // where
    //     F: FnMut(OutgoingBitVMXApiMessages),
    // {
    //     loop {
    //         if let Ok(Some((msg, from))) = self.channel.recv() {
    //             match serde_json::from_str(&msg) {
    //                 Ok(decoded_msg) => callback(decoded_msg),
    //                 Err(e) => println!("Failed to decode message from {}: {}", from, e),
    //             }
    //         }
    //         thread::sleep(Duration::from_millis(100));
    //     }
    // }

    pub fn get_message(&self) -> Result<Option<(OutgoingBitVMXApiMessages, u32)>> {
        if let Ok(Some((msg, from))) = self.channel.recv() {
            let dezerialized = serde_json::from_str(&msg)?;
            Ok(Some((dezerialized, from)))
        } else {
            Ok(None)
        }
    }
}
