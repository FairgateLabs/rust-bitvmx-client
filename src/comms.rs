use p2p_protocol::{Keypair, P2p, P2pReceiver, P2pSender, PeerId, ReceiveChannelData, SendChannelData};
use shlex::bytes;

use crate::{config::Config, errors::BitVMXError, program::participant::P2PAddress};

pub enum P2PMessageKind {
    Status,
    Keys,
    Nonces,
    Signatures,
    Setup,
}

pub struct P2PMessage {
    kind: P2PMessageKind,
    peer_id: PeerId,
    message: Vec<u8>,
}

impl P2PMessage {
    pub fn new(kind: P2PMessageKind, peer_id: PeerId, message: Vec<u8>) -> Self {
        Self {
            kind,
            peer_id,
            message,
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            kind: P2PMessageKind::Status,
            peer_id: PeerId::random(),
            message: bytes,
        }
    }

    pub fn kind(&self) -> &P2PMessageKind {
        &self.kind
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn message(&self) -> &Vec<u8> {
        &self.message
    }
}

pub struct P2PComms {
    sender: P2pSender,
    receiver: P2pReceiver,
    address: P2PAddress,
}

impl P2PComms {
    pub fn new(config: &Config, communications_key: Keypair) -> Result<Self, BitVMXError> {
        let address = config.p2p_address();
        let peer_id = communications_key.public().to_peer_id();
        
        // Listen for incoming connections
        let (sender, receiver) = P2p::new(Some(address.to_string()), Some(communications_key))?;

        Ok(Self { 
            sender,
            receiver,
            address: P2PAddress::new(address, peer_id), 
        })
    }

    pub fn connect(&mut self, peer_address: &P2PAddress) -> Result<(), BitVMXError> {
        // Dial
        let result = self.sender.try_send(SendChannelData::Dial(
            *peer_address.peer_id(), 
            peer_address.address().to_string()
        ));

        match result {
            Ok(_) => (),
            Err( e ) => {
                println!("Error dialing: {:?}", e);
                return Err(BitVMXError::P2PCommunicationError)
            }
        };

        loop {
            let data = self.receiver.receiver.try_recv();
            match data {
                Ok(ReceiveChannelData::Connected(peer_id, connected)) => {
                    println!("Peer {} {}", peer_id, if connected { "connected" } else { "disconnected" });
                    break
                }
                _ => continue
            }
        }

        Ok(())
    }

    pub fn send_message(&self, peer_address: &P2PAddress, message: Vec<u8>) -> Result<(), BitVMXError> {
        self.sender.try_send(SendChannelData::SendMsg(
            *peer_address.peer_id(), 
            message
        )).map_err(|_| BitVMXError::P2PCommunicationError)?;

        Ok(())
    }

    pub fn receive_message(&mut self) -> Option<Vec<u8>> {
        let data = self.receiver.receiver.try_recv();
        match data {
            Ok(ReceiveChannelData::Status(peer_id, status)) => {
                println!("Received status from {}: {}", peer_id, status);
                Some([status as u8].to_vec())
            }
            _ => {
                None
            }
        }
    }

    pub fn address(&self) -> &P2PAddress {
        &self.address
    }

    pub fn peer_id(&self) -> &PeerId {
        self.address.peer_id()
    }

    pub fn peer_id_bs58(&self) -> String {
        self.address.peer_id_bs58()
    }
}