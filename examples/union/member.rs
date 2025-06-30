use anyhow::Result;
use std::collections::HashMap;
use uuid::Uuid;

use bitcoin::{PublicKey, Txid};
use bitvmx_client::{
    client::BitVMXClient,
    config::Config,
    program::{
        participant::{P2PAddress, ParticipantRole},
        variables::PartialUtxo,
    },
    types::{OutgoingBitVMXApiMessages::*, L2_ID},
};

use tracing::{debug, info};

use crate::{request_pegin::RequestPegin, setup::{accept_pegin_setup::AcceptPegInSetup, dispute_core_setup::DisputeCoreSetup}};

macro_rules! expect_msg {
    ($self:expr, $pattern:pat => $expr:expr) => {{
        let msg = $self.bitvmx.wait_message(None, None)?;

        if let $pattern = msg {
            Ok($expr)
        } else {
            Err(anyhow::anyhow!(
                "Expected `{}` but got `{:?}`",
                stringify!($pattern),
                msg
            ))
        }
    }};
}

#[derive(Clone)]
pub struct DrpCovenant {
pub struct DrpCovenant {
    _covenant_id: Uuid,
    _counterparty: P2PAddress,
}

#[derive(Clone)]
pub struct Covenants {
pub struct Covenants {
    _drp_covenants: Vec<DrpCovenant>,
    // dispute_core_covenants: Vec<DisputeCoreCovenant>,
    // pairwise_penalization_covenants: Vec<PairwisePenalizationCovenant>,
}

#[derive(Clone)]
pub struct Keyring {
    pub take_pubkey: Option<PublicKey>,
    pub dispute_pubkey: Option<PublicKey>,
    pub take_aggregated_key: Option<PublicKey>,
    pub dispute_aggregated_key: Option<PublicKey>,
    pub communication_pubkey: Option<PublicKey>,
    pub pairwise_keys: HashMap<P2PAddress, PublicKey>,
}

#[derive(Clone)]
pub struct Member {
    pub config: Config,
    pub id: String,
    pub role: ParticipantRole,
    pub bitvmx: BitVMXClient,
    pub address: Option<P2PAddress>,
    pub keyring: Keyring,
    pub _covenants: Covenants,
    pub _covenants: Covenants,
}

impl Member {
    pub fn new(id: &str, role: ParticipantRole) -> Result<Self> {
        let config = Config::new(Some(format!("config/{}.yaml", id)))?;
        let bitvmx = BitVMXClient::new(config.broker_port, L2_ID);

        Ok(Self {
            config,
            id: id.to_string(),
            role,
            address: None,
            bitvmx,
            keyring: Keyring {
                take_pubkey: None,
                dispute_pubkey: None,
                take_aggregated_key: None,
                dispute_aggregated_key: None,
                communication_pubkey: None,
                pairwise_keys: HashMap::new(),
            },
            _covenants: Covenants {
            _covenants: Covenants {
                _drp_covenants: Vec::new(),
            },
        })
    }

    pub fn get_peer_info(&mut self) -> Result<P2PAddress> {
        self.bitvmx.get_comm_info()?;
        let addr = expect_msg!(self, CommInfo(addr) => addr)?;

        self.address = Some(addr.clone());
        Ok(addr)
    }

    pub fn setup_member_keys(&mut self) -> Result<(PublicKey, PublicKey, PublicKey)> {
        // TODO what id should we use for these keys?
        let id = Uuid::new_v4();
        self.bitvmx.get_pubkey(id, true)?;
        let take_pubkey = expect_msg!(self, PubKey(_, key) => key)?;
        debug!(id = self.id, take_pubkey = ?take_pubkey, "Take pubkey");

        let id = Uuid::new_v4();
        self.bitvmx.get_pubkey(id, true)?;
        let dispute_pubkey = expect_msg!(self, PubKey(_, key) => key)?;
        debug!(id = self.id, dispute_pubkey = ?dispute_pubkey, "Dispute pubkey");

        let id = Uuid::new_v4();
        self.bitvmx.get_pubkey(id, true)?;
        let communication_pubkey = expect_msg!(self, PubKey(_, key) => key)?;
        debug!(id = self.id, communication_pubkey = ?communication_pubkey, "Communication pubkey");

        self.keyring.take_pubkey = Some(take_pubkey);
        self.keyring.dispute_pubkey = Some(dispute_pubkey);
        self.keyring.communication_pubkey = Some(communication_pubkey);

        Ok((take_pubkey, dispute_pubkey, communication_pubkey))
    }

    pub fn setup_committee_keys(
        &mut self,
        members: &[Member],
        members_take_pubkeys: &[PublicKey],
        members_dispute_pubkeys: &[PublicKey],
        take_aggregation_id: Uuid,
        dispute_aggregation_id: Uuid,
    ) -> Result<()> {
        self.make_aggregated_keys(
            members,
            members_take_pubkeys,
            members_dispute_pubkeys,
            take_aggregation_id,
            dispute_aggregation_id,
        )?;
        self.make_pairwise_keys(members, take_aggregation_id)?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn setup_covenants(
        &mut self,
        dispute_core_id: Uuid,
        member_index: usize,
        members: &[Member],
        funding_utxos: &[PartialUtxo],
    ) -> Result<()> {
        info!(id = self.id, "Setting up covenants for member {}", self.id);
        DisputeCoreSetup::setup(
            dispute_core_id,
            member_index,
            &self.id,
            &self.role,
            members,
            funding_utxos,
            &self.keyring,
            &self.bitvmx,
            &self.bitvmx,
        )?;

        // Wait for the dispute core setup to complete
        let program_id = expect_msg!(self, SetupCompleted(program_id) => program_id)?;
        info!(id = self.id, program_id = ?program_id, "Dispute core setup completed");

        // TODO: add the rest of the covenants here

        // info!(
        //     id = self.id,
        //     drp_covenants_count = self.covenants.drp_covenants.len(),
        //     "Covenant setup complete"
        // );

        Ok(())
    }

    pub fn request_pegin(
        &mut self,
    ) -> Result<()> {
        info!(id = self.id, "Requesting pegin");
        // Enable RSK pegin monitoring using the public API
        self.bitvmx.subscribe_to_rsk_pegin()?;
        info!("Subscribed to RSK pegin");

        // Create a proper RSK pegin transaction and send it as if it was a user transaction
        let mut request_pegin = RequestPegin::new(&self.config)?;
        let stream_value = 100_000;
        let packet_number = 0;
        let rsk_address = "7ac5496aee77c1ba1f0854206a26dda82a81d6d8";
        let request_pegin_txid = request_pegin.create_and_send_transaction(self.keyring.take_aggregated_key.unwrap(), stream_value, packet_number, rsk_address)?;
        info!("Sent RSK pegin transaction to bitcoind");

        // Wait for Bitvmx news PeginTransactionFound message
        info!("Waiting for RSK pegin transaction to be found");
        let (found_txid, tx_status) = expect_msg!(self, PeginTransactionFound(txid, tx_status) => (txid, tx_status))?;
        assert_eq!(found_txid, request_pegin_txid, "Request Pegin Transaction not found");
        assert!(tx_status.confirmations > 0, "Request Pegin Transaction not confirmed");
        info!("RSK pegin transaction test completed successfully");
        info!("Transaction ID: {}", request_pegin_txid);

        // Get the SPV proof, this should be used by the union client to present to the smart contract
        self.bitvmx.get_spv_proof(found_txid)?;
        let spv_proof = expect_msg!(self, SPVProof(_, Some(spv_proof)) => spv_proof)?;
        info!("SPV proof: {:?}", spv_proof);

        // Union client calls the smart contract PegManager.requestPegin(spv_proof)
        // Smart contracts emits the  PeginRequested event

        Ok(())
    }

    pub fn accept_pegin(
    pub fn accept_pegin(
        &mut self,
        accept_pegin_covenant_id: Uuid,
        accept_pegin_covenant_id: Uuid,
        members: &[Member],
        request_pegin_txid: Txid,
        request_pegin_amount: u64,
        accept_pegin_sighash: &[u8],
    ) -> Result<()> {
        info!(id = self.id, "Accepting peg-in");
        AcceptPegInSetup::setup(
            accept_pegin_covenant_id,
            &self.id,
            &self.role,
            members,
            request_pegin_txid,
            request_pegin_amount,
            accept_pegin_sighash,
            &self.keyring,
            &self.bitvmx,
        )?;

        Ok(())
    }

    fn make_aggregated_keys(
        &mut self,
        members: &[Member],
        members_take_pubkeys: &[PublicKey],
        members_dispute_pubkeys: &[PublicKey],
        take_aggregation_id: Uuid,
        dispute_aggregation_id: Uuid,
    ) -> Result<()> {
        let addresses = self.get_addresses(members);

        let take_aggregated_key =
            self.setup_key(take_aggregation_id, &addresses, Some(members_take_pubkeys))?;

        self.keyring.take_aggregated_key = Some(take_aggregated_key);

        let dispute_aggregated_key = self.setup_key(
            dispute_aggregation_id,
            &addresses,
            Some(members_dispute_pubkeys),
        )?;

        self.keyring.dispute_aggregated_key = Some(dispute_aggregated_key);

        Ok(())
    }

    fn make_pairwise_keys(&mut self, members: &[Member], session_id: Uuid) -> Result<()> {
        let my_address = self.address()?.clone();

        // Create a sorted list of members to have a canonical order of pairs.
        let mut sorted_members = members.to_vec();
        sorted_members.sort_by(|a, b| a.address.cmp(&b.address));

        for i in 0..sorted_members.len() {
            for j in (i + 1)..sorted_members.len() {
                let member1 = &sorted_members[i];
                let member2 = &sorted_members[j];

                let op1_address = member1.address()?;
                let op2_address = member2.address()?;

                // Check if the current operator is part of the pair
                if my_address == *op1_address || my_address == *op2_address {
                    // Skip key generation if both members are Challengers
                    if matches!(member1.role, ParticipantRole::Verifier)
                        && matches!(member2.role, ParticipantRole::Verifier)
                    {
                        info!(
                            "Skipping key generation between two Challengers: {:?} and {:?}",
                            op1_address, op2_address
                        );
                        continue;
                    }

                    let participants = vec![op1_address.clone(), op2_address.clone()];

                    // Create a deterministic aggregation_id for the pair that includes session_id
                    let namespace = Uuid::NAMESPACE_DNS;
                    let name_to_hash =
                        format!("{:?}{:?}{:?}", op1_address, op2_address, session_id);

                    let aggregation_id = Uuid::new_v5(&namespace, name_to_hash.as_bytes());
                    let pairwise_key = self.setup_key(aggregation_id, &participants, None)?;

                    let other_address = self.get_counterparty_address(member1, member2)?;

                    self.keyring
                        .pairwise_keys
                        .insert(other_address.clone(), pairwise_key);

                    info!(peer = ?other_address, key = ?pairwise_key.to_string(), "Generated pairwise key");
                }
            }
        }
        Ok(())
    }

    fn setup_key(
        &mut self,
        aggregation_id: Uuid,
        addresses: &[P2PAddress],
        public_keys: Option<&[PublicKey]>,
    ) -> Result<PublicKey> {
        info!(
            id = self.id,
            aggregation_id = ?aggregation_id,
            addresses = ?addresses,
            "Setting up aggregated key"
        );
        self.bitvmx.setup_key(
            aggregation_id,
            addresses.to_vec(),
            public_keys.map(|keys| keys.to_vec()),
            0,
        )?;

        let aggregated_key = expect_msg!(self, AggregatedPubkey(_, key) => key)?;
        info!(
            id = self.id,
            "Key setup complete {}",
            aggregated_key.to_string()
        );

        Ok(aggregated_key)
    }

    /// Get own address
    fn address(&self) -> Result<&P2PAddress> {
        self.address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Member address not set for {}", self.id))
    }

    /// Get all addresses from a list of members
    fn get_addresses(&self, members: &[Member]) -> Vec<P2PAddress> {
        members.iter().filter_map(|m| m.address.clone()).collect()
    }

    /// Determine the counterparty address in a pair of members
    fn get_counterparty_address(&self, member1: &Member, member2: &Member) -> Result<P2PAddress> {
        let member1_address = member1.address()?;
        let member2_address = member2.address()?;
        let my_address = self.address()?;

        let counterparty_address = if my_address == member1_address {
            member2_address
        } else if my_address == member2_address {
            member1_address
        } else {
            return Err(anyhow::anyhow!(
                "Current member is not part of the address pair"
            ));
        };

        Ok(counterparty_address.clone())
    }
}
