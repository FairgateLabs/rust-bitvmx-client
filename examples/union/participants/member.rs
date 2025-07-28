use anyhow::Result;
use std::collections::HashMap;
use uuid::Uuid;

use bitcoin::{PublicKey, Txid};
use bitvmx_client::{
    client::BitVMXClient,
    config::Config,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::types::ACCEPT_PEGIN_TX,
        variables::{PartialUtxo, VariableTypes},
    },
    types::{OutgoingBitVMXApiMessages::*, L2_ID},
};

use tracing::{debug, info};

use crate::{
    expect_msg,
    setup::{
        accept_pegin_setup::AcceptPegInSetup, advance_funds_setup::AdvanceFunds,
        dispute_core_setup::DisputeCoreSetup, user_take_setup::UserTakeSetup,
    },
    wait_until_msg,
};

use crate::macros::wait_for_message_blocking;

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
    pub id: String,
    pub role: ParticipantRole,
    pub config: Config,
    pub address: Option<P2PAddress>,
    pub bitvmx: BitVMXClient,
    pub keyring: Keyring,
}

impl Member {
    pub fn new(id: &str, role: ParticipantRole) -> Result<Self> {
        let config = Config::new(Some(format!("config/{}.yaml", id)))?;
        let bitvmx = BitVMXClient::new(config.broker_port, L2_ID);

        Ok(Self {
            id: id.to_string(),
            role,
            config,
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
        })
    }

    pub fn get_peer_info(&mut self) -> Result<P2PAddress> {
        self.bitvmx.get_comm_info()?;
        let addr = expect_msg!(self.bitvmx, CommInfo(addr) => addr)?;

        self.address = Some(addr.clone());
        Ok(addr)
    }

    pub fn setup_member_keys(&mut self) -> Result<(PublicKey, PublicKey, PublicKey)> {
        // TODO what id should we use for these keys?
        let id = Uuid::new_v4();
        self.bitvmx.get_pubkey(id, true)?;
        let take_pubkey = expect_msg!(self.bitvmx, PubKey(_, key) => key)?;
        debug!(id = self.id, take_pubkey = ?take_pubkey, "Take pubkey");

        let id = Uuid::new_v4();
        self.bitvmx.get_pubkey(id, true)?;
        let dispute_pubkey = expect_msg!(self.bitvmx, PubKey(_, key) => key)?;
        debug!(id = self.id, dispute_pubkey = ?dispute_pubkey, "Dispute pubkey");

        let id = Uuid::new_v4();
        self.bitvmx.get_pubkey(id, true)?;
        let communication_pubkey = expect_msg!(self.bitvmx, PubKey(_, key) => key)?;
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

    pub fn setup_dispute_protocols(
        &mut self,
        committee_id: Uuid,
        members: &[Member],
        funding_utxos_per_member: &HashMap<PublicKey, Vec<PartialUtxo>>,
    ) -> Result<()> {
        info!(
            id = self.id,
            "Setting up dispute protocols for member {}", self.id
        );
        DisputeCoreSetup::setup(
            committee_id,
            &self.id,
            &self.role,
            members,
            &self.keyring,
            &self.bitvmx,
            funding_utxos_per_member,
        )?;

        // Wait for the dispute core setup to complete
        let program_id = expect_msg!(self.bitvmx, SetupCompleted(program_id) => program_id)?;
        info!(id = self.id, program_id = ?program_id, "Dispute core setup completed");

        // TODO: add the dispute channeles here

        Ok(())
    }

    pub fn accept_pegin(
        &mut self,
        protocol_id: Uuid,
        members: &[Member],
        request_pegin_txid: Txid,
        request_pegin_amount: u64,
        accept_pegin_sighash: &[u8],
        committee_id: Uuid,
        slot_index: u32,
    ) -> Result<()> {
        info!(id = self.id, "Accepting peg-in");
        AcceptPegInSetup::setup(
            protocol_id,
            &self.id,
            &self.role,
            members,
            request_pegin_txid,
            request_pegin_amount,
            accept_pegin_sighash,
            &self.keyring,
            &self.bitvmx,
            committee_id,
            slot_index,
        )?;

        Ok(())
    }

    pub fn request_pegout(
        &mut self,
        protocol_id: Uuid,
        committee_id: Uuid,
        user_pubkey: PublicKey,
        slot_id: u32,
        fee: u64,
        members: &[Member],
    ) -> Result<()> {
        UserTakeSetup::setup(
            protocol_id,
            committee_id,
            &self.id,
            members,
            user_pubkey,
            slot_id,
            fee,
            &self.bitvmx,
            self.keyring.take_aggregated_key.unwrap(),
        )?;

        Ok(())
    }

    pub fn advance_funds(
        &mut self,
        committee_id: Uuid,
        slot_id: usize,
        user_public_key: PublicKey,
        pegout_id: Vec<u8>,
    ) -> Result<()> {
        if self.role != ParticipantRole::Prover {
            return Err(anyhow::anyhow!("Committee member is not a Prover"));
        }

        self.bitvmx
            .get_var(committee_id, format!("{}_{}", ACCEPT_PEGIN_TX, slot_id))?;

        // Error: Expected `Variable(_, _, VariableTypes::Utxo(utxo))` but got `PeginTransactionFound(89b50f29978554d6fc0bde8c3c48bae87666a14620f99524c2b501e808d5e3e1, TransactionStatus { tx_id: 89b50f29978554d6fc0bde8c3c48bae87666a14620f99524c2b501e808d5e3e1, tx: Transaction { version: Version(2), lock_time: 0 blocks, input: [TxIn { previous_output: OutPoint { txid: 9713eaa973d9e7a8bf832c81ed9682a634b7968d45428d292538fcc011998f52, vout: 1 }, script_sig: Script(), sequence: Sequence(0xfffffffd), witness: Witness: { indices: 2, indices_start: 106, witnesses: [[0x30, 0x44, 0x02, 0x20, 0x67, 0xf6, 0xf0, 0x3d, 0x8d, 0x8f, 0x09, 0x8b, 0x74, 0x12, 0xa2, 0xd3, 0x92, 0x12, 0x73, 0xab, 0x4f, 0xcd, 0x04, 0xfd, 0x77, 0x3b, 0x1e, 0x33, 0x17, 0x18, 0x3e, 0x89, 0x7c, 0xd2, 0x66, 0x22, 0x02, 0x20, 0x21, 0x4c, 0x97, 0x12, 0x41, 0x8a, 0xef, 0xa5, 0x2a, 0x8d, 0x0f, 0x5e, 0x8f, 0xe7, 0xcd, 0xff, 0x57, 0xfc, 0xf1, 0xc7, 0x37, 0xdb, 0xa0, 0x4b, 0xf8, 0x5f, 0xb7, 0x14, 0x3a, 0x4f, 0x11, 0x6b, 0x01], [0x02, 0xf4, 0x00, 0xa0, 0xad, 0x70, 0xaa, 0x53, 0xec, 0x02, 0x94, 0x87, 0x9a, 0xbc, 0x74, 0x47, 0x49, 0x73, 0x44, 0x52, 0x11, 0x68, 0x11, 0xfc, 0xc2, 0x1f, 0x8c, 0xbb, 0xd2, 0x4d, 0x4b, 0xab, 0x7b]] } }], output: [TxOut { value: 100000 SAT, script_pubkey: Script(OP_PUSHNUM_1 OP_PUSHBYTES_32 13f9fc8e7cf742ab441578526130d4568373a5605185f57df2132e1d29b29dfd) }, TxOut { value: 0 SAT, script_pubkey: Script(OP_RETURN OP_PUSHBYTES_69 52534b5f504547494e00000000000000007ac5496aee77c1ba1f0854206a26dda82a81d6d8f400a0ad70aa53ec0294879abc744749734452116811fcc21f8cbbd24d4bab7b) }] }, block_info: Some(FullBlock { height: 210, hash: 57c74f2906abbe8e3fedfd82af159c1ea6979ddcb0eb0926b5bbdbba07dd2254, prev_hash: 1553a9652dae98a80f09bdd36b5dade60dce9aad8808a2db6eb0e9434aa9ce16, txs: [Transaction { version: Version(2), lock_time: 0 blocks, input: [TxIn { previous_output: OutPoint { txid: 0000000000000000000000000000000000000000000000000000000000000000, vout: 4294967295 }, script_sig: Script(OP_PUSHBYTES_2 d200 OP_0), sequence: Sequence(0xffffffff), witness: Witness: { indices: 1, indices_start: 33, witnesses: [[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]] } }], output: [TxOut { value: 2500000635 SAT, script_pubkey: Script(OP_0 OP_PUSHBYTES_20 597efad661d309d91cb56e276804beed5a58cebc) }, TxOut { value: 0 SAT, script_pubkey: Script(OP_RETURN OP_PUSHBYTES_36 aa21a9edd4948256db7b2c616176a62b4ad16922b79d90b96065c144895792701c7f98e6) }] }, Transaction { version: Version(2), lock_time: 0 blocks, input: [TxIn { previous_output: OutPoint { txid: 9713eaa973d9e7a8bf832c81ed9682a634b7968d45428d292538fcc011998f52, vout: 1 }, script_sig: Script(), sequence: Sequence(0xfffffffd), witness: Witness: { indices: 2, indices_start: 106, witnesses: [[0x30, 0x44, 0x02, 0x20, 0x67, 0xf6, 0xf0, 0x3d, 0x8d, 0x8f, 0x09, 0x8b, 0x74, 0x12, 0xa2, 0xd3, 0x92, 0x12, 0x73, 0xab, 0x4f, 0xcd, 0x04, 0xfd, 0x77, 0x3b, 0x1e, 0x33, 0x17, 0x18, 0x3e, 0x89, 0x7c, 0xd2, 0x66, 0x22, 0x02, 0x20, 0x21, 0x4c, 0x97, 0x12, 0x41, 0x8a, 0xef, 0xa5, 0x2a, 0x8d, 0x0f, 0x5e, 0x8f, 0xe7, 0xcd, 0xff, 0x57, 0xfc, 0xf1, 0xc7, 0x37, 0xdb, 0xa0, 0x4b, 0xf8, 0x5f, 0xb7, 0x14, 0x3a, 0x4f, 0x11, 0x6b, 0x01], [0x02, 0xf4, 0x00, 0xa0, 0xad, 0x70, 0xaa, 0x53, 0xec, 0x02, 0x94, 0x87, 0x9a, 0xbc, 0x74, 0x47, 0x49, 0x73, 0x44, 0x52, 0x11, 0x68, 0x11, 0xfc, 0xc2, 0x1f, 0x8c, 0xbb, 0xd2, 0x4d, 0x4b, 0xab, 0x7b]] } }], output: [TxOut { value: 100000 SAT, script_pubkey: Script(OP_PUSHNUM_1 OP_PUSHBYTES_32 13f9fc8e7cf742ab441578526130d4568373a5605185f57df2132e1d29b29dfd) }, TxOut { value: 0 SAT, script_pubkey: Script(OP_RETURN OP_PUSHBYTES_69 52534b5f504547494e00000000000000007ac5496aee77c1ba1f0854206a26dda82a81d6d8f400a0ad70aa53ec0294879abc744749734452116811fcc21f8cbbd24d4bab7b) }] }], orphan: false }), confirmations: 1, status: Confirmed })`
        let utxo =
            wait_until_msg!(&self.bitvmx, Variable(_, _, VariableTypes::Utxo(_utxo)) => _utxo);

        info!(
            id = self.id,
            "Advancing {} to user public key {}",
            utxo.2.unwrap(),
            user_public_key.to_string()
        );

        // Create the advance funds transaction and send it as if it was a transaction from and operator
        let mut advance_funds = AdvanceFunds::new(&self.config)?;
        advance_funds.create_and_send_tx(
            user_public_key,
            utxo.2.unwrap(),
            pegout_id,
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

        let aggregated_key = expect_msg!(self.bitvmx, AggregatedPubkey(_, key) => key)?;
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
