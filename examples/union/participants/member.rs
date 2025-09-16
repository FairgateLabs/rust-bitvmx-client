use anyhow::Result;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Amount;
use bitcoin::ScriptBuf;
use bitvmx_client::program::protocols::union::types::ADVANCE_FUNDS_INPUT;
use bitvmx_client::program::variables::VariableTypes;
use bitvmx_wallet::wallet::Destination;
use core::clone::Clone;
use protocol_builder::types::OutputType;
use protocol_builder::types::Utxo;
use std::collections::HashMap;
use std::thread;
use uuid::Uuid;

use bitcoin::{PublicKey, Txid};
use bitvmx_client::{
    client::BitVMXClient,
    config::Config,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::types::MemberData,
        variables::PartialUtxo,
    },
    types::{OutgoingBitVMXApiMessages::*, L2_ID},
};

use tracing::{debug, info};

use crate::wallet::helper::print_link;
use crate::{
    expect_msg,
    macros::wait_for_message_blocking,
    setup::{
        accept_pegin_setup::AcceptPegInSetup, advance_funds_setup::AdvanceFunds,
        dispute_core_setup::DisputeCoreSetup, user_take_setup::UserTakeSetup,
    },
    wait_until_msg,
};

#[derive(Clone)]
pub struct FundingAmount {
    pub speedup: u64,
    pub protocol_funding: u64,
    pub advance_funds: u64,
}

pub struct FundingUtxos {
    pub speedup: PartialUtxo,
    pub protocol_funding: PartialUtxo,
    pub advance_funds: PartialUtxo,
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
        thread::sleep(std::time::Duration::from_secs(5));
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

        info!(
            id = self.id,
            "Member keys setup complete: take_pubkey: {}, dispute_pubkey: {}, communication_pubkey: {}",
            take_pubkey.to_string(),
            dispute_pubkey.to_string(),
            communication_pubkey.to_string()
        );

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
        members: &Vec<MemberData>,
        funding_utxos_per_member: &HashMap<PublicKey, PartialUtxo>,
        my_speedup_funding: &Utxo,
        addresses: &Vec<P2PAddress>,
    ) -> Result<()> {
        info!(
            id = self.id,
            "Setting up dispute protocols for member {}", self.id
        );

        DisputeCoreSetup::setup(
            committee_id,
            &self.id,
            &members.clone(),
            self.keyring.take_aggregated_key.unwrap(),
            self.keyring.dispute_aggregated_key.unwrap(),
            &self.bitvmx,
            funding_utxos_per_member,
            my_speedup_funding,
            addresses,
        )?;

        let operator_count = members
            .iter()
            .filter(|m| m.role == ParticipantRole::Prover)
            .count();

        for i in 0..operator_count {
            // Wait for the dispute core setup to complete
            let program_id = expect_msg!(self.bitvmx, SetupCompleted(program_id) => program_id)?;
            info!(id = self.id, program_id = ?program_id, "Dispute core setup completed for operator index {}", i);
        }

        // TODO: add the dispute channeles here

        Ok(())
    }

    pub fn accept_pegin(
        &mut self,
        members: &Vec<MemberData>,
        request_pegin_txid: Txid,
        request_pegin_amount: u64,
        accept_pegin_sighash: &[u8],
        committee_id: Uuid,
        slot_index: usize,
        rootstock_address: String,
        reimbursement_pubkey: PublicKey,
        addresses: &Vec<P2PAddress>,
    ) -> Result<()> {
        info!(id = self.id, "Accepting peg-in");
        AcceptPegInSetup::setup(
            &self.id,
            &self.role,
            members,
            request_pegin_txid,
            request_pegin_amount,
            accept_pegin_sighash,
            self.keyring.take_aggregated_key.unwrap(),
            &self.bitvmx,
            committee_id,
            slot_index,
            rootstock_address,
            reimbursement_pubkey,
            addresses,
        )?;

        let program_id = wait_until_msg!(&self.bitvmx, SetupCompleted(_program_id) => _program_id);
        info!(id = "AcceptPegInSetup", program_id = ?program_id, "Accept pegin setup completed (from member)");

        Ok(())
    }

    pub fn request_pegout(
        &mut self,
        committee_id: Uuid,
        stream_id: u64,
        packet_number: u64,
        slot_index: usize,
        amount: u64,
        pegout_id: Vec<u8>,
        pegout_signature_hash: Vec<u8>,
        pegout_signature_message: Vec<u8>,
        user_pubkey: PublicKey,
        addresses: &Vec<P2PAddress>,
    ) -> Result<()> {
        UserTakeSetup::setup(
            committee_id,
            stream_id,
            packet_number,
            slot_index,
            amount,
            pegout_id,
            pegout_signature_hash,
            pegout_signature_message,
            user_pubkey,
            self.keyring.take_aggregated_key.unwrap(),
            &self.id,
            &self.bitvmx,
            addresses,
        )?;

        // Wait for the UserTake setup to complete
        let program_id = wait_until_msg!(&self.bitvmx, SetupCompleted(_program_id) => _program_id);
        info!(id = self.id, program_id = ?program_id, "UserTake setup completed (from member)");

        Ok(())
    }

    pub fn advance_funds(
        &mut self,
        protocol_id: Uuid,
        committee_id: Uuid,
        slot_index: usize,
        user_pubkey: PublicKey,
        pegout_id: Vec<u8>,
        selected_operator_pubkey: PublicKey,
        fee: u64,
    ) -> Result<()> {
        info!(
            id = self.id,
            "Advancing funds to user public key {}",
            user_pubkey.to_string()
        );

        AdvanceFunds::setup(
            &self.bitvmx,
            protocol_id,
            committee_id,
            slot_index,
            user_pubkey,
            selected_operator_pubkey,
            self.keyring.take_pubkey.unwrap(),
            pegout_id.clone(),
            self.address()?.clone(),
            fee,
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

        let take_aggregated_key = self.setup_key(
            take_aggregation_id,
            &addresses.clone(),
            Some(members_take_pubkeys),
        )?;

        self.keyring.take_aggregated_key = Some(take_aggregated_key);

        let dispute_aggregated_key = self.setup_key(
            dispute_aggregation_id,
            &addresses.clone(),
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

    pub fn get_funding_address(&self) -> Result<bitcoin::Address<NetworkUnchecked>> {
        self.bitvmx.get_funding_address(Uuid::new_v4())?;
        thread::sleep(std::time::Duration::from_secs(1));
        let address = wait_until_msg!(&self.bitvmx, FundingAddress(_, _address) => _address);
        Ok(address)
    }

    pub fn get_funding_balance(&self) -> Result<u64> {
        self.bitvmx.get_funding_balance(Uuid::new_v4())?;
        thread::sleep(std::time::Duration::from_secs(1));
        let amount = wait_until_msg!(&self.bitvmx, FundingBalance(_, _amount) => _amount);
        Ok(amount)
    }

    pub fn send_funds(&self, amount: u64, address: String, fee_rate: Option<u64>) -> Result<Txid> {
        self.bitvmx.send_funds(
            Uuid::new_v4(),
            Destination::Address(address, amount),
            fee_rate,
        )?;
        self.bitvmx.get_funding_address(Uuid::new_v4())?;
        thread::sleep(std::time::Duration::from_secs(1));
        let txid = wait_until_msg!(&self.bitvmx, FundsSent(_, _txid) => _txid);
        Ok(txid)
    }

    pub fn init_funds(&mut self, amounts: FundingAmount) -> Result<FundingUtxos> {
        let id = Uuid::new_v4();
        let fee_rate = self.get_fee_rate();
        let public_key = self.keyring.dispute_pubkey.unwrap();

        // Send funds to the public key
        info!(
            "Funding dispute pubkey of {} with: {}",
            self.id,
            amounts.speedup + amounts.protocol_funding + amounts.advance_funds
        );

        self.bitvmx.send_funds(
            id,
            Destination::Batch(vec![
                Destination::P2WPKH(public_key, amounts.speedup),
                Destination::P2WPKH(public_key, amounts.protocol_funding),
                Destination::P2WPKH(public_key, amounts.advance_funds),
            ]),
            Some(fee_rate),
        )?;

        thread::sleep(std::time::Duration::from_secs(2));
        let txid = wait_until_msg!(
            &self.bitvmx,
            FundsSent(_, _txid) => _txid
        );

        info!("Funded. Txid: {}", txid);
        print_link(self.config.bitcoin.network, txid);

        let wpkh = public_key.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);
        let speedup_ot = OutputType::SegwitPublicKey {
            value: Amount::from_sat(amounts.speedup),
            script_pubkey: script_pubkey.clone(),
            public_key: public_key,
        };
        let protocol_funding_ot = OutputType::SegwitPublicKey {
            value: Amount::from_sat(amounts.protocol_funding),
            script_pubkey: script_pubkey.clone(),
            public_key: public_key,
        };
        let advance_funds_ot = OutputType::SegwitPublicKey {
            value: Amount::from_sat(amounts.advance_funds),
            script_pubkey: script_pubkey.clone(),
            public_key: public_key,
        };

        // Output indexes should match the order in the Destination::Batch above
        Ok(FundingUtxos {
            speedup: (txid, 0, Some(amounts.speedup), Some(speedup_ot)),
            protocol_funding: (
                txid,
                1,
                Some(amounts.protocol_funding),
                Some(protocol_funding_ot),
            ),
            advance_funds: (txid, 2, Some(amounts.advance_funds), Some(advance_funds_ot)),
        })
    }

    pub fn set_advance_funds_input(&mut self, committee_id: Uuid, utxo: PartialUtxo) -> Result<()> {
        self.bitvmx
            .set_var(committee_id, ADVANCE_FUNDS_INPUT, VariableTypes::Utxo(utxo))?;

        Ok(())
    }

    fn get_fee_rate(&self) -> u64 {
        if self.config.bitcoin.network == bitcoin::Network::Regtest {
            10
        } else {
            1
        }
    }
}
