use anyhow::Result;
use std::{collections::HashMap, thread};
use uuid::Uuid;

use bitcoin::{PublicKey, Txid};
use bitvmx_client::{
    client::BitVMXClient,
    config::Config,
    program::{
        participant::{P2PAddress, ParticipantRole},
        protocols::union::{
            common::indexed_name,
            types::{ADVANCE_FUNDS_INPUT, ADVANCE_FUNDS_TX},
        },
        variables::{PartialUtxo, VariableTypes},
    },
    types::{OutgoingBitVMXApiMessages::*, L2_ID},
};

use tracing::{debug, info};

use crate::{
    expect_msg,
    macros::wait_for_message_blocking,
    setup::{
        accept_pegin_setup::AcceptPegInSetup,
        advance_funds_setup::{AdvanceFunds, AdvanceFundsHelper},
        dispute_core_setup::DisputeCoreSetup,
        user_take_setup::UserTakeSetup,
    },
    wait_until_msg,
};

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
        members: &[Member],
        funding_utxos_per_member: &HashMap<PublicKey, PartialUtxo>,
    ) -> Result<()> {
        info!(
            id = self.id,
            "Setting up dispute protocols for member {}", self.id
        );
        DisputeCoreSetup::setup(
            committee_id,
            &self.id,
            members,
            &self.keyring,
            &self.bitvmx,
            funding_utxos_per_member,
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
        protocol_id: Uuid,
        members: &[Member],
        request_pegin_txid: Txid,
        request_pegin_amount: u64,
        accept_pegin_sighash: &[u8],
        committee_id: Uuid,
        slot_index: usize,
        rootstock_address: String,
        reimbursement_pubkey: PublicKey,
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
            rootstock_address,
            reimbursement_pubkey,
        )?;

        let program_id = wait_until_msg!(&self.bitvmx, SetupCompleted(_program_id) => _program_id);
        info!(id = "AcceptPegInSetup", program_id = ?program_id, "Accept pegin setup completed (from member)");

        Ok(())
    }

    pub fn request_pegout(
        &mut self,
        protocol_id: Uuid,
        committee_id: Uuid,
        user_pubkey: PublicKey,
        slot_id: usize,
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

        // Wait for the UserTake setup to complete
        let program_id = wait_until_msg!(&self.bitvmx, SetupCompleted(_program_id) => _program_id);
        info!(id = self.id, program_id = ?program_id, "UserTake setup completed (from member)");

        Ok(())
    }

    pub fn advance_funds(
        &mut self,
        protocol_id: Uuid,
        committee_id: Uuid,
        slot_id: usize,
        user_pubkey: PublicKey,
        pegout_id: Vec<u8>,
        selected_operator_pubkey: PublicKey,
        members: &[Member],
    ) -> Result<()> {
        let mut helper = AdvanceFundsHelper::new(&self.config)?;

        // Check if this member is the selected operator for advance funds
        let mut utxo: Option<PartialUtxo> = None;
        if self.keyring.take_pubkey.unwrap() == selected_operator_pubkey {
            // NOTE: This flow will be moved inside bitvmx if we decided to add the operator wallet inside it
            // Fund operator wallet. This will be replaced with a wallet request in the future.
            let funded_utxo = helper.fund_operator_wallet(committee_id, slot_id, &self.bitvmx)?;
            utxo = Some(funded_utxo.clone());

            // Set UTXO. This won't be needed if bitvmx own the wallet.
            self.bitvmx.set_var(
                protocol_id,
                &indexed_name(ADVANCE_FUNDS_INPUT, slot_id),
                VariableTypes::Utxo(funded_utxo),
            )?;
        }

        info!(
            id = self.id,
            "Advancing funds to user public key {}",
            user_pubkey.to_string()
        );

        AdvanceFunds::setup(
            &self.bitvmx,
            protocol_id,
            committee_id,
            &members,
            slot_id,
            user_pubkey,
            selected_operator_pubkey,
            self.keyring.take_pubkey.unwrap(),
            pegout_id.clone(),
        )?;

        if self.keyring.take_pubkey.unwrap() == selected_operator_pubkey {
            info!(
                id = self.id,
                "Advance funds dispatch for member {}", self.id
            );

            thread::sleep(std::time::Duration::from_secs(5));

            let program_id =
                wait_until_msg!(&self.bitvmx, SetupCompleted(_program_id) => _program_id);
            info!(id = "AdvanceFundsSetup", program_id = ?program_id, "Advance funds setup completed (from setup)");

            // Sign and dispatch transaction.
            // NOTE: This is temporary, it will be done all internally by bitvmx in the future.
            let _ = self
                .bitvmx
                .get_transaction_by_name(protocol_id, ADVANCE_FUNDS_TX.to_string());
            thread::sleep(std::time::Duration::from_secs(1));
            let mut tx = wait_until_msg!(&self.bitvmx, TransactionInfo(_, _, _tx) => _tx);

            if let Some(ref utxo) = utxo {
                let signed_tx = helper
                    .sign_p2wpkh_transaction_single_input(&mut tx, utxo.2.clone().unwrap())?;

                let txid = signed_tx.compute_txid();
                info!(
                    id = self.id,
                    "Dispatching {} transaction: {:?}. Txid: {}", ADVANCE_FUNDS_TX, signed_tx, txid
                );

                self.bitvmx.dispatch_transaction(protocol_id, signed_tx)?;

                thread::sleep(std::time::Duration::from_secs(1));
                helper.mine_blocks(1)?;

                let status = wait_until_msg!(
                    &self.bitvmx,
                    Transaction(_, _status, _) => _status
                );
                info!(
                    id = self.id,
                    "Sent {} transaction with status: {:?}", ADVANCE_FUNDS_TX, status
                );

                // Get the SPV proof, this should be used by the union client to present to the smart contract
                self.bitvmx.get_spv_proof(txid)?;
                let spv_proof = wait_until_msg!(
                    &self.bitvmx,
                    SPVProof(_, Some(_spv_proof)) => _spv_proof
                );
                info!("SPV proof: {:?}", spv_proof);
            } else {
                return Err(anyhow::anyhow!(
                    "UTXO not initialized for signing transaction"
                ));
            }
        }

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
