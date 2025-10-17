use anyhow::Result;
use bitcoin::{Network, Txid};
use bitvmx_client::program::participant::CommsAddress;
use bitvmx_client::program::protocols::union::common::{
    get_accept_pegin_pid, get_dispute_aggregated_key_pid, get_take_aggreated_key_pid,
    get_user_take_pid,
};
use bitvmx_client::program::protocols::union::types::{
    MemberData, ACCEPT_PEGIN_TX, DUST_VALUE, SPEEDUP_VALUE, USER_TAKE_TX,
};
use bitvmx_client::program::{participant::ParticipantRole, variables::PartialUtxo};
use bitvmx_client::types::OutgoingBitVMXApiMessages::{SPVProof, Transaction};

use bitcoin::PublicKey;
use protocol_builder::types::Utxo;
use std::collections::HashMap;
use std::thread::{self};
use std::time::Duration;
use tracing::{info, info_span};
use uuid::Uuid;

use crate::bitcoin::{init_client, BitcoinWrapper};
use crate::macros::wait_for_message_blocking;
use crate::participants::common::prefixed_name;
use crate::participants::member::{FundingAmount, Member};
use crate::wait_until_msg;
use crate::wallet::helper::non_regtest_warning;

const FUNDING_AMOUNT_PER_SLOT: u64 = 9_500; // an approximation in satoshis
pub const PACKET_SIZE: u32 = 3; // number of slots per packet
const SPEED_UP_MIN_FUNDS: u64 = 30_000; // minimum speedup funds in satoshis

pub struct Committee {
    pub members: Vec<Member>,
    take_aggregation_id: Uuid,
    dispute_aggregation_id: Uuid,
    committee_id: Uuid,
    stream_denomination: u64,
    pub bitcoin_client: BitcoinWrapper,
}

impl Committee {
    pub fn new(stream_denomination: u64, network: Network) -> Result<Self> {
        non_regtest_warning(network, "You are working with REAL money.");

        let network_prefix = match network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "",
            _ => panic!("Unsupported network"),
        };

        let members = vec![
            Member::new(
                &prefixed_name(network_prefix, "op_1"),
                ParticipantRole::Prover,
            )?,
            Member::new(
                &prefixed_name(network_prefix, "op_2"),
                ParticipantRole::Prover,
            )?,
            Member::new(
                &prefixed_name(network_prefix, "op_3"),
                ParticipantRole::Prover,
            )?,
            Member::new(
                &prefixed_name(network_prefix, "op_4"),
                ParticipantRole::Verifier,
            )?,
        ];

        let (client, network) = init_client(members[0].config.clone())?;
        let bitcoin_client = BitcoinWrapper::new(client, network);
        let committee_id = Uuid::new_v4();
        let take_aggregation_id = get_take_aggreated_key_pid(committee_id);
        let dispute_aggregation_id = get_dispute_aggregated_key_pid(committee_id);

        Ok(Self {
            members,
            take_aggregation_id,
            dispute_aggregation_id,
            committee_id,
            stream_denomination,
            bitcoin_client,
        })
    }

    pub fn committee_id(&self) -> Uuid {
        self.committee_id
    }

    pub fn setup_keys(&mut self) -> Result<()> {
        // gather all operator addresses
        // in a real scenario, operators should get this from the chain
        self.all(|op| op.get_peer_info())?;

        // create members pubkeys
        let keys = self.all(|op| op.setup_member_keys())?;

        // collect members keys
        let members_take_pubkeys: Vec<PublicKey> = keys.iter().map(|k| k.0).collect();
        let members_dispute_pubkeys: Vec<PublicKey> = keys.iter().map(|k| k.1).collect();
        let _members_communication_pubkeys: Vec<PublicKey> = keys.iter().map(|k| k.2).collect();

        let take_aggregation_id = self.take_aggregation_id;
        let dispute_aggregation_id = self.dispute_aggregation_id;

        let committee_id = self.committee_id;
        let members = self.members.clone();
        let _ = self.all(|op: &mut Member| {
            op.setup_committee_keys(
                &members.clone(),
                &members_take_pubkeys,
                &members_dispute_pubkeys,
                take_aggregation_id,
                dispute_aggregation_id,
                committee_id,
            )
        })?;

        Ok(())
    }

    pub fn setup_dispute_protocols(&mut self) -> Result<()> {
        let (
            funding_utxos_per_member,
            speedup_funding_utxos_per_member,
            wt_funding_utxos_per_member,
        ) = self.init_funds()?;

        let members = self.get_member_data();
        let addresses = self.get_addresses();
        let seed = self.committee_id;

        // Setup Dispute Core covenant
        self.all(|op: &mut Member| {
            op.setup_dispute_core(
                seed,
                &members.clone(),
                &funding_utxos_per_member,
                &speedup_funding_utxos_per_member
                    .get(op.keyring.take_pubkey.as_ref().unwrap())
                    .unwrap(),
                &addresses.clone(),
            )
        })?;

        // Setup Init covenant
        let committee_id = self.committee_id;
        self.all(|op: &mut Member| {
            op.setup_init(
                committee_id,
                &members.clone(),
                &wt_funding_utxos_per_member,
                &addresses.clone(),
            )
        })?;

        // TODO re-enable dispute channels once protocol is finalized:
        // blocked by https://trello.com/c/eDA2ltcT/42-dispute-channel
        // // Setup Dispute Channel covenant
        // let committee_id = self.committee_id;
        // let wt_funding_map = wt_funding_utxos_per_member.clone();
        // self.all(|op: &mut Member| {
        //     op.setup_dispute_channel(
        //         committee_id,
        //         &members.clone(),
        //         &wt_funding_map,
        //         &addresses.clone(),
        //     )
        // })?;

        Ok(())
    }

    pub fn accept_pegin(
        &mut self,
        committee_id: Uuid,
        request_pegin_txid: Txid,
        amount: u64,
        accept_pegin_sighash: Vec<u8>,
        slot_index: usize,
        rootstock_address: String,
        reimbursement_pubkey: PublicKey,
        dispatch_tx: bool,
    ) -> Result<()> {
        let members = self.get_member_data();
        let addresses = self.get_addresses();

        self.all(|op: &mut Member| {
            op.accept_pegin(
                &members.clone(),
                request_pegin_txid,
                amount,
                accept_pegin_sighash.as_slice(),
                committee_id,
                slot_index,
                rootstock_address.clone(),
                reimbursement_pubkey.clone(),
                &addresses.clone(),
            )
        })?;

        if dispatch_tx {
            self.dispatch_transaction_and_wait_for_spv_proof(
                get_accept_pegin_pid(committee_id, slot_index),
                ACCEPT_PEGIN_TX.to_string(),
            )?;
        }

        Ok(())
    }

    pub fn setup_full_penalization(&mut self) -> Result<()> {
        let addresses = self.get_addresses();
        let committee_id = self.committee_id;

        self.all(|op: &mut Member| op.setup_full_penalization(committee_id, &addresses.clone()))?;

        Ok(())
    }

    pub fn wait_for_spv_proof(&self, txid: Txid) -> Result<()> {
        let bitvmx = &self.members[0].bitvmx;
        let status = wait_until_msg!(bitvmx, Transaction(_, _status, _) => _status);

        info!(
            "Sent {} transaction with {} confirmations.",
            txid, status.confirmations
        );

        info!("Waiting for SPV proof...",);
        let _ = bitvmx.get_spv_proof(txid);
        let spv_proof = wait_until_msg!(
            bitvmx,
            SPVProof(_, Some(_spv_proof)) => _spv_proof
        );
        info!("SPV proof: {:?}", spv_proof);
        Ok(())
    }

    fn dispatch_transaction_and_wait_for_spv_proof(
        &self,
        protocol_id: Uuid,
        tx_name: String,
    ) -> Result<()> {
        let tx = self.members[0].dispatch_transaction_by_name(protocol_id, tx_name.clone())?;
        let txid = tx.compute_txid();
        self.bitcoin_client.wait_for_blocks(1)?;
        self.wait_for_spv_proof(txid)?;
        Ok(())
    }

    pub fn request_pegout(
        &mut self,
        user_pubkey: PublicKey,
        slot_index: usize,
        stream_id: u64,
        packet_number: u64,
        amount: u64,
        pegout_id: Vec<u8>,
        pegout_signature_hash: Vec<u8>,
        pegout_signature_message: Vec<u8>,
    ) -> Result<PartialUtxo> {
        let committee_id = self.committee_id.clone();
        let addresses = self.get_addresses();

        self.all(|op: &mut Member| {
            op.request_pegout(
                committee_id,
                stream_id,
                packet_number,
                slot_index,
                amount,
                pegout_id.clone(),
                pegout_signature_hash.clone(),
                pegout_signature_message.clone(),
                user_pubkey,
                &addresses,
            )
        })?;

        let protocol_id = get_user_take_pid(committee_id, slot_index);
        let tx =
            self.members[0].dispatch_transaction_by_name(protocol_id, USER_TAKE_TX.to_string())?;
        let utxo = (
            tx.compute_txid(),
            0,
            Some(tx.output[0].value.to_sat()),
            None,
        );
        thread::sleep(Duration::from_secs(1));
        Ok(utxo)
    }

    pub fn advance_funds(
        &mut self,
        slot_id: usize,
        user_public_key: PublicKey,
        pegout_id: Vec<u8>,
        selected_operator_pubkey: PublicKey,
        fee: u64,
    ) -> Result<()> {
        let protocol_id = Uuid::new_v4();
        let committee_id = self.committee_id.clone();

        self.all(|op: &mut Member| {
            op.advance_funds(
                protocol_id,
                committee_id,
                slot_id,
                user_public_key,
                pegout_id.clone(),
                selected_operator_pubkey,
                fee,
            )
        })?;

        Ok(())
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        if self.members.is_empty() {
            return Err(anyhow::anyhow!("No members in the committee"));
        }
        Ok(self.members[0].keyring.take_aggregated_key.unwrap())
    }

    fn get_addresses(&self) -> Vec<CommsAddress> {
        self.members
            .iter()
            .map(|m| m.address.clone().unwrap())
            .collect()
    }

    fn get_member_data(&self) -> Vec<MemberData> {
        self.members
            .iter()
            .map(|m| MemberData {
                role: m.role.clone(),
                take_key: m.keyring.take_pubkey.unwrap(),
                dispute_key: m.keyring.dispute_pubkey.unwrap(),
            })
            .collect()
    }

    fn get_speedup_funds_value(&self) -> u64 {
        return if self.bitcoin_client.network() == Network::Regtest {
            100_000
        } else {
            SPEED_UP_MIN_FUNDS
        };
    }

    fn get_advance_funds_value(&self) -> u64 {
        return self.stream_denomination * 12 / 10;
    }

    fn get_operator_funding_value(&self) -> u64 {
        return FUNDING_AMOUNT_PER_SLOT * PACKET_SIZE as u64;
    }

    fn get_watchtower_funding_value(&self) -> u64 {
        return FUNDING_AMOUNT_PER_SLOT * PACKET_SIZE as u64;
    }

    fn get_funding_op_disabler_directory_value(&self) -> u64 {
        return DUST_VALUE * PACKET_SIZE as u64 + SPEEDUP_VALUE;
    }

    pub fn get_total_funds_value(&self) -> u64 {
        let fees = 5_000; // extra fees for safety

        return self.get_speedup_funds_value()
            + self.get_advance_funds_value()
            + self.get_operator_funding_value()
            + self.get_watchtower_funding_value()
            + self.get_funding_op_disabler_directory_value()
            + fees;
    }

    fn init_funds(
        &mut self,
    ) -> Result<(
        HashMap<PublicKey, PartialUtxo>,
        HashMap<PublicKey, Utxo>,
        HashMap<PublicKey, PartialUtxo>,
    )> {
        let mut funding_utxos_per_member: HashMap<PublicKey, PartialUtxo> = HashMap::new();
        let mut speedup_funding_utxos_per_member: HashMap<PublicKey, Utxo> = HashMap::new();
        let mut wt_funding_utxos_per_member: HashMap<PublicKey, PartialUtxo> = HashMap::new();

        let funding_amounts = FundingAmount {
            speedup: self.get_speedup_funds_value(),
            operator_funding: self.get_operator_funding_value()
                + self.get_funding_op_disabler_directory_value(),
            watchtower_funding: self.get_watchtower_funding_value(),
            advance_funds: self.get_advance_funds_value(),
        };

        for member in &mut self.members {
            let utxos = member.init_funds(funding_amounts.clone())?;

            funding_utxos_per_member
                .insert(member.keyring.take_pubkey.unwrap(), utxos.operator_funding);

            wt_funding_utxos_per_member.insert(
                member.keyring.take_pubkey.unwrap(),
                utxos.watchtower_funding,
            );

            let speedup = Utxo::new(
                utxos.speedup.0,
                utxos.speedup.1,
                utxos.speedup.2.unwrap(),
                &member.keyring.dispute_pubkey.unwrap(),
            );

            speedup_funding_utxos_per_member.insert(member.keyring.take_pubkey.unwrap(), speedup);

            // FIXME: speedup utxo is set in DisputeCoreSetup, should we do the same for advance funds?
            // or should speedup utxo set here too? Unify criteria.
            member.set_advance_funds_input(self.committee_id, utxos.advance_funds.clone())?;
        }

        Ok((
            funding_utxos_per_member,
            speedup_funding_utxos_per_member,
            wt_funding_utxos_per_member,
        ))
    }

    fn all<F, R>(&mut self, f: F) -> Result<Vec<R>>
    where
        F: Fn(&mut Member) -> Result<R> + Send + Sync + Clone,
        R: Send,
    {
        thread::scope(|s| {
            self.members
                .iter_mut()
                .map(|m| {
                    let f = f.clone();
                    let span = info_span!("member", id = %m.id);

                    thread::sleep(Duration::from_millis(2000)); // Simulate some delay for each member

                    s.spawn(move || span.in_scope(|| f(m)))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        })
    }
}
