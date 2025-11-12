use anyhow::{Error, Result};
use bitcoin::{Network, Txid};
use bitvmx_client::program::participant::CommsAddress;
use bitvmx_client::program::protocols::union::common::{
    estimate_fee, get_accept_pegin_pid, get_dispute_aggregated_key_pid, get_take_aggreated_key_pid,
    get_user_take_pid,
};
use bitvmx_client::program::protocols::union::types::{
    MemberData, StreamSettings, UnionSettings, ACCEPT_PEGIN_TX, DUST_VALUE, SPEEDUP_VALUE,
    USER_TAKE_TX,
};
use bitvmx_client::program::{participant::ParticipantRole, variables::PartialUtxo};

use bitcoin::PublicKey;
use protocol_builder::types::Utxo;
use std::collections::HashMap;
use std::thread::{self};
use std::time::Duration;
use tracing::info_span;
use uuid::Uuid;

use crate::bitcoin::{init_client, BitcoinWrapper};
use crate::participants::common::{get_default_union_settings, prefixed_name};
use crate::participants::member::{FundingAmount, Member};
use crate::wallet::helper::non_regtest_warning;

const FUNDING_AMOUNT_PER_SLOT: u64 = 9_000; // an approximation in satoshis
const DISPUTE_CHANNEL_FUNDING_PER_MEMBER: u64 = 540; // Output value that connect to dispute channel
pub const PACKET_SIZE: u32 = 3; // number of slots per packet
const SPEED_UP_MIN_FUNDS: u64 = 30_000; // minimum speedup funds in satoshis

pub struct Committee {
    pub members: Vec<Member>,
    take_aggregation_id: Uuid,
    dispute_aggregation_id: Uuid,
    committee_id: Uuid,
    stream_denomination: u64,
    pub bitcoin_client: BitcoinWrapper,
    pub union_settings: UnionSettings,
    pub stream_settings: StreamSettings,
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
                ParticipantRole::Verifier,
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

        let union_settings = get_default_union_settings();
        if !union_settings.settings.contains_key(&stream_denomination) {
            return Err(anyhow::anyhow!(format!(
                "Stream settings not found for denomination: {}",
                stream_denomination
            )));
        }

        let stream_settings = union_settings
            .settings
            .get(&stream_denomination)
            .unwrap()
            .clone();

        Ok(Self {
            members,
            take_aggregation_id,
            dispute_aggregation_id,
            committee_id,
            stream_denomination,
            bitcoin_client,
            union_settings,
            stream_settings,
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
        let _members_communication_pubkeys: Vec<PublicKey> = keys.iter().map(|k| k.2).collect();

        let take_aggregation_id = self.take_aggregation_id;
        let dispute_aggregation_id = self.dispute_aggregation_id;

        let committee_id = self.committee_id;
        let members = self.get_member_data();
        let addresses = self.get_addresses();

        let _ = self.all(|op: &mut Member| {
            op.setup_committee_keys(
                &addresses.clone(),
                &members.clone(),
                take_aggregation_id,
                dispute_aggregation_id,
                committee_id,
            )
        })?;

        Ok(())
    }

    pub fn setup_dispute_protocols(&mut self) -> Result<()> {
        let funding_utxos_per_member = self.init_funds()?;

        let settings = self.union_settings.clone();
        self.all(|op: &mut Member| op.save_union_settings(&settings))?;

        let members = self.get_member_data();
        let addresses = self.get_addresses();
        let committee_id = self.committee_id;
        let stream_denomination = self.stream_denomination;

        // Setup Dispute Core covenant
        self.all(|op: &mut Member| {
            op.setup_dispute_core(
                committee_id,
                &members.clone(),
                &funding_utxos_per_member,
                &addresses.clone(),
                stream_denomination,
            )
        })?;

        //  Setup DisputeChannels
        self.all(|op: &mut Member| {
            op.setup_dispute_channel(committee_id, &members.clone(), &addresses.clone())
        })?;

        // Setup FullPenalization protocol
        self.all(|op: &mut Member| op.setup_full_penalization(committee_id, &addresses.clone()))?;

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

    fn dispatch_transaction_and_wait_for_spv_proof(
        &self,
        protocol_id: Uuid,
        tx_name: String,
    ) -> Result<()> {
        let tx = self.members[0].dispatch_transaction_by_name(protocol_id, tx_name.clone())?;
        let txid = tx.compute_txid();
        self.bitcoin_client.wait_for_blocks(1)?;
        self.members[0].wait_for_spv_proof(txid)?;
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
        return FUNDING_AMOUNT_PER_SLOT * PACKET_SIZE as u64
            + SPEEDUP_VALUE
            + estimate_fee(1, PACKET_SIZE as usize + 2, 1);
    }

    fn get_watchtower_funding_value(&self) -> u64 {
        // Considerate each WT start enabler output
        return DISPUTE_CHANNEL_FUNDING_PER_MEMBER * self.members.len() as u64
            + SPEEDUP_VALUE
            + estimate_fee(1, self.members.len() as usize + 2, 1);
    }

    fn get_funding_wt_disabler_directory_value(&self) -> u64 {
        // Considerate each WT disabler directory output
        return DUST_VALUE * self.members.len() as u64
            + SPEEDUP_VALUE
            + estimate_fee(2, self.members.len(), 1);
    }

    fn get_funding_op_disabler_directory_value(&self) -> u64 {
        // Considerate each OP disabler directory output
        return DUST_VALUE * PACKET_SIZE as u64
            + SPEEDUP_VALUE
            + estimate_fee(2, PACKET_SIZE as usize + 1, 1);
    }

    pub fn get_total_funds_value(&self) -> u64 {
        let fees = 10_000; // extra fees for safety

        return self.get_speedup_funds_value()
            + self.get_advance_funds_value()
            + self.get_operator_funding_value()
            + self.get_funding_op_disabler_directory_value()
            + self.get_watchtower_funding_value()
            + self.get_funding_wt_disabler_directory_value()
            + fees;
    }

    fn init_funds(&mut self) -> Result<HashMap<PublicKey, PartialUtxo>> {
        let mut funding_utxos_per_member: HashMap<PublicKey, PartialUtxo> = HashMap::new();

        let funding_amounts = FundingAmount {
            speedup: self.get_speedup_funds_value(),
            protocol_funding: self.get_operator_funding_value()
                + self.get_funding_op_disabler_directory_value()
                + self.get_watchtower_funding_value()
                + self.get_funding_wt_disabler_directory_value()
                + 5_000, // extra for safety
            advance_funds: self.get_advance_funds_value(),
        };

        for member in &mut self.members {
            let utxos = member.init_funds(funding_amounts.clone())?;

            funding_utxos_per_member
                .insert(member.keyring.take_pubkey.unwrap(), utxos.operator_funding);

            let speedup = Utxo::new(
                utxos.speedup.0,
                utxos.speedup.1,
                utxos.speedup.2.unwrap(),
                &member.keyring.dispute_pubkey.unwrap(),
            );

            member.set_advance_funds_input(self.committee_id, utxos.advance_funds.clone())?;
            member.set_speedup_funding_utxo(speedup.clone())?;
        }

        Ok(funding_utxos_per_member)
    }

    pub fn get_stream_settings(&self, stream_denomination: u64) -> Result<StreamSettings, Error> {
        if !self
            .union_settings
            .settings
            .contains_key(&stream_denomination)
        {
            return Err(anyhow::anyhow!(format!(
                "Stream settings not found for denomination: {}",
                stream_denomination
            )));
        }

        Ok(self
            .union_settings
            .settings
            .get(&stream_denomination)
            .unwrap()
            .clone())
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
