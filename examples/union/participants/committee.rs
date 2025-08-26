use anyhow::Result;
use bitcoin::Txid;
use bitvmx_client::program::participant::CommsAddress;
use bitvmx_client::program::protocols::union::common::{
    get_accept_pegin_pid, get_dispute_aggregated_key_pid, get_take_aggreated_key_pid,
    get_user_take_pid,
};
use bitvmx_client::program::protocols::union::types::{MemberData, ACCEPT_PEGIN_TX, USER_TAKE_TX};
use bitvmx_client::program::{participant::ParticipantRole, variables::PartialUtxo};
use bitvmx_client::types::OutgoingBitVMXApiMessages::{SPVProof, Transaction, TransactionInfo};

use bitcoin::{Amount, PublicKey, ScriptBuf};
use bitvmx_wallet::wallet::Wallet;
use protocol_builder::types::{OutputType, Utxo};
use std::collections::HashMap;
use std::thread::{self};
use std::time::Duration;
use tracing::{info, info_span};
use uuid::Uuid;

use crate::bitcoin::{init_wallet, FEE, WALLET_NAME};
use crate::macros::wait_for_message_blocking;
use crate::participants::member::Member;
use crate::wait_until_msg;

pub struct Committee {
    pub members: Vec<Member>,
    take_aggregation_id: Uuid,
    dispute_aggregation_id: Uuid,
    committee_id: Uuid,
    pub wallet: Wallet,
}

impl Committee {
    pub fn new() -> Result<Self> {
        let members = vec![
            Member::new("op_1", ParticipantRole::Prover)?,
            Member::new("op_2", ParticipantRole::Prover)?,
            // Member::new("op_3", ParticipantRole::Prover)?,
            // Member::new("op_4", ParticipantRole::Verifier)?,
        ];

        let wallet = init_wallet()?;
        let committee_id = Uuid::new_v4();
        let take_aggregation_id = get_take_aggreated_key_pid(committee_id);
        let dispute_aggregation_id = get_dispute_aggregated_key_pid(committee_id);

        Ok(Self {
            members,
            take_aggregation_id,
            dispute_aggregation_id,
            committee_id,
            wallet,
        })
    }

    pub fn committee_id(&self) -> Uuid {
        self.committee_id
    }

    pub fn setup(&mut self) -> Result<PublicKey> {
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

        let members = self.members.clone();
        let _ = self.all(|op: &mut Member| {
            op.setup_committee_keys(
                &members.clone(),
                &members_take_pubkeys,
                &members_dispute_pubkeys,
                take_aggregation_id,
                dispute_aggregation_id,
            )
        })?;

        let seed = self.committee_id;

        let mut funding_utxos_per_member: HashMap<PublicKey, PartialUtxo> = HashMap::new();
        let mut speedup_funding_utxos_per_member: HashMap<PublicKey, Utxo> = HashMap::new();
        for member in &self.members {
            funding_utxos_per_member.insert(
                member.keyring.take_pubkey.unwrap(),
                self.get_funding_utxo(10_000_000, &member.keyring.dispute_pubkey.unwrap())?,
            );

            let partial =
                self.get_funding_utxo(10_000_000, &member.keyring.dispute_pubkey.unwrap())?;
            let utxo = Utxo::new(
                partial.0,
                partial.1,
                partial.2.unwrap(),
                &member.keyring.dispute_pubkey.unwrap(),
            );
            speedup_funding_utxos_per_member.insert(member.keyring.take_pubkey.unwrap(), utxo);
        }

        let members = self.get_member_data();
        let addresses = self.get_addresses();

        self.all(|op: &mut Member| {
            op.setup_dispute_protocols(
                seed,
                &members.clone(),
                &funding_utxos_per_member,
                &speedup_funding_utxos_per_member
                    .get(op.keyring.take_pubkey.as_ref().unwrap())
                    .unwrap(),
                &addresses.clone(),
            )
        })?;

        Ok(self.public_key()?)
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

        let protocol_id = get_accept_pegin_pid(committee_id, slot_index);
        self.dispatch_transaction_and_wait_for_spv_proof(protocol_id, ACCEPT_PEGIN_TX.to_string())?;

        Ok(())
    }

    fn dispatch_transaction_and_wait_for_spv_proof(
        &self,
        protocol_id: Uuid,
        tx_name: String,
    ) -> Result<()> {
        let bitvmx = &self.members[0].bitvmx;
        let _ = bitvmx.get_transaction_by_name(protocol_id, tx_name.clone());
        thread::sleep(std::time::Duration::from_secs(1));
        let tx = wait_until_msg!(bitvmx, TransactionInfo(_, _, _tx) => _tx);
        let txid = tx.compute_txid();
        info!(
            "Protocol handler {} dispatching {} transaction: {:?}",
            protocol_id,
            tx_name.clone(),
            tx
        );
        bitvmx.dispatch_transaction(protocol_id, tx)?;
        thread::sleep(std::time::Duration::from_secs(1));
        self.wallet.mine(1)?;

        let status = wait_until_msg!(bitvmx, Transaction(_, _status, _) => _status);

        info!(
            "Protocol handler {} sent {} transaction with status: {:?}",
            protocol_id,
            tx_name.clone(),
            status
        );

        info!(
            "Waiting for SPV proof for {} transaction...",
            tx_name.clone()
        );
        let _ = bitvmx.get_spv_proof(txid);
        let spv_proof = wait_until_msg!(
            bitvmx,
            SPVProof(_, Some(_spv_proof)) => _spv_proof
        );
        info!("{} SPV proof: {:?}", tx_name.clone(), spv_proof);
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
    ) -> Result<()> {
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
        self.dispatch_transaction_and_wait_for_spv_proof(protocol_id, USER_TAKE_TX.to_string())?;

        Ok(())
    }

    pub fn advance_funds(
        &mut self,
        slot_id: usize,
        user_public_key: PublicKey,
        pegout_id: Vec<u8>,
        selected_operator_pubkey: PublicKey,
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

    fn get_funding_utxo(&self, amount: u64, pubkey: &PublicKey) -> Result<PartialUtxo> {
        self.prepare_funding_utxo(&self.wallet, "fund_1", pubkey, amount, None)
    }

    fn prepare_funding_utxo(
        &self,
        wallet: &Wallet,
        funding_id: &str,
        public_key: &PublicKey,
        amount: u64,
        from: Option<&str>,
    ) -> Result<PartialUtxo> {
        let txid = wallet.fund_address(
            WALLET_NAME,
            from.unwrap_or(funding_id),
            *public_key,
            &vec![amount],
            FEE,
            false,
            true,
            None,
        )?;
        wallet.mine(1)?;

        let script_pubkey = ScriptBuf::new_p2wpkh(&public_key.wpubkey_hash().unwrap());

        let output_type = OutputType::SegwitPublicKey {
            value: Amount::from_sat(amount),
            script_pubkey,
            public_key: *public_key,
        };

        Ok((txid, 0, Some(amount), Some(output_type)))
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
