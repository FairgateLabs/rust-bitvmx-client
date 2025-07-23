use anyhow::Result;
use bitcoin::Txid;
use bitvmx_client::program::{participant::ParticipantRole, variables::PartialUtxo};

use bitcoin::{Amount, PublicKey, ScriptBuf};
use bitvmx_wallet::wallet::Wallet;
use protocol_builder::types::OutputType;
use std::collections::HashMap;
use std::thread::{self};
use std::time::Duration;
use tracing::info_span;
use uuid::Uuid;

use crate::bitcoin::{init_wallet, FEE, WALLET_NAME};
use crate::participants::member::Member;

pub struct Committee {
    members: Vec<Member>,
    take_aggregation_id: Uuid,
    dispute_aggregation_id: Uuid,
    committee_id: Uuid,
    wallet: Wallet,
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

        Ok(Self {
            members,
            take_aggregation_id: Uuid::new_v4(),
            dispute_aggregation_id: Uuid::new_v4(),
            committee_id: Uuid::new_v4(),
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

        self.all(|op| {
            op.setup_committee_keys(
                &members,
                &members_take_pubkeys,
                &members_dispute_pubkeys,
                take_aggregation_id,
                dispute_aggregation_id,
            )
        })?;

        let seed = self.committee_id;

        let mut funding_utxos_per_member: HashMap<PublicKey, Vec<PartialUtxo>> = HashMap::new();
        for member in &self.members {
            let funding_utxos = self.get_funding_utxos(member)?;
            funding_utxos_per_member.insert(member.keyring.take_pubkey.unwrap(), funding_utxos);
        }

        // setup covenants
        self.all(|op| op.setup_covenants(seed, &members, &funding_utxos_per_member))?;

        Ok(self.public_key()?)
    }

    pub fn accept_pegin(
        &mut self,
        committee_id: Uuid,
        request_pegin_txid: Txid,
        amount: u64,
        accept_pegin_sighash: Vec<u8>,
        slot_index: u32,
    ) -> Result<()> {
        let accept_pegin_covenant_id = Uuid::new_v4();
        let members = self.members.clone();

        self.all(|op| {
            op.accept_pegin(
                accept_pegin_covenant_id,
                &members,
                request_pegin_txid,
                amount,
                accept_pegin_sighash.as_slice(),
                committee_id,
                slot_index,
            )
        })?;

        Ok(())
    }

    pub fn request_pegout(&mut self, user_pubkey: PublicKey, slot_id: u32, fee: u64) -> Result<()> {
        let members = self.members.clone();
        let committee_id = self.committee_id.clone();
        let protocol_id = Uuid::new_v4();

        self.all(|op| {
            op.request_pegout(
                protocol_id,
                committee_id,
                user_pubkey,
                slot_id,
                fee,
                &members,
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

    fn get_funding_utxos(&self, member: &Member) -> Result<Vec<PartialUtxo>> {
        let count = match member.role {
            ParticipantRole::Prover => 2,
            ParticipantRole::Verifier => 1,
        };

        let utxos = (0..count)
            .map(|_| {
                self.prepare_funding_utxo(
                    &self.wallet,
                    "fund_1",
                    &member.keyring.dispute_pubkey.unwrap(),
                    10_000_000,
                    None,
                )
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(utxos)
    }

    fn prepare_funding_utxo(
        &self,
        wallet: &Wallet,
        funding_id: &str,
        public_key: &PublicKey,
        amount: u64,
        from: Option<&str>,
    ) -> Result<PartialUtxo> {
        // info!("Funding address: {:?} with: {}", public_key, amount);
        // info!("Funding address: {:?} with: {}", public_key, amount);
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
