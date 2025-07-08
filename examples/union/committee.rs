use anyhow::Result;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_client::{
    config::Config,
    program::{participant::ParticipantRole, variables::PartialUtxo},
};

use bitcoin::{hashes::Hash, Amount, Network, PublicKey, ScriptBuf};
use bitvmx_wallet::wallet::Wallet;
use protocol_builder::types::OutputType;
use std::thread::{self};
use std::time::Duration;
use tracing::{info, info_span};
use uuid::Uuid;

use crate::{
    bitcoin::{clear_db, FEE, FUNDING_ID, INITIAL_BLOCK_COUNT, WALLET_NAME},
    member::Member,
};

pub struct Committee {
    members: Vec<Member>,
    take_aggregation_id: Uuid,
    dispute_aggregation_id: Uuid,
    wallet: Wallet,
}

impl Committee {
    pub fn new() -> Result<Self> {
        let members = vec![
            Member::new("op_1", ParticipantRole::Prover)?,
            Member::new("op_2", ParticipantRole::Prover)?,
            Member::new("op_3", ParticipantRole::Prover)?,
            Member::new("op_4", ParticipantRole::Prover)?,
        ];

        let wallet = init_wallet()?;

        Ok(Self {
            members,
            take_aggregation_id: Uuid::new_v4(),
            dispute_aggregation_id: Uuid::new_v4(),
            wallet,
        })
    }

    pub fn setup(&mut self) -> Result<()> {
        // gather all operator addresses
        // in a real scenario, operators should get this from the chain
        self.all(|op| op.get_peer_info())?;

        // create members pubkeys
        let keys = self.all(|op| op.setup_member_keys())?;

        // collect members keys
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

        let mut op_funding_utxos: HashMap<String, PartialUtxo> = HashMap::new();
        let mut wt_funding_utxos: HashMap<String, PartialUtxo> = HashMap::new();

        for (index, member) in members.iter().enumerate() {
            if member.role == ParticipantRole::Prover {
                op_funding_utxos.insert(
                    member.id.clone(),
                    self.prepare_funding_utxo(
                        &self.bitcoin.wallet,
                        "fund_1", //&format!("op_{}_utxo", index),
                        //TODO we must use a different pub key here, same for the speedup funding
                        &member.keyring.dispute_pubkey.unwrap(),
                        10000000,
                        None,
                    )?,
                );
            }

            wt_funding_utxos.insert(
                member.id.clone(),
                self.prepare_funding_utxo(
                    &self.bitcoin.wallet,
                    "fund_1", //&format!("wt_{}_utxo", index),
                    //TODO we must use a different pub key here, same for the speedup funding
                    &member.keyring.dispute_pubkey.unwrap(),
                    10000000,
                    None,
                )?,
            );
        }

        // setup covenants
        for (member_index, member) in members.iter().enumerate() {
            info_span!("member", id = %member.id).in_scope(|| {
                info!("Setting up covenants for member {}", member.id);
            });

            let dispute_core_covenant_id = Uuid::new_v4();
            let funding_utxos = self.get_funding_utxos(member)?;

            self.all(|op| {
                op.setup_covenants(
                    dispute_core_covenant_id,
                    member_index,
                    &members,
                    &funding_utxos,
                )
            })?;
        }

        Ok(())
    }

    pub fn accept_pegin(&mut self) -> Result<()> {
        let accept_pegin_covenant_id = Uuid::new_v4();
        let members = self.members.clone();

        // TODO replace with actual peg-in request details
        let request_pegin_txid = Hash::all_zeros(); // This should be replaced with the actual Txid of the peg-in request
        let request_pegin_amount = 10000000; // This should be replaced with the actual amount of the peg-in request
        let accept_pegin_sighash = vec![0; 32]; // This should be replaced with the actual sighash of the accept peg-in tx

        self.all(|op| {
            op.accept_pegin(
                accept_pegin_covenant_id,
                &members,
                request_pegin_txid,
                request_pegin_amount,
                accept_pegin_sighash.as_slice(),
            )
        })?;

        Ok(())
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

fn init_wallet() -> Result<Wallet> {
    let config = Config::new(Some("config/op_1.yaml".to_string()))?;

    let wallet_config = match config.bitcoin.network {
        Network::Regtest => "config/wallet_regtest.yaml",
        Network::Testnet => "config/wallet_testnet.yaml",
        _ => panic!("Not supported network {}", config.bitcoin.network),
    };

    let wallet_config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::config::WalletConfig,
    >(Some(wallet_config.to_string()))?;
    if config.bitcoin.network == Network::Regtest {
        clear_db(&wallet_config.storage.path);
        clear_db(&wallet_config.key_storage.path);
    }

    let wallet = Wallet::new(wallet_config, true)?;
    wallet.mine(INITIAL_BLOCK_COUNT)?;

    wallet.create_wallet(WALLET_NAME)?;
    wallet.regtest_fund(WALLET_NAME, FUNDING_ID, 100_000_000)?;

    let _bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    Ok(wallet)
}
