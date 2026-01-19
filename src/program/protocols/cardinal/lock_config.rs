use bitcoin::{PublicKey, Txid};
use protocol_builder::scripts::{self, SignMode};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        protocols::{cardinal::EOL_TIMELOCK_DURATION, protocol_handler::external_fund_tx},
        variables::{Globals, PartialUtxo, VariableTypes},
    },
    types::{IncomingBitVMXApiMessages, ParticipantChannel, PROGRAM_TYPE_LOCK},
};

pub struct LockProtocolConfiguration {
    pub id: Uuid,
    pub operators_aggregated_pub: PublicKey,
    pub operators_aggregated_pub_happy_path: PublicKey,
    pub unspendable: PublicKey,
    pub user_pubkey: PublicKey,
    pub secret: Vec<u8>,
    pub ordinal_utxo: PartialUtxo,
    pub protocol_utxo: PartialUtxo,
    pub timelock_blocks: u16,       //lock request timelock in blocks
    pub eol_timelock_duration: u16, //end of life timelock duration in blocks
}

impl LockProtocolConfiguration {
    pub fn new(
        program_id: Uuid,
        operators_aggregated_pub: PublicKey,
        operators_aggregated_pub_happy_path: PublicKey,
        unspendable: PublicKey,
        user_pubkey: PublicKey,
        secret: Vec<u8>,
        ordinal_utxo: PartialUtxo,
        protocol_utxo: PartialUtxo,
        timelock_blocks: u16,
        eol_timelock_duration: u16,
    ) -> Self {
        Self {
            id: program_id,
            operators_aggregated_pub,
            operators_aggregated_pub_happy_path,
            unspendable,
            user_pubkey,
            secret,
            ordinal_utxo,
            protocol_utxo,
            timelock_blocks,
            eol_timelock_duration,
        }
    }

    pub fn new_from_globals(id: Uuid, globals: &Globals) -> Result<Self, BitVMXError> {
        let get = |key: &str| {
            globals
                .get_var(&id, key)?
                .ok_or(BitVMXError::VariableNotFound(id, key.to_string()))
        };

        let operators_aggregated_pub = get("operators_aggregated_pub")?.pubkey()?;
        let ops_agg_happy_path = get("operators_aggregated_happy_path")?.pubkey()?;
        let unspendable = get("unspendable")?.pubkey()?;
        let user_pubkey = get("user_pubkey")?.pubkey()?;
        let secret = get("secret")?.secret()?;
        let ordinal_utxo = get("ordinal_utxo")?.utxo()?;
        let protocol_utxo = get("protocol_utxo")?.utxo()?;
        let timelock_blocks = get("timelock_blocks")?.number()? as u16;
        let eol_timelock_duration = get(EOL_TIMELOCK_DURATION)?.number()? as u16;

        Ok(Self::new(
            id,
            operators_aggregated_pub,
            ops_agg_happy_path,
            unspendable,
            user_pubkey,
            secret,
            ordinal_utxo,
            protocol_utxo,
            timelock_blocks,
            eol_timelock_duration,
        ))
    }

    pub fn get_setup_messages(
        &self,
        addresses: Vec<crate::program::participant::CommsAddress>,
        leader: u16,
    ) -> Result<Vec<String>, BitVMXError> {
        Ok(vec![
            VariableTypes::PubKey(self.operators_aggregated_pub.clone())
                .set_msg(self.id, "operators_aggregated_pub")?,
            VariableTypes::PubKey(self.operators_aggregated_pub_happy_path.clone())
                .set_msg(self.id, "operators_aggregated_happy_path")?,
            VariableTypes::PubKey(self.unspendable.clone()).set_msg(self.id, "unspendable")?,
            VariableTypes::PubKey(self.user_pubkey.clone()).set_msg(self.id, "user_pubkey")?,
            VariableTypes::Secret(self.secret.clone()).set_msg(self.id, "secret")?,
            VariableTypes::Utxo(self.ordinal_utxo.clone()).set_msg(self.id, "ordinal_utxo")?,
            VariableTypes::Utxo(self.protocol_utxo.clone()).set_msg(self.id, "protocol_utxo")?,
            VariableTypes::Number(self.timelock_blocks as u32)
                .set_msg(self.id, "timelock_blocks")?,
            VariableTypes::Number(self.eol_timelock_duration as u32)
                .set_msg(self.id, EOL_TIMELOCK_DURATION)?,
            IncomingBitVMXApiMessages::Setup(
                self.id,
                PROGRAM_TYPE_LOCK.to_string(),
                addresses,
                leader,
            )
            .to_string()?,
        ])
    }

    pub fn setup(
        &self,
        id_channel_pairs: &Vec<ParticipantChannel>,
        addresses: Vec<crate::program::participant::CommsAddress>,
        leader: u16,
    ) -> Result<(), BitVMXError> {
        for id_channel_pair in id_channel_pairs {
            for msg in self.get_setup_messages(addresses.clone(), leader)? {
                id_channel_pair.channel.send(&id_channel_pair.id, msg)?;
            }
        }
        Ok(())
    }

    pub fn get_asset_utxo(&self, txid: &Txid) -> Result<PartialUtxo, BitVMXError> {
        let taproot_script_eol_timelock_expired_tx_lock = scripts::timelock(
            self.eol_timelock_duration,
            &bitcoin::PublicKey::from(self.user_pubkey),
            SignMode::Skip,
        );

        //this should be another aggregated to be signed later
        let taproot_script_all_sign_tx_lock = scripts::check_aggregated_signature(
            &self.operators_aggregated_pub,
            SignMode::Aggregate,
        );

        let asset_spending_condition = vec![
            taproot_script_eol_timelock_expired_tx_lock.clone(),
            taproot_script_all_sign_tx_lock.clone(),
        ];

        let asset_value = self.ordinal_utxo.2.unwrap();
        let asset_output_type = external_fund_tx(
            &self.operators_aggregated_pub,
            asset_spending_condition,
            asset_value,
        )?;

        Ok((txid.clone(), 0, Some(asset_value), Some(asset_output_type)))
    }
}
