use std::rc::Rc;

use bitcoin::PublicKey;
use protocol_builder::{
    builder::Protocol,
    scripts::{self, SignMode},
    types::OutputType,
};
use storage_backend::storage::Storage;
use tracing::info;
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{
        protocols::{
            cardinal::{
                slot, transfer::pub_too_group, LOCKED_ASSET_UTXO, OPERATORS_AGGREGATED_PUB,
                OPERATOR_COUNT, UNSPENDABLE,
            },
            claim::ClaimGate,
            protocol_handler::external_fund_tx,
        },
        variables::{Globals, PartialUtxo, VariableTypes},
    },
    types::{
        IncomingBitVMXApiMessages, ParticipantChannel, PROGRAM_TYPE_SLOT, PROGRAM_TYPE_TRANSFER,
    },
};

pub struct TransferConfig {
    pub id: Uuid,
    pub unspendable: PublicKey,
    pub aggregated_pub: PublicKey,
    pub operator_count: u32,
    pub too_groups: u32,
    pub locked_asset_utxo: PartialUtxo,
    pub groups_pub_keys: Vec<PublicKey>,
    pub sample_utxos: Option<(PartialUtxo, PartialUtxo)>,
    pub slot_id: Option<Uuid>,
}

impl TransferConfig {
    pub fn new(
        id: Uuid,
        unspendable: PublicKey,
        aggregated_pub: PublicKey,
        operator_count: u32,
        locked_asset_utxo: PartialUtxo,
        groups_pub_keys: Vec<PublicKey>,
        sample_utxos: Option<(PartialUtxo, PartialUtxo)>,
        slot_id: Option<Uuid>,
    ) -> Self {
        let too_groups = 2_u32.pow(operator_count) - 1;
        assert_ne!(
            sample_utxos.is_some(),
            slot_id.is_some(),
            "Either sample_utxos or slot_id must be provided, not both"
        );
        Self {
            id,
            unspendable,
            aggregated_pub,
            operator_count,
            too_groups,
            locked_asset_utxo,
            groups_pub_keys,
            sample_utxos,
            slot_id,
        }
    }

    pub fn new_from_globals(id: Uuid, globals: &Globals) -> Result<Self, BitVMXError> {
        let unspendable = globals.get_var(&id, UNSPENDABLE)?.unwrap().pubkey()?;
        let aggregated_pub = globals
            .get_var(&id, OPERATORS_AGGREGATED_PUB)?
            .unwrap()
            .pubkey()?;
        let operator_count = globals.get_var(&id, OPERATOR_COUNT)?.unwrap().number()? as u32;
        let locked_asset_utxo = globals.get_var(&id, LOCKED_ASSET_UTXO)?.unwrap().utxo()?;

        let too_groups = 2_u32.pow(operator_count as u32) - 1;
        let groups_pub_keys: Vec<PublicKey> = (1..=too_groups)
            .map(|gid| globals.get_var(&id, &pub_too_group(gid))?.unwrap().pubkey())
            .collect::<Result<Vec<_>, _>>()?;

        let op_won = globals.get_var(&id, "op_won")?;
        let op_gid = globals.get_var(&id, "op_gid")?;
        let sample_utxos = if op_won.is_some() && op_gid.is_some() {
            Some((op_won.unwrap().utxo()?, op_gid.unwrap().utxo()?))
        } else {
            None
        };

        let slot_id = globals
            .get_var(&id, "slot_program_id")?
            .and_then(|v| Some(v.uuid().unwrap()));

        Ok(Self {
            id,
            unspendable,
            aggregated_pub,
            operator_count,
            too_groups,
            locked_asset_utxo,
            groups_pub_keys,
            sample_utxos,
            slot_id,
        })
    }

    pub fn get_setup_messages(
        &self,
        addresses: Vec<crate::program::participant::CommsAddress>,
        leader: u16,
    ) -> Result<Vec<String>, BitVMXError> {
        let mut config_vec = vec![
            VariableTypes::PubKey(self.unspendable.clone()).set_msg(self.id, UNSPENDABLE)?,
            VariableTypes::PubKey(self.aggregated_pub.clone())
                .set_msg(self.id, OPERATORS_AGGREGATED_PUB)?,
            VariableTypes::Number(self.operator_count).set_msg(self.id, OPERATOR_COUNT)?,
            VariableTypes::Utxo(self.locked_asset_utxo.clone())
                .set_msg(self.id, LOCKED_ASSET_UTXO)?,
        ];

        for gid in 1..=self.too_groups {
            config_vec.push(
                VariableTypes::PubKey(self.groups_pub_keys[gid as usize - 1].clone())
                    .set_msg(self.id, &pub_too_group(gid))?,
            );
        }
        if let Some((utxo_0, utxo_1)) = &self.sample_utxos {
            config_vec.push(VariableTypes::Utxo(utxo_0.clone()).set_msg(self.id, "op_won")?);
            config_vec.push(VariableTypes::Utxo(utxo_1.clone()).set_msg(self.id, "op_gid")?);
        }
        if let Some(slot_id) = self.slot_id {
            config_vec.push(VariableTypes::Uuid(slot_id).set_msg(self.id, "slot_program_id")?);
        }

        config_vec.push(
            IncomingBitVMXApiMessages::SetupV2(
                self.id,
                PROGRAM_TYPE_TRANSFER.to_string(),
                addresses,
                leader,
            )
            .to_string()?,
        );

        Ok(config_vec)
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

    pub fn get_utxos(
        &self,
        storage: Rc<Storage>,
    ) -> Result<Vec<(Vec<PartialUtxo>, PartialUtxo)>, BitVMXError> {
        let dust = OutputType::generic_dust_limit(None).to_sat();
        let mut operator_txs = Vec::new();
        if let Some((utxo_0, utxo_1)) = &self.sample_utxos {
            for _op in 0..self.operator_count {
                let gidtxs: Vec<PartialUtxo> =
                    (1..=self.too_groups).map(|_gid| utxo_1.clone()).collect();

                operator_txs.push((gidtxs, utxo_0.clone()));
            }
        } else {
            let slot_uuid = self.slot_id.unwrap();

            let protocol_name = format!("{}_{}", PROGRAM_TYPE_SLOT, slot_uuid);
            let protocol = Protocol::load(&protocol_name, storage)?.unwrap();
            info!("Slot program: {}", protocol_name);

            for op in 0..self.operator_count {
                //  let gidtxs: Vec<PartialUtxo> = (1..=too_groups)
                // pub type PartialUtxo = (Txid, u32, Option<u64>, Option<OutputType>);
                let op_won_tx = protocol
                    .transaction_by_name(&ClaimGate::tx_success(&slot::claim_name(op as usize)))?;
                let tx_id = op_won_tx.compute_txid();

                let vout = 0;
                let verify_aggregated_action =
                    scripts::check_aggregated_signature(&self.aggregated_pub, SignMode::Aggregate);
                let output_action =
                    external_fund_tx(&self.aggregated_pub, vec![verify_aggregated_action], dust)?;

                let operator_won_tx = (tx_id, vout, Some(dust), Some(output_action));

                let mut gidtxs = vec![];

                for gid in 1..=self.too_groups {
                    let gittx =
                        protocol.transaction_by_name(&slot::group_id_tx(op as usize, gid as u8))?;
                    let tx_id = gittx.compute_txid();

                    let vout = 0;
                    let verify_aggregated_action = scripts::check_aggregated_signature(
                        &self.aggregated_pub,
                        SignMode::Aggregate,
                    );
                    let output_action = external_fund_tx(
                        &self.aggregated_pub,
                        vec![verify_aggregated_action],
                        dust,
                    )?;
                    gidtxs.push((tx_id, vout, Some(dust), Some(output_action)));
                }
                operator_txs.push((gidtxs, operator_won_tx));
            }
        }
        Ok(operator_txs)
    }
}
