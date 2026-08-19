//! Shared with `rust-bitvmx-client-types` — this file is copied verbatim on release.
//! Node-only code does not belong here; put it in the sibling `mod.rs`.

use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::{participant::ParticipantRole, variables::VariableTypes},
    types::IncomingBitVMXApiMessages,
};

use super::types::{
    AdvanceFundsRegistered, AdvanceFundsRequest, Committee, DisputeCoreData, FullPenalizationData,
    FundsAdvanceSPV, FundsAdvanced, InitData, PegInRequest, PegOutAccepted, PegOutRequest,
    PenalizedMember, RejectPeginData, UnionSPVNotification, ADVANCE_FUNDS_REQUEST, COMMITTEE,
    DISPUTE_CORE_DATA, FULL_PENALIZATION_DATA, FUNDS_ADVANCED, FUNDS_ADVANCE_SPV, INIT_DATA,
    PEGIN_REQUEST, PEGOUT_ACCEPTED, PEGOUT_REQUEST, REJECT_PEGIN_DATA, UNION_SPV_NOTIFICATION,
};

/// Transport for union messages carried over `IncomingBitVMXApiMessages::SetVar`/`GetVar`.
/// `KEY` must always name an existing `pub const` from `union::types` — never a re-typed literal.
pub trait UnionMessage: Serialize + DeserializeOwned + Sized {
    const KEY: &'static str;

    fn to_set_var(&self, id: Uuid) -> Result<IncomingBitVMXApiMessages, BitVMXError> {
        Ok(IncomingBitVMXApiMessages::SetVar(
            id,
            Self::KEY.to_string(),
            VariableTypes::String(serde_json::to_string(self)?),
        ))
    }

    fn get_var_msg(id: Uuid) -> IncomingBitVMXApiMessages {
        IncomingBitVMXApiMessages::GetVar(id, Self::KEY.to_string())
    }

    fn from_var(value: &VariableTypes) -> Result<Self, BitVMXError> {
        match value {
            VariableTypes::String(json) => Ok(serde_json::from_str(json)?),
            other => Err(BitVMXError::InvalidVariableType(format!("{:?}", other))),
        }
    }
}

impl UnionMessage for Committee {
    const KEY: &'static str = COMMITTEE;
}

impl UnionMessage for DisputeCoreData {
    const KEY: &'static str = DISPUTE_CORE_DATA;
}

impl UnionMessage for InitData {
    const KEY: &'static str = INIT_DATA;
}

impl UnionMessage for PegInRequest {
    const KEY: &'static str = PEGIN_REQUEST;
}

impl UnionMessage for RejectPeginData {
    const KEY: &'static str = REJECT_PEGIN_DATA;
}

impl UnionMessage for PegOutRequest {
    const KEY: &'static str = PEGOUT_REQUEST;
}

impl UnionMessage for PegOutAccepted {
    const KEY: &'static str = PEGOUT_ACCEPTED;
}

impl UnionMessage for AdvanceFundsRequest {
    const KEY: &'static str = ADVANCE_FUNDS_REQUEST;
}

impl UnionMessage for FundsAdvanced {
    const KEY: &'static str = FUNDS_ADVANCED;
}

impl UnionMessage for FundsAdvanceSPV {
    const KEY: &'static str = FUNDS_ADVANCE_SPV;
}

impl UnionMessage for UnionSPVNotification {
    const KEY: &'static str = UNION_SPV_NOTIFICATION;
}

impl UnionMessage for FullPenalizationData {
    const KEY: &'static str = FULL_PENALIZATION_DATA;
}

impl AdvanceFundsRegistered {
    pub fn key(slot_index: usize) -> String {
        Self::name(slot_index)
    }
}

impl PenalizedMember {
    pub fn key(index: usize, role: &ParticipantRole) -> String {
        Self::name(index, role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_via_set_var() {
        let committee_id = Uuid::new_v4();
        let msg = FullPenalizationData { committee_id };

        let set_var = msg.to_set_var(Uuid::nil()).unwrap();
        let payload = match set_var {
            IncomingBitVMXApiMessages::SetVar(id, key, value) => {
                assert_eq!(id, Uuid::nil());
                assert_eq!(key, FullPenalizationData::KEY);
                value
            }
            other => panic!("unexpected variant: {:?}", other),
        };

        let round_tripped = FullPenalizationData::from_var(&payload).unwrap();
        assert_eq!(round_tripped.committee_id, committee_id);
    }
}
