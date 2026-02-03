use bitcoin::PublicKey;
use emulator::{
    decision::challenge::{ForceChallenge, ForceCondition},
    executor::utils::FailConfiguration,
};
use protocol_builder::types::OutputType;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::variables::{Globals, PartialUtxo, VariableTypes},
    types::{IncomingBitVMXApiMessages, PROGRAM_TYPE_DRP},
};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DisputeConfiguration {
    pub id: Uuid,
    pub operators_aggregated_pub: PublicKey,
    pub protocol_connection: (PartialUtxo, Vec<usize>),
    pub prover_actions: Vec<(PartialUtxo, Vec<usize>)>,
    pub prover_enablers: Vec<OutputType>,
    pub verifier_actions: Vec<(PartialUtxo, Vec<usize>)>,
    pub verifier_enablers: Vec<OutputType>,
    pub timelock_blocks: u16,
    pub program_definition: String,
    pub fail_force_config: Option<ForceFailConfiguration>,
    pub notify_protocol: Vec<(String, Uuid)>,
    pub auto_dispatch_input: Option<u8>,
}

impl DisputeConfiguration {
    pub const NAME: &'static str = "dispute_configuration";

    pub fn new(
        id: Uuid,
        operators_aggregated_pub: PublicKey,
        protocol_connection: (PartialUtxo, Vec<usize>),
        prover_actions: Vec<(PartialUtxo, Vec<usize>)>,
        prover_enablers: Vec<OutputType>,
        verifier_actions: Vec<(PartialUtxo, Vec<usize>)>,
        verifier_enablers: Vec<OutputType>,
        timelock_blocks: u16,
        program_definition: String,
        fail_force_config: Option<ForceFailConfiguration>,
        notify_protocol: Vec<(String, Uuid)>,
        auto_dispatch_input: Option<u8>,
    ) -> Self {
        Self {
            id,
            operators_aggregated_pub,
            protocol_connection,
            prover_actions,
            prover_enablers,
            verifier_actions,
            verifier_enablers,
            timelock_blocks,
            program_definition,
            fail_force_config,
            notify_protocol,
            auto_dispatch_input,
        }
    }

    // The structure is serialized as a whole. If there is a performance hit it could be serialized in parts.
    pub fn load(id: &Uuid, globals: &Globals) -> Result<Self, BitVMXError> {
        let dispute_configuration = globals.get_var_or_err(id, Self::NAME)?.string()?;
        Ok(serde_json::from_str(&dispute_configuration)?)
    }

    pub fn get_setup_messages(
        &self,
        addresses: Vec<crate::program::participant::CommsAddress>,
        leader: u16,
    ) -> Result<Vec<String>, BitVMXError> {
        Ok(vec![
            VariableTypes::String(serde_json::to_string(&self)?).set_msg(self.id, Self::NAME)?,
            IncomingBitVMXApiMessages::Setup(
                self.id,
                PROGRAM_TYPE_DRP.to_string(),
                addresses,
                leader,
            )
            .to_string()?,
        ])
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ConfigResult {
    pub fail_config_prover: Option<FailConfiguration>,
    pub fail_config_verifier: Option<FailConfiguration>,
    pub force_challenge: ForceChallenge,
    pub force_condition: ForceCondition,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ForceFailConfiguration {
    pub prover_force_second_nary: bool,
    pub fail_input_tx: Option<String>,
    pub main: ConfigResult,
    pub read: ConfigResult, // for read challenge (2nd n-ary search)
}

impl Default for ConfigResult {
    fn default() -> Self {
        Self {
            fail_config_prover: None,
            fail_config_verifier: None,
            force_challenge: ForceChallenge::No,
            force_condition: ForceCondition::No,
        }
    }
}

impl Default for ForceFailConfiguration {
    fn default() -> Self {
        Self {
            prover_force_second_nary: false,
            fail_input_tx: None,
            main: ConfigResult::default(),
            read: ConfigResult::default(),
        }
    }
}
