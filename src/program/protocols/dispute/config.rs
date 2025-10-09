use bitcoin::PublicKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    errors::BitVMXError,
    program::variables::{Globals, PartialUtxo, VariableTypes},
    types::{IncomingBitVMXApiMessages, PROGRAM_TYPE_DRP},
};
use emulator::decision::challenge::ForceChallenge;
use emulator::decision::challenge::ForceCondition;
use emulator::executor::utils::FailConfiguration;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DisputeConfiguration {
    pub id: Uuid,
    pub operators_aggregated_pub: PublicKey,
    pub protocol_connection: (PartialUtxo, Vec<usize>),
    pub prover_actions: Vec<(PartialUtxo, Vec<usize>)>,
    pub verifier_actions: Vec<(PartialUtxo, Vec<usize>)>,
    pub timelock_blocks: u16,
    pub program_definition: String,
    pub fail_force_config: Option<ConfigResults>,
}

impl DisputeConfiguration {
    pub fn new(
        id: Uuid,
        operators_aggregated_pub: PublicKey,
        protocol_connection: (PartialUtxo, Vec<usize>),
        prover_actions: Vec<(PartialUtxo, Vec<usize>)>,
        verifier_actions: Vec<(PartialUtxo, Vec<usize>)>,
        timelock_blocks: u16,
        program_definition: String,
        fail_force_config: Option<ConfigResults>,
    ) -> Self {
        Self {
            id,
            operators_aggregated_pub,
            protocol_connection,
            prover_actions,
            verifier_actions,
            timelock_blocks,
            program_definition,
            fail_force_config,
        }
    }

    // The structure is serialized as a whole. If there is a performance hit it could be serialized in parts.
    pub fn load(id: &Uuid, globals: &Globals) -> Result<Self, BitVMXError> {
        let dispute_configuration = globals
            .get_var(id, "dispute_configuration")?
            .unwrap()
            .string()?;

        Ok(serde_json::from_str(&dispute_configuration)?)
    }

    pub fn get_setup_messages(
        &self,
        addresses: Vec<crate::program::participant::CommsAddress>,
        leader: u16,
    ) -> Result<Vec<String>, BitVMXError> {
        Ok(vec![
            VariableTypes::String(serde_json::to_string(&self)?)
                .set_msg(self.id, "dispute_configuration")?,
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
pub struct ConfigResults {
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

impl Default for ConfigResults {
    fn default() -> Self {
        Self {
            main: ConfigResult::default(),
            read: ConfigResult::default(),
        }
    }
}
