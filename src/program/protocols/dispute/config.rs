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
pub struct TestFailConfiguration {
    pub fail_prover: Option<FailConfiguration>,
    pub fail_verifier: Option<FailConfiguration>,
    pub force: ForceChallenge,
    pub force_condition: ForceCondition,
}
impl Default for TestFailConfiguration {
    fn default() -> Self {
        Self {
            fail_prover: None,
            fail_verifier: None,
            force: ForceChallenge::No,
            force_condition: ForceCondition::No,
        }
    }
}

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
    pub fail_configuration: Option<TestFailConfiguration>,
}

impl DisputeConfiguration {
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
        fail_configuration: Option<TestFailConfiguration>,
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
            fail_configuration,
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
