use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
/// AggregatedKeyProtocol - Simple protocol for generating an aggregated MuSig2 key
///
/// This protocol is used when multiple parties want to create a single
/// aggregated public key using MuSig2. Unlike full BitVMX protocols, this doesn't create
/// any Bitcoin transactions - it only orchestrates the key exchange.
///
/// # Use Case
///
/// - Multiple operators want to create a shared aggregated key
/// - No on-chain transactions needed
/// - Just key exchange and aggregation
/// - Result is stored in globals for later use
use bitcoin::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    errors::BitVMXError,
    program::{
        participant::{ParticipantKeyDeclaration, ParticipantKeys},
        protocols::protocol_handler::{ProtocolContext, ProtocolHandler},
        setup::steps::SetupStepName,
        variables::VariableTypes,
    },
    types::{OutgoingBitVMXApiMessages, ProgramContext},
};

/// AggregatedKeyProtocol - Manages aggregated key generation
#[derive(Clone, Serialize, Deserialize)]
pub struct AggregatedKeyProtocol {
    ctx: ProtocolContext,
}

impl AggregatedKeyProtocol {
    /// Creates a new AggregatedKeyProtocol instance
    pub fn new(ctx: ProtocolContext) -> Self {
        Self { ctx }
    }
}

impl ProtocolHandler for AggregatedKeyProtocol {
    fn context(&self) -> &ProtocolContext {
        &self.ctx
    }

    fn context_mut(&mut self) -> &mut ProtocolContext {
        &mut self.ctx
    }

    fn generate_keys<BC: BitcoinCoordinatorApi>(
        &self,
        program_context: &mut ProgramContext<BC>,
    ) -> Result<ParticipantKeyDeclaration, BitVMXError> {
        let optional_keys = program_context
            .globals
            .get_var_or_err(&self.ctx.id, "optional_keys")?
            .string()?;
        let optional_keys: Option<Vec<PublicKey>> =
            serde_json::from_str(&optional_keys).map_err(|_| BitVMXError::InvalidMessageFormat)?;

        let key = if let Some(keys) = optional_keys {
            keys.get(self.ctx.my_idx).copied().ok_or_else(|| {
                BitVMXError::InvalidMessage(format!(
                    "Optional key not found for participant index {} ({} keys provided)",
                    self.ctx.my_idx,
                    keys.len()
                ))
            })?
        } else {
            // Generate a single key for aggregation
            let key = program_context
                .key_manager
                .next_keypair(key_manager::key_type::BitcoinKeyType::P2tr)?;
            key
        };

        // Return participant keys with a single aggregated key named after the protocol ID
        let aggregated_name = self.ctx.id.to_string();
        ParticipantKeyDeclaration::new(
            vec![(aggregated_name.clone(), key.into())],
            vec![aggregated_name],
        )
    }

    fn build<BC: BitcoinCoordinatorApi>(
        &self,
        _keys: Vec<ParticipantKeys>,
        computed_aggregated: HashMap<String, PublicKey>,
        context: &ProgramContext<BC>,
    ) -> Result<(), BitVMXError> {
        tracing::info!(
            "AggregatedKeyProtocol::build() called for program {}",
            self.ctx.id,
        );

        let key_name = self.ctx.id.to_string();

        // Use the pre-computed aggregated key from KeysStep
        // Note: With a single participant, the "aggregated" key is just that participant's key
        let aggregated_key = computed_aggregated.get(&key_name).ok_or_else(|| {
            BitVMXError::InvalidMessage(format!(
                "Pre-computed aggregated key '{}' not found",
                key_name
            ))
        })?;

        // Store the aggregated key in globals for easy retrieval
        context.globals.set_var(
            &self.ctx.id,
            "final_aggregated_key",
            VariableTypes::PubKey(*aggregated_key),
        )?;

        tracing::info!(
            "AggregatedKeyProtocol: Stored final aggregated key: {} (program_id: {})",
            aggregated_key,
            self.ctx.id
        );

        context.broker_channel.send(
            &context.components_config.l2,
            OutgoingBitVMXApiMessages::AggregatedPubkey(self.ctx.id, *aggregated_key)
                .to_string()?,
        )?;

        Ok(())
    }

    // AggregatedKeyProtocol is used internally by SetupKey, which only expects
    // the AggregatedPubkey response. Suppress SetupCompleted to maintain backward compatibility.
    fn send_setup_completed(&self) -> bool {
        false
    }

    // Override setup_steps to only use KeysStep
    // No Nonces or Signatures needed - we're only generating a key, not signing
    fn setup_steps(&self) -> Option<Vec<SetupStepName>> {
        Some(vec![SetupStepName::Keys])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::str::FromStr;
    use uuid::Uuid;

    use crate::program::participant::ParticipantKeys;
    use crate::test_utils::{TestProgramContextEnv, TestStorageDir};
    use crate::types::PROGRAM_TYPE_AGGREGATED_KEY;

    fn public_key(value: &str) -> PublicKey {
        PublicKey::from_str(value).unwrap()
    }

    fn protocol(id: Uuid, my_idx: usize, dir: &TestStorageDir) -> AggregatedKeyProtocol {
        AggregatedKeyProtocol::new(ProtocolContext::new(
            id,
            PROGRAM_TYPE_AGGREGATED_KEY,
            my_idx,
            dir.storage(),
        ))
    }

    #[test]
    fn selects_the_optional_key_for_this_participant() {
        let mut env = TestProgramContextEnv::new("aggregated-key-optional").unwrap();
        let dir = TestStorageDir::new("aggregated-key-optional-protocol");
        let id = Uuid::new_v4();
        let protocol = protocol(id, 1, &dir);
        let keys = vec![
            public_key("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            public_key("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
        ];
        env.context
            .globals
            .set_var(
                &id,
                "optional_keys",
                VariableTypes::String(serde_json::to_string(&Some(keys.clone())).unwrap()),
            )
            .unwrap();

        let declaration = protocol.generate_keys(&mut env.context).unwrap();
        let participant_keys = ParticipantKeys::from(declaration.clone());

        assert_eq!(
            *participant_keys.get_public(&id.to_string()).unwrap(),
            keys[1]
        );
        assert_eq!(declaration.aggregated, HashSet::from([id.to_string()]));
        assert!(!protocol.send_setup_completed());
        assert_eq!(protocol.setup_steps(), Some(vec![SetupStepName::Keys]));
    }

    #[test]
    fn rejects_missing_optional_key_for_participant_index() {
        let mut env = TestProgramContextEnv::new("aggregated-key-missing-optional").unwrap();
        let dir = TestStorageDir::new("aggregated-key-missing-optional-protocol");
        let id = Uuid::new_v4();
        let protocol = protocol(id, 1, &dir);
        let keys = vec![public_key(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )];
        env.context
            .globals
            .set_var(
                &id,
                "optional_keys",
                VariableTypes::String(serde_json::to_string(&Some(keys)).unwrap()),
            )
            .unwrap();

        let error = protocol.generate_keys(&mut env.context).unwrap_err();

        assert!(matches!(
            error,
            BitVMXError::InvalidMessage(message)
                if message == "Optional key not found for participant index 1 (1 keys provided)"
        ));
    }

    #[test]
    fn build_requires_the_precomputed_aggregated_key() {
        let env = TestProgramContextEnv::new("aggregated-key-missing-computed").unwrap();
        let dir = TestStorageDir::new("aggregated-key-missing-computed-protocol");
        let id = Uuid::new_v4();
        let protocol = protocol(id, 0, &dir);

        let error = protocol
            .build(vec![], HashMap::new(), &env.context)
            .unwrap_err();

        assert!(matches!(
            error,
            BitVMXError::InvalidMessage(message)
                if message == format!("Pre-computed aggregated key '{}' not found", id)
        ));
        assert!(!env
            .context
            .globals
            .contains_var(&id, "final_aggregated_key")
            .unwrap());
    }

    #[test]
    fn build_stores_and_publishes_the_aggregated_key() {
        let mut env = TestProgramContextEnv::new("aggregated-key-build").unwrap();
        let dir = TestStorageDir::new("aggregated-key-build-protocol");
        let id = Uuid::new_v4();
        let protocol = protocol(id, 0, &dir);
        let aggregated_key =
            public_key("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        let computed = HashMap::from([(id.to_string(), aggregated_key)]);
        // Route the response back to the test channel so its payload can be asserted.
        env.context.components_config.l2 = env.context.components_config.bitvmx.clone();

        protocol.build(vec![], computed, &env.context).unwrap();

        assert_eq!(
            env.context
                .globals
                .get_var_or_err(&id, "final_aggregated_key")
                .unwrap()
                .pubkey()
                .unwrap(),
            aggregated_key
        );
        let (message, sender) = env.context.broker_channel.recv().unwrap().unwrap();
        assert_eq!(sender, env.context.components_config.bitvmx);
        assert!(matches!(
            OutgoingBitVMXApiMessages::from_string(&message).unwrap(),
            OutgoingBitVMXApiMessages::AggregatedPubkey(message_id, key)
                if message_id == id && key == aggregated_key
        ));
    }
}
