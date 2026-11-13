pub mod garbler_step;
pub mod keys_step;
pub mod nonces_step;
pub mod signatures_step;

pub use garbler_step::GarblerStep;
pub use keys_step::KeysStep;
pub use nonces_step::NoncesStep;
pub use signatures_step::SignaturesStep;

pub type ContributionMessage<T> = Vec<(PublicKey, PublicKey, Vec<(MessageId, T)>)>;

type ParticipantContributions<T> = HashMap<PublicKey, HashMap<PublicKey, Vec<(MessageId, T)>>>;

fn validate_entries<T>(
    contributions: &ContributionMessage<T>,
    expected_aggregated_keys: &HashSet<PublicKey>,
    contribution_name: &str,
    entry_name: &str,
) -> Result<(), BitVMXError> {
    let mut received_aggregated_keys = HashSet::new();

    for (aggregated, _, entries) in contributions {
        if !expected_aggregated_keys.contains(aggregated) {
            return Err(BitVMXError::InvalidMessage(format!(
                "Received {} for unexpected aggregated key {}",
                contribution_name, aggregated
            )));
        }
        if !received_aggregated_keys.insert(*aggregated) {
            return Err(BitVMXError::InvalidMessage(format!(
                "Received duplicate {} for aggregated key {}",
                contribution_name, aggregated
            )));
        }
        if entries.is_empty() {
            return Err(BitVMXError::InvalidMessage(format!(
                "Received no message {} for aggregated key {}",
                contribution_name, aggregated
            )));
        }

        let mut message_ids = HashSet::new();
        if entries
            .iter()
            .any(|(message_id, _)| !message_ids.insert(message_id))
        {
            return Err(BitVMXError::InvalidMessage(format!(
                "Received duplicate {} message IDs for aggregated key {}",
                entry_name, aggregated
            )));
        }
    }

    Ok(())
}

fn collect_other_participants<T>(
    participants: &[CommsAddress],
    my_idx: usize,
    globals: &Globals,
    protocol_id: &Uuid,
    step_name: &str,
) -> Result<ParticipantContributions<T>, BitVMXError>
where
    T: DeserializeOwned,
{
    let mut contributions = HashMap::new();

    for (idx, _) in participants.iter().enumerate() {
        if idx == my_idx {
            continue;
        }

        let participant_data: ContributionMessage<T> = serde_json::from_str(
            &load_participant_data(globals, protocol_id, idx, step_name)?,
        )?;

        for (aggregated, participant_pub_key, entries) in participant_data {
            if contributions
                .entry(aggregated)
                .or_insert_with(HashMap::new)
                .insert(participant_pub_key, entries)
                .is_some()
            {
                return Err(BitVMXError::InvalidMessage(format!(
                    "Received duplicate {} from participant key {}",
                    step_name, participant_pub_key
                )));
            }
        }
    }

    Ok(contributions)
}

use bitcoin::PublicKey;
use enum_dispatch::enum_dispatch;
use key_manager::musig2::types::MessageId;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use super::{load_participant_data, SetupStep, MY_KEYS};
use crate::comms_helper::CommsMessageType;
use crate::errors::BitVMXError;
use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use crate::program::participant::{CommsAddress, ParticipantKeys};
use crate::program::protocols::protocol_handler::ProtocolType;
use crate::program::variables::Globals;
use crate::types::ProgramContext;
use crate::types::ResultDisposition;

/// Enum representing the available setup step types.
///
/// This provides type-safe step names and avoids magic strings throughout the codebase.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SetupStepName {
    Keys,
    Nonces,
    Signatures,
    Garbler,
}

/// Concrete enum that groups all `SetupStep` implementations.
///
/// This allows us to avoid heap allocations (`Box<dyn SetupStep>`) while
/// still using a unified type that implements the `SetupStep` trait.
#[enum_dispatch(SetupStep)]
#[derive(Debug, Clone)]
pub enum SetupStepEnum {
    Keys(KeysStep),
    Nonces(NoncesStep),
    Signatures(SignaturesStep),
    Garbler(GarblerStep),
}

/// Factory function to create a concrete `SetupStepEnum` from its name.
pub fn create_setup_step(name: &SetupStepName) -> SetupStepEnum {
    match name {
        SetupStepName::Keys => SetupStepEnum::Keys(KeysStep::new()),
        SetupStepName::Nonces => SetupStepEnum::Nonces(NoncesStep::new()),
        SetupStepName::Signatures => SetupStepEnum::Signatures(SignaturesStep::new()),
        SetupStepName::Garbler => SetupStepEnum::Garbler(GarblerStep::new()),
    }
}

fn load_my_keys<BC: BitcoinCoordinatorApi>(
    protocol_id: &Uuid,
    context: &ProgramContext<BC>,
) -> Result<Option<ParticipantKeys>, BitVMXError> {
    context
        .globals
        .get_var(protocol_id, MY_KEYS)?
        .map(|value| {
            let keys_json = value.string()?;
            Ok(serde_json::from_str(&keys_json)?)
        })
        .transpose()
}

fn require_my_keys<BC: BitcoinCoordinatorApi>(
    protocol_id: &Uuid,
    context: &ProgramContext<BC>,
    missing_message: &str,
) -> Result<ParticipantKeys, BitVMXError> {
    load_my_keys(protocol_id, context)?
        .ok_or_else(|| BitVMXError::InvalidMessage(missing_message.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{program::variables::VariableTypes, test_utils::TestStorageDir};
    use std::str::FromStr;

    fn public_keys() -> (PublicKey, PublicKey) {
        (
            PublicKey::from_str(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            )
            .unwrap(),
            PublicKey::from_str(
                "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            )
            .unwrap(),
        )
    }

    #[test]
    fn shared_validation_accepts_valid_entries_and_rejects_duplicates() {
        let (aggregated, participant) = public_keys();
        let valid = vec![(aggregated, participant, vec![("message".to_string(), 1_u8)])];
        let expected = HashSet::from([aggregated]);

        validate_entries(&valid, &expected, "nonces", "nonce").unwrap();

        let duplicate_aggregate = vec![valid[0].clone(), valid[0].clone()];
        assert!(matches!(
            validate_entries(&duplicate_aggregate, &expected, "nonces", "nonce"),
            Err(BitVMXError::InvalidMessage(message))
                if message == format!("Received duplicate nonces for aggregated key {aggregated}")
        ));

        let duplicate_message_ids = vec![(
            aggregated,
            participant,
            vec![("message".to_string(), 1_u8), ("message".to_string(), 2_u8)],
        )];
        assert!(matches!(
            validate_entries(&duplicate_message_ids, &expected, "nonces", "nonce"),
            Err(BitVMXError::InvalidMessage(message))
                if message == format!("Received duplicate nonce message IDs for aggregated key {aggregated}")
        ));
    }

    #[test]
    fn shared_collection_skips_self_collects_entries_and_rejects_duplicate_keys() {
        let (aggregated, participant) = public_keys();
        let address = CommsAddress::new(
            "127.0.0.1:10000".parse().unwrap(),
            "participant".to_string(),
        );
        let participants = vec![address.clone(), address.clone(), address];
        let first = serde_json::to_string(&vec![(
            aggregated,
            aggregated,
            vec![("first".to_string(), 1_u8)],
        )])
        .unwrap();
        let third = serde_json::to_string(&vec![(
            aggregated,
            participant,
            vec![("third".to_string(), 2_u8)],
        )])
        .unwrap();

        let dir = TestStorageDir::new("shared-contribution-collection");
        let globals = Globals::new(dir.storage());
        let protocol_id = Uuid::new_v4();
        globals
            .set_var(
                &protocol_id,
                "participant_0_nonces",
                VariableTypes::String(first),
            )
            .unwrap();
        globals
            .set_var(
                &protocol_id,
                "participant_2_nonces",
                VariableTypes::String(third.clone()),
            )
            .unwrap();

        let collected =
            collect_other_participants::<u8>(&participants, 1, &globals, &protocol_id, "nonces")
                .unwrap();
        assert_eq!(collected[&aggregated].len(), 2);
        assert_eq!(collected[&aggregated][&participant][0].0, "third");

        let missing_id = Uuid::new_v4();
        globals
            .set_var(
                &missing_id,
                "participant_0_nonces",
                VariableTypes::String(serde_json::to_string(&Vec::<u8>::new()).unwrap()),
            )
            .unwrap();
        let missing =
            collect_other_participants::<u8>(&participants, 1, &globals, &missing_id, "nonces")
                .unwrap_err();
        assert!(matches!(
            missing,
            BitVMXError::InvalidMessage(message)
                if message == "Missing nonces for participant 2"
        ));

        let duplicate_id = Uuid::new_v4();
        for idx in [1, 2] {
            globals
                .set_var(
                    &duplicate_id,
                    &format!("participant_{idx}_nonces"),
                    VariableTypes::String(third.clone()),
                )
                .unwrap();
        }
        let duplicate =
            collect_other_participants::<u8>(&participants, 0, &globals, &duplicate_id, "nonces")
                .unwrap_err();
        assert!(matches!(
            duplicate,
            BitVMXError::InvalidMessage(message)
                if message == format!("Received duplicate nonces from participant key {participant}")
        ));
    }
}
