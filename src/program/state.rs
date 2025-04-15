use serde::{Deserialize, Serialize};

use crate::p2p_helper::P2PMessageType;

use super::participant::ParticipantRole;

#[derive(PartialEq, Clone, Serialize, Deserialize, Debug)]
pub enum ProgramState {
    /// Initial state when a program is first created
    New,

    /// Program is in setup phase, exchanging keys, nonces and signatures with counterparty.
    /// Contains a SettingUpState enum specifying the exact setup step.
    SettingUp(SettingUpState),

    /// Program setup is complete and is ready to send transactions monitor
    Monitoring,

    /// Program is dispatching transactions to the blockchain to complete the protocol
    /// TODO: Dispatching should have (Claimed, Challenged) inside it
    //Dispatching,

    /// Ready state after setup is completed and the transactions are being monitored
    Ready,
    // Program has been claimed by one party
    //Claimed,

    // Program has been challenged
    //Challenged,

    // Program encountered an error and cannot continue
    //Error,

    // Program has completed successfully
    //Completed,
}

#[derive(PartialEq, Clone, Serialize, Deserialize, Debug)]
pub enum SettingUpState {
    WaitingKeys,
    SendingKeys,
    WaitingNonces,
    SendingNonces,
    WaitingSignatures,
    SendingSignatures,
}

impl ProgramState {
    pub fn next_state(&self, role: &ParticipantRole) -> Self {
        match role {
            ParticipantRole::Prover => match self {
                ProgramState::New => ProgramState::SettingUp(SettingUpState::SendingKeys),
                ProgramState::SettingUp(SettingUpState::SendingKeys) => {
                    ProgramState::SettingUp(SettingUpState::WaitingKeys)
                }
                ProgramState::SettingUp(SettingUpState::WaitingKeys) => {
                    ProgramState::SettingUp(SettingUpState::SendingNonces)
                }
                ProgramState::SettingUp(SettingUpState::SendingNonces) => {
                    ProgramState::SettingUp(SettingUpState::WaitingNonces)
                }
                ProgramState::SettingUp(SettingUpState::WaitingNonces) => {
                    ProgramState::SettingUp(SettingUpState::SendingSignatures)
                }
                ProgramState::SettingUp(SettingUpState::SendingSignatures) => {
                    ProgramState::SettingUp(SettingUpState::WaitingSignatures)
                }
                ProgramState::SettingUp(SettingUpState::WaitingSignatures) => {
                    ProgramState::Monitoring
                }

                ProgramState::Monitoring => ProgramState::Ready,
                ProgramState::Ready => ProgramState::Ready,
                /*ProgramState::Claimed => ProgramState::Claimed,
                ProgramState::Challenged => ProgramState::Challenged,
                ProgramState::Error => ProgramState::Error,
                ProgramState::Completed => ProgramState::Completed,
                //TODO: This should change to Claimed or Challenged , there is 2 options .
                ProgramState::Dispatching => ProgramState::Dispatching,*/
            },
            ParticipantRole::Verifier => match self {
                ProgramState::New => ProgramState::SettingUp(SettingUpState::WaitingKeys),
                ProgramState::SettingUp(SettingUpState::WaitingKeys) => {
                    ProgramState::SettingUp(SettingUpState::SendingKeys)
                }
                ProgramState::SettingUp(SettingUpState::SendingKeys) => {
                    ProgramState::SettingUp(SettingUpState::WaitingNonces)
                }
                ProgramState::SettingUp(SettingUpState::WaitingNonces) => {
                    ProgramState::SettingUp(SettingUpState::SendingNonces)
                }
                ProgramState::SettingUp(SettingUpState::SendingNonces) => {
                    ProgramState::SettingUp(SettingUpState::WaitingSignatures)
                }
                ProgramState::SettingUp(SettingUpState::WaitingSignatures) => {
                    ProgramState::SettingUp(SettingUpState::SendingSignatures)
                }
                ProgramState::SettingUp(SettingUpState::SendingSignatures) => {
                    ProgramState::Monitoring
                }

                ProgramState::Monitoring => ProgramState::Ready,
                ProgramState::Ready => ProgramState::Ready,
                /*ProgramState::Claimed => ProgramState::Claimed,
                ProgramState::Challenged => ProgramState::Challenged,
                ProgramState::Error => ProgramState::Error,
                ProgramState::Completed => ProgramState::Completed,
                ProgramState::Dispatching => ProgramState::Dispatching,*/
            },
        }
    }

    pub fn should_answer_ack(&self, role: &ParticipantRole, msg_type: &P2PMessageType) -> bool {
        if role == &ParticipantRole::Prover {
            // Prover flow:
            // 1. Sends keys and waits for KeysAck
            // 2. Waits for Keys from verifier
            // 3. Sends nonces and waits for NoncesAck
            // 4. Waits for nonces from verifier
            // 5. Sends signatures and waits for SignaturesAck
            // 6. Waits for signatures from verifier
            match (self, msg_type) {
                (ProgramState::SettingUp(SettingUpState::SendingNonces), P2PMessageType::Keys) => {
                    true
                }
                (
                    ProgramState::SettingUp(SettingUpState::SendingSignatures),
                    P2PMessageType::PublicNonces,
                ) => true,
                _ => false,
            }
        } else {
            // Verifier flow:
            // 1. Waits for keys from prover
            // 2. Sends keys and waits for KeysAck
            // 3. Waits for nonces from prover
            // 4. Sends nonces and waits for NoncesAck
            // 5. Waits for signatures from prover
            // 6. Sends signatures and waits for SignaturesAck
            match (self, msg_type) {
                (ProgramState::SettingUp(SettingUpState::SendingKeys), P2PMessageType::Keys) => {
                    true
                }
                (
                    ProgramState::SettingUp(SettingUpState::SendingNonces),
                    P2PMessageType::PublicNonces,
                ) => true,
                (
                    ProgramState::SettingUp(SettingUpState::SendingSignatures),
                    P2PMessageType::PartialSignatures,
                ) => true,
                _ => false,
            }
        }
    }

    pub fn should_handle_msg(&self, msg_type: &P2PMessageType) -> bool {
        match (self, msg_type) {
            (ProgramState::SettingUp(SettingUpState::WaitingKeys), P2PMessageType::Keys) => true,
            (
                ProgramState::SettingUp(SettingUpState::WaitingNonces),
                P2PMessageType::PublicNonces,
            ) => true,
            (
                ProgramState::SettingUp(SettingUpState::WaitingSignatures),
                P2PMessageType::PartialSignatures,
            ) => true,
            (ProgramState::SettingUp(SettingUpState::SendingKeys), P2PMessageType::KeysAck) => true,
            (
                ProgramState::SettingUp(SettingUpState::SendingNonces),
                P2PMessageType::PublicNoncesAck,
            ) => true,
            (
                ProgramState::SettingUp(SettingUpState::SendingSignatures),
                P2PMessageType::PartialSignaturesAck,
            ) => true,
            _ => false,
        }
    }

    pub fn is_active(&self) -> bool {
        let is_setting_up = self.is_setting_up();
        let is_monitoring = self.is_monitoring();
        //let is_dispatching = self.is_dispatching();
        is_setting_up || is_monitoring //|| is_dispatching
    }

    pub fn is_setting_up(&self) -> bool {
        matches!(self, &ProgramState::New | &ProgramState::SettingUp(_))
    }

    pub fn is_monitoring(&self) -> bool {
        self == &ProgramState::Monitoring
    }
}
