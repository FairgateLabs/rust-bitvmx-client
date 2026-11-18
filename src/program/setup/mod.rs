pub mod setup_engine;
pub mod setup_step;
pub mod steps;

pub use setup_engine::{SetupEngine, SetupEngineState, StepState};
pub use setup_step::SetupStep;
pub(crate) use setup_step::{
    decode_contribution, decode_contribution_slice, load_participant_data,
};

pub(crate) const MY_KEYS: &str = "my_keys";
