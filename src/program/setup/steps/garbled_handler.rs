use crate::{
    config::ComponentsConfig,
    errors::BitVMXError,
    program::protocols::protocol_handler::ProtocolType,
};
use bitvmx_broker::identification::identifier::Identifier;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::async_dispatcher_step::AsyncStepHandler;

/// Data produced by the garbled circuit handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GarbledStepData {
    pub digest_circ: String,
    pub digest_ct: String,
    pub digest_io: String,
    pub proof_path: Option<String>,
}

// TODO: Replace with DispatcherJob<GarbledJobType> when the garbled-dispatcher branch is merged.
#[derive(Debug, Serialize, Deserialize)]
struct GarbledJob {
    job_id: String,
    job_type: GarbledJobType,
}

#[derive(Debug, Serialize, Deserialize)]
enum GarbledJobType {
    /// Prove(input_bytes, circuit_type, output_dir)
    Prove(Vec<u8>, String, String),
    /// Verify all participants' garbled step data
    Verify(Vec<GarbledStepData>),
}

/// [`AsyncStepHandler`] for garbled circuits.
///
/// TODO: Current implementation uses mock data. Replace internals with real
/// `DispatcherJob<GarbledJobType>` when the garbled-dispatcher branch is merged.
#[derive(Debug, Clone)]
pub struct GarbledHandler;

impl AsyncStepHandler for GarbledHandler {
    fn create_job(
        &self,
        protocol_id: &Uuid,
        _protocol: &mut ProtocolType,
    ) -> Result<String, BitVMXError> {
        let job_id = protocol_id.to_string();
        let output_dir = format!("./garbled-jobs/{}", job_id);

        // TODO: Get real input and circuit type from protocol
        let job = GarbledJob {
            job_id,
            job_type: GarbledJobType::Prove(
                vec![1, 1, 0],
                "simple".to_string(),
                output_dir,
            ),
        };

        serde_json::to_string(&job).map_err(|e| {
            BitVMXError::InvalidMessage(format!("Failed to serialize garbled job: {}", e))
        })
    }

    fn parse_result(&self, result: &[u8]) -> Result<String, BitVMXError> {
        let result_json: serde_json::Value =
            serde_json::from_slice(result).map_err(|e| {
                BitVMXError::InvalidMessage(format!(
                    "Failed to parse garbled result: {}",
                    e
                ))
            })?;

        let step_data = GarbledStepData {
            digest_circ: result_json["digest_circ"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            digest_ct: result_json["digest_ct"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            digest_io: result_json["digest_io"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            proof_path: result_json["proof_path"].as_str().map(|s| s.to_string()),
        };

        serde_json::to_string(&step_data).map_err(|e| {
            BitVMXError::InvalidMessage(format!("Failed to serialize garbled step data: {}", e))
        })
    }

    fn validate_received(&self, data: &str) -> Result<(), BitVMXError> {
        let step_data: GarbledStepData = serde_json::from_str(data).map_err(|e| {
            BitVMXError::InvalidMessage(format!(
                "Failed to deserialize garbled step data: {}",
                e
            ))
        })?;

        if step_data.digest_circ.is_empty()
            || step_data.digest_ct.is_empty()
            || step_data.digest_io.is_empty()
        {
            return Err(BitVMXError::InvalidMessage(
                "Received garbled step data with empty digests".to_string(),
            ));
        }

        Ok(())
    }

    fn dispatcher_id(&self, config: &ComponentsConfig) -> Option<Identifier> {
        config.garbled.clone()
    }

    fn create_verify_job(
        &self,
        protocol_id: &Uuid,
        all_data: &[String],
    ) -> Result<String, BitVMXError> {
        // Parse all participants' data
        let step_data: Vec<GarbledStepData> = all_data
            .iter()
            .map(|d| serde_json::from_str(d))
            .collect::<Result<_, _>>()
            .map_err(|e| {
                BitVMXError::InvalidMessage(format!(
                    "Failed to parse garbled step data for verification: {}",
                    e
                ))
            })?;

        // TODO: Replace with real verification job when garbled-dispatcher is integrated
        let job = GarbledJob {
            job_id: protocol_id.to_string(),
            job_type: GarbledJobType::Verify(step_data),
        };

        serde_json::to_string(&job).map_err(|e| {
            BitVMXError::InvalidMessage(format!(
                "Failed to serialize garbled verify job: {}",
                e
            ))
        })
    }

    fn parse_verify_result(&self, result: &[u8]) -> Result<(), BitVMXError> {
        // TODO: Replace with real verification result parsing
        let result_json: serde_json::Value =
            serde_json::from_slice(result).map_err(|e| {
                BitVMXError::InvalidMessage(format!(
                    "Failed to parse garbled verify result: {}",
                    e
                ))
            })?;

        let status = result_json["status"]
            .as_str()
            .unwrap_or("UNKNOWN");

        if status != "OK" {
            return Err(BitVMXError::InvalidMessage(format!(
                "Garbled verification failed: {}",
                result_json["details"].as_str().unwrap_or("unknown error")
            )));
        }

        Ok(())
    }
}
