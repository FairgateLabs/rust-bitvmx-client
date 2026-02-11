#![cfg(test)]
use anyhow::Result;
use bitvmx_job_dispatcher::dispatcher_message::DispatcherMessage;
use bitvmx_job_dispatcher_types::garbled_messages::GarbledJobType;
use garbled_nova::gadgets::bn254::{fq_to_input_bits, Fp254Impl, Fq};
use std::path::Path;
use tracing::info;

mod common;
use crate::common::config_trace;

// circuit to test
const TEST_CIRCUIT: TestCircuit = TestCircuit::Simple; // (fast, 2 gates)
// const TEST_CIRCUIT: TestCircuit = TestCircuit::FqAdd;  // (~4.3k gates)

#[derive(Clone, Copy)]
#[allow(dead_code)]
enum TestCircuit {
    /// y = (a & b) ^ d — 3 inputs, 2 gates, 1 output
    Simple,
    /// BN254 Fq field addition — 508 inputs, ~4.3k gates
    FqAdd,
}

impl TestCircuit {
    fn name(&self) -> &'static str {
        match self {
            TestCircuit::Simple => "simple",
            TestCircuit::FqAdd => "fq_add",
        }
    }

    fn input_bytes(&self) -> Vec<u8> {
        match self {
            TestCircuit::Simple => {
                // a=1, b=1, d=0 => y = (1 & 1) ^ 0 = 1
                vec![1, 1, 0]
            }
            TestCircuit::FqAdd => {
                let a = ark_bn254::Fq::from(123u64);
                let b = ark_bn254::Fq::from(456u64);
                let mut bits = Vec::with_capacity(2 * Fq::N_BITS);
                bits.extend(fq_to_input_bits(&a));
                bits.extend(fq_to_input_bits(&b));
                bits
            }
        }
    }
}

/// Check gnova binary exists
fn check_gnova_built() -> Result<()> {
    let binary = "../rust-bitvmx-gc/target/release/gnova";
    if !Path::new(binary).exists() {
        return Err(anyhow::anyhow!(
            "gnova binary not found at {}. Build with: cd ../rust-bitvmx-gc && cargo build --release --bin gnova",
            binary
        ));
    }
    Ok(())
}

#[ignore]
#[test]
pub fn test_gnova_commands() -> Result<()> {
    config_trace();
    check_gnova_built()?;

    // Set GNOVA_BIN for the correct relative path from rust-bitvmx-client
    std::env::set_var("GNOVA_BIN", "../rust-bitvmx-gc/target/release/gnova");

    let output_dir = "/tmp/gnova_commands_test";
    let _ = std::fs::remove_dir_all(output_dir);

    // --- Step 1: Prove ---
    let circuit = TEST_CIRCUIT;
    let input_bytes = circuit.input_bytes();
    info!(
        "Testing circuit: {} ({} input bytes)",
        circuit.name(),
        input_bytes.len()
    );

    let prove_job = GarbledJobType::Prove(
        input_bytes,
        circuit.name().to_string(),
        format!("{}/prove", output_dir),
    );

    let (cmd, args, json_path) = prove_job.command()?;
    info!("Running prove: {} {:?}", cmd, args);

    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(
        output.status.success(),
        "gnova prove failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let prove_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    assert_eq!(prove_json["status"], "success");
    assert_eq!(prove_json["type"], "ProveResult");
    let proof_path = prove_json["proof_path"].as_str().unwrap().to_string();
    info!("Prove succeeded, proof at: {}", proof_path);

    // --- Step 2: Verify ---
    let verify_job = GarbledJobType::Verify(proof_path, format!("{}/verify", output_dir));

    let (cmd, args, json_path) = verify_job.command()?;
    info!("Running verify: {} {:?}", cmd, args);

    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(
        output.status.success(),
        "gnova verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let verify_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    assert_eq!(verify_json["status"], "success");
    assert_eq!(verify_json["type"], "VerifyResult");
    assert_eq!(verify_json["valid"], true);
    info!("Verify succeeded, valid=true");

    // --- Step 3: Digests must match ---
    assert_eq!(prove_json["digest_circ"], verify_json["digest_circ"]);
    assert_eq!(prove_json["digest_ct"], verify_json["digest_ct"]);
    assert_eq!(prove_json["digest_io"], verify_json["digest_io"]);
    info!("Digests match between prove and verify");

    // Cleanup
    // let _ = std::fs::remove_dir_all(output_dir);

    Ok(())
}
