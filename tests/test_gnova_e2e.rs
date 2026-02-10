#![cfg(test)]
use anyhow::Result;
use bitvmx_job_dispatcher::dispatcher_message::DispatcherMessage;
use bitvmx_job_dispatcher_types::garbled_messages::GarbledJobType;
use std::path::Path;
use tracing::info;

mod common;
use crate::common::config_trace;

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
pub fn test_gnova_e2e() -> Result<()> {
    config_trace();
    check_gnova_built()?;

    let output_dir = "/tmp/gnova_e2e_test";
    let _ = std::fs::remove_dir_all(output_dir);

    // --- Step 1: Prove ---
    let input_bytes: Vec<u8> = vec![0, 1, 0, 1, 1, 0, 1, 0]; // 8 bits for basic circuit
    let prove_job = GarbledJobType::Prove(
        input_bytes,
        "basic".to_string(),
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
    let _ = std::fs::remove_dir_all(output_dir);

    Ok(())
}
