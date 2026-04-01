#![cfg(test)]
use anyhow::Result;
use bitvmx_broker::{
    broker_memstorage::MemStorage,
    channel::channel::DualChannel,
    identification::{allow_list::AllowList, identifier::Identifier, routing::RoutingTable},
    rpc::{sync_server::BrokerSync, tls_helper::Cert, BrokerConfig},
};
use bitvmx_job_dispatcher::dispatcher_job::{DispatcherJob, ResultMessage};
use bitvmx_job_dispatcher::dispatcher_message::DispatcherMessage;
use bitvmx_job_dispatcher::DispatcherHandler;
use bitvmx_job_dispatcher_types::garbled_messages::GarbledJobType;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::info;

mod common;
use crate::common::{clear_db, config_trace};

// circuit to test - use a compiled .circuit file
const TEST_CIRCUIT_PATH: &str = "../rust-bitvmx-circuit-compiler/examples/simple.circuit";
const INPUT_BYTES: &[u8] = &[0, 0, 1];

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

/// Check that the test circuit file exists
fn check_circuit_file() -> Result<()> {
    if !Path::new(TEST_CIRCUIT_PATH).exists() {
        return Err(anyhow::anyhow!(
            "Test circuit file not found at {}. Compile with: cd ../rust-bitvmx-circuit-compiler && cargo run --bin garble-compile compile -i examples/simple.garble -o examples/simple.circuit",
            TEST_CIRCUIT_PATH
        ));
    }
    Ok(())
}

/// Test combined prove + verify commands (GC + Lamport in one)
#[ignore]
#[test]
pub fn test_gnova_commands() -> Result<()> {
    config_trace();
    check_gnova_built()?;
    check_circuit_file()?;

    // Set GNOVA_BIN for the correct relative path from rust-bitvmx-client
    std::env::set_var("GNOVA_BIN", "../rust-bitvmx-gc/target/release/gnova");

    let output_dir = "/tmp/gnova_commands_test";
    let _ = std::fs::remove_dir_all(output_dir);

    // --- Step 1: Prove (generates both GC and Lamport proofs) ---
    let prove_job = GarbledJobType::Prove(
        INPUT_BYTES.to_vec(),
        TEST_CIRCUIT_PATH.to_string(),
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
    let lamport_proof_path = prove_json["lamport_proof_path"]
        .as_str()
        .unwrap()
        .to_string();
    info!("Prove succeeded:");
    info!("  GC proof at: {}", proof_path);
    info!("  Lamport proof at: {}", lamport_proof_path);
    info!("  digest_io: {}", prove_json["digest_io"]);
    info!("  digest_labels: {}", prove_json["digest_labels"]);
    info!("  digest_lamport: {}", prove_json["digest_lamport"]);

    // --- Step 2: Verify (verifies both GC and Lamport proofs) ---
    let prove_json_path = format!("{}/prove/output.json", output_dir);
    let verify_job = GarbledJobType::Verify(
        proof_path,
        TEST_CIRCUIT_PATH.to_string(),
        prove_json_path,
        format!("{}/verify", output_dir),
    );

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
    assert_eq!(verify_json["proofs_linked"], true);
    info!("Verify succeeded, valid=true, proofs_linked=true");

    // --- Step 3: Digests must match ---
    assert_eq!(prove_json["digest_circ"], verify_json["digest_circ"]);
    assert_eq!(prove_json["digest_ct"], verify_json["digest_ct"]);
    assert_eq!(prove_json["digest_io"], verify_json["digest_io"]);
    assert_eq!(prove_json["digest_labels"], verify_json["digest_labels"]);
    assert_eq!(prove_json["digest_lamport"], verify_json["digest_lamport"]);
    info!("All digests match between prove and verify");

    // --- Step 4: Verify linkage ---
    assert_eq!(
        prove_json["digest_io"], prove_json["digest_labels"],
        "digest_io should equal digest_labels for linked proofs"
    );
    info!("GC and Lamport proofs are linked (digest_io == digest_labels)");

    Ok(())
}

const E2E_PORT: u16 = 10500;
const PRIVK_PATH: &str = "../rust-bitvmx-broker/certs/services.key";

#[ignore]
#[test]
pub fn test_gnova_e2e() -> Result<()> {
    config_trace();
    check_gnova_built()?;
    check_circuit_file()?;

    // Set GNOVA_BIN path
    std::env::set_var("GNOVA_BIN", "../rust-bitvmx-gc/target/release/gnova");

    let storage_path = format!("/tmp/garbled_e2e_storage_{}.db", std::process::id());
    clear_db(&storage_path);

    // Start broker server
    info!("Starting broker server on port {}...", E2E_PORT);
    let mut server = init_broker_server(E2E_PORT)?;

    // Start garbled dispatcher
    info!("Starting garbled dispatcher...");
    let (disp_stop_tx, disp_stop_rx) = channel::<()>();
    let storage_path_clone = storage_path.clone();
    let disp_handle =
        thread::spawn(move || run_garbled_dispatcher(E2E_PORT, disp_stop_rx, &storage_path_clone));

    // Give dispatcher time to connect
    thread::sleep(Duration::from_secs(1));

    // Run client test
    info!("Running client test...");
    let client_result = run_garbled_client_test(E2E_PORT);

    // Cleanup
    info!("Shutting down...");
    let _ = disp_stop_tx.send(());
    let _ = disp_handle.join();
    server.close();
    clear_db(&storage_path);

    client_result
}

fn init_broker_server(port: u16) -> Result<BrokerSync> {
    let privk = fs::read_to_string(PRIVK_PATH)?;
    let cert = Cert::new_with_privk(&privk)?;
    let allow_list =
        AllowList::from_certs(vec![cert.clone()], vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])?;
    let routing = RoutingTable::new();
    routing.lock().unwrap().allow_all();
    let config = BrokerConfig::new(port, None, cert.get_pubk_hash()?);

    let storage = Arc::new(Mutex::new(MemStorage::new()));
    let server = BrokerSync::new(&config, storage, cert, allow_list, routing)?;
    Ok(server)
}

fn run_garbled_dispatcher(port: u16, stop_rx: Receiver<()>, storage_path: &str) -> Result<()> {
    let privk = fs::read_to_string(PRIVK_PATH)?;
    let cert = Cert::new_with_privk(&privk)?;
    let allow_list =
        AllowList::from_certs(vec![cert.clone()], vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])?;

    let config = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        cert.get_pubk_hash()?,
    );
    let channel = DualChannel::new(&config, cert, Some(1), allow_list)?;

    let mut dispatcher =
        DispatcherHandler::<GarbledJobType>::new_with_path(channel, storage_path, None, true)?;

    loop {
        if stop_rx.try_recv().is_ok() {
            info!("Dispatcher received stop signal");
            break;
        }
        let _ = dispatcher.tick();
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn run_garbled_client_test(port: u16) -> Result<()> {
    let privk = fs::read_to_string(PRIVK_PATH)?;
    let cert = Cert::new_with_privk(&privk)?;
    let allow_list =
        AllowList::from_certs(vec![cert.clone()], vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])?;

    let dispatcher_id = Identifier {
        pubkey_hash: cert.get_pubk_hash()?,
        id: 1,
    };

    let config = BrokerConfig::new(
        port,
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        cert.get_pubk_hash()?,
    );
    let channel = DualChannel::new(&config, cert, Some(2), allow_list)?;

    let output_dir = "/tmp/gnova_e2e_test";
    let _ = fs::remove_dir_all(output_dir);
    fs::create_dir_all(output_dir)?;

    // --- Step 1: Send Prove job (generates both GC + Lamport proofs) ---
    let prove_job = DispatcherJob {
        job_id: "prove_e2e".to_string(),
        job_type: GarbledJobType::Prove(
            INPUT_BYTES.to_vec(),
            TEST_CIRCUIT_PATH.to_string(),
            format!("{}/prove", output_dir),
        ),
    };

    let msg = serde_json::to_string(&prove_job)?;
    channel.send(&dispatcher_id, msg)?;

    info!("Waiting for Prove result...");
    let (prove_result, _) = wait_for_dispatcher_result(&channel, "ProveResult", 600)?;

    info!("Prove completed: status={}", prove_result["status"]);
    assert_eq!(prove_result["status"], "success");

    let proof_path = prove_result["proof_path"].as_str().unwrap().to_string();
    let lamport_proof_path = prove_result["lamport_proof_path"]
        .as_str()
        .unwrap()
        .to_string();
    info!("  GC proof at: {}", proof_path);
    info!("  Lamport proof at: {}", lamport_proof_path);

    // --- Step 2: Send Verify job (verifies both GC + Lamport proofs) ---
    info!("Sending Verify job...");

    let prove_json_path = format!("{}/prove/output.json", output_dir);
    let verify_job = DispatcherJob {
        job_id: "verify_e2e".to_string(),
        job_type: GarbledJobType::Verify(
            proof_path,
            TEST_CIRCUIT_PATH.to_string(),
            prove_json_path,
            format!("{}/verify", output_dir),
        ),
    };

    let msg = serde_json::to_string(&verify_job)?;
    channel.send(&dispatcher_id, msg)?;

    info!("Waiting for Verify result...");
    let (verify_result, _) = wait_for_dispatcher_result(&channel, "VerifyResult", 120)?;

    info!(
        "Verify completed: status={}, valid={}, proofs_linked={}",
        verify_result["status"], verify_result["valid"], verify_result["proofs_linked"]
    );
    assert_eq!(verify_result["status"], "success");
    assert_eq!(verify_result["valid"], true);
    assert_eq!(verify_result["proofs_linked"], true);

    // --- Step 3: Verify digests match ---
    assert_eq!(prove_result["digest_circ"], verify_result["digest_circ"]);
    assert_eq!(prove_result["digest_ct"], verify_result["digest_ct"]);
    assert_eq!(prove_result["digest_io"], verify_result["digest_io"]);
    assert_eq!(
        prove_result["digest_labels"],
        verify_result["digest_labels"]
    );
    assert_eq!(
        prove_result["digest_lamport"],
        verify_result["digest_lamport"]
    );
    info!("All digests match!");

    // Verify linkage
    assert_eq!(
        prove_result["digest_io"], prove_result["digest_labels"],
        "Proofs should be linked"
    );
    info!("Proofs are linked (digest_io == digest_labels)");

    let _ = fs::remove_dir_all(output_dir);
    info!("E2E test completed successfully!");
    Ok(())
}

fn wait_for_dispatcher_result(
    channel: &DualChannel,
    expected_type: &str,
    timeout_secs: u64,
) -> Result<(serde_json::Value, String)> {
    let start = std::time::Instant::now();
    loop {
        if start.elapsed().as_secs() > timeout_secs {
            return Err(anyhow::anyhow!("Timeout waiting for {}", expected_type));
        }

        if let Some((msg, _)) = channel.recv()? {
            let result_msg: ResultMessage = serde_json::from_str(&msg)?;
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&result_msg.result) {
                if json["type"] == expected_type {
                    return Ok((json, result_msg.job_id));
                }
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
}

/// Full protocol test: prover generates proofs, verifier verifies with public data
///
/// Verifier has access to:
/// - Circuit structure (public, known beforehand)
/// - garbling_public: garbled gates (ciphertexts), const labels, decode hints
/// - sha256_commitments: SHA256 hashes of wire labels (public Lamport commitments)
/// - GC proof and Lamport proof
///
/// Verifier can recompute:
/// - digest_circ: from circuit structure
/// - digest_ct: from garbled gates
/// - digest_lamport: from SHA256 commitments
///
/// Verifier cannot recompute:
/// - digest_io / digest_labels: requires actual wire labels
///
/// Verifier checks:
/// 1. GC proof valid
/// 2. Lamport proof valid
/// 3. digest_circ matches recomputed from circuit
/// 4. digest_ct matches recomputed from garbled gates
/// 5. digest_lamport matches recomputed from SHA256 commitments
/// 6. digest_io == digest_labels (proofs are linked)
#[ignore]
#[test]
pub fn test_full_protocol() -> Result<()> {
    config_trace();
    check_gnova_built()?;
    check_circuit_file()?;

    std::env::set_var("GNOVA_BIN", "../rust-bitvmx-gc/target/release/gnova");

    let output_dir = "/tmp/test_full_protocol";
    let _ = std::fs::remove_dir_all(output_dir);
    std::fs::create_dir_all(output_dir)?;

    info!("========== PROVER ==========");

    // 1. Generate GC + Lamport proofs
    info!("[prover] Generating GC and Lamport proofs...");
    let prove_job = GarbledJobType::Prove(
        INPUT_BYTES.to_vec(),
        TEST_CIRCUIT_PATH.to_string(),
        format!("{}/prove", output_dir),
    );

    let (cmd, args, json_path) = prove_job.command()?;
    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(output.status.success(), "Prove failed");

    let prove_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    let gc_proof_path = prove_json["proof_path"].as_str().unwrap().to_string();
    info!("[prover] Proofs generated");
    info!("  digest_io: {}", prove_json["digest_io"]);
    info!("  digest_labels: {}", prove_json["digest_labels"]);
    info!("  digest_lamport: {}", prove_json["digest_lamport"]);

    info!("========== VERIFIER ==========");
    info!("[verifier] Received: proofs, garbled gates, SHA256 commitments");

    // 1. Verify both proofs (gnova verify now does full digest verification)
    info!("[verifier] Verifying GC + Lamport proofs...");
    let prove_json_path = format!("{}/prove/output.json", output_dir);
    let verify_job = GarbledJobType::Verify(
        gc_proof_path,
        TEST_CIRCUIT_PATH.to_string(),
        prove_json_path,
        format!("{}/verify", output_dir),
    );

    let (cmd, args, json_path) = verify_job.command()?;
    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(
        output.status.success(),
        "Verify failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let verify_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;

    // gnova verify now does ALL verification including digest matching
    // Check individual verification results
    assert_eq!(verify_json["gc_proof_valid"], true, "GC proof invalid");
    info!("[verifier] ✓ GC proof valid");

    assert_eq!(
        verify_json["lamport_proof_valid"], true,
        "Lamport proof invalid"
    );
    info!("[verifier] ✓ Lamport proof valid");

    assert_eq!(verify_json["proofs_linked"], true, "Proofs not linked");
    info!("[verifier] ✓ Proofs linked (digest_io == digest_labels)");

    assert_eq!(
        verify_json["digest_circ_matches"], true,
        "digest_circ mismatch"
    );
    info!("[verifier] ✓ digest_circ matches - GC proof uses expected circuit structure");

    assert_eq!(verify_json["digest_ct_matches"], true, "digest_ct mismatch");
    info!("[verifier] ✓ digest_ct matches - GC proof uses received garbled gates");

    assert_eq!(
        verify_json["digest_lamport_matches"], true,
        "digest_lamport mismatch"
    );
    info!("[verifier] ✓ digest_lamport matches - Lamport proof binds to SHA256 commitments");

    // Overall validity (all checks passed)
    assert_eq!(verify_json["valid"], true, "Full verification failed");
    info!("[verifier] ✓ ALL CHECKS PASSED");

    info!("Full protocol test completed successfully!");
    Ok(())
}
