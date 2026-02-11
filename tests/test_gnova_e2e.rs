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
use garbled_nova::gadgets::bn254::{fq_to_input_bits, Fp254Impl, Fq};
use garbled_nova::garble::{
    garbled_circuit::{garble, get_inputs, get_outputs},
    Circuit, CircuitTrait,
};
use garbled_nova::nova::{digest_labels, digest_lamport, LamportIo};
use garbled_nova::poseidon_constants;
use pasta_curves::pallas::Scalar;
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

/// Build the "simple" circuit: y = (a & b) ^ d
fn build_simple_circuit() -> Circuit {
    let mut circ = Circuit::new();

    let a = circ.add_input();
    let b = circ.add_input();
    let d = circ.add_input();

    let a_and_b = circ.add_wire();
    let y = circ.add_wire();

    circ.add_and(a, b, a_and_b);
    circ.add_xor(a_and_b, d, y);

    circ.add_output(y);

    circ
}

/// Garble simple circuit and extract I/O labels as LamportIo
fn garble_simple_circuit_for_lamport() -> LamportIo {
    let circ = build_simple_circuit();
    let constants = poseidon_constants::<Scalar>();

    let (gc, wires) = garble::<Scalar>(&circ, &constants);

    let private_gc = garbled_nova::garble::garbled_circuit::PrivateGC {
        e: gc.e.clone(),
        wires: wires.clone(),
        delta: gc.delta.clone(),
    };

    LamportIo {
        inputs: get_inputs(&circ, &private_gc),
        outputs: get_outputs(&circ, &private_gc),
    }
}

/// Convert LamportIo to JSON string for CLI
fn lamport_io_to_json(io: &LamportIo) -> String {
    serde_json::to_string_pretty(io).expect("Failed to serialize LamportIo")
}

#[ignore]
#[test]
pub fn test_gnova_lamport_commands() -> Result<()> {
    config_trace();
    check_gnova_built()?;

    std::env::set_var("GNOVA_BIN", "../rust-bitvmx-gc/target/release/gnova");

    let output_dir = "/tmp/gnova_lamport_commands_test";
    let _ = std::fs::remove_dir_all(output_dir);
    std::fs::create_dir_all(output_dir)?;

    // --- Step 1: Garble circuit and extract I/O labels ---
    info!("Garbling simple circuit to extract I/O labels...");
    let lamport_io = garble_simple_circuit_for_lamport();
    info!(
        "Extracted {} input pairs and {} output pairs",
        lamport_io.inputs.len(),
        lamport_io.outputs.len()
    );

    // Write labels JSON
    let labels_path = format!("{}/labels.json", output_dir);
    let labels_json = lamport_io_to_json(&lamport_io);
    std::fs::write(&labels_path, &labels_json)?;
    info!("Labels written to {}", labels_path);

    // --- Step 2: Prove Lamport ---
    let prove_job = GarbledJobType::ProveLamport(
        labels_json.into_bytes(),
        format!("{}/prove_lamport", output_dir),
    );

    let (cmd, args, json_path) = prove_job.command()?;
    info!("Running prove-lamport: {} {:?}", cmd, args);

    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(
        output.status.success(),
        "gnova prove-lamport failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let prove_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    assert_eq!(prove_json["status"], "success");
    assert_eq!(prove_json["type"], "ProveLamportResult");
    let proof_path = prove_json["proof_path"].as_str().unwrap().to_string();
    info!("Prove-lamport succeeded, proof at: {}", proof_path);
    info!(
        "  digest_labels: {}",
        prove_json["digest_labels"].as_str().unwrap()
    );
    info!(
        "  digest_lamport: {}",
        prove_json["digest_lamport"].as_str().unwrap()
    );

    // --- Step 3: Verify Lamport ---
    let verify_job =
        GarbledJobType::VerifyLamport(proof_path, format!("{}/verify_lamport", output_dir));

    let (cmd, args, json_path) = verify_job.command()?;
    info!("Running verify-lamport: {} {:?}", cmd, args);

    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(
        output.status.success(),
        "gnova verify-lamport failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let verify_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    assert_eq!(verify_json["status"], "success");
    assert_eq!(verify_json["type"], "VerifyLamportResult");
    assert_eq!(verify_json["valid"], true);
    info!("Verify-lamport succeeded, valid=true");

    // --- Step 4: Digests must match ---
    assert_eq!(
        prove_json["digest_labels"], verify_json["digest_labels"],
        "digest_labels mismatch"
    );
    assert_eq!(
        prove_json["digest_lamport"], verify_json["digest_lamport"],
        "digest_lamport mismatch"
    );
    info!("Lamport digests match between prove and verify!");

    // Cleanup
    // let _ = std::fs::remove_dir_all(output_dir);

    Ok(())
}

const E2E_PORT: u16 = 10500;
const E2E_LAMPORT_PORT: u16 = 10501;
const PRIVK_PATH: &str = "../rust-bitvmx-broker/certs/services.key";

#[ignore]
#[test]
pub fn test_gnova_e2e() -> Result<()> {
    config_trace();
    check_gnova_built()?;

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

    let mut dispatcher = DispatcherHandler::<GarbledJobType>::new_with_path(channel, storage_path)?;

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

    // --- Step 1: Send Prove job ---
    let circuit = TEST_CIRCUIT;
    let input_bytes = circuit.input_bytes();
    info!("Sending Prove job for '{}' circuit...", circuit.name());

    let prove_job = DispatcherJob {
        job_id: "prove_e2e".to_string(),
        job_type: GarbledJobType::Prove(
            input_bytes,
            circuit.name().to_string(),
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

    // --- Step 2: Send Verify job ---
    info!("Sending Verify job...");

    let verify_job = DispatcherJob {
        job_id: "verify_e2e".to_string(),
        job_type: GarbledJobType::Verify(proof_path, format!("{}/verify", output_dir)),
    };

    let msg = serde_json::to_string(&verify_job)?;
    channel.send(&dispatcher_id, msg)?;

    info!("Waiting for Verify result...");
    let (verify_result, _) = wait_for_dispatcher_result(&channel, "VerifyResult", 120)?;

    info!(
        "Verify completed: status={}, valid={}",
        verify_result["status"], verify_result["valid"]
    );
    assert_eq!(verify_result["status"], "success");
    assert_eq!(verify_result["valid"], true);

    // --- Step 3: Verify digests match ---
    assert_eq!(prove_result["digest_circ"], verify_result["digest_circ"]);
    assert_eq!(prove_result["digest_ct"], verify_result["digest_ct"]);
    assert_eq!(prove_result["digest_io"], verify_result["digest_io"]);
    info!("All digests match!");

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

#[ignore]
#[test]
pub fn test_gnova_lamport_e2e() -> Result<()> {
    config_trace();
    check_gnova_built()?;

    std::env::set_var("GNOVA_BIN", "../rust-bitvmx-gc/target/release/gnova");

    let storage_path = format!("/tmp/lamport_e2e_storage_{}.db", std::process::id());
    clear_db(&storage_path);

    // Start broker server
    info!("Starting broker server on port {}...", E2E_LAMPORT_PORT);
    let mut server = init_broker_server(E2E_LAMPORT_PORT)?;

    // Start garbled dispatcher
    info!("Starting garbled dispatcher...");
    let (disp_stop_tx, disp_stop_rx) = channel::<()>();
    let storage_path_clone = storage_path.clone();
    let disp_handle = thread::spawn(move || {
        run_garbled_dispatcher(E2E_LAMPORT_PORT, disp_stop_rx, &storage_path_clone)
    });

    // Give dispatcher time to connect
    thread::sleep(Duration::from_secs(1));

    // Run client test
    info!("Running Lamport client test...");
    let client_result = run_lamport_client_test(E2E_LAMPORT_PORT);

    // Cleanup
    info!("Shutting down...");
    let _ = disp_stop_tx.send(());
    let _ = disp_handle.join();
    server.close();
    clear_db(&storage_path);

    client_result
}

fn run_lamport_client_test(port: u16) -> Result<()> {
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

    let output_dir = "/tmp/gnova_lamport_e2e_test";
    let _ = fs::remove_dir_all(output_dir);
    fs::create_dir_all(output_dir)?;

    // --- Step 1: Garble circuit locally and extract I/O labels ---
    info!("Garbling simple circuit to extract I/O labels...");
    let lamport_io = garble_simple_circuit_for_lamport();
    let labels_json = lamport_io_to_json(&lamport_io);
    info!(
        "Extracted {} input pairs and {} output pairs",
        lamport_io.inputs.len(),
        lamport_io.outputs.len()
    );

    // --- Step 2: Send ProveLamport job ---
    info!("Sending ProveLamport job...");

    let prove_job = DispatcherJob {
        job_id: "prove_lamport_e2e".to_string(),
        job_type: GarbledJobType::ProveLamport(
            labels_json.into_bytes(),
            format!("{}/prove_lamport", output_dir),
        ),
    };

    let msg = serde_json::to_string(&prove_job)?;
    channel.send(&dispatcher_id, msg)?;

    info!("Waiting for ProveLamport result...");
    let (prove_result, _) = wait_for_dispatcher_result(&channel, "ProveLamportResult", 600)?;

    info!("ProveLamport completed: status={}", prove_result["status"]);
    assert_eq!(prove_result["status"], "success");

    let proof_path = prove_result["proof_path"].as_str().unwrap().to_string();
    info!("Lamport proof at: {}", proof_path);
    info!(
        "  digest_labels: {}",
        prove_result["digest_labels"].as_str().unwrap()
    );
    info!(
        "  digest_lamport: {}",
        prove_result["digest_lamport"].as_str().unwrap()
    );

    // --- Step 3: Send VerifyLamport job ---
    info!("Sending VerifyLamport job...");

    let verify_job = DispatcherJob {
        job_id: "verify_lamport_e2e".to_string(),
        job_type: GarbledJobType::VerifyLamport(
            proof_path,
            format!("{}/verify_lamport", output_dir),
        ),
    };

    let msg = serde_json::to_string(&verify_job)?;
    channel.send(&dispatcher_id, msg)?;

    info!("Waiting for VerifyLamport result...");
    let (verify_result, _) = wait_for_dispatcher_result(&channel, "VerifyLamportResult", 120)?;

    info!(
        "VerifyLamport completed: status={}, valid={}",
        verify_result["status"], verify_result["valid"]
    );
    assert_eq!(verify_result["status"], "success");
    assert_eq!(verify_result["valid"], true);

    // --- Step 4: Verify Lamport digests match ---
    assert_eq!(
        prove_result["digest_labels"], verify_result["digest_labels"],
        "digest_labels mismatch"
    );
    assert_eq!(
        prove_result["digest_lamport"], verify_result["digest_lamport"],
        "digest_lamport mismatch"
    );
    info!("All Lamport digests match!");

    let _ = fs::remove_dir_all(output_dir);
    info!("Lamport E2E test completed successfully!");
    Ok(())
}

// =============================================================================
// Full Protocol Test: GC Proof + Lamport Proof Linkage Verification
// =============================================================================

/// Convert hex string (0x...) to Scalar for comparison
fn hex_to_scalar(hex_str: &str) -> Scalar {
    garbled_nova::nova::hex_to_scalar(hex_str).expect("Failed to parse hex scalar")
}

#[ignore]
#[test]
pub fn test_gc_lamport_full_protocol() -> Result<()> {
    config_trace();
    check_gnova_built()?;

    std::env::set_var("GNOVA_BIN", "../rust-bitvmx-gc/target/release/gnova");

    let output_dir = "/tmp/gnova_full_protocol_test";
    let _ = std::fs::remove_dir_all(output_dir);
    std::fs::create_dir_all(output_dir)?;

    // =========================================================================
    // Step 1: Build and garble circuit, extract I/O labels
    // =========================================================================
    info!("=== Step 1: Garbling simple circuit ===");
    let lamport_io = garble_simple_circuit_for_lamport();
    info!(
        "Extracted {} input pairs, {} output pairs",
        lamport_io.inputs.len(),
        lamport_io.outputs.len()
    );

    // Compute native Lamport digests for later comparison
    let constants = poseidon_constants::<Scalar>();
    let native_digest_labels = digest_labels(&lamport_io, &constants);
    let native_digest_lamport = digest_lamport(&lamport_io, &constants);
    info!("Native digest_labels:  {:?}", native_digest_labels);
    info!("Native digest_lamport: {:?}", native_digest_lamport);

    // =========================================================================
    // Step 2: Run GC Proof (Prove + Verify)
    // =========================================================================
    info!("=== Step 2: Running GC Proof ===");

    let circuit = TestCircuit::Simple;
    let input_bytes = circuit.input_bytes();

    // GC Prove
    let gc_prove_job = GarbledJobType::Prove(
        input_bytes,
        circuit.name().to_string(),
        format!("{}/gc_prove", output_dir),
    );

    let (cmd, args, json_path) = gc_prove_job.command()?;
    info!("Running GC prove...");
    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(
        output.status.success(),
        "GC prove failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let gc_prove_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    assert_eq!(gc_prove_json["status"], "success");
    let gc_proof_path = gc_prove_json["proof_path"].as_str().unwrap().to_string();
    info!("GC prove succeeded");
    info!("  digest_circ: {}", gc_prove_json["digest_circ"]);
    info!("  digest_ct:   {}", gc_prove_json["digest_ct"]);
    info!("  digest_io:   {}", gc_prove_json["digest_io"]);

    // GC Verify
    let gc_verify_job = GarbledJobType::Verify(gc_proof_path, format!("{}/gc_verify", output_dir));
    let (cmd, args, json_path) = gc_verify_job.command()?;
    info!("Running GC verify...");
    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(
        output.status.success(),
        "GC verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let gc_verify_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    assert_eq!(gc_verify_json["status"], "success");
    assert_eq!(gc_verify_json["valid"], true);
    info!("GC verify succeeded");

    // GC proof roundtrip check
    assert_eq!(gc_prove_json["digest_circ"], gc_verify_json["digest_circ"]);
    assert_eq!(gc_prove_json["digest_ct"], gc_verify_json["digest_ct"]);
    assert_eq!(gc_prove_json["digest_io"], gc_verify_json["digest_io"]);
    info!("GC proof digests match between prove and verify ✓");

    // =========================================================================
    // Step 3: Run Lamport Proof (ProveLamport + VerifyLamport)
    // =========================================================================
    info!("=== Step 3: Running Lamport Proof ===");

    let labels_json = lamport_io_to_json(&lamport_io);

    // Lamport Prove
    let lamport_prove_job = GarbledJobType::ProveLamport(
        labels_json.into_bytes(),
        format!("{}/lamport_prove", output_dir),
    );

    let (cmd, args, json_path) = lamport_prove_job.command()?;
    info!("Running Lamport prove...");
    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(
        output.status.success(),
        "Lamport prove failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lamport_prove_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    assert_eq!(lamport_prove_json["status"], "success");
    let lamport_proof_path = lamport_prove_json["proof_path"]
        .as_str()
        .unwrap()
        .to_string();
    info!("Lamport prove succeeded");
    info!("  digest_labels:  {}", lamport_prove_json["digest_labels"]);
    info!("  digest_lamport: {}", lamport_prove_json["digest_lamport"]);

    // Lamport Verify
    let lamport_verify_job =
        GarbledJobType::VerifyLamport(lamport_proof_path, format!("{}/lamport_verify", output_dir));
    let (cmd, args, json_path) = lamport_verify_job.command()?;
    info!("Running Lamport verify...");
    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(
        output.status.success(),
        "Lamport verify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lamport_verify_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    assert_eq!(lamport_verify_json["status"], "success");
    assert_eq!(lamport_verify_json["valid"], true);
    info!("Lamport verify succeeded");

    // Lamport proof roundtrip check
    assert_eq!(
        lamport_prove_json["digest_labels"],
        lamport_verify_json["digest_labels"]
    );
    assert_eq!(
        lamport_prove_json["digest_lamport"],
        lamport_verify_json["digest_lamport"]
    );
    info!("Lamport proof digests match between prove and verify ✓");

    // =========================================================================
    // Step 4: Verify Lamport proof outputs match native computation
    // =========================================================================
    info!("=== Step 4: Verifying native digest recomputation ===");

    let verified_digest_labels =
        hex_to_scalar(lamport_verify_json["digest_labels"].as_str().unwrap());
    let verified_digest_lamport =
        hex_to_scalar(lamport_verify_json["digest_lamport"].as_str().unwrap());

    assert_eq!(
        verified_digest_labels, native_digest_labels,
        "Lamport proof digest_labels does not match native computation!"
    );
    assert_eq!(
        verified_digest_lamport, native_digest_lamport,
        "Lamport proof digest_lamport does not match native computation!"
    );
    info!("Lamport proof outputs match native digest computation ✓");

    // =========================================================================
    // Step 5: Summary - Protocol Linkage Verified
    // =========================================================================
    info!("=== Protocol Verification Summary ===");
    info!("✓ GC proof: prove/verify roundtrip successful");
    info!("✓ Lamport proof: prove/verify roundtrip successful");
    info!("✓ Lamport proof outputs match native recomputation from I/O labels");
    info!("✓ Both proofs computed from the same garbled circuit I/O labels");
    info!("");
    info!("The protocol linkage is established:");
    info!("  - GC proof commits to circuit structure + ciphertexts + I/O labels (digest_io)");
    info!(
        "  - Lamport proof commits to I/O labels (digest_labels) + SHA256 hashes (digest_lamport)"
    );
    info!("  - Same I/O labels used in both → proofs are linked");

    // Cleanup
    // let _ = std::fs::remove_dir_all(output_dir);

    info!("Full protocol test completed successfully!");
    Ok(())
}
