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
use garbled_nova::garble::GarbledGate;
use garbled_nova::garble::{
    garbled_circuit::{garble, get_inputs, get_outputs},
    Circuit, CircuitTrait,
};
use garbled_nova::garble_proof::rust_verifications::{circuit_digest, compute_digest_ct};
use garbled_nova::nova::{
    compute_sha256_commitments, digest_labels, digest_lamport, digest_lamport_from_commitments,
    hex_to_scalar as nova_hex_to_scalar, scalar_to_hex, LamportIo,
};
use garbled_nova::poseidon_constants;
use garbled_nova::{
    digests::{recompute_all_digests, GCIo},
    gadgets::bigint::alloc_bigint_input,
};
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

// circuit to test - use a compiled .circuit file
const TEST_CIRCUIT_PATH: &str = "../rust-bitvmx-circuit-compiler/examples/simple.circuit";

#[derive(Clone, Copy)]
#[allow(dead_code)]
enum TestCircuit {
    /// y = (a & b) ^ c — 3 inputs (bools), 4 gates, 162 outputs (MPC-encoded bool)
    Simple,
    /// BN254 Fq field addition — 508 inputs, ~4.3k gates
    FqAdd,
}

impl TestCircuit {
    fn circuit_path(&self) -> &'static str {
        match self {
            TestCircuit::Simple => TEST_CIRCUIT_PATH,
            TestCircuit::FqAdd => "../rust-bitvmx-circuit-compiler/examples/fq_add.circuit",
        }
    }

    fn input_bytes(&self) -> Vec<u8> {
        match self {
            TestCircuit::Simple => {
                // For the compiled simple.garble circuit:
                // pub fn main(a: bool, b: bool, c: bool) -> bool { (a & b) ^ c }
                // 3 bool inputs (each 1 byte): a=1, b=1, c=0 -> y = (1 & 1) ^ 0 = 1
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

    /// Build the actual circuit (for computing digests)
    /// Note: This builds a hardcoded version for native digest computation.
    /// For the actual circuit, we use the compiled .circuit file.
    fn build_circuit(&self) -> Circuit {
        match self {
            TestCircuit::Simple => {
                // Matches the structure from simple.garble: (a & b) ^ c
                // But note that compiled garble circuits may differ in structure
                let mut circ = Circuit::new();

                let a = circ.add_input();
                let b = circ.add_input();
                let c = circ.add_input();

                let a_and_b = circ.add_wire();
                let y = circ.add_wire();

                circ.add_and(a, b, a_and_b);
                circ.add_xor(a_and_b, c, y);

                circ.add_output(y);

                circ
            }
            TestCircuit::FqAdd => {
                let mut circ = Circuit::new();
                let a_wires = Fq(alloc_bigint_input(&mut circ, Fq::N_BITS));
                let b_wires = Fq(alloc_bigint_input(&mut circ, Fq::N_BITS));
                let res = Fq::add(&mut circ, &a_wires, &b_wires);

                for &w in res.0.iter() {
                    circ.add_output(w);
                }

                circ
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
    let circuit = TestCircuit::Simple;
    let input_bytes = circuit.input_bytes();
    info!(
        "Testing circuit: {} ({} input bytes)",
        circuit.circuit_path(),
        input_bytes.len()
    );

    let prove_job = GarbledJobType::Prove(
        input_bytes,
        circuit.circuit_path().to_string(),
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
    let lamport_proof_path = prove_json["lamport_proof_path"].as_str().unwrap().to_string();
    info!("Prove succeeded:");
    info!("  GC proof at: {}", proof_path);
    info!("  Lamport proof at: {}", lamport_proof_path);
    info!("  digest_io: {}", prove_json["digest_io"]);
    info!("  digest_labels: {}", prove_json["digest_labels"]);
    info!("  digest_lamport: {}", prove_json["digest_lamport"]);

    // --- Step 2: Verify (verifies both GC and Lamport proofs) ---
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

    // --- Step 1: Send Prove job (generates both GC + Lamport proofs) ---
    let circuit = TestCircuit::Simple;
    let input_bytes = circuit.input_bytes();
    info!("Sending Prove job for circuit: {}...", circuit.circuit_path());

    let prove_job = DispatcherJob {
        job_id: "prove_e2e".to_string(),
        job_type: GarbledJobType::Prove(
            input_bytes,
            circuit.circuit_path().to_string(),
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
    let lamport_proof_path = prove_result["lamport_proof_path"].as_str().unwrap().to_string();
    info!("  GC proof at: {}", proof_path);
    info!("  Lamport proof at: {}", lamport_proof_path);

    // --- Step 2: Send Verify job (verifies both GC + Lamport proofs) ---
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
    assert_eq!(prove_result["digest_labels"], verify_result["digest_labels"]);
    assert_eq!(prove_result["digest_lamport"], verify_result["digest_lamport"]);
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

/// Parse garbling_io from prove JSON output to LamportIo
fn parse_garbling_io_from_json(json: &serde_json::Value) -> LamportIo {
    let garbling_io = &json["garbling_io"];

    let inputs: Vec<(Scalar, Scalar)> = garbling_io["inputs"]
        .as_array()
        .expect("garbling_io.inputs should be array")
        .iter()
        .map(|pair| {
            let arr = pair.as_array().expect("each input should be [x0, x1]");
            let x0 = nova_hex_to_scalar(arr[0].as_str().unwrap()).unwrap();
            let x1 = nova_hex_to_scalar(arr[1].as_str().unwrap()).unwrap();
            (x0, x1)
        })
        .collect();

    let outputs: Vec<(Scalar, Scalar)> = garbling_io["outputs"]
        .as_array()
        .expect("garbling_io.outputs should be array")
        .iter()
        .map(|pair| {
            let arr = pair.as_array().expect("each output should be [x0, x1]");
            let x0 = nova_hex_to_scalar(arr[0].as_str().unwrap()).unwrap();
            let x1 = nova_hex_to_scalar(arr[1].as_str().unwrap()).unwrap();
            (x0, x1)
        })
        .collect();

    LamportIo { inputs, outputs }
}

/// Parse garbling_public from prove JSON output to get the garbled gates
fn parse_garbling_public_gates(json: &serde_json::Value) -> Vec<GarbledGate<Scalar>> {
    let garbling_public = &json["garbling_public"];

    garbling_public["gates"]
        .as_array()
        .expect("garbling_public.gates should be array")
        .iter()
        .map(|gate| {
            let gate_type = gate["type"].as_str().expect("gate should have type");
            match gate_type {
                "And" => {
                    let ct_hex = gate["ct"].as_str().expect("AND gate should have ct");
                    let ct = nova_hex_to_scalar(ct_hex).expect("Failed to parse ct hex");
                    GarbledGate::And { ct }
                }
                "Noop" => GarbledGate::Noop,
                _ => panic!("Unknown gate type: {}", gate_type),
            }
        })
        .collect()
}

/// Convert hex string (0x...) to Scalar for comparison
fn hex_to_scalar(hex_str: &str) -> Scalar {
    garbled_nova::nova::hex_to_scalar(hex_str).expect("Failed to parse hex scalar")
}

/// Full protocol test: prover generates proofs, verifier verifies with public data
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

    // 1. Generate GC + Lamport proofs (single command now)
    info!("[prover] Generating GC and Lamport proofs...");
    let circuit = TestCircuit::Simple;
    let prove_job = GarbledJobType::Prove(
        circuit.input_bytes(),
        circuit.circuit_path().to_string(),
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

    // Extract I/O labels and garbled gates from prove output
    let lamport_io = parse_garbling_io_from_json(&prove_json);
    let garbled_gates = parse_garbling_public_gates(&prove_json);

    // Compute SHA256 commitments (public lamports)
    info!("[prover] Computing SHA256 commitments...");
    let sha256_commitments = compute_sha256_commitments(&lamport_io);
    info!(
        "[prover] {} SHA256 commitment pairs ready to send",
        sha256_commitments.len()
    );

    // Prover sends: proof.bin, lamport_proof.bin, sha256_commitments, garbling_public
    info!("[prover] Sending to verifier: proofs, SHA256 commitments, garbling_public");

    info!("========== VERIFIER ==========");
    info!("[verifier] Received: proofs, SHA256 commitments, garbling_public");

    // 1. Verify both proofs (single command now)
    info!("[verifier] Verifying GC + Lamport proofs...");
    let verify_job = GarbledJobType::Verify(gc_proof_path, format!("{}/verify", output_dir));

    let (cmd, args, json_path) = verify_job.command()?;
    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(output.status.success(), "Verify failed");

    let verify_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    assert_eq!(verify_json["valid"], true, "Proofs invalid");
    assert_eq!(verify_json["proofs_linked"], true, "Proofs not linked");
    info!("[verifier] Both proofs valid and linked");

    // Extract digests from verification
    let gc_digest_circ = hex_to_scalar(verify_json["digest_circ"].as_str().unwrap());
    let gc_digest_ct = hex_to_scalar(verify_json["digest_ct"].as_str().unwrap());
    let gc_digest_io = hex_to_scalar(verify_json["digest_io"].as_str().unwrap());
    let lamport_digest_labels = hex_to_scalar(verify_json["digest_labels"].as_str().unwrap());
    let lamport_digest_lamport = hex_to_scalar(verify_json["digest_lamport"].as_str().unwrap());

    info!("[verifier] GC digest_circ: {}", scalar_to_hex(&gc_digest_circ));
    info!("[verifier] GC digest_io: {}", scalar_to_hex(&gc_digest_io));
    info!("[verifier] Lamport digest_labels: {}", scalar_to_hex(&lamport_digest_labels));
    info!("[verifier] Lamport digest_lamport: {}", scalar_to_hex(&lamport_digest_lamport));

    // 2. Compute expected digests from public data
    info!("[verifier] Computing expected values from public data...");
    let constants = poseidon_constants::<Scalar>();

    let gc_io = GCIo {
        inputs: lamport_io.inputs.clone(),
        outputs: lamport_io.outputs.clone(),
    };

    let (expected_digest_circ, expected_digest_ct, expected_digest_io) =
        recompute_all_digests(&circuit.build_circuit(), &garbled_gates, &gc_io, &constants);

    // 3. Compute digest_lamport from public SHA256 commitments
    info!("[verifier] Computing digest_lamport from public SHA256 commitments...");
    let computed_digest_lamport = digest_lamport_from_commitments(&sha256_commitments, &constants);
    info!(
        "[verifier] Computed digest_lamport: {}",
        scalar_to_hex(&computed_digest_lamport)
    );

    // =========================================================================
    // Verification checks
    // =========================================================================
    info!("[verifier] Performing verification checks...");

    // 1. Lamport proof binds to public SHA256 commitments
    assert_eq!(
        lamport_digest_lamport, computed_digest_lamport,
        "Lamport proof digest_lamport does not match computation from SHA256 commitments!"
    );
    info!("[verifier] Lamport proof binds to public SHA256 commitments");

    // 2. GC digest_circ matches expected
    assert_eq!(
        gc_digest_circ, expected_digest_circ,
        "GC digest_circ does not match expected!"
    );
    info!("[verifier] GC digest_circ matches expected");

    // 3. GC digest_ct matches expected
    assert_eq!(
        gc_digest_ct, expected_digest_ct,
        "GC digest_ct does not match expected!"
    );
    info!("[verifier] GC digest_ct matches expected");

    // 4. GC digest_io matches expected
    assert_eq!(
        gc_digest_io, expected_digest_io,
        "GC digest_io does not match expected!"
    );
    info!("[verifier] GC digest_io matches expected");

    // 5. GC and Lamport proofs are linked (already checked by verify command)
    assert_eq!(
        gc_digest_io, lamport_digest_labels,
        "GC digest_io does not match Lamport digest_labels - proofs are not linked!"
    );
    info!("[verifier] GC and Lamport proofs are linked (same I/O labels)");

    info!("Full protocol test completed successfully!");
    Ok(())
}
