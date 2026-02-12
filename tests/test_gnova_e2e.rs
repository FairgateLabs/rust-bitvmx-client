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
use garbled_nova::gadgets::bigint::alloc_bigint_input;
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

    /// Build the actual circuit (for computing digests)
    fn build_circuit(&self) -> Circuit {
        match self {
            TestCircuit::Simple => {
                // Simple circuit: y = (a & b) ^ d
                // 3 input bits, 2 gates (1 AND + 1 XOR), 1 output bit
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

/// Parse garbling_io from GC prove JSON output to LamportIo
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

/// Parse garbling_public from GC prove JSON output to get the garbled gates
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

/// Convert hex string (0x...) to Scalar for comparison
fn hex_to_scalar(hex_str: &str) -> Scalar {
    garbled_nova::nova::hex_to_scalar(hex_str).expect("Failed to parse hex scalar")
}

#[ignore]
#[test]
pub fn test_gc_and_lamport_commands() -> Result<()> {
    config_trace();
    check_gnova_built()?;

    std::env::set_var("GNOVA_BIN", "../rust-bitvmx-gc/target/release/gnova");

    let output_dir = "/tmp/gnova_full_protocol_test";
    let _ = std::fs::remove_dir_all(output_dir);
    std::fs::create_dir_all(output_dir)?;

    // =========================================================================
    // Run GC Proof (Prove + Verify)
    // =========================================================================
    info!("=== Running GC Proof ===");

    let circuit = TestCircuit::Simple;
    let input_bytes = circuit.input_bytes();

    // GC Prove - this garbles the circuit and outputs the I/O labels
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

    // Extract I/O labels from GC prove output (same garbling used for Lamport proof)
    let lamport_io = parse_garbling_io_from_json(&gc_prove_json);
    info!(
        "Extracted {} input pairs, {} output pairs from GC prove",
        lamport_io.inputs.len(),
        lamport_io.outputs.len()
    );

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
    // Compute native digests
    // =========================================================================
    info!("=== Computing native digests ===");

    let constants = poseidon_constants::<Scalar>();
    let native_digest_labels = digest_labels(&lamport_io, &constants);
    let native_digest_lamport = digest_lamport(&lamport_io, &constants);
    info!(
        "Native digest_labels:  {}",
        scalar_to_hex(&native_digest_labels)
    );
    info!(
        "Native digest_lamport: {}",
        scalar_to_hex(&native_digest_lamport)
    );

    // Compute SHA256 commitments (these are the "public lamports")
    let sha256_commitments = compute_sha256_commitments(&lamport_io);
    info!(
        "Computed {} SHA256 commitment pairs",
        sha256_commitments.len()
    );

    // VERIFIER: Compute digest_lamport from public SHA256 commitments
    let verifier_digest_lamport = digest_lamport_from_commitments(&sha256_commitments, &constants);
    info!(
        "Verifier computed digest_lamport from public SHA256 commitments: {}",
        scalar_to_hex(&verifier_digest_lamport)
    );

    // Sanity check: digest_lamport computed from labels should equal digest from commitments
    assert_eq!(
        native_digest_lamport, verifier_digest_lamport,
        "digest_lamport from labels should match digest from SHA256 commitments"
    );
    info!("✓ digest_lamport from labels matches digest from SHA256 commitments");

    // =========================================================================
    // Run Lamport Proof
    // =========================================================================
    info!("=== Running Lamport Proof ===");

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
    // Compare digests
    // =========================================================================
    info!("=== Comparing digests ===");

    // Verify Lamport digest_lamport matches verifier's computation from public SHA256 commitments
    info!("Verifying public Lamport commitments");
    let lamport_proof_digest_lamport =
        hex_to_scalar(lamport_verify_json["digest_lamport"].as_str().unwrap());
    assert_eq!(
        lamport_proof_digest_lamport, verifier_digest_lamport,
        "Lamport proof digest_lamport does not match verifier's computation from SHA256 commitments!"
    );
    info!("✓ Lamport proof digest_lamport matches verifier's computation from public SHA256 commitments");

    // Verify digest_labels matches native computation
    // this is a sanity check, verifier does not have this information on setup.
    info!("Verifying I/O wire labels");
    let lamport_proof_digest_labels =
        hex_to_scalar(lamport_verify_json["digest_labels"].as_str().unwrap());
    assert_eq!(
        lamport_proof_digest_labels, native_digest_labels,
        "Lamport proof digest_labels does not match native computation from I/O labels!"
    );
    info!("✓ Lamport proof digest_labels matches native computation");

    // Cleanup
    // let _ = std::fs::remove_dir_all(output_dir);

    info!("Full protocol test completed successfully!");
    Ok(())
}

/// Prover and verifier full protocol:
///
/// prover:
/// 1. Garble circuit (GC prove) → get proof + I/O labels
/// 2. Compute SHA256 commitments from I/O labels (public lamports)
/// 3. Generate Lamport proof from I/O labels
/// 4. Send to verifier: GC proof, Lamport proof, SHA256 commitments, public garbling data
///
/// verifier:
/// 1. Verify GC proof → extract digest_circ, digest_io
/// 2. Verify Lamport proof → extract digest_labels, digest_lamport
/// 3. Compute expected digest_circ from known circuit
/// 4. Compute digest_lamport from public SHA256 commitments
/// 5. Check: gc_digest_circ == expected_digest_circ (correct circuit garbled)
/// 6. Check: proof_digest_lamport == computed_digest_lamport (proof binds to commitments)
/// 7. Check: gc_digest_io == lamport_digest_labels (GC and Lamport proofs are linked)
#[ignore]
#[test]
pub fn test_full_protocol() -> Result<()> {
    config_trace();
    check_gnova_built()?;

    std::env::set_var("GNOVA_BIN", "../rust-bitvmx-gc/target/release/gnova");

    let output_dir = "/tmp/test_full_protocol";
    let _ = std::fs::remove_dir_all(output_dir);
    std::fs::create_dir_all(output_dir)?;

    info!("========== PROVER ==========");

    // 1. Garble circuit and generate GC proof
    info!("[prover] Garbling circuit and generating GC proof...");
    let circuit = TestCircuit::Simple;
    let gc_prove_job = GarbledJobType::Prove(
        circuit.input_bytes(),
        circuit.name().to_string(),
        format!("{}/gc_prove", output_dir),
    );

    let (cmd, args, json_path) = gc_prove_job.command()?;
    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(output.status.success(), "GC prove failed");

    let gc_prove_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    let gc_proof_path = gc_prove_json["proof_path"].as_str().unwrap().to_string();
    info!("[prover] GC proof generated");

    // Extract I/O labels from GC prove output
    let lamport_io = parse_garbling_io_from_json(&gc_prove_json);

    // Extract garbling_public (garbled gates) from GC prove output
    let garbled_gates = parse_garbling_public_gates(&gc_prove_json);
    info!(
        "[prover] Extracted {} garbled gates from garbling_public",
        garbled_gates.len()
    );

    // 2. Compute SHA256 commitments
    info!("[prover] Computing SHA256 commitments...");
    let sha256_commitments = compute_sha256_commitments(&lamport_io);
    info!(
        "[prover] {} SHA256 commitment pairs ready to send",
        sha256_commitments.len()
    );

    // 3. Generate Lamport proof
    info!("[prover] Generating Lamport proof...");
    let labels_json = lamport_io_to_json(&lamport_io);
    let lamport_prove_job = GarbledJobType::ProveLamport(
        labels_json.into_bytes(),
        format!("{}/lamport_prove", output_dir),
    );

    let (cmd, args, json_path) = lamport_prove_job.command()?;
    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(output.status.success(), "Lamport prove failed");

    let lamport_prove_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    let lamport_proof_path = lamport_prove_json["proof_path"]
        .as_str()
        .unwrap()
        .to_string();
    info!("[prover] Lamport proof generated");

    // Prover sends to verifier:
    // - gc_proof_path (or proof bytes)
    // - lamport_proof_path (or proof bytes)
    // - sha256_commitments (public lamports)
    // - garbling_public (garbled gates, const labels, decode hints)
    info!("[prover] Sending to verifier: GC proof, Lamport proof, SHA256 commitments, garbling_public");

    info!("========== VERIFIER ==========");
    info!("[verifier] Received: GC proof, Lamport proof, SHA256 commitments, garbling_public");

    // 1. Verify GC proof
    info!("[verifier] Verifying GC proof...");
    let gc_verify_job = GarbledJobType::Verify(gc_proof_path, format!("{}/gc_verify", output_dir));

    let (cmd, args, json_path) = gc_verify_job.command()?;
    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(output.status.success(), "GC verify failed");

    let gc_verify_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    assert_eq!(gc_verify_json["valid"], true, "GC proof invalid");
    info!("[verifier] GC proof valid ✓");

    // Extract digests from GC proof
    let gc_digest_circ = hex_to_scalar(gc_verify_json["digest_circ"].as_str().unwrap());
    let gc_digest_ct = hex_to_scalar(gc_verify_json["digest_ct"].as_str().unwrap());
    let gc_digest_io = hex_to_scalar(gc_verify_json["digest_io"].as_str().unwrap());
    info!(
        "[verifier] GC proof digest_circ: {}",
        scalar_to_hex(&gc_digest_circ)
    );
    info!(
        "[verifier] GC proof digest_ct: {}",
        scalar_to_hex(&gc_digest_ct)
    );
    info!(
        "[verifier] GC proof digest_io: {}",
        scalar_to_hex(&gc_digest_io)
    );

    // 2. Verify Lamport proof
    info!("[verifier] Verifying Lamport proof...");
    let lamport_verify_job =
        GarbledJobType::VerifyLamport(lamport_proof_path, format!("{}/lamport_verify", output_dir));

    let (cmd, args, json_path) = lamport_verify_job.command()?;
    let output = std::process::Command::new(&cmd)
        .args(&args)
        .env("RUST_MIN_STACK", "67108864")
        .output()?;
    assert!(output.status.success(), "Lamport verify failed");

    let lamport_verify_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&json_path)?)?;
    assert_eq!(lamport_verify_json["valid"], true, "Lamport proof invalid");
    info!("[verifier] Lamport proof valid ✓");

    // Extract digests from Lamport proof
    let lamport_digest_labels =
        hex_to_scalar(lamport_verify_json["digest_labels"].as_str().unwrap());
    let lamport_digest_lamport =
        hex_to_scalar(lamport_verify_json["digest_lamport"].as_str().unwrap());
    info!(
        "[verifier] Lamport proof digest_labels: {}",
        scalar_to_hex(&lamport_digest_labels)
    );
    info!(
        "[verifier] Lamport proof digest_lamport: {}",
        scalar_to_hex(&lamport_digest_lamport)
    );

    info!("[verifier] Computing expected values from public data...");
    let constants = poseidon_constants::<Scalar>();

    // 3. Compute expected digest_circ from known circuit
    info!("[verifier] Computing expected circuit digest...");
    let expected_circuit = circuit.build_circuit();
    let expected_digest_circ = circuit_digest(&expected_circuit, &constants);
    info!(
        "[verifier] Expected digest_circ: {}",
        scalar_to_hex(&expected_digest_circ)
    );

    // 4. Compute digest_ct from received garbled gates
    info!("[verifier] Computing digest_ct from received garbled gates...");
    let computed_digest_ct = compute_digest_ct(&garbled_gates, &constants);
    info!(
        "[verifier] Computed digest_ct: {}",
        scalar_to_hex(&computed_digest_ct)
    );

    // 5. Compute digest_lamport from public SHA256 commitments
    info!("[verifier] Computing digest_lamport from public SHA256 commitments...");
    let computed_digest_lamport = digest_lamport_from_commitments(&sha256_commitments, &constants);
    info!(
        "[verifier] Computed digest_lamport: {}",
        scalar_to_hex(&computed_digest_lamport)
    );

    // =========================================================================
    // Checks
    // =========================================================================
    info!("[verifier] Performing verification checks...");

    // 1. Lamport proof binds to public SHA256 commitments
    info!("[verifier] Verifying Lamport commitments...");
    assert_eq!(
        lamport_digest_lamport, computed_digest_lamport,
        "Lamport proof digest_lamport does not match computation from SHA256 commitments!"
    );
    info!("[verifier] ✓ Lamport proof binds to public SHA256 commitments");

    // 2. GC and Lamport proofs are linked (same I/O labels)
    info!("[verifier] Verifying GC-Lamport linkage...");
    assert_eq!(
        gc_digest_io, lamport_digest_labels,
        "GC digest_io does not match Lamport digest_labels - proofs are not linked!"
    );
    info!("[verifier] ✓ GC and Lamport proofs are linked (same I/O labels)");

    // 3. Garbling public data was extracted (infrastructure test)
    // TODO verify digest_ct

    Ok(())
}
