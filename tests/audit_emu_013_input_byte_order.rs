//! EMU-013 (see BitVMX-CPU/docs/emulator-audit/tickets/EMU-013-input-leaf-byte-order.md):
//! the on-chain `input` challenge leaves compare the input word with the wrong byte order.
//!
//! The leaves are rebuilt exactly as `dispute/challenge.rs` builds them (same
//! `verify_winternitz_signatures_aux` call, reverse script and challenge script) and are run
//! with real Winternitz signatures over the same messages the client signs:
//! * a prover input word is signed as its raw input bytes (`split_input`);
//! * a read value is signed as `u32::to_be_bytes` (`set_input_u32`);
//! * a Const input word is compiled into the leaf as `u32::from_be_bytes(bytes)`.
//!
//! The Schnorr `<agg> OP_CHECKSIGVERIFY` prefix is stripped, everything after it is the real leaf.
//! A leaf that runs successfully means the VERIFIER WINS.
//!
//! The honest read value comes from the emulator itself (`load_input` + `read_mem`), so it is
//! what an honest prover commits in its trace.
//!
//! Run: `cargo test --release --test audit_emu_013_input_byte_order -- --nocapture --include-ignored`

use bitcoin::{secp256k1::Secp256k1, PublicKey, ScriptBuf};
use bitcoin_script_riscv::riscv::challenges::{input_challenge, rom_challenge};
use bitcoin_script_stack::stack::StackTracker;
use bitvmx_client::program::protocols::dispute::challenge::INPUT_CHALLENGE;
use bitvmx_cpu_definitions::constants::LAST_STEP_INIT;
use emulator::loader::program::load_elf;
use key_manager::winternitz::{
    checksum_length, message_digits_length, to_checksummed_message, Winternitz,
    WinternitzPublicKey, WinternitzSignature, WinternitzType,
};
use protocol_builder::scripts::{self, SignMode};

const ELF: &str = "./verifiers/add-test.elf";
const INPUT_SECTION: &str = ".input";
const INPUT_ADDRESS: u32 = 0xaa00_0000;

fn wots(message: &[u8], index: u32) -> (WinternitzPublicKey, WinternitzSignature) {
    let secret = [7u8; 32];
    let digits = message_digits_length(message.len());
    let checksummed = to_checksummed_message(message);
    let checksum_size = checksum_length(digits);
    let message_size = checksummed.len() - checksum_size;
    let w = Winternitz::new();
    let private = w
        .generate_private_key(&secret, WinternitzType::HASH160, message_size, checksum_size, index)
        .unwrap();
    let public = w
        .generate_public_key(&secret, WinternitzType::HASH160, message_size, checksum_size, index)
        .unwrap();
    (public, w.sign_message(message_size, &checksummed, &private))
}

/// Same as the "TODO: This is a workaround to reverse the order of the stack" block in challenge.rs.
fn reverse_script(total_len: u32) -> ScriptBuf {
    let mut stack = StackTracker::new();
    let all = stack.define(total_len, "all");
    for i in 1..total_len {
        stack.move_var_sub_n(all, total_len - i - 1);
    }
    stack.op_2drop(); // drop prover_continue
    stack.get_script()
}

fn aggregated() -> PublicKey {
    let secp = Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
    PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk))
}

/// Builds the real leaf for the given variables and challenge script, signs `messages` and runs it.
/// Returns true when the verifier wins.
fn run_leaf(vars: &[(&str, Vec<u8>)], total_nibbles: u32, challenge: Vec<ScriptBuf>) -> bool {
    let signed: Vec<(String, WinternitzPublicKey, WinternitzSignature)> = vars
        .iter()
        .enumerate()
        .map(|(i, (name, msg))| {
            let (pk, sig) = wots(msg, i as u32 + 1);
            (name.to_string(), pk, sig)
        })
        .collect();
    let names_and_keys: Vec<(&str, &WinternitzPublicKey)> =
        signed.iter().map(|(n, pk, _)| (n.as_str(), pk)).collect();

    let leaf = scripts::verify_winternitz_signatures_aux(
        &aggregated(),
        &names_and_keys,
        SignMode::Single,
        true,
        Some([vec![reverse_script(total_nibbles)], challenge].concat()),
    )
    .unwrap();

    // strip `<32-byte x-only key> OP_CHECKSIGVERIFY`
    let bytes = leaf.get_script().as_bytes();
    assert_eq!(bytes[0], 0x20);
    assert_eq!(bytes[33], 0xad);
    let body = ScriptBuf::from_bytes(bytes[34..].to_vec());

    // Witness: signatures in reverse key order (get_winternitz_signature_for_script iterates
    // the keys in reverse), each as (hash, digit) pairs (push_winternitz_signature).
    let mut stack = StackTracker::new();
    for (_, _, sig) in signed.iter().rev() {
        for i in 0..sig.len() {
            stack.hexstr(&hex::encode(sig.to_hashes()[i].clone()));
            stack.number(sig.checksummed_message_digits()[i] as u32);
        }
    }
    stack.custom(body, 0, false, 0, "leaf");
    stack.run().success
}

struct Read {
    address: u32,
    value: u32,
    last_step: u64,
}

fn read_vars(r1: &Read, r2: &Read) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("prover_read_1_address", r1.address.to_be_bytes().to_vec()),
        ("prover_read_1_value", r1.value.to_be_bytes().to_vec()),
        ("prover_read_1_last_step", r1.last_step.to_be_bytes().to_vec()),
        ("prover_read_2_address", r2.address.to_be_bytes().to_vec()),
        ("prover_read_2_value", r2.value.to_be_bytes().to_vec()),
        ("prover_read_2_last_step", r2.last_step.to_be_bytes().to_vec()),
    ]
}

/// "input" leaf for a prover/verifier-owned input word (challenge.rs `ProgramInputType::Prover`).
fn prover_input_leaf_verifier_wins(input_word: [u8; 4], read_value: u32) -> bool {
    prover_input_leaf(input_word, read_value, false)
}

/// Same leaf with the proposed fix (`swap_input_word_script` before `input_challenge`).
fn fixed_prover_input_leaf_verifier_wins(input_word: [u8; 4], read_value: u32) -> bool {
    prover_input_leaf(input_word, read_value, true)
}

/// Proposed fix: the input word is signed as raw input bytes, but memory words are read
/// little-endian, so the signed word is byte-swapped before `input_challenge` compares it with
/// the read values. Runs after the reverse script and leaves the layout `input_challenge` expects.
fn swap_input_word_script() -> ScriptBuf {
    let mut stack = StackTracker::new();
    let input = stack.define(INPUT_CHALLENGE[0].1 as u32 * 2, "prover_input");
    let rest: Vec<_> = INPUT_CHALLENGE
        .iter()
        .skip(1)
        .map(|(name, size)| stack.define(*size as u32 * 2, name))
        .collect();
    let input = stack.move_var(input);
    let nibbles = stack.explode(input);
    for i in [6, 7, 4, 5, 2, 3, 0, 1] {
        stack.move_var(nibbles[i]);
    }
    stack.join_count(nibbles[6], 7);
    for var in rest {
        stack.move_var(var);
    }
    stack.get_script()
}

fn prover_input_leaf(input_word: [u8; 4], read_value: u32, fixed: bool) -> bool {
    let mut vars = vec![("prover_program_input_0", input_word.to_vec())];
    let r1 = Read { address: INPUT_ADDRESS, value: read_value, last_step: LAST_STEP_INIT };
    let r2 = Read { address: 0xf000_0004, value: 0, last_step: 3 };
    vars.extend(read_vars(&r1, &r2));
    vars.push(("prover_continue", vec![0]));

    let total = INPUT_CHALLENGE.iter().map(|(_, s)| *s).sum::<usize>() as u32 * 2 + 2;
    let mut stack = StackTracker::new();
    input_challenge(&mut stack, INPUT_ADDRESS);
    let mut scripts = vec![stack.get_script()];
    if fixed {
        scripts.insert(0, swap_input_word_script());
    }
    run_leaf(&vars, total, scripts)
}

/// "input" leaf for a Const input word (challenge.rs `ProgramInputType::Const`).
fn const_input_leaf_verifier_wins(input_word: [u8; 4], read_value: u32) -> bool {
    const_input_leaf(u32::from_be_bytes(input_word), read_value) // as challenge.rs:447-450
}

/// Same leaf with the proposed fix (`u32::from_le_bytes`).
fn fixed_const_input_leaf_verifier_wins(input_word: [u8; 4], read_value: u32) -> bool {
    const_input_leaf(u32::from_le_bytes(input_word), read_value)
}

fn const_input_leaf(const_value: u32, read_value: u32) -> bool {
    let r1 = Read { address: INPUT_ADDRESS, value: read_value, last_step: LAST_STEP_INIT };
    let r2 = Read { address: 0xf000_0004, value: 0, last_step: 3 };
    let mut vars = read_vars(&r1, &r2);
    vars.push(("prover_continue", vec![0]));

    let total = INPUT_CHALLENGE.iter().map(|(_, s)| *s).sum::<usize>() as u32 * 2 + 2
        - INPUT_CHALLENGE[0].1 as u32 * 2;
    let mut stack = StackTracker::new();
    rom_challenge(&mut stack, INPUT_ADDRESS, const_value);
    run_leaf(&vars, total, vec![stack.get_script()])
}

/// The value an honest prover reads from the first input word.
fn honest_read(input_word: [u8; 4]) -> u32 {
    let mut program = load_elf(ELF, false).unwrap();
    program.load_input(input_word.to_vec(), INPUT_SECTION, false).unwrap(); // as program_definition.rs:109
    program.read_mem(INPUT_ADDRESS, false).unwrap()
}

const PALINDROME: [u8; 4] = [0x11, 0x11, 0x11, 0x11];
const NON_PALINDROME: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

#[test]
fn emu013_control_palindromic_input_works() {
    let honest = honest_read(PALINDROME);
    assert_eq!(honest, 0x1111_1111);
    for (kind, f) in [
        ("prover", prover_input_leaf_verifier_wins as fn([u8; 4], u32) -> bool),
        ("const", const_input_leaf_verifier_wins),
    ] {
        let honest_result = f(PALINDROME, honest);
        let lie_result = f(PALINDROME, 0x1111_1100);
        println!("{kind}: palindromic input, honest read -> verifier_wins = {honest_result}, lie -> {lie_result}");
        assert!(!honest_result, "{kind}: verifier must not win against the honest read");
        assert!(lie_result, "{kind}: verifier must win against a lie");
    }
}

#[test]
fn emu013_demo_honest_prover_loses_on_non_palindromic_input() {
    let honest = honest_read(NON_PALINDROME);
    println!("input bytes {:02x?}: the emulator reads 0x{honest:08x}", NON_PALINDROME);
    assert_eq!(honest, 0x0403_0201);
    let swapped = honest.swap_bytes();
    for (kind, f) in [
        ("prover", prover_input_leaf_verifier_wins as fn([u8; 4], u32) -> bool),
        ("const", const_input_leaf_verifier_wins),
    ] {
        let honest_result = f(NON_PALINDROME, honest);
        let swapped_result = f(NON_PALINDROME, swapped);
        println!("{kind}: honest read 0x{honest:08x} -> verifier_wins = {honest_result}; byte-swapped lie 0x{swapped:08x} -> verifier_wins = {swapped_result}");
        assert!(honest_result, "{kind}: bug not reproduced (verifier lost against honest read)");
        assert!(!swapped_result, "{kind}: bug not reproduced (verifier won against swapped lie)");
    }
}

#[test]
#[ignore = "EMU-013: fails until fixed"]
fn emu013_input_leaves_match_emulator_byte_order() {
    let honest = honest_read(NON_PALINDROME);
    for (kind, f) in [
        ("prover", prover_input_leaf_verifier_wins as fn([u8; 4], u32) -> bool),
        ("const", const_input_leaf_verifier_wins),
    ] {
        assert!(!f(NON_PALINDROME, honest), "{kind}: verifier wins against the honest read");
        assert!(f(NON_PALINDROME, honest.swap_bytes()), "{kind}: verifier can't prove a byte-swapped lie");
    }
}

#[test]
fn emu013_proposed_fix_matches_emulator_byte_order() {
    for word in [NON_PALINDROME, PALINDROME, [0xde, 0xad, 0xbe, 0xef], [0, 0, 0, 0x80]] {
        let honest = honest_read(word);
        for (kind, f) in [
            ("prover", fixed_prover_input_leaf_verifier_wins as fn([u8; 4], u32) -> bool),
            ("const", fixed_const_input_leaf_verifier_wins),
        ] {
            let honest_result = f(word, honest);
            let swapped_result = f(word, honest.swap_bytes());
            let lie_result = f(word, honest ^ 1);
            println!("fixed {kind} {word:02x?}: honest 0x{honest:08x} -> {honest_result}, swapped -> {swapped_result}, off-by-one-bit -> {lie_result}");
            assert!(!honest_result, "{kind}: verifier wins against the honest read");
            assert!(lie_result, "{kind}: verifier can't prove a lie");
            if honest != honest.swap_bytes() {
                assert!(swapped_result, "{kind}: verifier can't prove a byte-swapped lie");
            }
        }
    }
}
