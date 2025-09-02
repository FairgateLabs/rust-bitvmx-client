//! This example demonstrates a complete end-to-end workflow of peg-in and peg-out
//! operations within the Union Bridge.
//!
//! To run this example, use the following commands from the `rust-bitvmx-client` directory:
//! `cargo run --example union setup_bitcoin_node` - Sets up Bitcoin node
//! `cargo run --example union committee`          - Setups a new committee
//! `cargo run --example union request_pegin`      - Performs a request peg in
//! `cargo run --example union accept_pegin`       - Setups the accept peg in protocol
//! `cargo run --example union request_pegout`     - Setups the request peg out protocol
//! `cargo run --example union advance_funds`      - Performs an advancement of funds

use ::bitcoin::{OutPoint, PublicKey, Txid};
use anyhow::Result;
use bitvmx_client::program::protocols::union::{
    common::get_accept_pegin_pid, types::ACCEPT_PEGIN_TX,
};
use core::convert::Into;
use std::{env, thread, time::Duration};
use tracing::info;
use uuid::Uuid;

use crate::participants::{committee::Committee, member::Member, user::User};

mod macros;
mod participants;
mod setup;

mod bitcoin;
mod log;

// Adjust based on the network
pub const ADVANCE_FUNDS_FEE: u64 = 3000;
pub const ACCEPT_PEGIN_SPEEDUP_FEE: u64 = 5000;
pub const USER_TAKE_SPEEDUP_FEE: u64 = 3000;
pub const STREAM_DENOMINATION: u64 = 100_000;
static mut SLOT_INDEX_COUNTER: usize = 0;

pub fn main() -> Result<()> {
    log::configure_tracing();

    let args: Vec<String> = env::args().collect();
    let command = args.get(1);

    match command.map(|s| s.as_str()) {
        Some("setup_bitcoin_node") => setup_bitcoin_node()?,
        Some("committee") => cli_committee()?,
        Some("request_pegin") => cli_request_pegin()?,
        Some("accept_pegin") => cli_accept_pegin()?,
        Some("request_pegout") => cli_request_pegout()?,
        Some("advance_funds") => cli_advance_funds()?,
        Some("advance_funds_twice") => cli_advance_funds_twice()?,
        Some("invalid_reimbursement") => cli_invalid_reimbursement()?,
        Some(cmd) => {
            eprintln!("Unknown command: {}", cmd);
            print_usage();
            std::process::exit(1);
        }
        None => {
            print_usage();
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_usage() {
    println!("Usage:");
    println!("  cargo run --example union setup_bitcoin_node  - Sets up Bitcoin node only");
    println!("  cargo run --example union committee           - Setups a new committee");
    println!("  cargo run --example union request_pegin       - Setups a request pegin");
    println!("  cargo run --example union accept_pegin        - Setups the accept peg in protocol");
    println!(
        "  cargo run --example union request_pegout      - Setups the request peg out protocol"
    );
    println!("  cargo run --example union advance_funds       - Performs an advancement of funds");
    println!(
        "  cargo run --example union advance_funds_twice       - Performs advancement of funds twice"
    );
    println!("  cargo run --example union invalid_reimbursement - Forces invalid reimbursement to test challenge tx");
}

pub fn setup_bitcoin_node() -> Result<()> {
    bitcoin::stop_existing_bitcoind()?;
    let (_bitcoin_client, _bitcoind, _wallet) = bitcoin::prepare_bitcoin()?;

    Ok(())
}

pub fn cli_committee() -> Result<()> {
    committee()?;
    Ok(())
}

pub fn cli_request_pegin() -> Result<()> {
    let mut committee = committee()?;
    let mut user = User::new("user_1")?;
    request_pegin(&mut committee, &mut user)?;
    Ok(())
}

pub fn cli_accept_pegin() -> Result<()> {
    let mut committee = committee()?;
    let mut user = User::new("user_1")?;

    accept_pegin(&mut committee, &mut user)?;
    Ok(())
}

pub fn cli_request_pegout() -> Result<()> {
    request_pegout()?;
    Ok(())
}

pub fn cli_advance_funds() -> Result<()> {
    let mut committee = committee()?;
    let mut user = User::new("user_1")?;

    let (slot_index, _) = accept_pegin(&mut committee, &mut user)?;

    advance_funds(&mut committee, slot_index)?;
    Ok(())
}

pub fn cli_advance_funds_twice() -> Result<()> {
    let mut committee = committee()?;
    let mut user = User::new("user_1")?;

    // First advance should use funding UTXO
    let (slot_index, _) = accept_pegin(&mut committee, &mut user)?;
    advance_funds(&mut committee, slot_index)?;

    // Second advance should use change UTXO and Operator Take UTXO
    let (slot_index, _) = accept_pegin(&mut committee, &mut user)?;
    advance_funds(&mut committee, slot_index)?;

    Ok(())
}

pub fn cli_invalid_reimbursement() -> Result<()> {
    let mut committee = committee()?;
    let mut user = User::new("user_1")?;

    let (slot_index, _) = accept_pegin(&mut committee, &mut user)?;

    invalid_reimbursement(&mut committee, slot_index)?;
    Ok(())
}

fn get_and_increment_slot_index() -> usize {
    unsafe {
        let current_index = SLOT_INDEX_COUNTER;
        SLOT_INDEX_COUNTER += 1;
        current_index
    }
}

pub fn committee() -> Result<Committee> {
    // A new package is created. A committee is selected. Union client requests the setup of the
    // corresponding keys and programs.
    let mut committee = Committee::new(STREAM_DENOMINATION)?;
    committee.setup()?;
    committee.mine_and_wait(10)?;

    info!("Committee setup complete.");
    Ok(committee)
}

pub fn request_pegin(committee: &mut Committee, user: &mut User) -> Result<(Txid, u64)> {
    let committee_public_key = committee.public_key()?;

    let amount: u64 = STREAM_DENOMINATION; // This should be replaced with the actual amount of the peg-in request
    let request_pegin_txid = user.request_pegin(&committee_public_key, amount)?;

    Ok((request_pegin_txid, amount))
}

pub fn accept_pegin(committee: &mut Committee, user: &mut User) -> Result<(usize, u64)> {
    let (request_pegin_txid, amount) = request_pegin(committee, user)?;

    // This came from the contracts
    let rootstock_address = user.get_rsk_address();
    let reimbursement_pubkey = user.public_key()?;
    let accept_pegin_sighash = vec![0; 32]; // This should be replaced with the actual sighash of the accept peg-in tx
    let slot_index = get_and_increment_slot_index(); // This should be replaced with the actual slot index

    committee.accept_pegin(
        committee.committee_id(),
        request_pegin_txid,
        amount,
        accept_pegin_sighash,
        slot_index,
        rootstock_address.clone(),
        reimbursement_pubkey.clone(),
        false,
    )?;

    let protocol_id = get_accept_pegin_pid(committee.committee_id(), slot_index);
    let accept_pegin_tx =
        committee.dispatch_transaction_by_name(protocol_id, ACCEPT_PEGIN_TX.to_string())?;
    thread::sleep(Duration::from_secs(1));
    let accept_pegin_txid = accept_pegin_tx.compute_txid();
    user.create_and_dispatch_speedup(
        OutPoint {
            txid: accept_pegin_txid.into(),
            vout: 1,
        },
        ACCEPT_PEGIN_SPEEDUP_FEE,
    )?;

    committee.mine_and_wait(3)?;
    committee.wait_for_spv_proof(accept_pegin_txid)?;

    Ok((slot_index, amount))
}

pub fn request_pegout() -> Result<()> {
    let mut committee = committee()?;
    let mut user = User::new("user_1")?;

    let (slot_index, amount) = accept_pegin(&mut committee, &mut user)?;

    let user_pubkey = user.public_key()?;
    let stream_id = 0; // This should be replaced with the actual stream ID
    let packet_number = 0; // This should be replaced with the actual packet number
    let pegout_id = vec![0; 32]; // This should be replaced with the actual peg-out ID
    let pegout_signature_hash = vec![0; 32]; // This should be replaced with the actual peg-out signature hash
    let pegout_signature_message = vec![0; 32]; // This should be replaced with the actual peg-out signature message

    let user_take_utxo = committee.request_pegout(
        user_pubkey,
        slot_index,
        stream_id,
        packet_number,
        amount,
        pegout_id,
        pegout_signature_hash,
        pegout_signature_message,
    )?;

    user.create_and_dispatch_user_take_speedup(user_take_utxo.clone(), USER_TAKE_SPEEDUP_FEE)?;

    committee.mine_and_wait(3)?;
    committee.wait_for_spv_proof(user_take_utxo.0)?;

    Ok(())
}

pub fn advance_funds(committee: &mut Committee, slot_index: usize) -> Result<()> {
    // This came from the contracts
    let user_public_key = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"; // Placeholder for the actual user public key
    let pegout_id = vec![0; 32]; // Placeholder for the actual peg-out ID

    // Get the selected operator's take public key (simulating what Union Client would provide)
    let operator_id = 1; // Placeholder for the actual operator ID
    let selected_operator_pubkey = committee.members[operator_id].keyring.take_pubkey.unwrap();

    committee.advance_funds(
        slot_index,
        user_public_key.parse::<PublicKey>().unwrap(),
        pegout_id,
        selected_operator_pubkey,
        ADVANCE_FUNDS_FEE,
    )?;

    committee.mine_and_wait(30)?;
    info!("Advance funds complete.");
    Ok(())
}

pub fn invalid_reimbursement(committee: &mut Committee, slot_index: usize) -> Result<()> {
    info!("Forcing member 0 to dispatch invalid reimbursement transaction...");
    // Force member 0 to dispatch reimbursement without proper advancement setup
    let committee_id = committee.committee_id();
    let operator_index = 0;
    let member: &mut Member = &mut committee.members[operator_index];
    let operator_pubkey = member.keyring.take_pubkey.unwrap();

    member.advance_funds(
        Uuid::new_v4(),
        committee_id,
        slot_index,
        operator_pubkey,
        vec![0; 32],
        operator_pubkey,
        ADVANCE_FUNDS_FEE,
    )?;

    info!("Starting mining loop to ensure challenge transaction is dispatched...");
    committee.mine_and_wait(20)?;

    info!("Invalid reimbursement test complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::pegin;

    #[test]
    fn test_union_pegin() {
        pegin().expect("Failed to run peg-in");
        //thread::sleep(Duration::from_secs(10));
    }
}
