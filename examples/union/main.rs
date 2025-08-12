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

use ::bitcoin::PublicKey;
use anyhow::Result;
use std::{env, thread, time::Duration};
use tracing::info;

use crate::participants::{committee::Committee, user::User};

mod macros;
mod participants;
mod setup;

mod bitcoin;
mod log;

pub fn main() -> Result<()> {
    log::configure_tracing();

    let args: Vec<String> = env::args().collect();
    let command = args.get(1);

    match command.map(|s| s.as_str()) {
        Some("setup_bitcoin_node") => setup_bitcoin_node()?,
        Some("committee") => committee()?,
        Some("request_pegin") => request_pegin()?,
        Some("accept_pegin") => accept_pegin()?,
        Some("request_pegout") => request_pegout()?,
        Some("advance_funds") => advance_funds()?,
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
}

pub fn setup_bitcoin_node() -> Result<()> {
    bitcoin::stop_existing_bitcoind()?;
    let (_bitcoin_client, _bitcoind, _wallet) = bitcoin::prepare_bitcoin()?;

    Ok(())
}

pub fn committee() -> Result<()> {
    // A new package is created. A committee is selected. Union client requests the setup of the
    // corresponding keys and programs.
    let mut committee = Committee::new()?;
    committee.setup()?;

    info!("Waiting some time to ensure all setup messages are processed...");
    thread::sleep(Duration::from_secs(2));
    info!("Mining 1 block and wait...");
    committee.wallet.mine(1)?;
    thread::sleep(Duration::from_secs(2));
    info!("Committee setup complete.");

    Ok(())
}

pub fn request_pegin() -> Result<()> {
    // A peg-in request is reported by the Union Client.
    let mut committee = Committee::new()?;
    let committee_public_key = committee.setup()?;

    let mut user = User::new("user_1")?;
    let amount: u64 = 100_000; // This should be replaced with the actual amount of the peg-in request
    user.request_pegin(&committee_public_key, amount)?;

    Ok(())
}

pub fn accept_pegin() -> Result<()> {
    // A peg-in request is reported by the Union Client. The committee accepts the peg-in request.
    let mut committee = Committee::new()?;
    let committee_public_key = committee.setup()?;

    let mut user = User::new("user_1")?;
    let amount = 100_000; // This should be replaced with the actual amount of the peg-in request

    let request_pegin_txid = user.request_pegin(&committee_public_key, amount)?;
    let rootstock_address = user.get_rsk_address();
    let reimbursement_pubkey = user.public_key()?;

    // This came from the contracts
    let accept_pegin_sighash = vec![0; 32]; // This should be replaced with the actual sighash of the accept peg-in tx
    let slot_index = 0; // This should be replaced with the actual slot index

    committee.accept_pegin(
        committee.committee_id(),
        request_pegin_txid,
        amount,
        accept_pegin_sighash,
        slot_index,
        rootstock_address.clone(),
        reimbursement_pubkey.clone(),
    )?;
    Ok(())
}

pub fn request_pegout() -> Result<()> {
    // A peg-in request is reported by the Union Client. The committee accepts the peg-in request.
    let mut committee = Committee::new()?;
    let committee_public_key = committee.setup()?;

    let mut user = User::new("user_1")?;
    let amount = 100_000; // This should be replaced with the actual amount of the peg-in request

    let request_pegin_txid = user.request_pegin(&committee_public_key, amount)?;
    let rootstock_address = user.get_rsk_address();
    let reimbursement_pubkey = user.public_key()?;

    // This came from the contracts
    let accept_pegin_sighash = vec![0; 32]; // This should be replaced with the actual sighash of the accept peg-in tx
    let slot_index = 0u64; // This should be replaced with the actual slot index

    committee.accept_pegin(
        committee.committee_id(),
        request_pegin_txid,
        amount,
        accept_pegin_sighash,
        slot_index,
        rootstock_address.clone(),
        reimbursement_pubkey.clone(),
    )?;

    // Wait some time to ensure the accept peg-in is processed
    thread::sleep(Duration::from_secs(5));

    let user_pubkey = user.public_key()?;
    let stream_id = 0; // This should be replaced with the actual stream ID
    let packet_number = 0; // This should be replaced with the actual packet number
    let pegout_id = vec![0; 32]; // This should be replaced with the actual peg-out ID
    let pegout_signature_hash = vec![0; 32]; // This should be replaced with the actual peg-out signature hash
    let pegout_signature_message = vec![0; 32]; // This should be replaced with the actual peg-out signature message

    committee.request_pegout(
        user_pubkey,
        slot_index,
        stream_id,
        packet_number,
        amount,
        pegout_id,
        pegout_signature_hash,
        pegout_signature_message,
    )?;

    Ok(())
}

pub fn advance_funds() -> Result<()> {
    // Advance funds to a user after a request pegout is not successfully processed.
    let mut committee = Committee::new()?;
    let committee_public_key = committee.setup()?;

    let mut user = User::new("user_1")?;
    let amount = 100_000; // This should be replaced with the actual amount of the peg-in request

    let request_pegin_txid = user.request_pegin(&committee_public_key, amount)?;

    // This came from the contracts
    let rootstock_address = user.get_rsk_address();
    let reimbursement_pubkey = user.public_key()?;
    let accept_pegin_sighash = vec![0; 32]; // This should be replaced with the actual sighash of the accept peg-in tx
    let slot_index = 0; // This should be replaced with the actual slot index

    committee.accept_pegin(
        committee.committee_id(),
        request_pegin_txid,
        amount,
        accept_pegin_sighash,
        slot_index,
        rootstock_address.clone(),
        reimbursement_pubkey.clone(),
    )?;

    // After some time, a peg-out request is not successfully processed and an operator is selected to advance funds.
    thread::sleep(Duration::from_secs(10));

    let user_public_key = "026e14224899cf9c780fef5dd200f92a28cc67f71c0af6fe30b5657ffc943f08f4"; // Placeholder for the actual user public key
    let pegout_id = vec![0; 32]; // Placeholder for the actual peg-out ID
    let slot_id = 0; // Placeholder for the slot ID
    let operator_id = 0; // Placeholder for the actual operator ID

    // Get the selected operator's take public key (simulating what Union Client would provide)
    let selected_operator_pubkey = committee.members[operator_id].keyring.take_pubkey.unwrap();

    committee.advance_funds(
        slot_id,
        user_public_key.parse::<PublicKey>().unwrap(),
        pegout_id,
        selected_operator_pubkey,
    )?;

    info!("Waiting some time to ensure all advance funds messages are processed...");
    thread::sleep(Duration::from_secs(2));
    info!("Mining 1 block and wait...");
    committee.wallet.mine(1)?;
    thread::sleep(Duration::from_secs(2));
    info!("Advance funds complete.");

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
