//! This example demonstrates a complete end-to-end workflow of peg-in and peg-out
//! operations within the Union Bridge.
//!
//! To run this example, use the following commands from the `rust-bitvmx-client` directory:
//! `cargo run --example union setup_bitcoin_node` - Sets up Bitcoin node
//! `cargo run --example union committee`          - Setups a new committee
//! `cargo run --example union accept_pegin`       - Setups the accept peg in protocol
//! `cargo run --example union pegin`              - Runs the pegin flow

use anyhow::Result;
use std::env;

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
    println!("  cargo run --example union request_pegin       - Setups a rerquest pegin");
    println!("  cargo run --example union accept_pegin        - Setups the accept peg in protocol");
    println!(
        "  cargo run --example union request_pegout      - Setups the request peg out in protocol"
    );
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

    // This came from the contracts
    let accept_pegin_sighash = vec![0; 32]; // This should be replaced with the actual sighash of the accept peg-in tx
    let slot_index = 0; // This should be replaced with the actual slot index

    committee.accept_pegin(
        committee.committee_id(),
        request_pegin_txid,
        amount,
        accept_pegin_sighash,
        slot_index,
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

    // This came from the contracts
    let accept_pegin_sighash = vec![0; 32]; // This should be replaced with the actual sighash of the accept peg-in tx
    let slot_index = 0; // This should be replaced with the actual slot index

    committee.accept_pegin(
        committee.committee_id(),
        request_pegin_txid,
        amount,
        accept_pegin_sighash,
        slot_index,
    )?;

    let user_pubkey = user.public_key()?;
    let fee = 1000; // This should be the fee for the peg-out

    committee.request_pegout(user_pubkey, slot_index, fee)?;

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
