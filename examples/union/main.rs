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

use crate::committee::Committee;

mod committee;
mod member;
mod setup;

mod bitcoin;
mod log;

pub fn main() -> Result<()> {
    log::configure_tracing();

    let args: Vec<String> = env::args().collect();
    let command = args.get(1);

    match command.map(|s| s.as_str()) {
        Some("setup_bitcoin_node") => setup_bitcoin_node()?,
        Some("accept_pegin") => accept_pegin()?,
        Some("committee") => committee()?,
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
    println!("  cargo run --example union accept_pegin        - Setups the accept peg in protocol");
    println!("  cargo run --example union pegin               - Runs the pegin flow");
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

pub fn accept_pegin() -> Result<()> {
    // A peg-in request is reported by the Union Client. The committee accepts the peg-in request.
    let mut committee = Committee::new()?;
    committee.setup()?;
    committee.accept_pegin()?;
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
