//! This example demonstrates a complete end-to-end workflow of peg-in and peg-out
//! operations within the Union Bridge.
//!
//! To run this example, use the following commands from the `rust-bitvmx-client` directory:
//! `cargo run --example union setup_bitcoin_node` - Sets up Bitcoin node
//! `cargo run --example union pegin` - Runs the peg-in example
//!

use anyhow::Result;
use std::env;

mod committee;
use committee::Committee;

mod log;
mod bitcoin;

pub fn main() -> Result<()> {
    log::configure_tracing();
    
    let args: Vec<String> = env::args().collect();
    let command = args.get(1);
    
    match command.map(|s| s.as_str()) {
        Some("setup_bitcoin_node") => setup_bitcoin_node()?,
        Some("pegin") => pegin()?,
        Some(cmd) => {
            eprintln!("Unknown command: {}", cmd);
            print_usage();
            std::process::exit(1);
        },
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
    println!("  cargo run --example union pegin               - Runs the peg-in flow");
}

pub fn setup_bitcoin_node() -> Result<()> {
    bitcoin::stop_existing_bitcoind()?;
    let (_bitcoin_client, _bitcoind, _wallet) = bitcoin::prepare_bitcoin()?;

    Ok(())
}

pub fn pegin() -> Result<()> {
    // 0. A new package is created. A committee is selected. Union client requests the setup of the
    // corresponding keys and programs.
    let _committee = setup()?;

    Ok(())
}

pub fn setup() -> Result<Committee> {
    let mut committee = Committee::new()?;
    committee.setup()?;

    Ok(committee)
}
