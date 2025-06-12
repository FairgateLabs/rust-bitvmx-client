//! This example demonstrates a complete end-to-end workflow of peg-in and peg-out
//! operations within the Union Bridge.
//!
//! To run this example, use the following command from the `rust-bitvmx-client` directory:
//! `cargo run --example bridge`
//!
//! To run just the bitcoin setup, use:
//! `BITCOIN_ONLY=1 cargo run --example bridge`

use anyhow::Result;
use std::env;

mod committee;
use committee::Committee;

mod log;
mod bitcoin;

pub fn main() -> Result<()> {
    log::configure_tracing();
    
    // Check if we should run only bitcoin setup
    if env::var("BITCOIN_ONLY").is_ok() {
        println!("Running Bitcoin setup only...");
        let (_bitcoin_client, _bitcoind, _wallet) = bitcoin::prepare_bitcoin()?;
        println!("Bitcoin setup completed successfully!");
        return Ok(());
    }
    
    pegin()?;

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
