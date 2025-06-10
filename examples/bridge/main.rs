//! This example demonstrates a complete end-to-end workflow of peg-in and peg-out
//! operations within the Union Bridge.
//!
//! To run this example, use the following command from the `rust-bitvmx-client` directory:
//! `cargo run --example bridge`

use anyhow::Result;

mod committee;
use committee::Committee;

mod log;

pub fn main() -> Result<()> {
    log::configure_tracing();
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
