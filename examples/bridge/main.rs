//! This example demonstrates a complete end-to-end workflow of peg-in and peg-out
//! operations within the Union Bridge.
//!
//! To run this example, use the following command from the `rust-bitvmx-client` directory:
//! `cargo run --example union`

use anyhow::Result;

mod committee;
use committee::Committee;

mod log;

pub fn main() -> Result<()> {
    log::configure_tracing();
    run()?;

    Ok(())
}

pub fn run() -> Result<()> {
    let mut committee = Committee::new()?;
    committee.run()?;
    Ok(())
}
