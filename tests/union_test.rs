#![cfg(test)]

use anyhow::Result;
use bitcoin::Network;

use crate::common::{check_bitvmx_cpu_built, clear_db, config_trace, helper::TestHelper};

mod common;

fn test_union_aux(name: &str) -> Result<()> {
    let independent = true;
    let network = Network::Regtest;

    // Check if BitVMX-CPU is built before running the test
    check_bitvmx_cpu_built()?;

    config_trace();

    TestHelper::clear_regtest_dbs()?;
    clear_db("/tmp/regtest/master_wallet.db");

    let _helper = TestHelper::new(network, independent, None)?;

    // execute cargo run --release --example union request_pegout in a separate process
    let mut child = std::process::Command::new("cargo")
        .args(["run", "--release", "--example", "union", name])
        .spawn()?;

    child.wait()?;

    Ok(())
}

#[ignore]
#[test]
pub fn test_union_request_pegout() -> Result<()> {
    test_union_aux("request_pegout")
}

#[ignore]
#[test]
pub fn test_union_committee() -> Result<()> {
    test_union_aux("committee")
}

#[ignore]
#[test]
pub fn test_union_advance() -> Result<()> {
    test_union_aux("advance_funds")
}

#[ignore]
#[test]
pub fn test_union_fund() -> Result<()> {
    test_union_aux("fund_members")
}
