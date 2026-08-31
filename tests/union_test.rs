#![cfg(test)]

use anyhow::Result;
use bitcoin::{
    absolute, key::Parity, secp256k1::Secp256k1, transaction, Address, Amount, Network, OutPoint,
    PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClientApi;
use bitvmx_client::program::protocols::union::common::{
    request_pegin_op_return_data, REQUEST_PEGIN_OP_RETURN_LEN,
};
use protocol_builder::builder::{Protocol, ProtocolBuilder};

use crate::common::{
    check_bitvmx_cpu_built, clear_db, config_trace,
    helper::{Mode, TestHelper},
    prepare_bitcoin_guarded,
};
use crate::fixtures::{
    address_to_bytes, create_rsk_request_pegin_transaction, hardcoded_unspendable,
    sign_p2wpkh_transaction_single_input, user_keypair_with_parity,
};

mod common;
mod fixtures;

fn test_union_aux(name: &str) -> Result<()> {
    // Check if BitVMX-CPU is built before running the test
    check_bitvmx_cpu_built()?;

    config_trace();

    TestHelper::clear_regtest_dbs()?;
    clear_db("/tmp/regtest/master_wallet.db");

    let _helper = TestHelper::new(Mode::RegtestIndependent, None)?;

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

// Amount used to fund/spend the speedup output under test. Kept well above the dust
// threshold so the spend transaction's change output is standard.
const PARITY_SPEND_TEST_VALUE: u64 = 50_000;
const PARITY_SPEND_TEST_FEE: u64 = 1_000;

// Proves that a P2WPKH output built from a reimbursement key via the same production
// helper the accept-pegin protocol uses (`ProtocolBuilder::add_speedup_output`) carries
// the full, parity-preserving script pubkey and can actually be spent by that key's
// owner, for both an even- and an odd-parity key. Also confirms the request-pegin
// Taproot leaves (which x-only the reimbursement key on purpose) are unaffected.
fn assert_reimbursement_parity_is_preserved(parity: Parity) -> Result<()> {
    config_trace();

    let (bitcoin_client, _bitcoind, _wallet) = prepare_bitcoin_guarded()?;
    let network = Network::Regtest;
    let secp = Secp256k1::new();

    let aggregated_key = PublicKey {
        compressed: true,
        inner: hardcoded_unspendable(),
    };

    let (user_address, user_pubkey, user_sk) =
        user_keypair_with_parity(&secp, &bitcoin_client, network, parity)?;

    // Round-trip through the same OP_RETURN encoder the request-pegin transaction uses,
    // and reconstruct the reimbursement key the way a downstream consumer (contracts,
    // union client) would from the wire payload. This is what makes the test sensitive
    // to the encoder: an x-only-truncating encoder yields a different key here.
    let rootstock_address = address_to_bytes("7ac5496aee77c1ba1f0854206a26dda82a81d6d8")?;
    let op_return_payload = request_pegin_op_return_data(0, rootstock_address, &user_pubkey)?;
    let reimbursement_pubkey =
        PublicKey::from_slice(&op_return_payload[37..REQUEST_PEGIN_OP_RETURN_LEN])?;
    assert_eq!(
        reimbursement_pubkey, user_pubkey,
        "reimbursement pubkey decoded from the OP_RETURN payload must match the original {parity:?} key"
    );

    // Build the speedup output exactly as accept_pegin.rs's add_speedup_output does,
    // from the key reconstructed off the wire, not the original in-memory key.
    let mut protocol = Protocol::new("parity_speedup_test");
    let pb = ProtocolBuilder {};
    pb.add_speedup_output(
        &mut protocol,
        "speedup_tx",
        PARITY_SPEND_TEST_VALUE,
        &reimbursement_pubkey,
    )?;
    let built_tx = protocol.transaction_by_name("speedup_tx")?;
    let speedup_script_pubkey = built_tx.output[0].script_pubkey.clone();

    // Compare the *full* script pubkey, not the X coordinate alone: an x-only comparison
    // would pass even if the encoder truncated parity away.
    let expected_script_pubkey =
        ScriptBuf::new_p2wpkh(&user_pubkey.wpubkey_hash().expect("key is compressed"));
    assert_eq!(
        speedup_script_pubkey, expected_script_pubkey,
        "speedup output script_pubkey must equal P2WPKH({parity:?} key)"
    );

    // Fund that exact script on regtest, then spend it with the user's secret key. This
    // is the assertion that actually proves the fix: signature verification only passes
    // if the key that funded the output is the same one used to sign the spend.
    let dest_address = Address::from_script(&speedup_script_pubkey, network)?;
    let (funding_tx, vout) =
        bitcoin_client.fund_address(&dest_address, Amount::from_sat(PARITY_SPEND_TEST_VALUE))?;

    let funds_input = TxIn {
        previous_output: OutPoint::new(funding_tx.compute_txid(), vout),
        script_sig: ScriptBuf::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };
    let change_output = TxOut {
        value: Amount::from_sat(PARITY_SPEND_TEST_VALUE - PARITY_SPEND_TEST_FEE),
        script_pubkey: user_address.script_pubkey(),
    };
    let mut spend_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![funds_input],
        output: vec![change_output],
    };

    let signed_spend_tx = sign_p2wpkh_transaction_single_input(
        &secp,
        network,
        &mut spend_tx,
        &user_pubkey,
        user_sk,
        PARITY_SPEND_TEST_VALUE,
    )?;

    // send_transaction runs full consensus script verification; it only succeeds if
    // user_sk actually unlocks speedup_script_pubkey.
    let spend_txid = bitcoin_client.send_transaction(&signed_spend_tx)?;
    bitcoin_client.mine_blocks(1)?;
    assert!(
        bitcoin_client
            .get_tx_confirmations(&spend_txid)?
            .unwrap_or(0)
            > 0,
        "spend of the {parity:?}-parity speedup output was not accepted"
    );

    // The request-pegin transaction (taproot output + 70-byte OP_RETURN) still builds and
    // relays for this parity. The tapscript path x-onlys the reimbursement key on purpose
    // and must stay unaffected by this fix. Note this does not spend the timelock leaf.
    let request_pegin_txid = create_rsk_request_pegin_transaction(
        aggregated_key,
        network,
        &bitcoin_client,
        &secp,
        (user_address, user_pubkey, user_sk),
    )?;
    bitcoin_client.mine_blocks(1)?;
    assert!(
        bitcoin_client
            .get_tx_confirmations(&request_pegin_txid)?
            .unwrap_or(0)
            > 0,
        "request pegin transaction for {parity:?} parity was not accepted"
    );

    Ok(())
}

#[ignore]
#[test]
pub fn test_union_reimbursement_parity_odd() -> Result<()> {
    assert_reimbursement_parity_is_preserved(Parity::Odd)
}

#[ignore]
#[test]
pub fn test_union_reimbursement_parity_even() -> Result<()> {
    assert_reimbursement_parity_is_preserved(Parity::Even)
}
