use crate::{
    bitcoin::{BitcoinWrapper, HIGH_FEE_NODE_ENABLED},
    participants::{committee::Committee, member::Member, user::User},
    wallet::{
        helper::{
            ask_user_confirmation, create_wallet, fund_members, fund_user_pegin_utxos,
            fund_user_speedup, load_change_key_from_env, load_private_key_from_env, print_balance,
            print_link, print_members_balances, recover_funds, recover_user_funds,
            string_to_network, wallet_recover_funds,
        },
        master_wallet::MasterWallet,
    },
};
use ::bitcoin::{Network, OutPoint, PublicKey, Txid};
use anyhow::Result;
use bitvmx_client::program::{
    participant::ParticipantRole,
    protocols::union::{
        common::{
            double_indexed_name, get_accept_pegin_pid, get_dispute_core_pid,
            get_full_penalization_pid, triple_indexed_name,
        },
        types::{
            ACCEPT_PEGIN_TX, DISPUTE_CORE_LONG_TIMELOCK, DISPUTE_CORE_SHORT_TIMELOCK,
            OP_DISABLER_DIRECTORY_TX, OP_DISABLER_TX, OP_INITIAL_DEPOSIT_TX, OP_LAZY_DISABLER_TX,
            OP_SELF_DISABLER_TX, WT_DISABLER_DIRECTORY_TX, WT_DISABLER_TX, WT_SELF_DISABLER_TX,
            WT_START_ENABLER_TX,
        },
    },
};
use core::convert::Into;
use std::{env, thread, time::Duration};
use tracing::info;
use uuid::Uuid;

mod bitcoin;
mod dev;
mod log;
mod macros;
mod participants;
mod setup;
mod wallet;

// Network and stream denomination configuration
pub const NETWORK: Network = Network::Regtest;
pub const STREAM_DENOMINATION: u64 = 100_000;

static mut SLOT_INDEX_COUNTER: usize = 0;

pub fn main() -> Result<()> {
    log::configure_tracing();

    let args: Vec<String> = env::args().collect();
    let command = args.get(1);

    match command.map(|s| s.as_str()) {
        Some("setup_bitcoin_node") => setup_bitcoin_node()?,
        Some("committee") => cli_committee()?,
        Some("watchtowers_start_enabler") => cli_watchtowers_start_enabler()?,
        Some("request_pegin") => cli_request_pegin()?,
        Some("accept_pegin") => cli_accept_pegin()?,
        Some("request_pegout") => cli_request_pegout()?,
        Some("advance_funds") => cli_advance_funds()?,
        Some("advance_funds_twice") => cli_advance_funds_twice()?,
        Some("invalid_reimbursement") => cli_invalid_reimbursement()?,
        Some("double_reimbursement") => cli_double_reimbursement()?,
        Some("operator_disabler") => cli_operator_disabler()?,
        Some("watchtower_disabler") => cli_watchtower_disabler()?,
        Some("self_disablers") => cli_self_disablers()?,
        // Utils
        Some("create_wallet") => cli_create_wallet(args.get(2))?,
        Some("latency") => cli_latency(args.get(2))?,
        Some("members_balance") => cli_members_balance()?,
        Some("wallet_balance") => cli_wallet_balance()?,
        Some("fund_members") => cli_fund_members()?,
        Some("members_recover_funds") => cli_members_recover_funds()?,
        Some("user_recover_funds") => cli_user_recover_funds()?,
        Some("wallet_recover_funds") => cli_wallet_recover_funds()?,
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

fn print_cmd_help(cmd: &str, description: &str) {
    println!(
        "  cargo run --release --example union {:<30} - {}",
        cmd, description
    );
}

fn print_usage() {
    println!("Protocol examples:");
    print_cmd_help("committee", "Setups a new committee");
    print_cmd_help("request_pegin", "Setups a request pegin");
    print_cmd_help("accept_pegin", "Setups the accept peg in protocol");
    print_cmd_help("request_pegout", "Setups the request peg out protocol");
    print_cmd_help("advance_funds", "Performs an advancement of funds");
    print_cmd_help("advance_funds_twice", "Performs advancement of funds twice");
    print_cmd_help(
        "invalid_reimbursement",
        "Forces invalid reimbursement to test challenge tx",
    );
    print_cmd_help(
        "watchtowers_start_enabler",
        "Dispatch WT start enabler transactions",
    );
    print_cmd_help(
        "self_disablers",
        "Dispatch WT and OP self disablers transactions",
    );
    print_cmd_help(
        "operator_disabler",
        "Dispatch OP disabler directory transactions",
    );
    print_cmd_help(
        "watchtower_disabler",
        "Dispatch WT disabler directory transactions",
    );

    // Testing commands
    println!("\nUtility commands:");
    print_cmd_help("setup_bitcoin_node", "Sets up Bitcoin node only");
    print_cmd_help(
        "create_wallet",
        "Create wallet: key pair and address. (optionally pass network: regtest, testnet, bitcoin)",
    );
    print_cmd_help("wallet_balance", "Print Master wallet balance");
    print_cmd_help(
        "latency",
        "Analyses latency to the Bitcoin node. (optionally pass network: regtest, testnet, bitcoin)",
    );
    print_cmd_help("members_balance", "Print members balance");
    print_cmd_help(
        "fund_members",
        "Funds all committee members from master wallet with a testing amount",
    );
    print_cmd_help(
        "members_recover_funds",
        "Send all members funds to master wallet address",
    );
    print_cmd_help(
        "user_recover_funds",
        "Send user funds to master wallet address",
    );
    print_cmd_help(
        "wallet_recover_funds",
        "Send master wallet funds to address",
    );
}

fn cli_create_wallet(network: Option<&String>) -> Result<()> {
    let network = string_to_network(network)?;
    create_wallet(network)?;
    Ok(())
}

fn cli_latency(network: Option<&String>) -> Result<()> {
    let network = string_to_network(network)?;
    dev::latency(network)?;
    Ok(())
}

pub fn setup_bitcoin_node() -> Result<()> {
    bitcoin::stop_existing_bitcoind()?;
    let (_bitcoin_client, _bitcoind) = bitcoin::prepare_bitcoin()?;

    Ok(())
}

pub fn cli_committee() -> Result<()> {
    let mut wallet = get_master_wallet()?;
    committee(&mut wallet)?;
    Ok(())
}

pub fn cli_watchtowers_start_enabler() -> Result<()> {
    let mut wallet = get_master_wallet()?;
    let committee = committee(&mut wallet)?;

    dispatch_wt_start_enabler(&committee)?;
    Ok(())
}

pub fn cli_request_pegin() -> Result<()> {
    let (committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;

    request_pegin(committee.public_key()?, &mut user)?;
    Ok(())
}

pub fn cli_accept_pegin() -> Result<()> {
    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;

    request_and_accept_pegin(&mut committee, &mut user)?;
    Ok(())
}

pub fn cli_request_pegout() -> Result<()> {
    request_pegout()?;
    Ok(())
}

pub fn cli_advance_funds() -> Result<()> {
    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;
    let (slot_index, _) = request_and_accept_pegin(&mut committee, &mut user)?;

    advance_funds(&mut committee, user.public_key()?, slot_index, true)?;
    Ok(())
}

pub fn cli_advance_funds_twice() -> Result<()> {
    let (mut committee, mut user, _) = pegin_setup(2, NETWORK == Network::Regtest)?;

    // First advance should use funding UTXO
    let (slot_index, _) = request_and_accept_pegin(&mut committee, &mut user)?;
    advance_funds(&mut committee, user.public_key()?, slot_index, true)?;

    // Second advance should use change UTXO and Operator Take UTXO
    let (slot_index, _) = request_and_accept_pegin(&mut committee, &mut user)?;
    advance_funds(&mut committee, user.public_key()?, slot_index, true)?;

    Ok(())
}

pub fn cli_invalid_reimbursement() -> Result<()> {
    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;
    let (slot_index, _) = request_and_accept_pegin(&mut committee, &mut user)?;

    invalid_reimbursement(&mut committee, slot_index)?;
    Ok(())
}
pub fn cli_self_disablers() -> Result<()> {
    if HIGH_FEE_NODE_ENABLED {
        // Due to self disablers does not have speedup by now
        info!("This example works better with a client node with low fees. Please disable HIGH_FEE_NODE_ENABLED and try again.");
        return Ok(());
    }

    let committee = committee(&mut get_master_wallet()?)?;
    let committee_id = committee.committee_id();

    for member in committee.members {
        let dispute_core_pid =
            get_dispute_core_pid(committee_id, &member.keyring.take_pubkey.unwrap());

        let tx = member
            .dispatch_transaction_by_name(dispute_core_pid, WT_SELF_DISABLER_TX.to_string())?;
        info!(
            "Dispatched {} with txid: {}",
            WT_SELF_DISABLER_TX,
            tx.compute_txid()
        );

        if member.role == ParticipantRole::Prover {
            let tx = member
                .dispatch_transaction_by_name(dispute_core_pid, OP_SELF_DISABLER_TX.to_string())?;
            info!(
                "Dispatched {} with txid: {}",
                OP_SELF_DISABLER_TX,
                tx.compute_txid()
            );
        }
    }

    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;
    Ok(())
}

pub fn cli_double_reimbursement() -> Result<()> {
    // NOTE: This example works better with a client node with low fees.
    // It require a fine timming to dispatch TXs and that's hard to reach if there is high fees
    // Key: Second reimbursement kickoff tx should be dispatched right after the first reimbursement kickoff tx is mined
    // and before the operator take is mined.
    if HIGH_FEE_NODE_ENABLED {
        info!("This example works better with a client node with low fees. Please disable HIGH_FEE_NODE_ENABLED and try again.");
        return Ok(());
    }

    let (mut committee, mut user, _) = pegin_setup(2, NETWORK == Network::Regtest)?;

    // Accept 2 pegins to have 2 operator take TXs to dispatch
    let (slot_index, _) = request_and_accept_pegin(&mut committee, &mut user)?;
    (_, _) = request_and_accept_pegin(&mut committee, &mut user)?;

    // Advance funds to the first pegin so it dispatch OP_INITIAL_SETUP and REIMBURSETMENT_TX for slot 0
    let operator_id = advance_funds(&mut committee, user.public_key()?, slot_index, false)?;

    // Wait some blocks to get INITIAL_SETUP and REIMBURSEMENT_TX mined
    wait_for_blocks(&committee.bitcoin_client, 3)?;

    // Dispatch second reimbusement without advancing funds.
    // It should be dispatched before the OPERATOR_TAKE_TX from the first pegin is mined
    info!(
        "Forcing member {} to dispatch another reimbursement transaction...",
        operator_id
    );
    let pegout_id = vec![0; 32]; // fake pegout id, it's trying to cheat
    committee.members[operator_id].dispatch_reimbursement(
        committee.committee_id(),
        slot_index + 1,
        pegout_id,
    )?;

    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;
    Ok(())
}

pub fn cli_members_balance() -> Result<()> {
    let mut committee = Committee::new(STREAM_DENOMINATION, NETWORK)?;
    committee.setup_keys()?;

    info!("Members balances:");
    print_members_balances(committee.members.as_slice())?;
    Ok(())
}

pub fn cli_wallet_balance() -> Result<()> {
    let mut wallet = get_master_wallet()?;
    let address = wallet.wallet.receive_address()?;

    info!("Master Wallet info:");
    info!("Address: {}", address);

    print_balance(&wallet)?;
    Ok(())
}

pub fn cli_wallet_recover_funds() -> Result<()> {
    let mut wallet = get_master_wallet()?;
    let address = "tb1qnfgpa7wlmjs435x6nrpv7p6yrvwe8gkscwfv0q".to_string();

    info!("Master Wallet info:");
    print_balance(&wallet)?;

    wallet_recover_funds(&mut wallet, address)?;
    Ok(())
}

pub fn cli_members_recover_funds() -> Result<()> {
    let mut committee = Committee::new(STREAM_DENOMINATION, NETWORK)?;
    committee.setup_keys()?;

    let mut wallet = get_master_wallet()?;
    let address = wallet.wallet.receive_address()?;

    recover_funds(
        committee.members.as_slice(),
        address.to_string(),
        wallet.network(),
    )?;

    wait_for_blocks(&committee.bitcoin_client, 1)?;
    thread::sleep(Duration::from_secs(5)); // wait for the wallet to update

    info!("Balances after funds recovery:");
    print_members_balances(committee.members.as_slice())?;
    print_balance(&wallet)?;

    Ok(())
}

pub fn cli_user_recover_funds() -> Result<()> {
    let user = get_user()?;
    let mut master_wallet = get_master_wallet()?;
    let address = master_wallet.wallet.receive_address()?;

    info!("Master wallet balance before recovery:");
    print_balance(&master_wallet)?;

    recover_user_funds(&user, address.to_string())?;

    wait_for_blocks(&BitcoinWrapper::new(user.bitcoin_client, user.network), 1)?;
    thread::sleep(Duration::from_secs(5)); // wait for the wallet to update

    info!("Master wallet balance after recovery:");
    print_balance(&master_wallet)?;

    Ok(())
}

pub fn cli_fund_members() -> Result<()> {
    let mut committee = Committee::new(STREAM_DENOMINATION, NETWORK)?;
    committee.setup_keys()?;

    info!("Balances before funding:");
    print_members_balances(committee.members.as_slice())?;

    let mut wallet = get_master_wallet()?;

    let amount = 10_000;
    fund_members(&mut wallet, committee.members.as_slice(), amount)?;

    wait_for_blocks(&committee.bitcoin_client, 1)?;

    thread::sleep(Duration::from_secs(10)); // wait for the wallet to update
    info!("Balances after funding:");
    print_members_balances(committee.members.as_slice())?;

    print_balance(&wallet)?;
    Ok(())
}

pub fn cli_operator_disabler() -> Result<()> {
    // NOTE: This example works better with a client node with low fees.
    // It require a fine timming to dispatch TXs and that's hard to reach if there is high fees
    // Key: Second reimbursement kickoff tx should be dispatched right after the first reimbursement kickoff tx is mined
    // and before the operator take is mined.
    if HIGH_FEE_NODE_ENABLED {
        info!("This example works better with a client node with low fees. Please disable HIGH_FEE_NODE_ENABLED and try again.");
        return Ok(());
    }

    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;

    if committee.members.len() < 3 {
        info!("This example requires 3 committee members or more.");
        info!("Current members: {}", committee.members.len());
        return Ok(());
    }

    let full_penalization_pid = get_full_penalization_pid(committee.committee_id());

    // Dispatch OP_DISABLER_DIRECTORY_TX for each operator
    // Temporary test due to it's not connected to dispute channels yet
    for (op_index, member) in committee.members.iter().enumerate() {
        if member.role == ParticipantRole::Prover {
            // Dispatch OP_INITIAL_DEPOSIT_TX, it has the funding UTXO for OP_DISABLER_DIRECTORY_TX
            // and OP_INITIAL_DEPOSIT_TX is not dispatched until there is a reimbursement
            let dispute_core_pid = get_dispute_core_pid(
                committee.committee_id(),
                &member.keyring.take_pubkey.unwrap(),
            );
            let tx = committee.members[op_index].dispatch_transaction_by_name(
                dispute_core_pid,
                OP_INITIAL_DEPOSIT_TX.to_string(),
            )?;

            info!(
                "Dispatched {} with txid: {}",
                OP_INITIAL_DEPOSIT_TX,
                tx.compute_txid()
            );

            thread::sleep(Duration::from_secs(2));
            wait_for_blocks(&committee.bitcoin_client, 1)?;

            let wt_index = (op_index + 1) % committee.members.len();
            let tx_name = double_indexed_name(OP_DISABLER_DIRECTORY_TX, op_index, wt_index);

            let tx = committee.members[wt_index]
                .dispatch_transaction_by_name(full_penalization_pid, tx_name.clone())?;

            info!("Dispatched {} with txid: {}", tx_name, tx.compute_txid());
        }
    }
    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;

    let (slot_index, _) = request_and_accept_pegin(&mut committee, &mut user)?;

    // NOTE: When doing an advance funds, the operator will try to dispatch its OP_INITIAL_DEPOSIT_TX in order to send the REIMBURSEMENT_KICKOFF_TX
    // In this example we already dispatched OP_INITIAL_DEPOSIT_TX above, so you will see an error in the logs
    // Advance funds to dispatch REIMBURSEMENT_KICKOFF_TX without challenge (just for testing purposes)
    let operator_index = advance_funds(&mut committee, user.public_key()?, slot_index, false)?;
    wait_for_blocks(
        &committee.bitcoin_client,
        DISPUTE_CORE_SHORT_TIMELOCK as u32 + 2,
    )?;

    // Its the watchtower who should dispatch the operator disabler directory tx in the step above
    let watchtower_challenger_index = (operator_index + 1) % committee.members.len();
    let watchtower_honest_index = (operator_index + 2) % committee.members.len();

    // Dispatch OP_LAZY_DISABLER_TX to disable reimbursement kickoff for `slot_index`
    let tx_name = triple_indexed_name(
        OP_LAZY_DISABLER_TX,
        operator_index,
        watchtower_challenger_index,
        slot_index,
    );

    // watchtower_honest_index is dispatching tx of watchtower_challenger_index in case it's not doing it.
    let tx = committee.members[watchtower_honest_index]
        .dispatch_transaction_by_name(full_penalization_pid, tx_name.clone())?;

    info!("Dispatched {} with txid: {}", tx_name, tx.compute_txid());

    // Dispatch OP_DISABLER_TX to disable operator enabler for `slot_index + 1`
    let tx_name = triple_indexed_name(
        OP_DISABLER_TX,
        operator_index,
        watchtower_challenger_index,
        slot_index + 1,
    );

    // watchtower_honest_index is dispatching tx of watchtower_challenger_index in case it's not doing it.
    let tx = committee.members[watchtower_honest_index]
        .dispatch_transaction_by_name(full_penalization_pid, tx_name.clone())?;

    info!("Dispatched {} with txid: {}", tx_name, tx.compute_txid());

    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;

    Ok(())
}

pub fn cli_watchtower_disabler() -> Result<()> {
    // NOTE: This example works better with a client node with low fees.
    if HIGH_FEE_NODE_ENABLED {
        info!("This example works better with a client node with low fees. Please disable HIGH_FEE_NODE_ENABLED and try again.");
        return Ok(());
    }

    let (committee, _user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;

    if committee.members.len() < 3 {
        info!("This example requires 3 committee members or more.");
        info!("Current members: {}", committee.members.len());
        return Ok(());
    }

    if committee.members[0].role != ParticipantRole::Prover
        || committee.members[1].role != ParticipantRole::Prover
        || committee.members[2].role != ParticipantRole::Verifier
        || committee.members[3].role != ParticipantRole::Verifier
    {
        info!("This example requires 2 operators and 2 watchtowers in the committee.");
        return Ok(());
    }

    let full_penalization_pid = get_full_penalization_pid(committee.committee_id());

    // Each watchtower just can be challenged and penalized by an operator.
    // Challenge pairs (watchtower_index, operator_index)
    let challenge_pairs: Vec<(usize, usize)> = [(0, 1), (1, 0), (2, 0), (3, 1)].to_vec();

    // Dispatch WT_START_ENABLER, it has the funding UTXO for WT_DISABLER_DIRECTORY_TX
    // and WT_START_ENABLER is not dispatched until there is a challenge
    dispatch_wt_start_enabler(&committee)?;

    // Dispatch WT_DISABLER_DIRECTORY_TX for each watchtower
    // Temporary test due to it's not connected to dispute channels yet
    for (wt_index, op_index) in challenge_pairs {
        let tx_name = double_indexed_name(WT_DISABLER_DIRECTORY_TX, wt_index, op_index);

        let tx = committee.members[wt_index]
            .dispatch_transaction_by_name(full_penalization_pid, tx_name.clone())?;

        info!("Dispatched {} with txid: {}", tx_name, tx.compute_txid());
        wait_for_blocks(&committee.bitcoin_client, 1)?;

        // Its the operator who should dispatch the watchtower y disabler directory tx in the step above
        let op_honest_index = (wt_index + 2) % committee.members.len();

        // Dispatch WT_DISABLER_TX to disable watchtower start enabler enabler for operator_enabler
        for member_index_to_disable in 0..committee.members.len() {
            let tx_name =
                triple_indexed_name(WT_DISABLER_TX, wt_index, op_index, member_index_to_disable);

            // operator_enabler_index is dispatching tx of op_index in case it's not doing it.
            let tx = committee.members[op_honest_index]
                .dispatch_transaction_by_name(full_penalization_pid, tx_name.clone())?;

            info!("Dispatched {} with txid: {}", tx_name, tx.compute_txid());
        }
    }
    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;

    Ok(())
}

pub fn committee(wallet: &mut MasterWallet) -> Result<Committee> {
    // A new package is created. A committee is selected. Union client requests the setup of the
    // corresponding keys and programs.
    let mut committee = Committee::new(STREAM_DENOMINATION, NETWORK)?;
    committee.setup_keys()?;

    info!("Balances before funding:");
    print_members_balances(committee.members.as_slice())?;

    let amount = committee.get_total_funds_value();
    fund_members(wallet, committee.members.as_slice(), amount)?;

    wait_for_blocks(&committee.bitcoin_client, 1)?;
    thread::sleep(Duration::from_secs(10)); // wait for the wallet to update

    info!("Balances after funding:");
    print_members_balances(committee.members.as_slice())?;

    committee.setup_dispute_protocols()?;
    committee.setup_full_penalization()?;

    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;

    info!("Balances after dispute core protocol:");
    print_members_balances(committee.members.as_slice())?;

    info!("Committee setup complete.");
    confirm_to_continue();
    Ok(committee)
}

pub fn dispatch_wt_start_enabler(committee: &Committee) -> Result<()> {
    for member in committee.members.iter() {
        let protocol_id = get_dispute_core_pid(
            committee.committee_id(),
            &member.keyring.take_pubkey.unwrap(),
        );

        info!(
            "Dispatching transaction: {}, protocol id: {}",
            WT_START_ENABLER_TX, protocol_id,
        );

        member.dispatch_transaction_by_name(protocol_id, WT_START_ENABLER_TX.to_string())?;
    }

    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;

    Ok(())
}

pub fn request_pegin(committee_public_key: PublicKey, user: &mut User) -> Result<(Txid, u64)> {
    let amount: u64 = STREAM_DENOMINATION; // This should be replaced with the actual amount of the peg-in request
    let request_pegin_txid = user.request_pegin(&committee_public_key, amount)?;

    thread::sleep(Duration::from_secs(5)); // wait for the bitcoin node to update
    wait_for_blocks(
        &BitcoinWrapper::new_from_config(&user.config)?,
        get_blocks_to_wait(),
    )?;
    thread::sleep(Duration::from_secs(5)); // wait for the coordinator to update

    user.get_request_pegin_spv(request_pegin_txid)?;

    info!("Request pegin completed.");
    confirm_to_continue();
    Ok((request_pegin_txid, amount))
}

pub fn request_and_accept_pegin(
    committee: &mut Committee,
    user: &mut User,
) -> Result<(usize, u64)> {
    let (request_pegin_txid, amount) = request_pegin(committee.public_key()?, user)?;

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
    let accept_pegin_tx = committee.members[0]
        .dispatch_transaction_by_name(protocol_id, ACCEPT_PEGIN_TX.to_string())?;
    thread::sleep(Duration::from_secs(1));

    let accept_pegin_txid = accept_pegin_tx.compute_txid();
    info!("Accept peg-in TX dispatched. Txid: {}", accept_pegin_txid);
    print_link(NETWORK, accept_pegin_txid);

    if NETWORK == Network::Regtest || ask_user_confirmation("Dispatch speedup transaction?: ") {
        user.create_and_dispatch_speedup(
            OutPoint {
                txid: accept_pegin_txid.into(),
                vout: 1,
            },
            get_accept_pegin_fee()?,
        )?;
    }

    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;
    committee.wait_for_spv_proof(accept_pegin_txid)?;

    info!("Pegin accepted and confirmed.");
    confirm_to_continue();
    Ok((slot_index, amount))
}

pub fn request_pegout() -> Result<()> {
    let (mut committee, mut user, _) = pegin_setup(1, true)?;
    let (slot_index, amount) = request_and_accept_pegin(&mut committee, &mut user)?;

    let user_pubkey = user.public_key()?;
    let stream_id = 0; // This should be replaced with the actual stream ID
    let packet_number = 0; // This should be replaced with the actual packet number
    let pegout_id = vec![0; 32]; // This should be replaced with the actual peg-out ID
    let pegout_signature_hash =
        hex::decode("dea309782c51c214e276f9fe20015d778dab47d41e704705844401525c65aea4")?; // This should be replaced with the actual peg-out signature hash
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

    info!("User take TX dispatched. Txid: {}", user_take_utxo.0);
    print_link(NETWORK, user_take_utxo.0);

    if NETWORK == Network::Regtest || ask_user_confirmation("Dispatch speedup transaction?: ") {
        user.create_and_dispatch_user_take_speedup(user_take_utxo.clone(), get_user_take_fee()?)?;
    }

    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;
    committee.wait_for_spv_proof(user_take_utxo.0)?;

    info!("Pegout request accepted and confirmed.");
    confirm_to_continue();
    Ok(())
}

pub fn advance_funds(
    committee: &mut Committee,
    user_pubkey: PublicKey,
    slot_index: usize,
    should_wait: bool,
) -> Result<usize> {
    // This came from the contracts
    let pegout_id = vec![0; 32]; // Placeholder for the actual peg-out ID

    // Get the selected operator's take public key (simulating what Union Client would provide)
    let operator_id = 1; // Placeholder for the actual operator ID
    let selected_operator_pubkey = committee.members[operator_id].keyring.take_pubkey.unwrap();

    committee.advance_funds(
        slot_index,
        user_pubkey,
        pegout_id,
        selected_operator_pubkey,
        get_advance_funds_fee()?,
    )?;

    if should_wait {
        wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;
    }

    info!("Advance funds complete.");
    confirm_to_continue();
    Ok(operator_id)
}

pub fn invalid_reimbursement(committee: &mut Committee, slot_index: usize) -> Result<()> {
    info!("Forcing member 0 to dispatch invalid reimbursement transaction...");
    // Force member 0 to dispatch reimbursement without proper advancement setup
    let committee_id = committee.committee_id();
    let operator_index = 0;
    let member: &mut Member = &mut committee.members[operator_index];
    let operator_pubkey = member.keyring.take_pubkey.unwrap();

    // If just one member execute advance_funds the other one will not know it should advance funds and will try to challenge it.
    member.advance_funds(
        Uuid::new_v4(),
        committee_id,
        slot_index,
        operator_pubkey,
        vec![0; 32],
        operator_pubkey,
        get_advance_funds_fee()?,
    )?;

    info!("Starting mining loop to ensure challenge transaction is dispatched...");
    wait_for_blocks(
        &committee.bitcoin_client,
        get_blocks_to_wait() + DISPUTE_CORE_LONG_TIMELOCK as u32,
    )?;

    info!("Invalid reimbursement test complete.");
    Ok(())
}

fn get_and_increment_slot_index() -> usize {
    unsafe {
        let current_index = SLOT_INDEX_COUNTER;
        SLOT_INDEX_COUNTER += 1;
        current_index
    }
}

fn confirm_to_continue() {
    if NETWORK == Network::Regtest {
        return;
    }

    if !ask_user_confirmation(
        format!("Running in {} network. Do you want to continue?", NETWORK).as_str(),
    ) {
        print!("Operation cancelled by user.\n");
        std::process::exit(0);
    }
}

fn get_master_wallet() -> Result<MasterWallet> {
    let wallet = MasterWallet::new(
        NETWORK,
        load_private_key_from_env(NETWORK),
        load_change_key_from_env(NETWORK),
    )?;
    Ok(wallet)
}

fn get_user() -> Result<User> {
    let id = if NETWORK == Network::Testnet {
        "testnet_user_1"
    } else {
        "user_1"
    };

    let user = User::new(id)?;
    Ok(user)
}

fn pegin_setup(
    pegin_quantity: usize,
    set_user_speedup: bool,
) -> Result<(Committee, User, MasterWallet)> {
    let mut wallet = get_master_wallet()?;
    let committee = committee(&mut wallet)?;
    let mut user = get_user()?;

    let amount = STREAM_DENOMINATION + user.get_request_pegin_fees();

    fund_user_pegin_utxos(&mut wallet, &mut user, amount, pegin_quantity)?;
    if set_user_speedup {
        fund_user_speedup(
            &mut wallet,
            &mut user,
            get_accept_pegin_fee()? * (pegin_quantity * 2) as u64,
        )?;
    }

    Ok((committee, user, wallet))
}

fn get_user_take_fee() -> Result<u64, anyhow::Error> {
    match NETWORK {
        Network::Regtest => Ok(3000),
        Network::Testnet => Ok(300),
        _ => Err(anyhow::anyhow!("Unsupported network")),
    }
}

fn get_accept_pegin_fee() -> Result<u64, anyhow::Error> {
    match NETWORK {
        Network::Regtest => Ok(5000),
        Network::Testnet => Ok(300),
        _ => Err(anyhow::anyhow!("Unsupported network")),
    }
}

fn get_advance_funds_fee() -> Result<u64, anyhow::Error> {
    match NETWORK {
        Network::Regtest => Ok(3000),
        Network::Testnet => Ok(300),
        _ => Err(anyhow::anyhow!("Unsupported network")),
    }
}

fn get_blocks_to_wait() -> u32 {
    match NETWORK {
        Network::Regtest => {
            if HIGH_FEE_NODE_ENABLED {
                15
            } else {
                2
            }
        }
        Network::Testnet => 1,
        _ => Err(anyhow::anyhow!("Unsupported network")).unwrap(),
    }
}

fn wait_for_blocks(bitcoin_client: &BitcoinWrapper, mut blocks: u32) -> Result<()> {
    bitcoin_client.wait_for_blocks(blocks)?;

    if NETWORK != Network::Regtest {
        while ask_user_confirmation(
            format!("{} blocks waited. Wait for an extra block?: ", blocks).as_str(),
        ) {
            blocks += 1;
            bitcoin_client.wait_for_blocks(1)?;
        }
    }
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
