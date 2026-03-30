use crate::{
    bitcoin::{BitcoinWrapper, HIGH_FEE_NODE_ENABLED},
    participants::{
        committee::Committee,
        common::{
            calculate_taproot_key_path_sighash, format_solidity_data_file, get_user_take_tx,
            PEGIN_CONFIRMATIONS,
        },
        member::Member,
        user::User,
    },
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
use ::bitcoin::{hashes::Hash, Network, OutPoint, PublicKey, Transaction, Txid};
use anyhow::Result;
use bitvmx_client::{
    program::{
        participant::ParticipantRole,
        protocols::{
            dispute::program_input,
            union::{
                common::{
                    get_accept_pegin_pid, get_advance_funds_pid, get_dispute_channel_pid,
                    get_dispute_core_pid, indexed_name,
                },
                types::{
                    FundsAdvanced, ACCEPT_PEGIN_TX, ADVANCE_FUNDS_TX, CANCEL_TAKE0_TX,
                    CHALLENGE_TX, INPUT_NOT_REVEALED_TX, OPERATOR_TAKE_TX, OPERATOR_WON_TX,
                    OP_SELF_DISABLER_TX, REIMBURSEMENT_KICKOFF_TX, REQUEST_PEGIN_TX,
                    REVEAL_INPUT_TX, WT_SELF_DISABLER_TX,
                    WT_START_ENABLER_TX,
                },
            },
        },
        variables::VariableTypes,
    },
    types::OutgoingBitVMXApiMessages,
};
use core::convert::Into;
use std::{env, thread, time::Duration};
use tracing::{error, info};
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

// Fixed pegout ID used for testing (equivalent to bytes32(uint256(1)) in Solidity)
pub const TESTING_PEGOUT_ID: [u8; 32] = {
    let mut id = [0u8; 32];
    id[31] = 1;
    id
};

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
        Some("challenge") => cli_challenge(args.get(2))?,
        Some("challenge_reason") => cli_challenge_reason(args.get(2))?,
        Some("wt_disabler") => cli_wt_disabler()?,
        Some("op_no_cosign") => cli_op_no_cosign()?,
        Some("wt_no_challenge") => cli_wt_no_challenge()?,
        Some("input_not_revealed") => cli_input_not_revealed()?,
        Some("double_challenge") => cli_double_challenge()?,
        Some("self_disablers") => cli_self_disablers()?,
        Some("cancel_take0") => cli_cancel_take0()?,
        Some("reject_pegin") => cli_reject_pegin()?,
        // Utils
        Some("create_wallet") => cli_create_wallet(args.get(2))?,
        Some("latency") => cli_latency(args.get(2))?,
        Some("members_balance") => cli_members_balance()?,
        Some("wallet_balance") => cli_wallet_balance()?,
        Some("fund_members") => cli_fund_members()?,
        Some("members_recover_funds") => cli_members_recover_funds()?,
        Some("user_recover_funds") => cli_user_recover_funds()?,
        Some("wallet_recover_funds") => cli_wallet_recover_funds()?,
        Some("solidity_txs") => cli_solidity_txs()?,
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
    print_cmd_help(
        "reject_pegin",
        "Dispatch REJECT_PEGIN_TX to reject a peg in request before it's accepted",
    );
    print_cmd_help("accept_pegin", "Setups the accept peg in protocol");
    print_cmd_help(
        "cancel_take0",
        "Dispatch CANCEL_TAKE0_TX to disable UserTake Protocol",
    );
    print_cmd_help("request_pegout", "Setups the request peg out protocol");
    print_cmd_help("advance_funds", "Performs an advancement of funds");
    print_cmd_help("advance_funds_twice", "Performs advancement of funds twice");
    print_cmd_help(
        "challenge",
        "Forces challenge. It receives `op` or `wt` as argument to decide the winner",
    );
    print_cmd_help(
        "challenge_reason",
        "Forces challenge with a particular reason with a WT winning it. It receives a list of reasons separated by commas. `slot,pegout_id,operator_pubkey,funds_advanced`",
    );
    print_cmd_help(
        "wt_disabler",
        "Forces an already disabler watchtower to open a new challenge to dispatch WT_DISABLER_TX",
    );
    print_cmd_help(
        "op_no_cosign",
        "Forces to dispatch OP_NO_COSIGN_TX after a challenge",
    );
    print_cmd_help(
        "wt_no_challenge",
        "Forces to dispatch WT_NO_CHALLENGE_TX after a challenge",
    );
    print_cmd_help(
        "input_not_revealed",
        "Forces INPUT_NOT_REVEALED_TX to be dispatched",
    );
    print_cmd_help(
        "double_challenge",
        "Forces to send TWO_DISPUTE_PENALIZATION_TX to test double challenge handling",
    );
    print_cmd_help(
        "watchtowers_start_enabler",
        "Dispatch WT start enabler transactions",
    );
    print_cmd_help(
        "self_disablers",
        "Dispatch WT and OP self disablers transactions",
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
    print_cmd_help("print_txs", "Print protocol TXs to create contracts tests");
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

    request_pegin(&committee, &mut user)?;
    Ok(())
}

pub fn cli_reject_pegin() -> Result<()> {
    let (committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;

    let (txid, _, _) = request_pegin(&committee, &mut user)?;

    let member_index = 1;
    committee.members[member_index].reject_pegin(committee.committee_id(), txid, member_index)?;

    thread::sleep(Duration::from_secs(1));
    wait_for_blocks(&committee.bitcoin_client, 5)?;

    Ok(())
}

pub fn cli_accept_pegin() -> Result<()> {
    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;

    request_and_accept_pegin(&mut committee, &mut user)?;
    Ok(())
}

pub fn cli_cancel_take0() -> Result<()> {
    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;

    let (slot_index, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;
    thread::sleep(Duration::from_secs(1));

    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;

    let op_index = 1;
    let cancel_name = indexed_name(CANCEL_TAKE0_TX, op_index);

    info!("Forcing member to cancel accept pegin transaction...");
    let tx = committee.members[op_index].dispatch_transaction_by_name(
        get_accept_pegin_pid(committee.committee_id(), slot_index),
        cancel_name.clone(),
    )?;

    info!("{} dispatched. Txid: {}", cancel_name, tx.compute_txid());

    thread::sleep(Duration::from_secs(1));
    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;

    Ok(())
}

pub fn cli_request_pegout() -> Result<()> {
    request_pegout()?;
    Ok(())
}

pub fn cli_advance_funds() -> Result<()> {
    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;
    let (slot_index, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;

    advance_funds(&mut committee, user.public_key()?, slot_index, true)?;
    Ok(())
}

pub fn cli_advance_funds_twice() -> Result<()> {
    let (mut committee, mut user, _) = pegin_setup(2, NETWORK == Network::Regtest)?;

    // First advance should use funding UTXO
    let (slot_index, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;
    advance_funds(&mut committee, user.public_key()?, slot_index, true)?;

    // Second advance should use change UTXO and Operator Take UTXO
    let (slot_index, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;
    advance_funds(&mut committee, user.public_key()?, slot_index, true)?;

    Ok(())
}

pub fn cli_solidity_txs() -> Result<()> {
    if HIGH_FEE_NODE_ENABLED {
        info!("This example run faster with a client node with low fees. You can disable it setting HIGH_FEE_NODE_ENABLED to false.");
    }

    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;
    let (slot_index, _, _, request_pegin_tx) =
        request_and_accept_pegin(&mut committee, &mut user)?;
    let op_index = advance_funds(&mut committee, user.public_key()?, slot_index, false)?;

    let committee_agg_key = committee.public_key()?;
    let dispute_keys = committee.get_dispute_keys();
    let operator_count = committee.members.iter().filter(|m| m.role == ParticipantRole::Prover).count();
    let watchtower_count = committee.members.iter().filter(|m| m.role == ParticipantRole::Verifier).count();

    let committee_id = committee.committee_id();
    let accept_pegin_pid = get_accept_pegin_pid(committee_id, slot_index);
    let dispute_core_pid = get_dispute_core_pid(
        committee_id,
        &committee.members[op_index].keyring.take_pubkey.unwrap(),
    );
    let advance_funds_pid = get_advance_funds_pid(committee_id, slot_index);

    let op_take_name = indexed_name(OPERATOR_TAKE_TX, op_index);
    let op_won_name = indexed_name(OPERATOR_WON_TX, op_index);
    let reimb_name = indexed_name(REIMBURSEMENT_KICKOFF_TX, slot_index);
    let challenge_name = indexed_name(CHALLENGE_TX, slot_index);
    let reveal_name = indexed_name(REVEAL_INPUT_TX, slot_index);
    let input_not_revealed_name = indexed_name(INPUT_NOT_REVEALED_TX, slot_index);

    let named_txs: Vec<(&str, Transaction)> = vec![
        (REQUEST_PEGIN_TX, request_pegin_tx),
        (
            ADVANCE_FUNDS_TX,
            get_transaction(&committee.members[op_index], advance_funds_pid, ADVANCE_FUNDS_TX)?,
        ),
        (
            ACCEPT_PEGIN_TX,
            get_transaction(&committee.members[op_index], accept_pegin_pid, ACCEPT_PEGIN_TX)?,
        ),
        (
            &op_take_name,
            get_transaction(&committee.members[op_index], accept_pegin_pid, &op_take_name)?,
        ),
        (
            &op_won_name,
            get_transaction(&committee.members[op_index], accept_pegin_pid, &op_won_name)?,
        ),
        (
            &reimb_name,
            get_transaction(&committee.members[op_index], dispute_core_pid, &reimb_name)?,
        ),
        (
            &challenge_name,
            get_transaction(
                &committee.members[op_index + 1],
                dispute_core_pid,
                &challenge_name,
            )?,
        ),
        (
            &reveal_name,
            get_transaction(&committee.members[op_index], dispute_core_pid, &reveal_name)?,
        ),
        (
            &input_not_revealed_name,
            get_transaction(
                &committee.members[op_index + 1],
                dispute_core_pid,
                &input_not_revealed_name,
            )?,
        ),
    ];

    let export_txids = [
        REQUEST_PEGIN_TX,
        // ADVANCE_FUNDS_TX,
        ACCEPT_PEGIN_TX,
        // &op_take_name,
        // &op_won_name,
        &reimb_name,
        &challenge_name,
        &reveal_name,
        // &input_not_revealed_name,
    ];

    let solidity_file = format_solidity_data_file(
        &committee_agg_key,
        &dispute_keys,
        &user.public_key()?,
        &TESTING_PEGOUT_ID,
        op_index,
        operator_count,
        watchtower_count,
        &named_txs,
        &export_txids,
    );

    let output_path = match std::env::var("EXAMPLE_LOG_DIR") {
        Ok(log_dir) => std::path::PathBuf::from(log_dir).join("BitVMXCompatibilityData.sol"),
        Err(_) => std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../BitVMXCompatibilityData.sol"),
    };
    std::fs::write(&output_path, &solidity_file)?;
    info!("Written to: {}", output_path.display());
    Ok(())
}

fn get_transaction(member: &Member, protocol_id: Uuid, tx_name: &str) -> Result<Transaction> {
    member
        .bitvmx
        .get_transaction_by_name(protocol_id, tx_name.to_string())?;
    thread::sleep(std::time::Duration::from_millis(200));
    let tx = wait_until_msg!(&member.bitvmx, OutgoingBitVMXApiMessages::TransactionInfo(_, _, _tx) => _tx);
    Ok(tx)
}

pub fn cli_challenge(winner: Option<&String>) -> Result<()> {
    if HIGH_FEE_NODE_ENABLED {
        // Due to self disablers does not have speedup by now
        info!("This example works better with a client node with low fees. Please disable HIGH_FEE_NODE_ENABLED and try again.");
        return Ok(());
    }

    let op_wins = match winner {
        Some(val) if val == "op" => true,
        Some(val) if val == "wt" => false,
        _ => {
            error!("Please provide a winner: op/wt");
            return Ok(());
        }
    };

    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;
    let (slot_index, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;

    let op_index = 1;
    challenge(
        &mut committee,
        op_index,
        slot_index,
        true,
        op_wins,
        ChallengeReason::funds_advanced(),
    )?;
    Ok(())
}

pub fn cli_challenge_reason(input: Option<&String>) -> Result<()> {
    if HIGH_FEE_NODE_ENABLED {
        info!("This example works better with a client node with low fees. Please disable HIGH_FEE_NODE_ENABLED and try again.");
        return Ok(());
    }

    if input.is_none() {
        error!("Please provide a list of reasons separated by commas. `slot,pegout_id,operator_pubkey,funds_advanced`");
        return Ok(());
    }

    let reasons = input.unwrap();
    let slot = reasons.contains("slot");
    let pegout_id = reasons.contains("pegout_id");
    let operator_pubkey = reasons.contains("operator_pubkey");
    let funds_advanced = reasons.contains("funds_advanced");

    let challenge_reason = ChallengeReason {
        slot_index: slot,
        pegout_id,
        operator_pubkey,
        funds_advanced,
    };

    info!("Starting challenge with reason: {:?}", challenge_reason);

    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;
    let (slot_index, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;

    let op_index = 1;
    challenge(
        &mut committee,
        op_index,
        slot_index,
        true,
        false,
        challenge_reason,
    )?;
    Ok(())
}

pub fn cli_wt_disabler() -> Result<()> {
    if HIGH_FEE_NODE_ENABLED {
        // Due to self disablers does not have speedup by now
        info!("This example works better with a client node with low fees. Please disable HIGH_FEE_NODE_ENABLED and try again.");
        return Ok(());
    }

    let (mut committee, mut user, _) = pegin_setup(2, NETWORK == Network::Regtest)?;
    let (slot_index, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;

    // First challenge where WT are penalized. Operator 0 wins.
    let op_index = 0;
    challenge(
        &mut committee,
        op_index,
        slot_index,
        false,
        true,
        ChallengeReason::funds_advanced(),
    )?;
    let additional_blocks = 200;

    info!(
        "Starting mining {} blocks in loop to ensure challenges and DRP txs are dispatched...",
        additional_blocks
    );
    wait_for_blocks(
        &committee.bitcoin_client,
        get_blocks_to_wait() + additional_blocks as u32,
    )?;

    let (slot_index, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;

    // Now Operator 1 is challenged
    // In this second challenge WTs are already penalized. WT_DISABLERs should be dispatched.
    let op_index = 1;
    challenge(
        &mut committee,
        op_index,
        slot_index,
        true,
        true,
        ChallengeReason::funds_advanced(),
    )?;

    Ok(())
}

pub fn cli_op_no_cosign() -> Result<()> {
    if HIGH_FEE_NODE_ENABLED {
        // Due to self disablers does not have speedup by now
        info!("This example works better with a client node with low fees. Please disable HIGH_FEE_NODE_ENABLED and try again.");
        return Ok(());
    }

    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;
    let (slot_index, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;

    let op_index = 1;
    challenge(
        &mut committee,
        op_index,
        slot_index,
        false,
        true,
        ChallengeReason::funds_advanced(),
    )?;

    let blocks_to_wait = PEGIN_CONFIRMATIONS as u32 + 15; // Amount of blocks enough to allow WT to open a challenge but not enough to dispatch the OP_COSIGN_TX. Fine tunning may be required.
    info!("Mining {} blocks...", blocks_to_wait);
    wait_for_blocks(&committee.bitcoin_client, blocks_to_wait)?;

    // Shutdown operator to avoid him to respond to challenge with OP_COSIGN_TX
    committee.members[op_index].bitvmx.shutdown();

    // Amount of blocks enough to allow WT to dispatch OP_NO_COSIGN_TX and following TXs
    let blocks_to_wait = committee.stream_settings.op_no_cosign_timelock + PEGIN_CONFIRMATIONS + 30;
    info!("Mining {} blocks...", blocks_to_wait);
    wait_for_blocks(&committee.bitcoin_client, blocks_to_wait as u32)?;

    Ok(())
}

pub fn cli_wt_no_challenge() -> Result<()> {
    if HIGH_FEE_NODE_ENABLED {
        // Due to self disablers does not have speedup by now
        info!("This example works better with a client node with low fees. Please disable HIGH_FEE_NODE_ENABLED and try again.");
        return Ok(());
    }

    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;
    let (slot_index, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;
    let op_index = 1;

    challenge(
        &mut committee,
        op_index,
        slot_index,
        false,
        true,
        ChallengeReason::funds_advanced(),
    )?;

    let blocks_to_wait = PEGIN_CONFIRMATIONS as u32 + 22; // Amount of blocks enough to allow WT to open a challenge but not enough to dispatch the START_CH. Fine tunning may be required.
    info!("Mining {} blocks...", blocks_to_wait);
    wait_for_blocks(&committee.bitcoin_client, blocks_to_wait)?;

    for (wt_index, _) in committee.members.iter().enumerate() {
        if wt_index == op_index {
            continue;
        }

        // Shutdown watchtowers to avoid them to send START_CH
        committee.members[wt_index].bitvmx.shutdown();
    }
    // Amount of blocks enough to allow OP to dispatch WT_NO_CHALLENGE_TX and following TXs
    let blocks_to_wait =
        committee.stream_settings.wt_no_challenge_timelock + PEGIN_CONFIRMATIONS + 30;
    info!("Mining {} blocks...", blocks_to_wait);
    wait_for_blocks(&committee.bitcoin_client, blocks_to_wait as u32)?;

    Ok(())
}

pub fn cli_input_not_revealed() -> Result<()> {
    if HIGH_FEE_NODE_ENABLED {
        // Due to self disablers does not have speedup by now
        info!("This example works better with a client node with low fees. Please disable HIGH_FEE_NODE_ENABLED and try again.");
        return Ok(());
    }

    let (mut committee, mut user, _) = pegin_setup(1, NETWORK == Network::Regtest)?;
    let (slot_index, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;
    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;

    let op_index = 1;
    challenge(
        &mut committee,
        op_index,
        slot_index,
        false,
        false,
        ChallengeReason::funds_advanced(),
    )?;

    let blocks_to_wait = PEGIN_CONFIRMATIONS as u32 + 4; // Wait some blocks to mine ADVANCE_FUNDS_TX and REIMBURSEMENT_KICKOFF_TX. Fine tunning may be required.
    wait_for_blocks(&committee.bitcoin_client, blocks_to_wait)?;

    // Kill operator client after some blocks to simulate offline behavior
    committee.members[op_index].bitvmx.shutdown();

    // Wait some blocks to be able to dispatch and mine INPUT_NOT_REVEALED_TX
    let blocks_to_wait = committee.stream_settings.input_not_revealed_timelock as u32 + 10;
    wait_for_blocks(&committee.bitcoin_client, blocks_to_wait)?;

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

pub fn cli_double_challenge() -> Result<()> {
    if true {
        error!("This example is not implemented yet.");
        error!("Challenge transaction should be handled in dispute core and reveal transaction should be dispatched.");
        return Ok(());
    }

    // NOTE: This example works better with a client node with low fees.
    // It require a fine timming to dispatch TXs and that's hard to reach if there is high fees
    if HIGH_FEE_NODE_ENABLED {
        info!("This example works better with a client node with low fees. Please disable HIGH_FEE_NODE_ENABLED and try again.");
        return Ok(());
    }

    let (mut committee, mut user, _) = pegin_setup(2, NETWORK == Network::Regtest)?;

    // Accept 2 pegins to have 2 operator take TXs to dispatch
    let (slot_index, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;
    (_, _, _, _) = request_and_accept_pegin(&mut committee, &mut user)?;

    let operator_id = 1;
    // Dispatch first reimbusement without advancing funds.
    info!(
        "Forcing member {} to first reimbursement transaction...",
        operator_id
    );
    committee.members[operator_id].dispatch_reimbursement(
        committee.committee_id(),
        slot_index,
        vec![0; 32],
    )?;

    // Wait some blocks to get INITIAL_SETUP and REIMBURSEMENT_TX mined
    wait_for_blocks(&committee.bitcoin_client, PEGIN_CONFIRMATIONS as u32 + 3)?;

    // Dispatch second reimbusement without advancing funds.
    info!(
        "Forcing member {} to second reimbursement transaction...",
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

pub fn request_pegin(committee: &Committee, user: &mut User) -> Result<(Txid, u64, Transaction)> {
    let amount: u64 = STREAM_DENOMINATION;
    let committee_public_key = committee.public_key()?;
    let dispute_keys = committee.get_dispute_keys();
    let request_pegin_timelock = committee.stream_settings.request_pegin_timelock;

    let (request_pegin_txid, request_pegin_tx) = user.request_pegin(
        &committee_public_key,
        amount,
        dispute_keys.as_slice(),
        request_pegin_timelock,
    )?;

    thread::sleep(Duration::from_secs(5)); // wait for the bitcoin node to update
    wait_for_blocks(
        &BitcoinWrapper::new_from_config(&user.config)?,
        get_blocks_to_wait(),
    )?;
    thread::sleep(Duration::from_secs(5)); // wait for the coordinator to update

    user.get_request_pegin_spv(request_pegin_txid)?;

    info!("Request pegin completed.");
    confirm_to_continue();
    Ok((request_pegin_txid, amount, request_pegin_tx))
}

pub fn request_and_accept_pegin(
    committee: &mut Committee,
    user: &mut User,
) -> Result<(usize, u64, Transaction, Transaction)> {
    let (request_pegin_txid, amount, request_pegin_tx) = request_pegin(committee, user)?;

    // This came from the contracts
    let rootstock_address = user.get_rsk_address();
    let reimbursement_pubkey = user.public_key()?;
    let accept_pegin_sighash = vec![0; 32]; // This should be replaced with the actual sighash of the accept peg-in tx
    let slot_index = get_and_increment_slot_index(); // This should be replaced with the actual slot index

    committee.accept_pegin(
        committee.committee_id(),
        request_pegin_txid,
        amount,
        accept_pegin_sighash.clone(),
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
                vout: 2,
            },
            get_accept_pegin_fee()?,
        )?;
    }

    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;
    committee.members[0].wait_for_spv_proof(accept_pegin_txid)?;

    info!("Pegin accepted and confirmed.");
    confirm_to_continue();
    Ok((slot_index, amount, accept_pegin_tx, request_pegin_tx))
}

pub fn request_pegout() -> Result<()> {
    let (mut committee, mut user, _) = pegin_setup(1, true)?;
    let (slot_index, stream_value, accept_pegin_tx, _) =
        request_and_accept_pegin(&mut committee, &mut user)?;

    let user_pubkey = user.public_key()?;
    let pegout_id = vec![0; 32]; // This should be replaced with the actual peg-out ID

    // This is done in the contracts
    let user_take_tx = get_user_take_tx(stream_value, accept_pegin_tx.compute_txid(), user_pubkey);
    let user_take_sighash = calculate_taproot_key_path_sighash(
        &user_take_tx,
        0,
        &[
            accept_pegin_tx.output[0].clone(),
            accept_pegin_tx.output[1].clone(),
        ],
    )?;
    // End - This is done in the contracts

    let pegout_signature_hash = user_take_sighash; // This should be replaced with the actual peg-out signature hash

    let user_take_utxo = committee.request_pegout(
        user_pubkey,
        slot_index,
        stream_value,
        pegout_id,
        pegout_signature_hash.to_vec(),
    )?;

    info!("User take TX dispatched. Txid: {}", user_take_utxo.0);
    print_link(NETWORK, user_take_utxo.0);

    if NETWORK == Network::Regtest || ask_user_confirmation("Dispatch speedup transaction?: ") {
        user.create_and_dispatch_user_take_speedup(user_take_utxo.clone(), get_user_take_fee()?)?;
    }

    wait_for_blocks(&committee.bitcoin_client, get_blocks_to_wait())?;
    committee.members[0].wait_for_spv_proof(user_take_utxo.0)?;

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
    let pegout_id = TESTING_PEGOUT_ID.to_vec();

    // Get the selected operator's take public key (simulating what Union Client would provide)
    let operator_id = 1; // Placeholder for the actual operator ID
    let selected_operator_pubkey = committee.members[operator_id].keyring.take_pubkey.unwrap();

    committee.advance_funds(
        slot_index,
        user_pubkey,
        &pegout_id,
        selected_operator_pubkey,
        get_advance_funds_fee()?,
    )?;

    // Register this information with the info in AdvanceFundsRegistered event from RSK contract.
    let txid = Txid::all_zeros(); // Placeholder for the actual transaction ID of the advance funds transaction
    committee.advance_funds_registered(slot_index, &pegout_id, &selected_operator_pubkey, &txid)?;

    if should_wait {
        wait_for_blocks(
            &committee.bitcoin_client,
            get_blocks_to_wait() + committee.stream_settings.long_timelock as u32 + 10,
        )?;

        // Wait for the FundsAdvanced message
        let (program_id, name, variable_type) = wait_until_msg!(&committee.members[operator_id].bitvmx, OutgoingBitVMXApiMessages::Variable(_program_id, _name, _type) =>(_program_id, _name, _type));
        if name != FundsAdvanced::name() {
            return Err(anyhow::anyhow!(
                "Expected FundsAdvanced variable after advance funds, got {} from {}",
                name,
                program_id
            ));
        }

        let data: FundsAdvanced = match variable_type {
            VariableTypes::String(spv_json) => serde_json::from_str(&spv_json)?,
            _ => {
                return Err(anyhow::anyhow!(
                    "Expected String variable type after advance funds, got {:?}",
                    variable_type
                ))
            }
        };

        info!("FundsAdvanced message received: {:?}", data);
        committee.members[operator_id].wait_for_spv_proof(data.txid)?;
    }

    info!("Advance funds complete.");
    confirm_to_continue();
    Ok(operator_id)
}

fn challenge(
    committee: &mut Committee,
    operator_index: usize,
    slot_index: usize,
    should_wait: bool,
    op_wins: bool,
    chr: ChallengeReason,
) -> Result<usize> {
    info!("Forcing member 0 to dispatch invalid reimbursement transaction...");
    // Force member 0 to dispatch reimbursement without proper advancement setup
    let committee_id = committee.committee_id();
    let members_len = committee.members.len();

    let operator_pubkey = committee.members[operator_index]
        .keyring
        .take_pubkey
        .unwrap();
    let pegout_id = vec![0; 32]; // Pegout ID should be get from contracts event.

    let user_pubkey = committee.members[operator_index]
        .keyring
        .take_aggregated_key
        .unwrap(); // fake user pub key
    let wrong_operator_pubkey = committee.members[operator_index]
        .keyring
        .take_aggregated_key
        .unwrap(); // fake operator pubkey
    let wrong_pegout_id = vec![1; 32]; // fake pegout id
    let wrong_slot_index = slot_index + 1; // fake slot index

    // This operator is the one that will be challenged. So make advance funds with "correct" data.
    committee.members[operator_index].advance_funds(
        committee_id,
        slot_index,
        user_pubkey,
        vec![0; 32],
        operator_pubkey,
        get_advance_funds_fee()?,
    )?;

    // Force different challenge reasons for each WT to ensure all paths are tested
    let id = if chr.pegout_id {
        wrong_pegout_id.clone()
    } else {
        pegout_id.clone()
    };

    let slot = if chr.slot_index {
        wrong_slot_index
    } else {
        slot_index
    };

    let pubkey = if chr.operator_pubkey {
        wrong_operator_pubkey
    } else {
        operator_pubkey
    };

    for index in 0..members_len {
        if index == operator_index {
            continue;
        }

        // A wrong slot here, would be equivalent to a false trigger operator take
        committee.members[index].advance_funds(
            committee_id,
            slot,
            user_pubkey.clone(),
            pegout_id.clone(),
            pubkey,
            0,
        )?;
    }

    // If funds_advanced is true, watchtowers wont even know about funds_advance
    if !chr.funds_advanced {
        // Placeholder for the actual transaction ID of the advance funds transaction
        let txid = Txid::all_zeros();

        // Register this information with the info in AdvanceFundsRegistered event from RSK contract.
        committee.advance_funds_registered(slot, &id, &pubkey, &txid)?;
    }

    set_drp_input(
        &mut committee.members[operator_index],
        committee_id,
        members_len,
        operator_index,
        op_wins,
    )?;

    if should_wait {
        let additional_blocks = committee.stream_settings.long_timelock + 250;

        info!(
            "Starting mining {} blocks in loop to ensure challenges and DRP txs are dispatched...",
            additional_blocks
        );
        wait_for_blocks(
            &committee.bitcoin_client,
            get_blocks_to_wait() + additional_blocks as u32,
        )?;
    }

    info!("Challenge test complete.");
    Ok(operator_index)
}

fn set_drp_input(
    member: &mut Member,
    committee_id: Uuid,
    members_len: usize,
    op_index: usize,
    op_wins: bool,
) -> Result<()> {
    // Set DRP Operator input for each Watchtower
    for wt_index in 0..members_len {
        if wt_index == op_index {
            continue;
        }

        let drp_pid = get_dispute_channel_pid(committee_id, op_index, wt_index);

        // Force someone to win
        let data = if op_wins {
            "11111111".to_string()
        } else {
            "00000000".to_string()
        };
        let input_pos = 0;

        let set_input_1 = VariableTypes::Input(hex::decode(data).unwrap());
        member
            .bitvmx
            .set_var(drp_pid, &program_input(input_pos, None), set_input_1)?;
    }
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
                20 + PEGIN_CONFIRMATIONS as u32
            } else {
                2 + PEGIN_CONFIRMATIONS as u32
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

#[derive(Debug, Clone)]
struct ChallengeReason {
    pub pegout_id: bool,
    pub operator_pubkey: bool,
    pub slot_index: bool,
    pub funds_advanced: bool,
}

impl ChallengeReason {
    fn none() -> Self {
        Self {
            pegout_id: false,
            operator_pubkey: false,
            slot_index: false,
            funds_advanced: false,
        }
    }

    // fn pegout_id() -> Self {
    //     let mut r = Self::none();
    //     r.pegout_id = true;
    //     r
    // }

    // fn operator_pubkey() -> Self {
    //     let mut r = Self::none();
    //     r.operator_pubkey = true;
    //     r
    // }

    // fn slot_index() -> Self {
    //     let mut r = Self::none();
    //     r.slot_index = true;
    //     r
    // }

    fn funds_advanced() -> Self {
        let mut r = Self::none();
        r.funds_advanced = true;
        r
    }

    // fn all() -> Self {
    //     ChallengeReason {
    //         pegout_id: true,
    //         operator_pubkey: true,
    //         slot_index: true,
    //         funds_advanced: true,
    //     }
    // }
}
