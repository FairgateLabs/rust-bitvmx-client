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
use bitvmx_client::program::protocols::union::{
    common::{get_accept_pegin_pid, get_init_pid},
    types::{ACCEPT_PEGIN_TX, START_ENABLER_TX_SUFFIX, WATCHTOWER},
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
        Some("watchtowers_init") => cli_watchtowers_init()?,
        Some("request_pegin") => cli_request_pegin()?,
        Some("accept_pegin") => cli_accept_pegin()?,
        Some("request_pegout") => cli_request_pegout()?,
        Some("advance_funds") => cli_advance_funds()?,
        Some("advance_funds_twice") => cli_advance_funds_twice()?,
        Some("invalid_reimbursement") => cli_invalid_reimbursement()?,
        Some("double_reimbursement") => cli_double_reimbursement()?,
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

fn print_usage() {
    println!("Usage:");
    println!("  cargo run --example union setup_bitcoin_node  - Sets up Bitcoin node only");
    println!("  cargo run --example union committee           - Setups a new committee");
    println!(
        "  cargo run --example union watchtowers_init    - Setups the watchtowers init protocol"
    );
    println!("  cargo run --example union request_pegin       - Setups a request pegin");
    println!("  cargo run --example union accept_pegin        - Setups the accept peg in protocol");
    println!(
        "  cargo run --example union request_pegout      - Setups the request peg out protocol"
    );
    println!("  cargo run --example union advance_funds       - Performs an advancement of funds");
    println!(
        "  cargo run --example union advance_funds_twice       - Performs advancement of funds twice"
    );
    println!("  cargo run --example union invalid_reimbursement     - Forces invalid reimbursement to test challenge tx");
    // Testing commands
    println!(
        "  cargo run --example union create_wallet        - Create wallet: key pair and address. (optionally pass network: regtest, testnet, bitcoin)"
    );
    println!("  cargo run --example union wallet_balance      - Print Master wallet balance");
    println!("  cargo run --example union latency             - Analyses latency to the Bitcoin node. (optionally pass network: regtest, testnet, bitcoin)");
    println!("  cargo run --example union members_balance            - Print members balance");
    println!(
        "  cargo run --example union fund_members        - Funds all committee members from master wallet with a testing amount"
    );
    println!("  cargo run --example union members_recover_funds       - Send all members funds to master wallet address");
    println!("  cargo run --example union user_recover_funds  - Send user funds to master wallet address");
    println!(
        "  cargo run --example union wallet_recover_funds  - Send master wallet funds to address"
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

pub fn cli_watchtowers_init() -> Result<()> {
    let mut wallet = get_master_wallet()?;
    let mut committee = committee(&mut wallet)?;

    watchtowers_init(&mut committee)?;
    Ok(())
}

pub fn cli_request_pegin() -> Result<()> {
    let mut wallet = get_master_wallet()?;
    let committee = committee(&mut wallet)?;
    let mut user = get_user()?;

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

    let blocks = if NETWORK == Network::Regtest { 30 } else { 1 };
    wait_for_blocks(&committee.bitcoin_client, blocks)?;
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

    let blocks = if NETWORK == Network::Regtest { 10 } else { 1 };
    wait_for_blocks(&committee.bitcoin_client, blocks)?;

    info!("Balances after dispute core protocol:");
    print_members_balances(committee.members.as_slice())?;

    info!("Committee setup complete.");
    confirm_to_continue();
    Ok(committee)
}

pub fn watchtowers_init(committee: &mut Committee) -> Result<()> {
    for member in committee.members.iter() {
        let protocol_id = get_init_pid(
            committee.committee_id(),
            &member.keyring.take_pubkey.unwrap(),
        );

        info!(
            "Dispatching transaction: {}, protocol id: {}",
            format!("{}{}", WATCHTOWER, START_ENABLER_TX_SUFFIX),
            protocol_id,
        );

        member.dispatch_transaction_by_name(
            protocol_id,
            format!("{}{}", WATCHTOWER, START_ENABLER_TX_SUFFIX),
        )?;
    }

    wait_for_blocks(&committee.bitcoin_client, 1)?;

    Ok(())
}

pub fn request_pegin(committee_public_key: PublicKey, user: &mut User) -> Result<(Txid, u64)> {
    let amount: u64 = STREAM_DENOMINATION; // This should be replaced with the actual amount of the peg-in request
    let request_pegin_txid = user.request_pegin(&committee_public_key, amount)?;

    wait_for_blocks(&BitcoinWrapper::new_from_config(&user.config)?, 1)?;
    thread::sleep(Duration::from_secs(2)); // wait for the coordinator to update

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

    let blocks = if NETWORK == Network::Regtest { 3 } else { 0 };
    wait_for_blocks(&committee.bitcoin_client, blocks)?;
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
    let pegout_signature_hash = vec![0; 32]; // This should be replaced with the actual peg-out signature hash
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

    let blocks = if NETWORK == Network::Regtest { 3 } else { 0 };
    wait_for_blocks(&committee.bitcoin_client, blocks)?;
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
        let blocks = if NETWORK == Network::Regtest { 30 } else { 1 };
        wait_for_blocks(&committee.bitcoin_client, blocks)?;
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

    member.advance_funds(
        Uuid::new_v4(),
        committee_id,
        slot_index,
        operator_pubkey,
        vec![0; 32],
        operator_pubkey,
        get_advance_funds_fee()?,
    )?;

    let blocks = if NETWORK == Network::Regtest { 30 } else { 7 };
    info!("Starting mining loop to ensure challenge transaction is dispatched...");
    wait_for_blocks(&committee.bitcoin_client, blocks)?;

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
