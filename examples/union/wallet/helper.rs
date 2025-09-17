use crate::participants::user::User;
use crate::{participants::member::Member, MasterWallet};
use anyhow::{anyhow, Result};
use bitcoin::{Address, CompressedPublicKey, Network, Txid};
use bitvmx_wallet::wallet::{Destination, Wallet};
use core::option::Option;
use key_manager::{key_manager::KeyManager, key_store::KeyStore};
use std::env;
use std::io::{self, Write};
use storage_backend::storage::Storage;
use tracing::info;
use tracing::warn;

const TESTNET_FEE_RATE: u64 = 1; // sats/vbyte
const MIN_FUNDS_RECOVERY: u64 = 5000;
const TX_SIZE: u64 = 140;

pub fn create_wallet(network: Network) -> Result<()> {
    info!("Generating wallet for network {}...", network);

    let mut config = bitvmx_client::config::Config::new(Some("config/op_1.yaml".to_string()))?;
    config.key_storage.path = "/tmp/tmp_wallet/keys.db".to_string();
    config.storage.path = "/tmp/tpm_wallet/storage.db".to_string();

    let key_derivation_seed: [u8; 32] = *b"1337beafdeadbeafdeadbeafdeadbeaf";

    let key_manager = KeyManager::new(
        network,
        "m/84/0/0/0/",
        Some(key_derivation_seed),
        None,
        KeyStore::new(std::rc::Rc::new(Storage::new(&config.key_storage)?)),
        std::rc::Rc::new(Storage::new(&config.storage)?),
    )?;

    let pubkey = key_manager.derive_keypair(0)?;
    let privkey = key_manager.export_secret(&pubkey)?;
    let change_pubkey = key_manager.derive_keypair(1)?;
    let change_privkey = key_manager.export_secret(&change_pubkey)?;
    let compressed = CompressedPublicKey::try_from(pubkey).unwrap();
    let address = Address::p2wpkh(&compressed, network);

    info!("Wallet info:");
    info!("  Pubkey: {}", pubkey);
    info!("  Privkey: {}", privkey);
    info!("  Address: {}", address);
    info!("");
    info!("  Change Privkey: {}", change_privkey);

    Ok(())
}

pub fn fund_members(wallet: &mut MasterWallet, members: &[Member], amount: u64) -> Result<Txid> {
    let fee_rate = get_fee_rate(wallet.network());

    let balance = wallet.wallet.balance();
    info!("Master wallet balance:");
    info!("Confirmed: {} sats", balance.confirmed.to_sat());
    info!("Untrusted: {} sats", balance.untrusted_pending.to_sat());
    info!("Trusted: {} sats", balance.trusted_pending.to_sat());
    info!("Immature: {} sats", balance.immature.to_sat());

    let mut batch = Vec::new();

    for member in members {
        let address = member.get_funding_address()?;
        info!("Address: {:?}", address);

        let checked_address = address
            .require_network(wallet.network())
            .expect("address not valid for this network");

        let destination = Destination::Address(checked_address.to_string(), amount);
        batch.push(destination);
    }

    info!(
        "Funding {} members with {} sats each. fee rate: {} sats/vbyte",
        members.len(),
        amount,
        fee_rate
    );
    non_regtest_warning(wallet.network(), "You are about to transfer REAL money.");

    let tx = wallet
        .wallet
        .send_funds(Destination::Batch(batch), Some(fee_rate))?;

    let txid = tx.compute_txid();
    info!("Funded members with txid: {}", txid);
    print_link(wallet.network(), txid);

    info!("Master wallet balance after funding members:");
    print_balance(wallet)?;
    Ok(txid)
}

pub fn fund_user_pegin_utxos(
    wallet: &mut MasterWallet,
    user: &mut User,
    amount_in_sats: u64,
    utxos_quantity: usize,
) -> Result<()> {
    let fee_rate = get_fee_rate(wallet.network());
    info!(
        "Funding user pegin address with {} sats. UTXOs quantity: {}. fee rate: {} sats/vbyte",
        amount_in_sats, utxos_quantity, fee_rate
    );
    non_regtest_warning(wallet.network(), "You are about to transfer REAL money.");

    let pubkey = user.public_key()?;
    let mut batch = Vec::new();
    for _i in 0..utxos_quantity {
        let destination = Destination::P2WPKH(pubkey, amount_in_sats);
        batch.push(destination);
    }

    let destination = Destination::Batch(batch);
    let tx = wallet.wallet.send_funds(destination, Some(fee_rate))?;
    let txid = tx.compute_txid();

    for i in 0..utxos_quantity {
        user.add_request_pegin_utxo((txid, i as u32, Some(amount_in_sats), None));
    }
    info!("Pegin UTXOs Added. Txid: {}", txid);

    Ok(())
}

pub fn fund_user_speedup(
    wallet: &mut MasterWallet,
    user: &mut User,
    amount_in_sats: u64,
) -> Result<()> {
    let fee_rate = get_fee_rate(wallet.network());
    info!(
        "Funding user speedup with {} sats. fee rate: {} sats/vbyte",
        amount_in_sats, fee_rate
    );
    non_regtest_warning(wallet.network(), "You are about to transfer REAL money.");

    let pubkey = user.public_key()?;
    let destination = Destination::P2WPKH(pubkey, amount_in_sats);
    let tx = wallet.wallet.send_funds(destination, Some(fee_rate))?;
    let txid = tx.compute_txid();

    user.set_speedup_utxo((txid, 0, Some(amount_in_sats), None));
    info!("Speedup UTXO set. Txid: {}", txid);

    Ok(())
}

pub fn print_members_balances(members: &[Member]) -> Result<()> {
    for member in members {
        let balance = member.get_funding_balance()?;
        info!("Member {} balance: {} sats", member.id, balance);
    }
    Ok(())
}

pub fn print_link(network: Network, txid: bitcoin::Txid) {
    if network == Network::Regtest {
        return;
    }

    let url = match network {
        Network::Testnet => format!("https://mempool.space/testnet/tx/{}", txid),
        Network::Bitcoin => format!("https://mempool.space/tx/{}", txid),
        _ => "Unsupported network".to_string(),
    };
    info!("View transaction at: {}", url);
}

pub fn recover_funds(members: &[Member], address: String, network: Network) -> Result<()> {
    info!("Recovering funds to address: {}", address);
    let fee_rate = get_fee_rate(network);
    info!("Fee rate: {} sats/vbyte", fee_rate);
    non_regtest_warning(network, "You are about to transfer REAL money.");

    for member in members {
        let balance = member.get_funding_balance()?;
        info!("Member {} balance: {} sats", member.id, balance);
        if balance <= MIN_FUNDS_RECOVERY {
            info!(
                "Member {} balance {} sats is too low to recover, skipping",
                member.id, balance
            );
            continue;
        }

        let amount = balance - fee_rate * TX_SIZE * 2; // leave some sats for fees. 2 factor is to considerate multiple inputs

        info!("Recovering {} sats from member {}", amount, member.id);
        non_regtest_warning(network, "You are about to transfer REAL money.");

        let txid = match member.send_funds(amount, address.clone(), Some(fee_rate)) {
            Ok(txid) => txid,
            Err(e) => {
                warn!(
                    "Failed to recover funds from member {} to address {}: {}",
                    member.id, address, e
                );
                continue;
            }
        };
        print_link(network, txid);
    }
    Ok(())
}

pub fn recover_user_funds(user: &User, address: String) -> Result<()> {
    let mut wallet = Wallet::from_config(user.config.bitcoin.clone(), user.config.wallet.clone())?;

    // Sync the wallet
    info!("Syncing user wallet...");
    wallet.sync_wallet()?;
    info!("User wallet synced.");

    let balance = wallet.balance().confirmed.to_sat();
    info!("User wallet balance: {} sats", balance);

    if balance <= MIN_FUNDS_RECOVERY {
        info!(
            "User wallet balance {} sats is too low to recover, skipping",
            balance
        );
        return Ok(());
    }

    let fee_rate = get_fee_rate(user.network);
    info!(
        "Recovering {} sats from user to address: {}",
        balance, address
    );
    info!("Fee rate: {} sats/vbyte", fee_rate);
    non_regtest_warning(user.network, "You are about to transfer REAL money.");

    let txid = wallet
        .send_funds(
            Destination::Address(address, balance - fee_rate * TX_SIZE * 2),
            Some(fee_rate),
        )
        .map_err(|e| anyhow::anyhow!("Failed to recover funds from user to address: {}", e))?
        .compute_txid();
    print_link(user.network, txid);

    Ok(())
}

/// Ask the user a yes/no question and return true if they confirm (`y` or `yes`).
pub fn ask_user_confirmation(prompt: &str) -> bool {
    loop {
        print!("{} [y/N]: ", prompt);
        io::stdout().flush().unwrap(); // Make sure prompt is shown

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            println!("Failed to read input, try again.");
            continue;
        }

        match input.trim().to_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" | "" => return false, // default is "no"
            _ => {
                println!("Please answer 'y' or 'n'.");
                continue;
            }
        }
    }
}

pub fn non_regtest_warning(network: Network, message: &str) {
    if network == Network::Regtest {
        return;
    }

    print!("\nWarning: {}. {:?} network.\n", message, network);
    print!("This may incur real costs and is not recommended for testing purposes.\n");
    if !ask_user_confirmation("Do you want to proceed?") {
        print!("Operation cancelled by user.\n");
        std::process::exit(0);
    }
}

pub fn get_network_prefix(network: Network, env_var: bool) -> &'static str {
    match (network, env_var) {
        (Network::Regtest, false) => "regtest",
        (Network::Regtest, true) => "REGTEST",

        (Network::Testnet, false) => "testnet",
        (Network::Testnet, true) => "TESTNET",

        (Network::Bitcoin, false) => "mainnet",
        (Network::Bitcoin, true) => "MAINNET",

        (other, _) => panic!("Unsupported network: {:?}", other),
    }
}

pub fn string_to_network(network: Option<&String>) -> Result<Network> {
    let network = match network {
        Some(net) => match net.as_str() {
            "regtest" => Network::Regtest,
            "testnet" => Network::Testnet,
            "mainnet" => Network::Bitcoin,
            _ => {
                return Err(anyhow!(
                    "Unsupported network string: {}. Use 'regtest' or 'testnet'.",
                    net
                ));
            }
        },
        None => {
            warn!("No network specified. Using regtest.");
            Network::Regtest
        }
    };
    Ok(network)
}

pub fn load_private_key_from_env(network: Network) -> Option<String> {
    if network == Network::Regtest {
        return None;
    }

    let env_var_name = &format!(
        "{}_MASTER_WALLET_PRIVKEY",
        get_network_prefix(network, true)
    );

    env_var_or_default(env_var_name, None)
}

pub fn load_change_key_from_env(network: Network) -> Option<String> {
    if network == Network::Regtest {
        return None;
    }
    let env_var_name = &format!(
        "{}_MASTER_WALLET_CHANGE_KEY",
        get_network_prefix(network, true)
    );

    env_var_or_default(env_var_name, None)
}

fn env_var_or_default(var_name: &str, default: Option<String>) -> Option<String> {
    match env::var(var_name) {
        Ok(val) => Some(val),
        Err(_) => {
            info!(
                "Environment variable {} not set. Defaulting to {:?}.",
                var_name, default
            );
            default
        }
    }
}

pub fn print_balance(wallet: &MasterWallet) -> Result<()> {
    let balance = wallet.wallet.balance();
    info!("Master wallet balance:");
    info!("Confirmed: {} sats", balance.confirmed.to_sat());
    info!("Untrusted: {} sats", balance.untrusted_pending.to_sat());
    info!("Trusted: {} sats", balance.trusted_pending.to_sat());
    info!("Immature: {} sats", balance.immature.to_sat());
    Ok(())
}

fn get_fee_rate(network: Network) -> u64 {
    if network == Network::Regtest {
        10
    } else {
        TESTNET_FEE_RATE
    }
}
