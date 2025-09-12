use anyhow::{anyhow, Result};
use bitcoin::Network;
use core::option::Option;
use std::io::{self, Write};
use tracing::warn;

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

pub fn prefixed_name(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        return name.to_string();
    }
    format!("{}_{}", prefix, name)
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

pub fn get_network_prefix(network: Network, env_var: bool) -> Result<&'static str> {
    match (network, env_var) {
        (Network::Regtest, false) => Ok("regtest"),
        (Network::Regtest, true) => Ok("REGTEST"),

        (Network::Testnet, false) => Ok("testnet"),
        (Network::Testnet, true) => Ok("TESTNET"),

        (Network::Bitcoin, false) => Ok("mainnet"),
        (Network::Bitcoin, true) => Ok("MAINNET"),

        (other, _) => Err(anyhow!("Unsupported network: {:?}", other)),
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
