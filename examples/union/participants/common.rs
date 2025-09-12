use bitcoin::Network;
use std::io::{self, Write};

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

pub fn regtest_warning(network: Network, message: &str) {
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
