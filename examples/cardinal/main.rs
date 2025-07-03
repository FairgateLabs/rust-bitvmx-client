use std::env;

use anyhow::Result;

mod burn_and_get;
mod common;
mod lockreq;
mod lockservice;
mod log;

pub fn main() -> Result<()> {
    log::config_trace();

    let args: Vec<String> = env::args().collect();
    let command = args.get(1);

    match command.map(|s| s.as_str()) {
        Some("service") => lockservice::main()?,
        Some("lockreq") => lockreq::main()?,
        Some("burn_and_get") => burn_and_get::main()?,
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
    println!("  cargo run --example cardinal service         - Runs the lock service");
    println!("  cargo run --example cardinal lockreq         - Runs the lock request client");
    println!("  cargo run --example cardinal burn_and_get    - Runs the burn and get flow");
}
