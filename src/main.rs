use anyhow::Result;
use clap::{Arg, Command};
use rust_bitvmx_client::client::repl::Repl;
use tracing::error;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let filter = EnvFilter::builder()
        .parse("info,libp2p=off") // Include everything at "info" except `libp2p`
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_env_filter(filter)
        .init();

    let mut repl = match Repl::new(get_config()) {
        Ok(r) => r,
        Err(e) => {
            error!("{:?}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = repl.run() {
        error!("{:?}", e);
        std::process::exit(1);
    }

    Ok(())
}

fn get_config() -> Option<String> {
    let matches = Command::new("BitVMX client")
        .arg(
            Arg::new("configuration")
                .help("Optional configuration")
                .index(1),
        )
        .get_matches();

    let config = if let Some(config) = matches.get_one::<String>("configuration") {
        Some(config.clone())
    } else {
        None
    };

    config
}
