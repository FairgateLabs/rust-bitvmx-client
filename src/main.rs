use anyhow::Result;
use clap::{Arg, Command};
use rust_bitvmx_client::client::repl::Repl;
use tracing::error;

fn main() -> Result<()>{
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .init();

    let mut repl = match Repl::new(get_config()) {
        Ok(r) => r,
        Err(e) => {
            error!("{:?}", e);
            std::process::exit(1);
        },
    };
    
    if let Err(e) = repl.run() {
        error!("{:?}", e);
        std::process::exit(1);
    }

    Ok(())
}

fn get_config() -> Option<String> {
    let matches = Command::new("BitVMX client")
        .arg(Arg::new("configuration")
            .help("Optional configuration")
            .index(1)
        ).get_matches();

    let config = if let Some(config) = matches.get_one::<String>("configuration") {
        Some(config.clone())
    } else {
        None
    };

    config
}
