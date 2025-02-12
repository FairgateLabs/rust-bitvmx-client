use anyhow::Result;
use bitvmx_client::client::repl::Repl;
use tracing::error;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let filter = EnvFilter::builder()
    .parse("info,libp2p=off,bitvmx_transaction_monitor=off,bitcoin_indexer=off,bitvmx_orchestrator=off,tarpc=off") // Include everything at "info" except `libp2p`
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_env_filter(filter)
        .init();

    let mut repl = match Repl::new() {
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
