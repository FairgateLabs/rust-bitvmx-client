use std::sync::Once;
use tracing_subscriber::EnvFilter;

static INIT: Once = Once::new();

pub fn configure_tracing() {
    INIT.call_once(|| {
        let default_modules = [
            "info",
            "bitvmx_transaction_monitor=off",
            "bitvmx_broker=off",
            "bitcoin_indexer=off",
            "bitcoin_coordinator=info",
            "bitvmx_operator_comms=off",
            "tarpc=off",
            "key_manager=off",
            "memory=off",
            "bitvmx_client::config=off",
            "bitvmx_wallet=off",
            "bitvmx_bitcoin_rpc=off",
        ];

        let filter = EnvFilter::builder()
            .parse(default_modules.join(","))
            .expect("Invalid filter");

        tracing_subscriber::fmt()
            .with_target(true)
            .with_env_filter(filter)
            .init();
    });
}
