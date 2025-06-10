use anyhow::Result;


pub fn main() -> Result<()> {
    configure_tracing();

    // 0. A new package is created. A committee is selected. Union client requests the setup of the
    // committee key and corresponding programs.
    setup()?;

    // 1. Union client queries the chain for a temporary peg in address.
    get_temporary_peg_in_address()?;

    // 2. Union client requests bitvxm to build a PegInRequest transaction and it submits it to the
    // chain.
    request_peg_in()?;

    Ok(())
}

fn configure_tracing() {
    INIT.call_once(|| {
        let default_modules = [
            "info",
            "libp2p=off",
            "bitvmx_transaction_monitor=off",
            "bitcoin_indexer=off",
            "bitcoin_coordinator=info",
            "p2p_protocol=off",
            "p2p_handler=off",
            "tarpc=off",
            "key_manager=off",
            "memory=off",
        ];
    
        let filter = EnvFilter::builder()
            .parse(default_modules.join(","))
            .expect("Invalid filter");

        tracing_subscriber::fmt()
            .without_time()
            .with_target(true)
            .with_env_filter(filter)
            .init();
    });
}
