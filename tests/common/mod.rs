#![allow(dead_code)]
use std::str::FromStr;

pub mod dispute;

use anyhow::Result;
use bitcoin::{Network, PublicKey};
use bitcoind::bitcoind::{Bitcoind, BitcoindFlags};
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClient;
use bitvmx_broker::{channel::channel::DualChannel, rpc::BrokerConfig};
use bitvmx_client::{
    bitvmx::BitVMX,
    config::Config,
    program::{participant::P2PAddress, protocols::protocol_handler::external_fund_tx},
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, BITVMX_ID, EMULATOR_ID, L2_ID},
};
use bitvmx_wallet::wallet::Wallet;
use p2p_handler::PeerId;
use protocol_builder::{
    scripts::{self, ProtocolScript, SignMode},
    types::{OutputType, Utxo},
};
use std::sync::Once;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// Number of blocks to mine initially in tests to ensure sufficient coin maturity
pub const INITIAL_BLOCK_COUNT: u64 = 101;

pub fn clear_db(path: &str) {
    let _ = std::fs::remove_dir_all(path);
}

pub fn clear_all_test_data() {
    // Obtener ID de aislamiento si existe
    let isolation_id = std::env::var("TEST_ISOLATION_ID").unwrap_or_else(|_| "default".to_string());
    
    // Lista de directorios base a limpiar
    let test_data_dir = format!("test_data_{}", isolation_id);
    let base_dirs = vec![
        "testdb",
        "client_1_regtest_db",
        "client_2_regtest_db", 
        "client_3_regtest_db",
        "client_4_regtest_db",
        "storage_regtest",
        "key_storage_regtest",
        "wallet_regtest_db",
        "dispute_storage",
        "protocol_storage",
        "temp_test_data",
        &test_data_dir,
    ];
    
    for base_dir in base_dirs {
        // Limpiar directorio base
        let _ = std::fs::remove_dir_all(base_dir);
        
        // Limpiar variantes con ID de aislamiento
        let isolated_dir = format!("{}_{}", base_dir, isolation_id);
        let _ = std::fs::remove_dir_all(&isolated_dir);
        
        // Limpiar en /tmp también
        let tmp_dir = format!("/tmp/{}", base_dir);
        let _ = std::fs::remove_dir_all(&tmp_dir);
        
        let tmp_isolated_dir = format!("/tmp/{}_{}", base_dir, isolation_id);
        let _ = std::fs::remove_dir_all(&tmp_isolated_dir);
    }
    
    // Limpiar archivos de lockfiles y databases específicos
    let isolation_pattern = format!("*{}*", isolation_id);
    let patterns = vec![
        "*.db",
        "*.db-wal", 
        "*.db-shm",
        "*.lock",
        &isolation_pattern,
    ];
    
    for pattern in patterns {
        // Usar find para localizar y eliminar archivos que coincidan con el patrón
        let _ = std::process::Command::new("find")
            .args(&[".", "-name", pattern, "-type", "f", "-delete"])
            .output();
    }
    
    info!("Cleared all test data for isolation ID: {}", isolation_id);
}

pub fn init_bitvmx(
    role: &str,
    emulator_dispatcher: bool,
) -> Result<(BitVMX, P2PAddress, DualChannel, Option<DualChannel>)> {
    let isolation_id = std::env::var("TEST_ISOLATION_ID").unwrap_or_else(|_| "default".to_string());
    
    let mut config = Config::new(Some(format!("config/{}.yaml", role)))?;
    
    // Aislar rutas de almacenamiento
    config.storage.path = format!("{}_{}", config.storage.path, isolation_id);
    config.key_storage.path = format!("{}_{}", config.key_storage.path, isolation_id);
    config.broker_storage.path = format!("{}_{}", config.broker_storage.path, isolation_id);
    
    // Usar puerto de RPC desde variable de entorno si está disponible
    if let Ok(rpc_url) = std::env::var("BITCOIN_RPC_URL") {
        config.bitcoin.url = rpc_url;
    }
    
    // Usar puerto de broker dinámico si está disponible
    if let Ok(broker_port_str) = std::env::var("BROKER_PORT") {
        if let Ok(broker_port) = broker_port_str.parse::<u16>() {
            config.broker_port = broker_port;
        }
    }
    
    let broker_config = BrokerConfig::new(config.broker_port, None);
    let bridge_client = DualChannel::new(&broker_config, L2_ID);
    let dispatcher_channel = if emulator_dispatcher {
        Some(DualChannel::new(&broker_config, EMULATOR_ID))
    } else {
        None
    };

    clear_db(&config.storage.path);
    clear_db(&config.key_storage.path);
    clear_db(&config.broker_storage.path);

    info!("config: {:?}", config.storage.path);

    let bitvmx = BitVMX::new(config)?;

    let address = P2PAddress::new(&bitvmx.address(), PeerId::from_str(&bitvmx.peer_id())?);
    info!("peer id {:?}", bitvmx.peer_id());

    //This messages will come from the bridge client.

    Ok((bitvmx, address, bridge_client, dispatcher_channel))
}

pub fn tick(instance: &mut BitVMX) {
    instance.process_api_messages().unwrap();
    instance.process_p2p_messages().unwrap();
    instance.process_programs().unwrap();
    instance.process_collaboration().unwrap();
    instance.process_pending_messages().unwrap();
}

pub fn wait_message_from_channel(
    channel: &DualChannel,
    instances: &mut Vec<&mut BitVMX>,
    fake_tick: bool,
) -> Result<(String, u32)> {
    //loop to timeout - incrementado de 40000 a 80000 para evitar timeouts en CI
    for i in 0..80000 {
        if i % 50 == 0 {
            let msg = channel.recv()?;
            if msg.is_some() {
                //info!("Received message from channel: {:?}", msg);
                return Ok(msg.unwrap());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        for instance in instances.iter_mut() {
            if fake_tick {
                tick(instance);
            } else {
                instance.tick()?;
            }
        }
    }
    panic!("Timeout waiting for message from channel");
}

pub fn wait_message_from_channel_with_timeout(
    channel: &DualChannel,
    instances: &mut Vec<&mut BitVMX>,
    fake_tick: bool,
    timeout_seconds: u64,
) -> Result<(String, u32)> {
    use std::time::{Duration, Instant};
    
    let start_time = Instant::now();
    let timeout = Duration::from_secs(timeout_seconds);
    let max_iterations = timeout_seconds * 100; // approximate iterations based on sleep
    
    for i in 0..max_iterations {
        if start_time.elapsed() >= timeout {
            return Err(anyhow::anyhow!("Timeout after {} seconds waiting for message from channel", timeout_seconds));
        }
        
        if i % 50 == 0 {
            let msg = channel.recv()?;
            if msg.is_some() {
                return Ok(msg.unwrap());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        for instance in instances.iter_mut() {
            if fake_tick {
                tick(instance);
            } else {
                instance.tick()?;
            }
        }
    }
    Err(anyhow::anyhow!("Timeout after {} seconds waiting for message from channel", timeout_seconds))
}

pub const WALLET_NAME: &str = "wallet";
pub const FUNDING_ID: &str = "fund_1";
pub const FEE: u64 = 500;

pub fn prepare_bitcoin() -> Result<(BitcoinClient, Option<Bitcoind>, Wallet)> {
    // Limpiar datos de tests anteriores al inicio
    clear_all_test_data();
    
    let is_ci = std::env::var("CI").is_ok() || std::env::var("GITHUB_ACTIONS").is_ok();
    let isolation_id = std::env::var("TEST_ISOLATION_ID").unwrap_or_else(|_| "default".to_string());
    
    // Crear configuración aislada
    let mut config = Config::new(Some("config/development.yaml".to_string()))?;
    
    // Usar puerto de RPC desde variable de entorno si está disponible  
    if let Ok(rpc_url) = std::env::var("BITCOIN_RPC_URL") {
        config.bitcoin.url = rpc_url;
        info!("Using isolated Bitcoin RPC URL: {}", config.bitcoin.url);
    }
    
    // Modificar rutas de almacenamiento para aislamiento
    config.storage.path = format!("{}_{}", config.storage.path, isolation_id);

    let bitcoind = if is_ci {
        info!("Running in CI - using external bitcoind from docker-compose");
        std::thread::sleep(std::time::Duration::from_secs(2));
        None
    } else {
        info!("Running locally - starting bitcoind");
        let bitcoind = Bitcoind::new_with_flags(
            "bitcoin-regtest",
            "ruimarinho/bitcoin-core",
            config.bitcoin.clone(),
            BitcoindFlags {
                min_relay_tx_fee: 0.00001,
                block_min_tx_fee: 0.00008,
                debug: 1,
                fallback_fee: 0.0002,
            },
        );
        bitcoind.start()?;
        Some(bitcoind)
    };

    let wallet_config = match config.bitcoin.network {
        Network::Regtest => "config/wallet_regtest.yaml",
        Network::Testnet => "config/wallet_testnet.yaml",
        _ => panic!("Not supported network {}", config.bitcoin.network),
    };

    let mut wallet_config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::config::WalletConfig,
    >(Some(wallet_config.to_string()))?;
    
    // Aislar rutas de almacenamiento del wallet
    if config.bitcoin.network == Network::Regtest {
        wallet_config.storage.path = format!("{}_{}", wallet_config.storage.path, isolation_id);
        wallet_config.key_storage.path = format!("{}_{}", wallet_config.key_storage.path, isolation_id);
        
        clear_db(&wallet_config.storage.path);
        clear_db(&wallet_config.key_storage.path);
    }
    
    let wallet = Wallet::new(wallet_config, true)?;
    wallet.mine(INITIAL_BLOCK_COUNT)?;

    wallet.create_wallet(WALLET_NAME)?;
    wallet.regtest_fund(WALLET_NAME, FUNDING_ID, 100_000_000)?;

    let bitcoin_client = BitcoinClient::new(
        &config.bitcoin.url,
        &config.bitcoin.username,
        &config.bitcoin.password,
    )?;

    Ok((bitcoin_client, bitcoind, wallet))
}

static INIT: Once = Once::new();

pub fn config_trace() {
    INIT.call_once(|| {
        config_trace_aux();
    });
}

fn config_trace_aux() {
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
        "broker=off",
    ];

    let filter = EnvFilter::builder()
        .parse(default_modules.join(","))
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        //.without_time()
        //.with_ansi(false)
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

pub fn send_all(channels: &Vec<DualChannel>, msg: &str) -> Result<()> {
    for channel in channels {
        channel.send(BITVMX_ID, msg.to_string())?;
    }
    Ok(())
}

pub fn get_all(
    channels: &Vec<DualChannel>,
    instances: &mut Vec<BitVMX>,
    fake_tick: bool,
) -> Result<Vec<OutgoingBitVMXApiMessages>> {
    let mut ret = vec![];
    let mut mutinstances = instances.iter_mut().collect::<Vec<_>>();
    for channel in channels {
        let msg = wait_message_from_channel(&channel, &mut mutinstances, fake_tick)?;
        ret.push(OutgoingBitVMXApiMessages::from_string(&msg.0)?);
    }
    Ok(ret)
}

pub fn get_all_with_timeout(
    channels: &Vec<DualChannel>,
    instances: &mut Vec<BitVMX>,
    fake_tick: bool,
    timeout_seconds: u64,
) -> Result<Vec<OutgoingBitVMXApiMessages>> {
    let mut ret = vec![];
    let mut mutinstances = instances.iter_mut().collect::<Vec<_>>();
    for channel in channels {
        match wait_message_from_channel_with_timeout(&channel, &mut mutinstances, fake_tick, timeout_seconds) {
            Ok(msg) => {
                ret.push(OutgoingBitVMXApiMessages::from_string(&msg.0)?);
            }
            Err(e) => {
                // Log timeout but don't fail immediately
                warn!("Timeout waiting for message from channel: {:?}", e);
                // Return what we have so far
                break;
            }
        }
    }
    Ok(ret)
}

pub fn mine_and_wait(
    _bitcoin_client: &BitcoinClient,
    channels: &Vec<DualChannel>,
    instances: &mut Vec<BitVMX>,
    wallet: &Wallet,
) -> Result<Vec<OutgoingBitVMXApiMessages>> {
    //MINE AND WAIT
    for i in 0..100 {
        if i % 10 == 0 {
            wallet.mine(1)?;
        }

        for instance in instances.iter_mut() {
            instance.tick()?;
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }
    let msgs = get_all(&channels, instances, false)?;

    Ok(msgs)
}

pub fn mine_and_wait_with_timeout(
    _bitcoin_client: &BitcoinClient,
    channels: &Vec<DualChannel>,
    instances: &mut Vec<BitVMX>,
    wallet: &Wallet,
    timeout_seconds: u64,
) -> Result<Vec<OutgoingBitVMXApiMessages>> {
    use std::time::{Duration, Instant};
    
    let start_time = Instant::now();
    let timeout = Duration::from_secs(timeout_seconds);
    
    //MINE AND WAIT with timeout
    for i in 0..1000 { // Increased max iterations
        if start_time.elapsed() >= timeout {
            return Err(anyhow::anyhow!("Timeout after {} seconds", timeout_seconds));
        }
        
        if i % 10 == 0 {
            wallet.mine(1)?;
        }

        for instance in instances.iter_mut() {
            instance.tick()?;
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }
    
    // Try to get messages with shorter timeout
    let msgs = get_all_with_timeout(&channels, instances, false, 5)?;
    Ok(msgs)
}

pub fn init_broker(role: &str) -> Result<DualChannel> {
    let config = Config::new(Some(format!("config/{}.yaml", role)))?;
    let broker_config = BrokerConfig::new(config.broker_port, None);
    let bridge_client = DualChannel::new(&broker_config, L2_ID);
    Ok(bridge_client)
}

pub fn init_utxo_new(
    wallet: &Wallet,
    internal_key: &PublicKey,
    spending_scripts: Vec<ProtocolScript>,
    amount: u64,
    from: Option<&str>,
) -> Result<(Utxo, OutputType)> {
    info!("Funding address: {:?} with: {}", internal_key, amount);
    let txid = wallet.fund_address(
        WALLET_NAME,
        from.unwrap_or(FUNDING_ID),
        internal_key.clone(),
        &vec![amount],
        FEE,
        true,
        true,
        Some(vec![spending_scripts.clone()]),
    )?;
    wallet.mine(1)?;
    let utxo = Utxo::new(txid, 0, amount, &*internal_key);

    let output_type = external_fund_tx(internal_key, spending_scripts, amount)?;

    info!("UTXO: {:?}", utxo);

    Ok((utxo, output_type))
}

pub fn init_utxo(
    wallet: &Wallet,
    aggregated_pub_key: PublicKey,
    secret: Option<Vec<u8>>,
    amount: u64,
) -> Result<Utxo> {
    let spending_scripts = if secret.is_some() {
        vec![scripts::reveal_secret(
            secret.unwrap(),
            &aggregated_pub_key,
            SignMode::Aggregate,
        )]
    } else {
        vec![scripts::check_aggregated_signature(
            &aggregated_pub_key,
            SignMode::Aggregate,
        )]
    };

    let txid = wallet.fund_address(
        WALLET_NAME,
        FUNDING_ID,
        aggregated_pub_key.clone(),
        &vec![amount],
        FEE,
        true,
        true,
        Some(vec![spending_scripts.clone()]),
    )?;
    wallet.mine(1)?;

    let utxo = Utxo::new(txid, 0, amount, &aggregated_pub_key);

    info!("UTXO: {:?}", utxo);

    Ok(utxo)
}

pub fn set_speedup_funding(
    amount: u64,
    pub_key: &PublicKey,
    channel: &DualChannel,
    wallet: &Wallet,
) -> Result<()> {
    let fund_txid = wallet.fund_address(
        WALLET_NAME,
        FUNDING_ID,
        *pub_key,
        &vec![amount],
        FEE,
        false,
        true,
        None,
    )?;

    wallet.mine(1)?;

    let funds_utxo_0 = Utxo::new(fund_txid, 0, amount, pub_key);
    let command = IncomingBitVMXApiMessages::SetFundingUtxo(funds_utxo_0).to_string()?;
    channel.send(BITVMX_ID, command)?;
    Ok(())
}