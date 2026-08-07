#![allow(dead_code)]
#![cfg(test)]

pub mod dispute;
pub mod helper;

use anyhow::Result;
use bitcoin::{Amount, PublicKey, Txid, XOnlyPublicKey};
use bitcoind::{
    bitcoind::{Bitcoind, BitcoindFlags},
    config::BitcoindConfig,
};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use bitvmx_broker::{
    identification::{allow_list::AllowList, identifier::Identifier},
    rpc::{tls_helper::Cert, BrokerConfig},
    RemoteChannel,
};
use bitvmx_client::{
    bitvmx::BitVMX,
    config::Config,
    program::{participant::CommsAddress, protocols::protocol_handler::external_fund_tx},
    types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages, ParticipantChannel},
};
use bitvmx_job_dispatcher::DispatcherHandler;
use bitvmx_job_dispatcher_types::emulator_messages::EmulatorJobType;
use bitvmx_settings::settings;
use bitvmx_wallet::wallet::{Destination, RegtestWallet, Wallet};
use protocol_builder::{
    scripts::{self, ProtocolScript, SignMode},
    types::{OutputType, Utxo},
};
use std::{path::Path, process::Command, sync::Once};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::common::{dispute::process_dispatcher_non_blocking, helper::InternalWallet};

/// Number of blocks to mine initially in tests to ensure sufficient coin maturity
pub const INITIAL_BLOCK_COUNT: u64 = 101;

/// RAII guard for bitcoind that ensures cleanup on Drop.
/// This prevents Docker containers from being left running if a test panics.
pub struct BitcoindGuard {
    bitcoind: Option<Bitcoind>,
}

impl BitcoindGuard {
    pub fn new(bitcoind: Option<Bitcoind>) -> Self {
        Self { bitcoind }
    }

    /// Explicitly stop bitcoind (useful for checking errors).
    pub fn stop(mut self) -> Result<()> {
        if let Some(bitcoind) = self.bitcoind.take() {
            bitcoind.stop()?;
        }
        Ok(())
    }
}

impl Drop for BitcoindGuard {
    fn drop(&mut self) {
        if let Some(bitcoind) = self.bitcoind.take() {
            if let Err(e) = bitcoind.stop() {
                warn!("BitcoindGuard: failed to stop bitcoind on drop: {}", e);
            }
        }
    }
}

pub const LOCAL_SLEEP_MS: u64 = 100;

// Slightly higher in CI to absorb shared-runner variability. Kept as a
// separate constant so the CI value can be tuned independently.
pub const CI_SLEEP_MS: u64 = 150;

pub fn clear_db(path: &str) {
    // Only try to remove if the path exists
    if std::path::Path::new(path).exists() {
        let _ = std::fs::remove_dir_all(path);
    }
}

/// Check if Docker is available and running
pub fn check_docker_available() -> Result<bool> {
    // Check if docker command exists and daemon is running
    let output = Command::new("docker").arg("info").output();

    match output {
        Ok(result) => Ok(result.status.success()),
        Err(_) => Ok(false),
    }
}

/// Ensure Docker is available, returning a helpful error if not
pub fn ensure_docker_available() -> Result<()> {
    if !check_docker_available()? {
        let docker_host = std::env::var("DOCKER_HOST").ok();
        let docker_sock_standard = std::path::Path::new("/var/run/docker.sock").exists();
        let docker_sock_macos = std::env::var("HOME")
            .ok()
            .map(|home| std::path::Path::new(&format!("{}/.docker/run/docker.sock", home)).exists())
            .unwrap_or(false);

        let mut error_msg = "\n❌ Docker daemon is not running or not accessible.\n\n".to_string();
        error_msg.push_str("To fix this issue:\n\n");

        if cfg!(target_os = "macos") {
            error_msg.push_str("On macOS, Docker Desktop uses a non-standard socket location.\n");
            error_msg.push_str("Option 1: Set DOCKER_HOST environment variable:\n");
            error_msg.push_str("  export DOCKER_HOST=unix://$HOME/.docker/run/docker.sock\n");

            if !docker_sock_macos {
                error_msg.push_str("Option 2: Create a symlink (requires sudo):\n");
                error_msg
                    .push_str("  sudo ln -sf ~/.docker/run/docker.sock /var/run/docker.sock\n\n");
            }

            if docker_sock_macos && !docker_sock_standard {
                error_msg
                    .push_str("Note: Docker Desktop socket found at ~/.docker/run/docker.sock\n");
                error_msg.push_str("      but not accessible at /var/run/docker.sock\n");
            }
        } else {
            error_msg.push_str("1. Make sure Docker is installed\n");
            error_msg.push_str("2. Start Docker daemon\n");
            error_msg.push_str("3. Verify with: docker info\n\n");
        }

        if docker_host.is_some() {
            error_msg.push_str(&format!("Current DOCKER_HOST: {}\n", docker_host.unwrap()));
        }

        anyhow::bail!(error_msg);
    }
    Ok(())
}

pub fn init_bitvmx(
    role: &str,
    emulator_dispatcher: bool,
) -> Result<(BitVMX, CommsAddress, RemoteChannel, Option<RemoteChannel>)> {
    init_bitvmx_with_storage(role, emulator_dispatcher, true)
}

/// Bring up a second instance on the storage an earlier one left behind, for
/// tests that need to observe what survives a restart.
pub fn restart_bitvmx(
    role: &str,
    emulator_dispatcher: bool,
) -> Result<(BitVMX, CommsAddress, RemoteChannel, Option<RemoteChannel>)> {
    init_bitvmx_with_storage(role, emulator_dispatcher, false)
}

pub fn init_bitvmx_with_storage(
    role: &str,
    emulator_dispatcher: bool,
    clear_storage: bool,
) -> Result<(BitVMX, CommsAddress, RemoteChannel, Option<RemoteChannel>)> {
    let config = Config::new(Some(format!("config/{}.yaml", role)))?;
    let allow_list = AllowList::from_file(&config.broker.allow_list)?;
    let broker_config = BrokerConfig::new(
        config.broker.port,
        None,
        config.broker.get_pubk_hash()?,
        Some(config.broker.settings.clone()),
    );
    let bridge_client = RemoteChannel::new(
        &broker_config,
        Cert::new_with_privk(
            settings::decrypt_or_read_file(&config.testing.l2.priv_key)?.as_str(),
        )?,
        Some(config.testing.l2.id),
        allow_list.clone(),
    )?;
    let dispatcher_channel = if emulator_dispatcher {
        Some(RemoteChannel::new(
            &broker_config,
            Cert::new_with_privk(
                settings::decrypt_or_read_file(&config.testing.emulator.priv_key)?.as_str(),
            )?,
            Some(config.testing.emulator.id),
            allow_list,
        )?)
    } else {
        None
    };

    if clear_storage {
        clear_db(&config.storage.path);
        clear_db(&config.key_storage.path);
        clear_db(&config.broker.storage.path);
        clear_db(&config.comms.storage_path);
        Wallet::clear_db(&config.wallet)?;
    }

    info!("config: {:?}", config.storage.path);

    let bitvmx = BitVMX::new(config)?;

    let address = CommsAddress::new(bitvmx.address(), bitvmx.pubkey_hash()?);
    info!("public key hash {:?}", bitvmx.pubkey_hash());

    //This messages will come from the bridge client.

    Ok((bitvmx, address, bridge_client, dispatcher_channel))
}

pub fn tick(instance: &mut BitVMX) -> Result<()> {
    instance.process_api_messages()?;
    instance.process_comms_messages()?;
    instance.process_programs()?;
    instance.process_pending_messages()?;
    Ok(())
}

pub fn wait_message_from_channel(
    channel: &RemoteChannel,
    instances: &mut Vec<&mut BitVMX>,
    fake_tick: bool,
) -> Result<(String, Identifier)> {
    // Use longer sleep in CI for stability, shorter locally for speed
    let sleep_ms = if std::env::var("GITHUB_ACTIONS").is_ok() {
        CI_SLEEP_MS
    } else {
        LOCAL_SLEEP_MS
    };

    for i in 0..40000 {
        if i % 50 == 0 {
            let msg = channel.recv()?;
            if msg.is_some() {
                //info!("Received message from channel: {:?}", msg);
                return Ok(msg.unwrap());
            }
            std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
        }
        for instance in instances.iter_mut() {
            if fake_tick {
                tick(instance)?;
            } else {
                instance.tick()?;
            }
        }
    }
    panic!("Timeout waiting for message from channel");
}

pub const WALLET_NAME: &str = "wallet";
pub const FUNDING_ID: &str = "fund_1";
pub const FEE: u64 = 500;

pub fn prepare_bitcoin() -> Result<(BitcoinClient, Option<Bitcoind>, InternalWallet)> {
    let wallet_config = bitvmx_settings::settings::load_config_file::<
        bitvmx_wallet::wallet::config::Config,
    >(Some("config/wallet_regtest.yaml".to_string()))?;

    // Clear indexer, monitor, key manager and wallet data.
    clear_db(&wallet_config.storage.path);
    clear_db(&wallet_config.key_storage.path);
    // Wallet::clear_db may fail if the directory doesn't exist, which is fine
    let _ = Wallet::clear_db(&wallet_config.wallet);

    let is_ci = std::env::var("GITHUB_ACTIONS").is_ok();

    let bitcoind = if is_ci {
        info!("Running in CI - using external bitcoind from docker-compose");
        std::thread::sleep(std::time::Duration::from_secs(2));
        None
    } else {
        // Clean up any existing bitcoin-regtest container before starting a new one
        // This prevents conflicts when running tests sequentially or in parallel
        info!("Cleaning up any existing bitcoin-regtest container");
        // Try multiple times to ensure cleanup succeeds (handles race conditions)
        for attempt in 0..3 {
            let _ = Command::new("docker")
                .args(&["stop", "bitcoin-regtest"])
                .output();
            std::thread::sleep(std::time::Duration::from_millis(100));

            let _ = Command::new("docker")
                .args(&["rm", "-f", "bitcoin-regtest"])
                .output();

            // Check if container still exists
            let check_output = Command::new("docker")
                .args(&[
                    "ps",
                    "-a",
                    "--filter",
                    "name=bitcoin-regtest",
                    "--format",
                    "{{.Names}}",
                ])
                .output();

            if let Ok(output) = check_output {
                let container_exists =
                    String::from_utf8_lossy(&output.stdout).contains("bitcoin-regtest");
                if !container_exists {
                    break; // Container successfully removed
                }
            }

            if attempt < 2 {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
        // Final delay to ensure Docker has processed the removal
        std::thread::sleep(std::time::Duration::from_millis(500));

        let bitcoind_instance = Bitcoind::new(
            BitcoindConfig::default(),
            wallet_config.bitcoin.clone(),
            Some(BitcoindFlags {
                min_relay_tx_fee: 0.00001,
                block_min_tx_fee: 0.00002,
                debug: 1,
                fallback_fee: 0.0002,
                maxmempool: None,
            }),
        );

        info!("Starting bitcoind");
        bitcoind_instance.start()?;
        Some(bitcoind_instance)
    };

    let (bitcoin_client, bc2) = if is_ci {
        // In CI mode, use the wallet-specific endpoint to avoid RPC wallet errors
        (
            BitcoinClient::new_with_wallet(
                &wallet_config.bitcoin.url,
                &wallet_config.bitcoin.username,
                &wallet_config.bitcoin.password,
                &wallet_config.bitcoin.wallet,
            )?,
            BitcoinClient::new_with_wallet(
                &wallet_config.bitcoin.url,
                &wallet_config.bitcoin.username,
                &wallet_config.bitcoin.password,
                &wallet_config.bitcoin.wallet,
            )?,
        )
    } else {
        // Local mode uses the regular client
        (
            BitcoinClient::new(
                &wallet_config.bitcoin.url,
                &wallet_config.bitcoin.username,
                &wallet_config.bitcoin.password,
            )?,
            BitcoinClient::new(
                &wallet_config.bitcoin.url,
                &wallet_config.bitcoin.username,
                &wallet_config.bitcoin.password,
            )?,
        )
    };

    // Create a new local wallet
    let mut wallet =
        Wallet::from_config(wallet_config.bitcoin.clone(), wallet_config.wallet.clone())?;

    if is_ci {
        info!("CI mode: initializing wallet and funding from pre-existing test_wallet");
        let _address = bitcoin_client.init_wallet(&wallet_config.bitcoin.wallet)?;
        info!("Funding local wallet from test_wallet in CI mode");
        bitcoin_client.fund_address(&wallet.receive_address()?, Amount::from_int_btc(10))?;
    } else {
        info!("Local mode: full initialization with mining and funding");
        let _address = bitcoin_client.init_wallet(&wallet_config.bitcoin.wallet)?;
        bitcoin_client.mine_blocks_to_address(INITIAL_BLOCK_COUNT, &_address)?;
        bitcoin_client.fund_address(&wallet.receive_address()?, Amount::from_int_btc(10))?;
    }

    // Sync the wallet with the Bitcoin node to the latest block
    wallet.sync_wallet()?;

    Ok((
        bitcoin_client,
        bitcoind,
        InternalWallet::new(bc2, wallet, true),
    ))
}

/// Same as prepare_bitcoin but wraps bitcoind in a guard for automatic cleanup.
/// Use this for new tests to ensure bitcoind stops even if the test panics.
pub fn prepare_bitcoin_guarded() -> Result<(BitcoinClient, BitcoindGuard, InternalWallet)> {
    let (bitcoin_client, bitcoind, wallet) = prepare_bitcoin()?;
    Ok((bitcoin_client, BitcoindGuard::new(bitcoind), wallet))
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
        "bitvmx_client=info",
        "bitvmx_transaction_monitor=off",
        "bitcoin_indexer=off",
        "bitcoin_coordinator=info",
        "bitvmx_wallet=info",
        "tarpc=off",
        "key_manager=off",
        "memory=off",
        "bitvmx_broker=off",
    ];

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_modules.join(",")))
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        //.without_time()
        //.with_ansi(false)
        .with_target(true)
        .with_env_filter(filter)
        .init();
}

/// Check gnova binary exists
pub fn check_gnova_built() -> Result<()> {
    #[cfg(target_os = "windows")]
    let binary = "../rust-bitvmx-gc/target/release/gnova.exe";
    #[cfg(not(target_os = "windows"))]
    let binary = "../rust-bitvmx-gc/target/release/gnova";
    if !Path::new(binary).exists() {
        return Err(anyhow::anyhow!(
            "gnova binary not found at {}. Build with: cd ../rust-bitvmx-gc && cargo build --release --bin gnova",
            binary
        ));
    }
    Ok(())
}

/// Checks if BitVMX-CPU is properly built and required files exist
/// Returns an error if dependencies are missing
pub fn check_bitvmx_cpu_built() -> Result<()> {
    #[cfg(not(target_os = "windows"))]
    let emulator_binary = "../BitVMX-CPU/target/release/emulator";
    #[cfg(target_os = "windows")]
    let emulator_binary = "../BitVMX-CPU/target/release/emulator.exe";

    let program_dir = "../BitVMX-CPU/docker-riscv32/riscv32/build";

    if !Path::new(emulator_binary).exists() {
        warn!(
            "⚠️  BitVMX-CPU emulator binary not found at: {}\n\
             Please build BitVMX-CPU first by running:\n\
             cd ../BitVMX-CPU && cargo build --release --bin emulator\n\
             Or use the provided script: ./scripts/build-emulator.sh",
            emulator_binary
        );
        return Err(anyhow::anyhow!(
            "BitVMX-CPU emulator not built. Run: cd ../BitVMX-CPU && cargo build --release --bin emulator"
        ));
    }

    if !Path::new(program_dir).exists() {
        warn!(
            "⚠️  BitVMX-CPU program directory not found at: {}\n\
             Please ensure BitVMX-CPU is properly set up.",
            program_dir
        );
        return Err(anyhow::anyhow!(
            "BitVMX-CPU program directory not found at: {}",
            program_dir
        ));
    }

    Ok(())
}

pub fn send_all(id_channel_pairs: &Vec<ParticipantChannel>, msg: &str) -> Result<()> {
    for id_channel_pair in id_channel_pairs {
        id_channel_pair
            .channel
            .send(&id_channel_pair.id, msg.to_string())?;
    }
    Ok(())
}

pub fn get_all(
    channels: &Vec<RemoteChannel>,
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

pub fn mine_and_wait(
    _bitcoin_client: &BitcoinClient,
    channels: &Vec<RemoteChannel>,
    instances: &mut Vec<BitVMX>,
    wallet: &InternalWallet,
) -> Result<Vec<OutgoingBitVMXApiMessages>> {
    mine_and_wait_blocks(_bitcoin_client, channels, instances, wallet, 10, None)
}

pub fn mine_and_wait_with_dispatcher(
    _bitcoin_client: &BitcoinClient,
    channels: &Vec<RemoteChannel>,
    instances: &mut Vec<BitVMX>,
    wallet: &InternalWallet,
    dispatchers: &mut Vec<DispatcherHandler<EmulatorJobType>>,
    multiple_dispatcher_tries: bool,
) -> Result<Vec<OutgoingBitVMXApiMessages>> {
    mine_and_wait_blocks(
        _bitcoin_client,
        channels,
        instances,
        wallet,
        10,
        Some((dispatchers, multiple_dispatcher_tries)),
    )
}

pub fn mine_and_wait_blocks(
    _bitcoin_client: &BitcoinClient,
    channels: &Vec<RemoteChannel>,
    instances: &mut Vec<BitVMX>,
    wallet: &InternalWallet,
    blocks: u32,
    dispatchers: Option<(&mut Vec<DispatcherHandler<EmulatorJobType>>, bool)>,
) -> Result<Vec<OutgoingBitVMXApiMessages>> {
    //MINE AND WAIT
    let iters = blocks * 10;
    let (dispatchers, multiple_tries) = match dispatchers {
        Some((d, t)) => (d, t),
        None => (&mut vec![], false),
    };
    let mut result = false;
    wallet.mine(blocks as u64)?;
    for i in 0..iters {
        if dispatchers.len() > 0 && (!result || multiple_tries) {
            result = process_dispatcher_non_blocking(dispatchers, instances)?;
        }
        if i % 10 == 0 {
            wallet.mine(1)?;
        }

        for instance in instances.iter_mut() {
            instance.tick()?;
        }
        let sleep_ms = if std::env::var("GITHUB_ACTIONS").is_ok() {
            CI_SLEEP_MS
        } else {
            LOCAL_SLEEP_MS
        };
        std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
    }
    let msgs = get_all(&channels, instances, false)?;

    Ok(msgs)
}

pub fn init_broker(role: &str) -> Result<ParticipantChannel> {
    let config = Config::new(Some(format!("config/{}.yaml", role)))?;
    let allow_list = AllowList::from_file(&config.broker.allow_list)?;
    let broker_config = BrokerConfig::new(
        config.broker.port,
        None,
        config.broker.get_pubk_hash()?,
        Some(config.broker.settings.clone()),
    );
    let bridge_client = RemoteChannel::new(
        &broker_config,
        Cert::new_with_privk(
            settings::decrypt_or_read_file(&config.testing.l2.priv_key)?.as_str(),
        )?,
        Some(config.testing.l2.id),
        allow_list.clone(),
    )?;
    let particiant_channel = ParticipantChannel {
        id: config.components.bitvmx,
        channel: bridge_client,
    };
    Ok(particiant_channel)
}

pub fn init_utxo_new(
    wallet: &mut InternalWallet,
    internal_key: &PublicKey,
    spending_scripts: Vec<ProtocolScript>,
    amount: u64,
) -> Result<(Utxo, OutputType)> {
    info!("Funding address: {:?} with: {}", internal_key, amount);
    let tx = wallet.fund_destination(Destination::P2TR(
        XOnlyPublicKey::from(internal_key.clone()),
        spending_scripts.clone(),
        amount,
    ))?;
    wallet.mine(1)?;
    let utxo = Utxo::new(tx.compute_txid(), 0, amount, &*internal_key);

    let output_type = external_fund_tx(internal_key, spending_scripts, amount)?;

    info!("UTXO: {:?}", utxo);

    Ok((utxo, output_type))
}

pub fn fake_utxo(
    internal_key: &PublicKey,
    spending_scripts: Vec<ProtocolScript>,
    amount: u64,
) -> Result<(Utxo, OutputType)> {
    let fake_txid: Txid =
        "0000000000000000000000000000000000000000000000000000000000000000".parse()?;

    let utxo = Utxo::new(fake_txid, 0, amount, &*internal_key);

    let output_type = external_fund_tx(internal_key, spending_scripts, amount)?;

    info!("UTXO: {:?}", utxo);

    Ok((utxo, output_type))
}

pub fn init_utxo(
    wallet: &mut InternalWallet,
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

    let tx = wallet.fund_destination(Destination::P2TR(
        aggregated_pub_key.into(),
        spending_scripts,
        amount,
    ))?;
    wallet.mine(1)?;

    let utxo = Utxo::new(tx.compute_txid(), 0, amount, &aggregated_pub_key);

    info!("UTXO: {:?}", utxo);

    Ok(utxo)
}

fn print_advance_options(n: usize) {
    println!("\n--- Interactive mode ---");
    for i in 1..=n {
        println!("  [{i}]            tick operator {i}");
    }
    let comms_keys = ['q', 'w', 'e', 'r'];
    for i in 0..n.min(4) {
        println!(
            "  [{}]            process_comms_messages op {}",
            comms_keys[i],
            i + 1
        );
    }
    println!("  [a/A]          tick ALL operators");
    println!("  [m/M]          mine 1 block");
    println!("  [g/G]          get messages from channels");
    println!("  [Q/Esc]        quit");
    println!("------------------------");
}

/// Process a single key character. Returns `Ok(false)` when the key means quit.
fn advance_key(
    c: char,
    instances: &mut Vec<BitVMX>,
    channels: &Vec<RemoteChannel>,
    wallet: Option<&Wallet>,
) -> Result<bool> {
    match c {
        '1'..='4' => {
            let idx = (c as usize) - ('1' as usize);
            if idx < instances.len() {
                info!("[advance] tick operator {}", idx + 1);
                instances[idx].tick()?;
            } else {
                info!(
                    "[advance] no operator {} (only {} instances)",
                    idx + 1,
                    instances.len()
                );
            }
        }
        'q' | 'w' | 'e' | 'r' => {
            let idx = match c {
                'q' => 0,
                'w' => 1,
                'e' => 2,
                _ => 3,
            };
            if idx < instances.len() {
                info!("[advance] process_comms_messages operator {}", idx + 1);
                instances[idx].process_comms_messages()?;
            } else {
                info!(
                    "[advance] no operator {} (only {} instances)",
                    idx + 1,
                    instances.len()
                );
            }
        }
        'a' | 'A' => {
            info!("[advance] tick all {} operators", instances.len());
            for (i, instance) in instances.iter_mut().enumerate() {
                info!("[advance]   ticking operator {}", i + 1);
                instance.tick()?;
            }
        }
        'm' | 'M' => {
            if let Some(wallet) = wallet {
                info!("[advance] mine 1 block");
                wallet.mine(1)?;
            }
        }
        'g' | 'G' => {
            info!("[advance] get messages ({} channels)", channels.len());
            for (i, channel) in channels.iter().enumerate() {
                match channel.recv() {
                    Ok(Some((msg, id))) => {
                        info!("[advance] channel {} from {:?}: {}", i + 1, id, msg);
                    }
                    Ok(None) => {
                        info!("[advance] channel {}: (no messages)", i + 1);
                    }
                    Err(e) => {
                        info!("[advance] channel {}: error: {}", i + 1, e);
                    }
                }
            }
        }
        'Q' => {
            info!("[advance] quit");
            return Ok(false);
        }
        other => {
            info!("[advance] unknown key '{}'", other);
            print_advance_options(instances.len());
        }
    }
    Ok(true)
}

pub fn interactive_advance(
    instances: &mut Vec<BitVMX>,
    channels: &Vec<RemoteChannel>,
    wallet: Option<&Wallet>,
) -> Result<()> {
    use console::{Key, Term};

    let term = Term::stdout();
    print_advance_options(instances.len());

    loop {
        let key = term.read_key()?;
        let c = match key {
            Key::Char(c) => c,
            Key::Escape => 'Q',
            _ => continue,
        };
        if !advance_key(c, instances, channels, wallet)? {
            break;
        }
    }
    Ok(())
}

pub fn scripted_advance(
    sequence: &str,
    interval_ms: u64,
    instances: &mut Vec<BitVMX>,
    channels: &Vec<RemoteChannel>,
    wallet: Option<&Wallet>,
) -> Result<()> {
    info!(
        "[scripted] running sequence {:?} with {}ms interval",
        sequence, interval_ms
    );
    for c in sequence.chars() {
        info!("[scripted] key '{}'", c);
        if !advance_key(c, instances, channels, wallet)? {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(interval_ms));
    }
    info!("[scripted] sequence complete");
    Ok(())
}

/// Parse a log file produced by a manual run and reconstruct the keystroke sequence.
/// Matches lines containing `[advance]` or `[interactive]` markers written by `advance_key`.
pub fn generate_sequence_from_log(log_path: &str) -> Result<String> {
    let content = std::fs::read_to_string(log_path)
        .map_err(|e| anyhow::anyhow!("cannot read log file {}: {}", log_path, e))?;

    let mut sequence = String::new();

    for line in content.lines() {
        // Locate the action payload after either marker prefix.
        let payload = if let Some(pos) = line.find("[advance]") {
            line[pos + "[advance]".len()..].trim()
        } else if let Some(pos) = line.find("[interactive]") {
            line[pos + "[interactive]".len()..].trim()
        } else {
            continue;
        };

        if let Some(rest) = payload.strip_prefix("tick operator ") {
            if let Ok(n @ 1..=4) = rest.trim().parse::<u8>() {
                sequence.push((b'0' + n) as char);
            }
        } else if let Some(rest) = payload.strip_prefix("process_comms_messages operator ") {
            if let Ok(n @ 1..=4) = rest.trim().parse::<usize>() {
                sequence.push(['q', 'w', 'e', 'r'][n - 1]);
            }
        } else if payload.starts_with("tick all") {
            sequence.push('a');
        } else if payload.starts_with("mine 1 block") {
            sequence.push('m');
        } else if payload.starts_with("get messages") {
            sequence.push('g');
        } else if payload.starts_with("quit") {
            sequence.push('Q');
        }
        // sub-lines ("ticking operator N", channel results, etc.) are intentionally skipped
    }

    info!(
        "[generate_sequence] parsed {} keys from {}",
        sequence.len(),
        log_path
    );
    Ok(sequence)
}

pub fn set_speedup_funding(
    amount: u64,
    pub_key: &PublicKey,
    channel: &RemoteChannel,
    wallet: &mut InternalWallet,
    bitvmx_id: &Identifier,
) -> Result<()> {
    let fund_tx = wallet.fund_destination(Destination::P2WPKH(*pub_key, amount))?;

    let funds_utxo_0 = Utxo::new(fund_tx.compute_txid(), 0, amount, pub_key);
    let command = IncomingBitVMXApiMessages::SetFundingUtxo(funds_utxo_0).to_string()?;
    channel.send(bitvmx_id, command)?;
    Ok(())
}
