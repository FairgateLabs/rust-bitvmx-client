use std::rc::Rc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::{env, fs};

use bitvmx_broker::channel::queue_channel::{QueueChannel, ReceiveHandlerChannel};
use bitvmx_broker::identification::identifier::Identifier;
use bitvmx_settings::settings;
use key_manager::{create_key_manager_from_config, key_manager::KeyManager};
use storage_backend::storage::Storage;
use storage_backend::storage_config::StorageConfig;
use uuid::Uuid;

use crate::config::Config;
use crate::errors::BitVMXError;

/// Temporary storage directory for unit tests. Creates a unique path under the
/// system temp dir and removes it on drop.
pub struct TestStorageDir {
    path: String,
}

impl TestStorageDir {
    pub fn new(prefix: &str) -> Self {
        Self {
            path: env::temp_dir()
                .join(format!("{}-{}", prefix, Uuid::new_v4()))
                .to_string_lossy()
                .into_owned(),
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn config(&self) -> StorageConfig {
        StorageConfig {
            path: self.path.clone(),
            password: None,
        }
    }

    pub fn storage(&self) -> Rc<Storage> {
        Rc::new(Storage::new(&self.config()).unwrap())
    }
}

impl Drop for TestStorageDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Comms test environment built from `config/development.yaml` with all storage
/// redirected to a unique temp dir (removed on drop). Provides a `KeyManager`
/// with the development comms RSA key imported, and can build a `QueueChannel`
/// for tests that exercise the comms send path.
pub struct TestCommsEnv {
    pub config: Config,
    pub storage: Rc<Storage>,
    pub key_manager: Rc<KeyManager>,
    pub rsa_public_key: String,
    _dir: TestStorageDir,
}

impl TestCommsEnv {
    pub fn new(prefix: &str) -> Result<Self, BitVMXError> {
        let dir = TestStorageDir::new(prefix);
        fs::create_dir_all(dir.path()).map_err(|_| BitVMXError::SerializationError)?;

        let mut config = Config::new(Some("config/development.yaml".to_string()))?;
        config.storage.path = format!("{}/storage.db", dir.path());
        config.key_storage.path = format!("{}/keys.db", dir.path());
        config.comms.storage_path = format!("{}/comms.db", dir.path());
        // QueueChannel binds a local server on the comms address; give each
        // env its own port so parallel tests don't collide, and keep the port
        // real (not OS-assigned) so messages can be delivered back to it.
        static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(23100);
        config
            .comms
            .address
            .set_port(NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed));

        let storage = Rc::new(Storage::new(&config.storage)?);
        let key_manager = Rc::new(create_key_manager_from_config(
            &config.key_manager,
            &config.key_storage,
        )?);
        let rsa_public_key = key_manager
            .import_rsa_private_key(&settings::decrypt_or_read_file(config.comms_key())?)?;

        Ok(Self {
            config,
            storage,
            key_manager,
            rsa_public_key,
            _dir: dir,
        })
    }

    /// Tick the channel until a message is delivered and received, or panic
    /// after a few seconds. Delivery goes through the channel's local server,
    /// so this works for self-addressed messages without an external broker.
    pub fn receive_one(channel: &mut QueueChannel) -> Result<(Identifier, Vec<u8>), BitVMXError> {
        for _ in 0..100 {
            channel.tick()?;
            let mut received = channel.check_receive()?;
            if let Some(ReceiveHandlerChannel::Msg(identifier, data)) = received.pop() {
                return Ok((identifier, data));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("no message received after 5 seconds");
    }

    /// Build a QueueChannel using the development broker settings. The channel
    /// runs its own local server, so messages sent to its own address are
    /// delivered back to it on tick without an external broker.
    pub fn queue_channel(&self) -> Result<QueueChannel, BitVMXError> {
        Ok(QueueChannel::new_with_paths(
            "comms",
            self.config.comms.address,
            &self.config.comms.priv_key,
            self.storage.clone(),
            Some(self.config.comms.storage_path.clone()),
            &self.config.broker.allow_list,
            &self.config.broker.routing_table,
            self.config.broker.settings.clone(),
        )?)
    }
}
