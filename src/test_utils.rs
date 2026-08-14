use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::{env, fs};

use bitcoin::{Transaction, Txid};
use bitcoin_coordinator::{
    errors::BitcoinCoordinatorError,
    types::{AckNews, News},
    TransactionStatus, TypesToMonitor,
};
use bitvmx_broker::identification::allow_list::AllowList;
use bitvmx_broker::identification::identifier::Identifier;
use bitvmx_broker::identification::routing::RoutingTable;
use bitvmx_broker::{BrokerNode, ReceivedMessage};
use bitvmx_settings::settings;
use key_manager::{create_key_manager_from_config, key_manager::KeyManager};
use protocol_builder::types::{output::SpeedupData, Utxo};
use storage_backend::storage::Storage;
use storage_backend::storage_config::StorageConfig;
use uuid::Uuid;

use crate::config::Config;
use crate::errors::BitVMXError;
use crate::leader_broadcast::LeaderBroadcastHelper;
use crate::ports::bitcoin_coordinator::BitcoinCoordinatorApi;
use crate::program::participant::CommsAddress;
use crate::program::variables::{Globals, WitnessVars};
use crate::types::ProgramContext;

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
/// with the development comms RSA key imported, and can build a `BrokerNode`
/// for tests that exercise the comms send path.
///
/// Internal building block of [`TestProgramContextEnv`] — write tests against
/// that instead; the context env costs barely more and provides everything
/// this does plus globals, broker channel and the coordinator mock.
struct TestCommsEnv {
    config: Config,
    storage: Rc<Storage>,
    key_manager: Rc<KeyManager>,
    rsa_public_key: String,
    _dir: TestStorageDir,
}

impl TestCommsEnv {
    fn new(prefix: &str) -> Result<Self, BitVMXError> {
        let dir = TestStorageDir::new(prefix);
        fs::create_dir_all(dir.path()).map_err(|_| BitVMXError::SerializationError)?;

        let mut config = Config::new(Some("config/development.yaml".to_string()))?;
        config.storage.path = format!("{}/storage.db", dir.path());
        config.key_storage.path = format!("{}/keys.db", dir.path());
        config.comms.storage_path = format!("{}/comms.db", dir.path());
        config.broker.storage.path = format!("{}/broker.db", dir.path());
        // BrokerNode binds a local server on the comms address; give each
        // env its own port so parallel tests don't collide, and keep the port
        // real (not OS-assigned) so messages can be delivered back to it.
        static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(23100);
        config
            .comms
            .address
            .set_port(NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed));
        // The broker server binds its own port too, so take it from the same counter.
        config.broker.port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);

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
    fn receive_one(channel: &mut BrokerNode) -> Result<(Identifier, String), BitVMXError> {
        for _ in 0..100 {
            channel.tick()?;
            let mut received = channel.check_receive(None)?;
            if let Some(ReceivedMessage::Msg(identifier, data)) = received.pop() {
                return Ok((identifier, data));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("no message received after 5 seconds");
    }

    /// Tick both channels until the receiver gets a message, or panic after a
    /// few seconds. Use for cross-channel delivery: the sender's tick pushes
    /// the queued message to the receiver's local server.
    fn receive_via(
        sender: &mut BrokerNode,
        receiver: &mut BrokerNode,
    ) -> Result<(Identifier, String), BitVMXError> {
        for _ in 0..100 {
            sender.tick()?;
            receiver.tick()?;
            let mut received = receiver.check_receive(None)?;
            if let Some(ReceivedMessage::Msg(identifier, data)) = received.pop() {
                return Ok((identifier, data));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("no message received after 5 seconds");
    }

    /// Tick both channels long enough for any queued message to be delivered
    /// and assert none arrives on either side. Use to verify a code path
    /// deliberately sent nothing.
    fn assert_no_delivery(a: &mut BrokerNode, b: &mut BrokerNode) {
        for _ in 0..10 {
            a.tick().unwrap();
            b.tick().unwrap();
            assert!(
                a.check_receive(None).unwrap().is_empty(),
                "unexpected message delivered to first channel"
            );
            assert!(
                b.check_receive(None).unwrap().is_empty(),
                "unexpected message delivered to second channel"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Build an extra comms identity listening on its own port, for tests that
    /// need a real remote peer distinct from [`Self::broker_node`] (which
    /// uses the op_1 key). Peer `index` uses the development `op_{index + 2}`
    /// key, so each index is a distinct identity (0..=8 available). Its comms
    /// storage lives in the same temp dir.
    fn peer_channel(&self, index: usize) -> Result<BrokerNode, BitVMXError> {
        static NEXT_PEER_PORT: AtomicU16 = AtomicU16::new(24100);
        let mut address = self.config.comms.address;
        address.set_port(NEXT_PEER_PORT.fetch_add(1, Ordering::Relaxed));
        let name = format!("peer-{}", index);
        Ok(BrokerNode::new_peers_with_paths(
            &name,
            address,
            &format!("config/keys/op_{}.key", index + 2),
            self.storage.clone(),
            &format!("{}/comms-{}.db", self._dir.path(), name),
            &self.config.comms.allow_list,
            self.config.broker.settings.clone(),
        )?)
    }

    /// Build a BrokerNode using the development broker settings. The channel
    /// runs its own local server, so messages sent to its own address are
    /// delivered back to it on tick without an external broker.
    fn broker_node(&self) -> Result<BrokerNode, BitVMXError> {
        Ok(BrokerNode::new_peers_with_paths(
            "comms",
            self.config.comms.address,
            &self.config.comms.priv_key,
            self.storage.clone(),
            &self.config.comms.storage_path,
            &self.config.comms.allow_list,
            self.config.broker.settings.clone(),
        )?)
    }
}

/// A transaction registered for dispatch on the [`BitcoinCoordinatorMock`],
/// with every argument the caller passed.
#[derive(Debug, Clone)]
pub struct MockDispatch {
    pub tx: Transaction,
    pub speedup_data: Option<SpeedupData>,
    pub context: String,
    pub target_block_height: Option<u32>,
    pub confirmation_trigger: Option<u32>,
    pub stuck_in_mempool_blocks: Option<u32>,
}

/// In-memory mock of the bitcoin coordinator port. Records every call so unit
/// tests can assert on the interactions, and lets tests stage the values
/// returned by the query methods (`is_ready`, `get_transaction`, `get_news`).
/// No bitcoind or coordinator storage involved.
pub struct BitcoinCoordinatorMock {
    ready: Cell<bool>,
    tick_count: Cell<u32>,
    dispatched: RefCell<Vec<MockDispatch>>,
    cancelled: RefCell<Vec<TypesToMonitor>>,
    monitored: RefCell<Vec<TypesToMonitor>>,
    funding: RefCell<Vec<Utxo>>,
    acked: RefCell<Vec<AckNews>>,
    transactions: RefCell<HashMap<Txid, TransactionStatus>>,
    news: RefCell<News>,
}

impl BitcoinCoordinatorMock {
    pub fn new() -> Self {
        Self {
            ready: Cell::new(true),
            tick_count: Cell::new(0),
            dispatched: RefCell::new(Vec::new()),
            cancelled: RefCell::new(Vec::new()),
            monitored: RefCell::new(Vec::new()),
            funding: RefCell::new(Vec::new()),
            acked: RefCell::new(Vec::new()),
            transactions: RefCell::new(HashMap::new()),
            news: RefCell::new(News {
                monitor_news: Vec::new(),
                coordinator_news: Vec::new(),
            }),
        }
    }

    /// Stage the value returned by `is_ready` (defaults to `true`).
    pub fn set_ready(&self, ready: bool) {
        self.ready.set(ready);
    }

    /// Stage the status returned by `get_transaction` for `txid`. Unstaged
    /// txids make `get_transaction` return an error.
    pub fn set_transaction_status(&self, txid: Txid, status: TransactionStatus) {
        self.transactions.borrow_mut().insert(txid, status);
    }

    /// Stage the news returned by `get_news` (defaults to empty news).
    pub fn set_news(&self, news: News) {
        *self.news.borrow_mut() = news;
    }

    pub fn tick_count(&self) -> u32 {
        self.tick_count.get()
    }

    pub fn dispatched(&self) -> Vec<MockDispatch> {
        self.dispatched.borrow().clone()
    }

    pub fn cancelled(&self) -> Vec<TypesToMonitor> {
        self.cancelled.borrow().clone()
    }

    pub fn monitored(&self) -> Vec<TypesToMonitor> {
        self.monitored.borrow().clone()
    }

    pub fn funding(&self) -> Vec<Utxo> {
        self.funding.borrow().clone()
    }

    pub fn acked_count(&self) -> usize {
        self.acked.borrow().len()
    }
}

impl BitcoinCoordinatorApi for BitcoinCoordinatorMock {
    fn is_ready(&self) -> Result<bool, BitcoinCoordinatorError> {
        Ok(self.ready.get())
    }

    fn tick(&self) -> Result<(), BitcoinCoordinatorError> {
        self.tick_count.set(self.tick_count.get() + 1);
        Ok(())
    }

    fn dispatch_without_speedup(
        &self,
        tx: Transaction,
        context: String,
        target_block_height: Option<u32>,
        confirmation_trigger: Option<u32>,
        stuck_in_mempool_blocks: Option<u32>,
    ) -> Result<(), BitcoinCoordinatorError> {
        self.dispatched.borrow_mut().push(MockDispatch {
            tx,
            speedup_data: None,
            context,
            target_block_height,
            confirmation_trigger,
            stuck_in_mempool_blocks,
        });
        Ok(())
    }

    fn dispatch_with_speedup(
        &self,
        tx: Transaction,
        speedup_data: SpeedupData,
        context: String,
        target_block_height: Option<u32>,
        confirmation_trigger: Option<u32>,
    ) -> Result<(), BitcoinCoordinatorError> {
        self.dispatched.borrow_mut().push(MockDispatch {
            tx,
            speedup_data: Some(speedup_data),
            context,
            target_block_height,
            confirmation_trigger,
            stuck_in_mempool_blocks: None,
        });
        Ok(())
    }

    fn dispatch(
        &self,
        tx: Transaction,
        speedup_data: Option<SpeedupData>,
        context: String,
        target_block_height: Option<u32>,
        confirmation_trigger: Option<u32>,
    ) -> Result<(), BitcoinCoordinatorError> {
        match speedup_data {
            Some(speedup_data) => self.dispatch_with_speedup(
                tx,
                speedup_data,
                context,
                target_block_height,
                confirmation_trigger,
            ),
            None => self.dispatch_without_speedup(
                tx,
                context,
                target_block_height,
                confirmation_trigger,
                None,
            ),
        }
    }

    fn cancel(&self, data: TypesToMonitor) -> Result<(), BitcoinCoordinatorError> {
        self.cancelled.borrow_mut().push(data);
        Ok(())
    }

    fn add_funding(&self, utxo: Utxo) -> Result<(), BitcoinCoordinatorError> {
        self.funding.borrow_mut().push(utxo);
        Ok(())
    }

    fn get_transaction(&self, txid: Txid) -> Result<TransactionStatus, BitcoinCoordinatorError> {
        self.transactions
            .borrow()
            .get(&txid)
            .cloned()
            .ok_or_else(|| {
                BitcoinCoordinatorError::Internal(format!(
                    "BitcoinCoordinatorMock: no status staged for txid {}",
                    txid
                ))
            })
    }

    fn get_news(&self) -> Result<News, BitcoinCoordinatorError> {
        Ok(self.news.borrow().clone())
    }

    fn ack_news(&self, news: AckNews) -> Result<(), BitcoinCoordinatorError> {
        self.acked.borrow_mut().push(news);
        Ok(())
    }

    fn monitor(&self, data: TypesToMonitor) -> Result<(), BitcoinCoordinatorError> {
        self.monitored.borrow_mut().push(data);
        Ok(())
    }
}

/// Unit-test environment providing a full `ProgramContext` backed by the
/// [`BitcoinCoordinatorMock`]: real comms channel, key manager, globals,
/// witness vars and broker channel (all on the [`TestCommsEnv`] temp storage),
/// with the bitcoin coordinator mocked so no bitcoind is needed.
pub struct TestProgramContextEnv {
    env: TestCommsEnv,
    pub context: ProgramContext<BitcoinCoordinatorMock>,
    /// Remote peer identities; peer `i` uses the development `op_{i + 2}` key
    /// on its own port, so each index is a distinct identity (0..=8 available).
    pub peers: Vec<BrokerNode>,
}

impl TestProgramContextEnv {
    pub fn new(prefix: &str) -> Result<Self, BitVMXError> {
        Self::new_with_peers(prefix, 0)
    }

    /// Like [`Self::new`], but also instantiates `peer_count` remote peer
    /// channels, addressable through [`Self::peer_address`] and read back
    /// with [`Self::receive_via_peer`].
    pub fn new_with_peers(prefix: &str, peer_count: usize) -> Result<Self, BitVMXError> {
        let env = TestCommsEnv::new(prefix)?;

        let comms = env.broker_node()?;

        // Stands in for the services broker bitvmx hosts.
        let allow_list = AllowList::new();
        allow_list.lock().unwrap().set_allow_all(true);
        let routing_table = RoutingTable::new();
        routing_table.lock().unwrap().allow_all();

        let broker_channel = BrokerNode::new_services(
            "services",
            SocketAddr::new(env.config.broker.ip, env.config.broker.port),
            &settings::decrypt_or_read_file(&env.config.broker.priv_key)?,
            env.storage.clone(),
            &env.config.broker.storage.path,
            allow_list,
            routing_table,
            env.config.components.bitvmx.clone(),
            env.config.broker.settings.clone(),
        )?;

        let context = ProgramContext::new(
            comms,
            env.key_manager.clone(),
            env.rsa_public_key.clone(),
            BitcoinCoordinatorMock::new(),
            broker_channel,
            Globals::new(env.storage.clone()),
            WitnessVars::new(env.storage.clone()),
            env.config.components.clone(),
            LeaderBroadcastHelper::new(env.storage.clone()),
        );

        let peers = (0..peer_count)
            .map(|index| env.peer_channel(index))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            env,
            context,
            peers,
        })
    }

    /// Comms address of peer `index` (its real address and pubkey hash).
    pub fn peer_address(&self, index: usize) -> Result<CommsAddress, BitVMXError> {
        let peer = &self.peers[index];
        Ok(CommsAddress::new(peer.get_address(), peer.get_pubk_hash()?))
    }

    /// Comms address of the context's own channel. Messages sent here are
    /// delivered back to the channel itself on tick (see [`Self::receive_one`]).
    pub fn self_address(&self) -> Result<CommsAddress, BitVMXError> {
        Ok(CommsAddress::new(
            self.context.comms.get_address(),
            self.context.comms.get_pubk_hash()?,
        ))
    }

    /// Tick the context channel until a message is delivered and received, or
    /// panic after a few seconds. Works for self-addressed messages (sent to
    /// [`Self::self_address`]) without an external broker.
    pub fn receive_one(&mut self) -> Result<(Identifier, String), BitVMXError> {
        TestCommsEnv::receive_one(&mut self.context.comms)
    }

    /// Tick the context channel and peer `index` until the peer receives a
    /// message, or panic after a few seconds.
    pub fn receive_via_peer(&mut self, index: usize) -> Result<(Identifier, String), BitVMXError> {
        TestCommsEnv::receive_via(&mut self.context.comms, &mut self.peers[index])
    }

    /// Assert that neither the context channel nor peer `index` receives
    /// anything (see [`TestCommsEnv::assert_no_delivery`]).
    pub fn assert_no_delivery_via_peer(&mut self, index: usize) {
        TestCommsEnv::assert_no_delivery(&mut self.context.comms, &mut self.peers[index]);
    }

    pub fn coordinator_mock(&self) -> &BitcoinCoordinatorMock {
        &self.context.bitcoin_coordinator
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin_coordinator::types::CoordinatorNews;

    use crate::program::protocols::protocol_handler::{new_protocol_type, ProtocolHandler};
    use crate::program::setup::steps::{KeysStep, SetupStepEnum};
    use crate::program::setup::SetupStep;
    use crate::types::PROGRAM_TYPE_AGGREGATED_KEY;

    fn dummy_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    }

    #[test]
    fn test_program_context_env_wires_mock_coordinator() {
        let env = TestProgramContextEnv::new("program-context-env").unwrap();
        let mock = env.coordinator_mock();

        // ready is staged, defaults to true
        assert!(mock.is_ready().unwrap());
        mock.set_ready(false);
        assert!(!mock.is_ready().unwrap());

        mock.tick().unwrap();
        assert_eq!(mock.tick_count(), 1);

        // dispatch is recorded with all its arguments
        let tx = dummy_tx();
        let txid = tx.compute_txid();
        mock.dispatch(tx, None, "ctx".to_string(), Some(100), Some(3))
            .unwrap();
        mock.dispatch_without_speedup(dummy_tx(), "stuck".to_string(), None, None, Some(7))
            .unwrap();
        let dispatched = mock.dispatched();
        assert_eq!(dispatched.len(), 2);
        assert_eq!(dispatched[0].tx.compute_txid(), txid);
        assert!(dispatched[0].speedup_data.is_none());
        assert_eq!(dispatched[0].context, "ctx");
        assert_eq!(dispatched[0].target_block_height, Some(100));
        assert_eq!(dispatched[0].confirmation_trigger, Some(3));
        assert_eq!(dispatched[0].stuck_in_mempool_blocks, None);
        assert_eq!(dispatched[1].stuck_in_mempool_blocks, Some(7));

        // unstaged txid is an error instead of a silent default
        assert!(mock.get_transaction(txid).is_err());

        // staged status is returned (built via serde: the blockchain status
        // enum is not re-exported through bitcoin_coordinator)
        let status: TransactionStatus = serde_json::from_value(serde_json::json!({
            "tx": null,
            "block_info": null,
            "confirmations": 0,
            "status": "NotFound",
        }))
        .unwrap();
        mock.set_transaction_status(txid, status.clone());
        assert_eq!(mock.get_transaction(txid).unwrap(), status);

        // funding utxos are recorded
        let utxo = Utxo {
            txid,
            vout: 1,
            amount: 5000,
            pub_key: "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
                .parse()
                .unwrap(),
        };
        mock.add_funding(utxo.clone()).unwrap();
        assert_eq!(mock.funding(), vec![utxo]);

        // staged news round-trips; acks are recorded
        let news = News {
            monitor_news: vec![],
            coordinator_news: vec![CoordinatorNews::TxNotFound { txid }],
        };
        mock.set_news(news.clone());
        assert_eq!(mock.get_news().unwrap(), news);
        mock.ack_news(AckNews::Coordinator(CoordinatorNews::TxNotFound { txid }))
            .unwrap();
        assert_eq!(mock.acked_count(), 1);

        // monitor / cancel are recorded
        mock.monitor(TypesToMonitor::NewBlock).unwrap();
        assert_eq!(mock.monitored(), vec![TypesToMonitor::NewBlock]);
        mock.cancel(TypesToMonitor::NewBlock).unwrap();
        assert_eq!(mock.cancelled(), vec![TypesToMonitor::NewBlock]);

        // the context is wired to the same config the comms env loaded
        assert_eq!(
            env.context.components_config.bitvmx,
            env.env.config.components.bitvmx
        );

        // ProtocolHandler and SetupStep dispatch accept the mocked context.
        let protocol = new_protocol_type(
            Uuid::new_v4(),
            PROGRAM_TYPE_AGGREGATED_KEY,
            0,
            env.env.storage.clone(),
        )
        .unwrap();
        assert_eq!(protocol.requested_confirmations(&env.context), Some(1));

        let setup_step = SetupStepEnum::Keys(KeysStep::new());
        assert!(setup_step
            .can_advance(&protocol, &[], &env.context)
            .unwrap());
    }
}
