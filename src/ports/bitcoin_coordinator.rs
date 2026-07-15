use bitcoin::{Transaction, Txid};
use bitcoin_coordinator::{
    coordinator::BitcoinCoordinator,
    errors::BitcoinCoordinatorError,
    types::{AckNews, News},
    TransactionStatus, TypesToMonitor,
};
use protocol_builder::types::{output::SpeedupData, Utxo};

/// Port for the bitcoin coordinator. Mirrors the public API of
/// [`BitcoinCoordinator`] so `ProgramContext` can be instantiated with the
/// real coordinator in production or a mock in unit tests.
pub trait BitcoinCoordinatorApi {
    /// Returns `true` when the monitor is fully synced with the chain.
    fn is_ready(&self) -> Result<bool, BitcoinCoordinatorError>;

    /// Advances the monitor and runs one tick of the coordinator.
    fn tick(&self) -> Result<(), BitcoinCoordinatorError>;

    /// Registers a transaction for dispatch without speedup support.
    fn dispatch_without_speedup(
        &self,
        tx: Transaction,
        context: String,
        target_block_height: Option<u32>,
        confirmation_trigger: Option<u32>,
        stuck_in_mempool_blocks: Option<u32>,
    ) -> Result<(), BitcoinCoordinatorError>;

    /// Registers a transaction for dispatch with CPFP speedup support enabled.
    fn dispatch_with_speedup(
        &self,
        tx: Transaction,
        speedup_data: SpeedupData,
        context: String,
        target_block_height: Option<u32>,
        confirmation_trigger: Option<u32>,
    ) -> Result<(), BitcoinCoordinatorError>;

    /// Dispatches a transaction with or without speedup support, chosen by the
    /// presence of `speedup_data`.
    fn dispatch(
        &self,
        tx: Transaction,
        speedup_data: Option<SpeedupData>,
        context: String,
        target_block_height: Option<u32>,
        confirmation_trigger: Option<u32>,
    ) -> Result<(), BitcoinCoordinatorError>;

    /// Cancels monitoring and removes the targeted transactions from
    /// coordinator storage.
    fn cancel(&self, data: TypesToMonitor) -> Result<(), BitcoinCoordinatorError>;

    /// Registers a funding UTXO available to pay future speedup fees.
    fn add_funding(&self, utxo: Utxo) -> Result<(), BitcoinCoordinatorError>;

    /// Queries the current blockchain status of a transaction.
    fn get_transaction(&self, txid: Txid) -> Result<TransactionStatus, BitcoinCoordinatorError>;

    /// Returns all unacknowledged monitor and coordinator news.
    fn get_news(&self) -> Result<News, BitcoinCoordinatorError>;

    /// Acknowledges a news item so it is not returned again.
    fn ack_news(&self, news: AckNews) -> Result<(), BitcoinCoordinatorError>;

    /// Registers data to be monitored without scheduling a dispatch.
    fn monitor(&self, data: TypesToMonitor) -> Result<(), BitcoinCoordinatorError>;
}

/// Adapter: the real coordinator satisfies the port by delegating to its
/// inherent methods.
impl BitcoinCoordinatorApi for BitcoinCoordinator {
    fn is_ready(&self) -> Result<bool, BitcoinCoordinatorError> {
        BitcoinCoordinator::is_ready(self)
    }

    fn tick(&self) -> Result<(), BitcoinCoordinatorError> {
        BitcoinCoordinator::tick(self)
    }

    fn dispatch_without_speedup(
        &self,
        tx: Transaction,
        context: String,
        target_block_height: Option<u32>,
        confirmation_trigger: Option<u32>,
        stuck_in_mempool_blocks: Option<u32>,
    ) -> Result<(), BitcoinCoordinatorError> {
        BitcoinCoordinator::dispatch_without_speedup(
            self,
            tx,
            context,
            target_block_height,
            confirmation_trigger,
            stuck_in_mempool_blocks,
        )
    }

    fn dispatch_with_speedup(
        &self,
        tx: Transaction,
        speedup_data: SpeedupData,
        context: String,
        target_block_height: Option<u32>,
        confirmation_trigger: Option<u32>,
    ) -> Result<(), BitcoinCoordinatorError> {
        BitcoinCoordinator::dispatch_with_speedup(
            self,
            tx,
            speedup_data,
            context,
            target_block_height,
            confirmation_trigger,
        )
    }

    fn dispatch(
        &self,
        tx: Transaction,
        speedup_data: Option<SpeedupData>,
        context: String,
        target_block_height: Option<u32>,
        confirmation_trigger: Option<u32>,
    ) -> Result<(), BitcoinCoordinatorError> {
        BitcoinCoordinator::dispatch(
            self,
            tx,
            speedup_data,
            context,
            target_block_height,
            confirmation_trigger,
        )
    }

    fn cancel(&self, data: TypesToMonitor) -> Result<(), BitcoinCoordinatorError> {
        BitcoinCoordinator::cancel(self, data)
    }

    fn add_funding(&self, utxo: Utxo) -> Result<(), BitcoinCoordinatorError> {
        BitcoinCoordinator::add_funding(self, utxo)
    }

    fn get_transaction(&self, txid: Txid) -> Result<TransactionStatus, BitcoinCoordinatorError> {
        BitcoinCoordinator::get_transaction(self, txid)
    }

    fn get_news(&self) -> Result<News, BitcoinCoordinatorError> {
        BitcoinCoordinator::get_news(self)
    }

    fn ack_news(&self, news: AckNews) -> Result<(), BitcoinCoordinatorError> {
        BitcoinCoordinator::ack_news(self, news)
    }

    fn monitor(&self, data: TypesToMonitor) -> Result<(), BitcoinCoordinatorError> {
        BitcoinCoordinator::monitor(self, data)
    }
}
