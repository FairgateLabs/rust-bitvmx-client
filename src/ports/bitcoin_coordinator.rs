use bitcoin::{BlockHash, Transaction, Txid};
use bitcoin_coordinator::{
    coordinator::BitcoinCoordinator,
    errors::BitcoinCoordinatorError,
    types::{AckNews, News},
    FullBlock, MonitorTarget, TransactionStatus,
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
    fn cancel(
        &self,
        targets: &[MonitorTarget],
        context: &str,
    ) -> Result<(), BitcoinCoordinatorError>;

    /// Registers a funding UTXO available to pay future speedup fees.
    fn add_funding(&self, utxo: Utxo) -> Result<(), BitcoinCoordinatorError>;

    /// Queries the current blockchain status of a transaction.
    fn get_transaction(&self, txid: Txid) -> Result<TransactionStatus, BitcoinCoordinatorError>;

    /// Returns the block at this height and hash, `None` when it is above the indexed height or a reorg replaced it.
    fn get_block(
        &self,
        height: u32,
        hash: &BlockHash,
    ) -> Result<Option<FullBlock>, BitcoinCoordinatorError>;

    /// Returns the block that confirms `txid`. `None` when the transaction is not
    /// confirmed in the chain the monitor knows right now, or its block is no longer available.
    fn get_confirming_block(
        &self,
        txid: Txid,
    ) -> Result<Option<FullBlock>, BitcoinCoordinatorError> {
        match self.get_transaction(txid)? {
            TransactionStatus::Confirmed {
                block_height,
                block_hash,
                ..
            } => self.get_block(block_height, &block_hash),
            _ => Ok(None),
        }
    }

    /// Returns unacknowledged monitor and coordinator news. `max_keys` limits the monitor news to the first
    /// `max_keys` transactions and block heights, `None` returns all of it.
    fn get_news(&self, max_keys: Option<usize>) -> Result<News, BitcoinCoordinatorError>;

    /// Acknowledges a news item so it is not returned again.
    fn ack_news(&self, news: AckNews) -> Result<(), BitcoinCoordinatorError>;

    /// Registers data to be monitored without scheduling a dispatch.
    fn monitor(
        &self,
        targets: &[MonitorTarget],
        context: String,
        confirmation_trigger: Option<u32>,
    ) -> Result<(), BitcoinCoordinatorError>;
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

    fn cancel(
        &self,
        targets: &[MonitorTarget],
        context: &str,
    ) -> Result<(), BitcoinCoordinatorError> {
        BitcoinCoordinator::cancel(self, targets, context)
    }

    fn add_funding(&self, utxo: Utxo) -> Result<(), BitcoinCoordinatorError> {
        BitcoinCoordinator::add_funding(self, utxo)
    }

    fn get_transaction(&self, txid: Txid) -> Result<TransactionStatus, BitcoinCoordinatorError> {
        BitcoinCoordinator::get_transaction(self, txid)
    }

    fn get_block(
        &self,
        height: u32,
        hash: &BlockHash,
    ) -> Result<Option<FullBlock>, BitcoinCoordinatorError> {
        BitcoinCoordinator::get_block(self, height, hash)
    }

    fn get_news(&self, max_keys: Option<usize>) -> Result<News, BitcoinCoordinatorError> {
        BitcoinCoordinator::get_news(self, max_keys)
    }

    fn ack_news(&self, news: AckNews) -> Result<(), BitcoinCoordinatorError> {
        BitcoinCoordinator::ack_news(self, news)
    }

    fn monitor(
        &self,
        targets: &[MonitorTarget],
        context: String,
        confirmation_trigger: Option<u32>,
    ) -> Result<(), BitcoinCoordinatorError> {
        BitcoinCoordinator::monitor(self, targets, context, confirmation_trigger)
    }
}
