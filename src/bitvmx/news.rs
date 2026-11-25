//! Bitcoin coordinator and monitor news.

use super::{BitVMX, Context, CLIENT_GLOBAL_SETTINGS_UUID, NEW_BLOCK_CONTEXT, SEND_NEW_BLOCK_NEWS};
use crate::{
    errors::BitVMXError,
    news_retry_queue::NewsRetryQueue,
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    types::{
        ErrorReportKind, NoOpReason, OutgoingBitVMXApiMessages, ResultDisposition, RetryReason,
        RSK_PEGIN_TAG,
    },
};
use bitcoin::Txid;
use bitcoin_coordinator::{
    types::{AckNews, CoordinatorNews},
    BlockRef, MonitorNews, MonitorTarget, NewsKind, TransactionStatus,
};
use std::time::Duration;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// How many transactions and block heights one `get_news` call reads.
/// 50 is the value the monitor recommends (see `Monitor::get_news`).
const MAX_NEWS_KEYS_PER_FETCH: usize = 50;

/// How long a monitor news waits in the retry queue when its reaction
/// asks to retry without a delay, or fails with a non-fatal error.
const DEFAULT_NEWS_RETRY_DELAY: Duration = Duration::from_secs(10);

impl<BC: BitcoinCoordinatorApi> BitVMX<BC> {
    /// Owns the coordinator and news transactions; requires no active global transaction.
    pub fn process_bitcoin_updates_with_throttle(&mut self) -> Result<(), BitVMXError> {
        if self.coordinator_throttle.should_call() {
            let had_work = self.process_bitcoin_updates()?;
            self.coordinator_throttle.record(had_work);
        }
        Ok(())
    }

    /// Sends a transaction news from the monitor to whoever subscribed to it, read from the context: the
    /// program for a `ProgramId`, or the API requester for a `RequestId`. Returns what to do with the reaction
    /// and the news, see `react_to_monitor_news`.
    ///
    /// `spent_vout` is set when the news comes from a SpendingUtxo subscription, and then `tx_id` is the
    /// spent output's txid. It is `None` for a plain transaction subscription.
    fn route_tx_news_to_owner(
        &mut self,
        tx_id: Txid,
        tx_status: TransactionStatus,
        context_data: String,
        spent_vout: Option<u32>,
    ) -> Result<ResultDisposition, BitVMXError> {
        // An unreadable context can never be routed, so retrying it would loop forever.
        let context = match Context::from_string(&context_data) {
            Ok(context) => context,
            Err(error) => {
                warn!(
                    "route_tx_news_to_owner: unreadable context {:?} for {}: {}",
                    context_data, tx_id, error
                );
                return Ok(ResultDisposition::NoOp(NoOpReason::Uncorrelatable));
            }
        };
        debug!(
            "Transaction Found: {:?} {:?} for context: {:?}",
            tx_id, tx_status, context
        );

        match &context {
            Context::ProgramId(program_id) => match self.load_program(program_id)? {
                Some(program) => {
                    return program.notify_news(
                        tx_id,
                        spent_vout,
                        tx_status,
                        context_data,
                        &self.program_context,
                    );
                }
                None => {
                    warn!("route_tx_news_to_owner: Program {} not found", program_id);
                    return Ok(ResultDisposition::NoOp(NoOpReason::Orphaned));
                }
            },
            Context::RequestId(request_id, from) => {
                info!("Sending News: {:?} for context: {:?}", tx_id, context);
                // The response type follows the subscription the requester made.
                let response = match spent_vout {
                    Some(vout) => OutgoingBitVMXApiMessages::SpendingUTXOTransactionFound(
                        *request_id,
                        tx_id,
                        vout,
                        tx_status,
                    ),
                    None => OutgoingBitVMXApiMessages::Transaction(*request_id, tx_status, None),
                };
                self.program_context
                    .broker_channel
                    .send_service(from, response.to_string()?)?;
            }
            _ => {}
        }
        Ok(ResultDisposition::Success)
    }

    /// Ticks the coordinator and wallet, then processes and acknowledges one batch of pending monitor and coordinator
    /// news, each item in its own transaction. Monitor news comes in the order the monitor decided it, across blocks and
    /// reorgs, so the chain can move on while older news is still pending. Before the batch, queued news retries that are
    /// due are handed to their owners again. Returns whether there was any work.
    fn process_bitcoin_updates(&mut self) -> Result<bool, BitVMXError> {
        let store = self.store.clone();
        let (ready, monitor_news, coordinator_news) = Self::run_transaction(&store, || {
            self.program_context.bitcoin_coordinator.tick()?;
            if let Some(wallet) = self.wallet.as_mut() {
                wallet.tick()?;
            }
            if !self.program_context.bitcoin_coordinator.is_ready()? {
                return Ok((false, Vec::new(), Vec::new()));
            }
            if !self.chain_synced {
                return Ok((true, Vec::new(), Vec::new()));
            }

            let news = self
                .program_context
                .bitcoin_coordinator
                .get_news(Some(MAX_NEWS_KEYS_PER_FETCH))?;
            Ok((true, news.monitor_news, news.coordinator_news))
        })?;

        self.reporter
            .rpc_recovered(&self.program_context.broker_channel);
        if !ready {
            return Ok(true);
        }
        if !self.chain_synced {
            // The coordinator has ticked and caught up, so the indexer is initialized. Runs once per start.
            Self::run_transaction(&store, || self.subscribe_to_new_blocks())?;
            info!("Sync complete, starting normal operation");
            self.chain_synced = true;
            return Ok(true);
        }

        // Queued retries go first. A news queued below is not due before the next call.
        let settled_retries = self.process_due_news_retries()?;

        let had_monitor_news = !monitor_news.is_empty();
        for news in monitor_news {
            self.react_to_monitor_news(news, None)?;
        }
        // Each item is acknowledged in the same transaction that processes it, so a failed step rolls the
        // ack back and the item stays in coordinator storage for the next fetch.
        let had_coordinator_news = !coordinator_news.is_empty();
        for news in coordinator_news {
            self.run_tx_step("coordinator news", |this| {
                this.process_coordinator_news(&news)?;
                this.program_context
                    .bitcoin_coordinator
                    .ack_news(AckNews::Coordinator(news))?;
                Ok(())
            })?;
        }
        Ok(had_monitor_news || had_coordinator_news || settled_retries)
    }

    /// Subscribes the client to every new block. Called only after the coordinator has ticked and caught up, because
    /// before the first tick the indexer is not initialized. On a restart the subscription is already stored, and
    /// registering it again only refreshes it.
    fn subscribe_to_new_blocks(&self) -> Result<(), BitVMXError> {
        self.program_context.bitcoin_coordinator.monitor(
            &[MonitorTarget::NewBlock],
            NEW_BLOCK_CONTEXT.to_string(),
            None,
        )?;
        Ok(())
    }

    /// Hands every queued news whose delay has passed to its owner again, oldest first. Returns whether any of them was
    /// settled, so a news that only asks to be retried again does not keep the coordinator throttle busy.
    fn process_due_news_retries(&mut self) -> Result<bool, BitVMXError> {
        let due = self.news_retry_queue.due(NewsRetryQueue::now_ms()?)?;
        let mut settled_any = false;
        for (id, entry) in due {
            settled_any |= self.react_to_monitor_news(entry.news, Some((id, entry.attempts)))?;
        }
        Ok(settled_any)
    }

    /// Runs the reaction to one monitor news in its own transaction and acts on its disposition:
    /// - `Success`: the reaction is committed together with consuming the news.
    /// - `NoOp`: the reaction is rolled back, and the news is consumed in a new transaction.
    /// - `Retry(NewsNotReady)`: the reaction is rolled back, and in a new transaction the news is consumed and queued
    ///   to be handed to its owner again after `retry_after`, or after `DEFAULT_NEWS_RETRY_DELAY` when it is `None`.
    /// - `Fail`, or `Retry` with any other reason: not expected for news. Handled like `NoOp` and logged as an error.
    ///
    /// A fatal error stops the node and leaves the news untouched. Any other error is reported and logged, and the news
    /// is queued like a retry after `DEFAULT_NEWS_RETRY_DELAY`.
    fn react_to_monitor_news(
        &mut self,
        news: MonitorNews,
        queued: Option<(Uuid, u32)>,
    ) -> Result<bool, BitVMXError> {
        let store = self.store.clone();
        let result = Self::run_transaction_committing_if(&store, || {
            let disposition = self.process_monitor_news(&news)?;
            let keep = disposition == ResultDisposition::Success;
            if keep {
                self.consume_monitor_news(&news, queued)?;
            }
            Ok((disposition, keep))
        });

        let retry_after = match result {
            Ok(ResultDisposition::Success) => return Ok(true),
            Ok(ResultDisposition::Retry(RetryReason::NewsNotReady { retry_after })) => {
                retry_after.unwrap_or(DEFAULT_NEWS_RETRY_DELAY)
            }
            Ok(ResultDisposition::NoOp(reason)) => {
                debug!(
                    "Monitor news consumed without a reaction ({:?}): {:?}",
                    reason, news
                );
                self.run_tx_step("monitor news consume", |this| {
                    this.consume_monitor_news(&news, queued)
                })?;
                return Ok(true);
            }
            // Fail, or Retry with any other reason: not expected for news.
            Ok(unexpected) => {
                error!(
                    "Unexpected disposition {:?} for monitor news {:?}",
                    unexpected, news
                );
                self.run_tx_step("monitor news consume", |this| {
                    this.consume_monitor_news(&news, queued)
                })?;
                return Ok(true);
            }
            Err(error) => {
                // A fatal error stops here. Any other one is reported to L2 and logged.
                Self::finish_step::<()>(
                    "monitor news",
                    Err(error),
                    &mut self.reporter,
                    &self.program_context.broker_channel,
                )?;
                DEFAULT_NEWS_RETRY_DELAY
            }
        };

        let attempts = queued.map_or(1, |(_, attempts)| attempts + 1);
        info!(
            "Monitor news will be retried in {:?} (attempt {}): {:?}",
            retry_after, attempts, news
        );
        self.run_tx_step("monitor news retry", |this| match queued {
            Some((id, _)) => this.news_retry_queue.reschedule(&id, retry_after),
            None => {
                this.program_context
                    .bitcoin_coordinator
                    .ack_news(AckNews::Monitor(news.clone()))?;
                this.news_retry_queue.push(news.clone(), retry_after)
            }
        })?;
        Ok(false)
    }

    /// Consumes a monitor news so it is not handed to its owner again: acks a fetched news in the coordinator, or removes
    /// the retry queue entry of a queued one.
    fn consume_monitor_news(
        &self,
        news: &MonitorNews,
        queued: Option<(Uuid, u32)>,
    ) -> Result<(), BitVMXError> {
        match queued {
            Some((id, _)) => self.news_retry_queue.remove(&id),
            None => {
                self.program_context
                    .bitcoin_coordinator
                    .ack_news(AckNews::Monitor(news.clone()))?;
                Ok(())
            }
        }
    }

    /// Handles a monitor news, an observation on chain: transactions go to their owner, output pattern
    /// matches and new blocks go to L2. Returns the owner's disposition for transaction news, and `Success`
    /// for the rest.
    fn process_monitor_news(
        &mut self,
        news: &MonitorNews,
    ) -> Result<ResultDisposition, BitVMXError> {
        match (&news.target, &news.kind) {
            (MonitorTarget::Transaction(_), NewsKind::Transaction { txid, status, .. }) => {
                //TODO: Handle reorg case with due_to_reorg
                return self.route_tx_news_to_owner(
                    *txid,
                    status.clone(),
                    news.context.clone(),
                    None,
                );
            }
            (MonitorTarget::SpendingUtxo(outpoint), NewsKind::Transaction { status, .. }) => {
                // Consumers expect the spent output's txid and vout. The spender comes inside the status.
                return self.route_tx_news_to_owner(
                    outpoint.txid,
                    status.clone(),
                    news.context.clone(),
                    Some(outpoint.vout),
                );
            }
            (MonitorTarget::OutputPattern(filter), NewsKind::Transaction { txid, status, .. }) => {
                if filter.tag == RSK_PEGIN_TAG {
                    self.notify_l2(&OutgoingBitVMXApiMessages::PeginTransactionFound(
                        *txid,
                        status.clone(),
                    ))?;
                }
                self.notify_l2(&OutgoingBitVMXApiMessages::OutputPatternTransactionFound(
                    *txid,
                    status.clone(),
                    filter.tag.clone(),
                ))?;
            }
            (MonitorTarget::NewBlock, NewsKind::Block(BlockRef { height, hash })) => {
                debug!("New block: {} {}", height, hash);
                if self.should_send_new_block_news() {
                    self.notify_l2(&OutgoingBitVMXApiMessages::NewBlock(*hash, *height))?;
                }
            }
            // The transaction was mined before the first block the indexer read, and the monitor dropped the subscription.
            (MonitorTarget::Transaction(txid), NewsKind::UnreachableTx) => {
                // TODO: Tell the owner from the context that this transaction will never be reported.
                warn!(
                    "Transaction {} is unreachable, its subscription was dropped (context {})",
                    txid, news.context
                );
            }
            // The output is older than the indexed window and no spender was found. The subscription stays, so a
            // spender found later is still reported.
            (MonitorTarget::SpendingUtxo(outpoint), NewsKind::ProbablyUnreachableUTXO) => {
                // TODO: Tell the owner from the context, so it decides whether to keep waiting or cancel.
                warn!(
                    "Spend of {} is probably unreachable, its subscription stays (context {})",
                    outpoint, news.context
                );
            }
            // The monitor never produces any other pair, so reaching this is a bug. Acked so it never loops.
            (target, kind) => {
                error!(
                    "Unexpected monitor news {:?} for target {:?} and context {}",
                    kind, target, news.context
                );
            }
        }
        Ok(ResultDisposition::Success)
    }

    /// Sends an API message to L2.
    fn notify_l2(&self, message: &OutgoingBitVMXApiMessages) -> Result<(), BitVMXError> {
        let data = serde_json::to_string(message)?;
        self.program_context
            .broker_channel
            .send_service(&self.config.components.l2, data)?;
        Ok(())
    }

    /// Handles a coordinator news, a problem dispatching or funding a transaction. Problems L2 can act on
    /// are sent as error reports to the program's L2 or the requester, read from the context; the rest
    /// are only logged.
    fn process_coordinator_news(
        &mut self,
        coordinator_news: &CoordinatorNews,
    ) -> Result<(), BitVMXError> {
        let broker_channel = &self.program_context.broker_channel;
        match coordinator_news {
            CoordinatorNews::InsufficientFunds {
                available,
                required,
            } => {
                info!(
                    "Insufficient funds for transaction. Available: {}, Required: {}",
                    available, required
                );
                // No txid or context, so the program cannot be identified.
                self.reporter.coordinator_news(
                    None,
                    ErrorReportKind::InsufficientFunds {
                        available: *available,
                        required: *required,
                    },
                    broker_channel,
                )?;
            }
            CoordinatorNews::DispatchError { txid, context } => {
                error!("Dispatch Transaction Error: {:?} {:?}", txid, context);
                if let Some(wallet) = self.wallet.as_mut() {
                    if let Some(wallet_tx) = wallet.get_wallet_tx(*txid)? {
                        wallet.cancel_tx(&wallet_tx.tx_node.tx)?;
                    }
                }
                self.reporter.coordinator_news(
                    Some(context.as_str()),
                    ErrorReportKind::TransactionDispatchFailed { txid: *txid },
                    broker_channel,
                )?;
            }
            CoordinatorNews::SpeedupDispatchError { txid, context } => {
                error!("Speedup dispatch error: {:?} {:?}", txid, context);
                self.reporter.coordinator_news(
                    Some(context.as_str()),
                    ErrorReportKind::SpeedupDispatchFailed { txid: *txid },
                    broker_channel,
                )?;
            }
            CoordinatorNews::TransactionStuckInMempool { txid, context } => {
                warn!("Transaction stuck in mempool: {:?} {:?}", txid, context);
                self.reporter.coordinator_news(
                    Some(context.as_str()),
                    ErrorReportKind::TransactionStuckInMempool { txid: *txid },
                    broker_channel,
                )?;
            }
            CoordinatorNews::MaxFeeRateReached {
                txid,
                effective_fee_rate,
                context,
            } => {
                warn!(
                    "Speedup for {:?} reached the fee rate cap at {} sat/vB. No further boosts",
                    txid, effective_fee_rate
                );
                self.reporter.coordinator_news(
                    Some(context.as_str()),
                    ErrorReportKind::MaxFeeRateReached {
                        txid: *txid,
                        effective_fee_rate: *effective_fee_rate,
                    },
                    broker_channel,
                )?;
            }
            CoordinatorNews::EstimateFeerateTooHigh {
                estimated_fee_rate,
                max_fee_rate,
            } => {
                warn!(
                    "Estimated fee rate {} exceeds the configured maximum {}",
                    estimated_fee_rate, max_fee_rate
                );
                self.reporter.coordinator_news(
                    None,
                    ErrorReportKind::FeeRateTooHigh {
                        estimated: *estimated_fee_rate,
                        max: *max_fee_rate,
                    },
                    broker_channel,
                )?;
            }
            CoordinatorNews::FundingNotAvailable => {
                error!("No funding UTXO is available");
                self.reporter.coordinator_news(
                    None,
                    ErrorReportKind::FundingNotAvailable,
                    broker_channel,
                )?;
            }
            CoordinatorNews::InvalidFundingUtxo {
                amount,
                min_required,
            } => {
                error!(
                    "Funding UTXO of {} is below the {} minimum",
                    amount, min_required
                );
                self.reporter.coordinator_news(
                    None,
                    ErrorReportKind::InvalidFundingUtxo {
                        amount: *amount,
                        min_required: *min_required,
                    },
                    broker_channel,
                )?;
            }
            // Not reported: our own invariant broke, which is not L2's problem.
            CoordinatorNews::InvalidStateTransition { txid, from, to } => {
                error!(
                    "Invalid state transition for {:?}: {:?} -> {:?}",
                    txid, from, to
                );
            }
            // Not reported: bookkeeping after the tx already finalized or failed.
            CoordinatorNews::TransactionEvicted { txid, context } => {
                debug!(
                    "Transaction evicted from tracking: {:?} {:?}",
                    txid, context
                );
            }
            // Not reported: the caller asked for something invalid.
            CoordinatorNews::InvalidCancel { txid, reason } => {
                warn!("Cancel rejected for {:?}: {}", txid, reason);
            }
            // Not reported: the coordinator's own store has no row for this txid, which
            // is internal bookkeeping and not a statement about the chain.
            CoordinatorNews::TxNotFound { txid } => {
                error!("Coordinator has no record of transaction {:?}", txid);
            }
        }
        Ok(())
    }

    /// Whether L2 asked to receive a `NewBlock` message for every new block, read from the global settings.
    fn should_send_new_block_news(&self) -> bool {
        self.program_context
            .globals
            .get_var(&CLIENT_GLOBAL_SETTINGS_UUID, SEND_NEW_BLOCK_NEWS)
            .ok()
            .flatten()
            .and_then(|value| value.bool().ok())
            .unwrap_or(false)
    }
}
