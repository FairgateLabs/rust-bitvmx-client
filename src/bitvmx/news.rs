//! Bitcoin coordinator and monitor news.

use super::{BitVMX, Context, CLIENT_GLOBAL_SETTINGS_UUID, SEND_NEW_BLOCK_NEWS};
use crate::{
    errors::BitVMXError,
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    types::{ErrorReportKind, OutgoingBitVMXApiMessages, RSK_PEGIN_TAG},
};
use bitcoin::Txid;
use bitcoin_coordinator::{
    types::{AckNews, CoordinatorNews},
    BlockRef, MonitorNews, MonitorTarget, NewsKind, TransactionStatus,
};
use tracing::{debug, error, info, warn};

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
    /// program for a `ProgramId`, or the API requester for a `RequestId`.
    ///
    /// `spent_vout` is set when the news comes from a SpendingUtxo subscription, and then `tx_id` is the
    /// spent output's txid. It is `None` for a plain transaction subscription.
    fn route_tx_news_to_owner(
        &mut self,
        tx_id: Txid,
        tx_status: TransactionStatus,
        context_data: String,
        spent_vout: Option<u32>,
    ) -> Result<(), BitVMXError> {
        let context = Context::from_string(&context_data)?;
        debug!(
            "Transaction Found: {:?} {:?} for context: {:?}",
            tx_id, tx_status, context
        );

        match &context {
            Context::ProgramId(program_id) => match self.load_program(program_id)? {
                Some(program) => {
                    program.notify_news(
                        tx_id,
                        spent_vout,
                        tx_status,
                        context_data,
                        &self.program_context,
                    )?;
                }
                None => {
                    warn!("route_tx_news_to_owner: Program {} not found", program_id);
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
        Ok(())
    }

    /// Ticks the coordinator and wallet, then processes and acknowledges the pending monitor and
    /// coordinator news, each item in its own transaction. Returns whether there was any work.
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

            let news = self.program_context.bitcoin_coordinator.get_news(None)?;
            Ok((true, news.monitor_news, news.coordinator_news))
        })?;

        self.reporter
            .rpc_recovered(&self.program_context.broker_channel);
        if !ready {
            return Ok(true);
        }
        if !self.chain_synced {
            info!("Sync complete, starting normal operation");
            self.chain_synced = true;
            return Ok(true);
        }

        // Each item is acknowledged in the same transaction that processes it, so a failed step rolls the
        // ack back and the item stays in coordinator storage for the next fetch.
        let had_monitor_news = !monitor_news.is_empty();
        for news in monitor_news {
            self.run_tx_step("monitor news", |this| {
                this.process_monitor_news(&news)?;
                this.program_context
                    .bitcoin_coordinator
                    .ack_news(AckNews::Monitor(news))?;
                Ok(())
            })?;
        }
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
        Ok(had_monitor_news || had_coordinator_news)
    }

    /// Handles a monitor news, an observation on chain: transactions go to their owner, output pattern
    /// matches and new blocks go to L2.
    fn process_monitor_news(&mut self, news: &MonitorNews) -> Result<(), BitVMXError> {
        match (&news.target, &news.kind) {
            (MonitorTarget::Transaction(_), NewsKind::Transaction { txid, status, .. }) => {
                self.route_tx_news_to_owner(*txid, status.clone(), news.context.clone(), None)?;
                //TODO: Handle reorg case with due_to_reorg
            }
            (MonitorTarget::SpendingUtxo(outpoint), NewsKind::Transaction { status, .. }) => {
                // Consumers expect the spent output's txid and vout. The spender comes inside the status.
                self.route_tx_news_to_owner(
                    outpoint.txid,
                    status.clone(),
                    news.context.clone(),
                    Some(outpoint.vout),
                )?;
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
            (_, NewsKind::Block(BlockRef { height, hash })) => {
                debug!("New block: {} {}", height, hash);
                if self.should_send_new_block_news() {
                    self.notify_l2(&OutgoingBitVMXApiMessages::NewBlock(*hash, *height))?;
                }
            }
            (target, kind) => {
                warn!(
                    "Unhandled monitor news {:?} for target {:?} and context {}",
                    kind, target, news.context
                );
            }
        }
        Ok(())
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
