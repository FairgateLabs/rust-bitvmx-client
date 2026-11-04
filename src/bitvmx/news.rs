//! Bitcoin coordinator and monitor news.

use super::{BitVMX, Context, CLIENT_GLOBAL_SETTINGS_UUID, SEND_NEW_BLOCK_NEWS};
use crate::{
    errors::BitVMXError,
    ports::bitcoin_coordinator::BitcoinCoordinatorApi,
    program::variables::VariableTypes,
    types::{ErrorReportKind, OutgoingBitVMXApiMessages, ProgramContext, RSK_PEGIN_TAG},
};
use bitcoin::Txid;
use bitcoin_coordinator::{
    types::{AckNews, CoordinatorNews},
    AckMonitorNews, MonitorNews, TransactionStatus,
};
use tracing::{debug, error, info, warn};

impl<BC: BitcoinCoordinatorApi> BitVMX<BC> {
    /// Owns the coordinator and news transactions; requires no active global transaction.
    pub fn process_bitcoin_updates_with_throttle(&mut self) -> Result<(), BitVMXError> {
        if self.coordinator_throttle.should_call() {
            let had_work = self.process_bitcoin_updates()?;
            self.coordinator_throttle.record(had_work);
            return Ok(());
        }
        Ok(())
    }

    pub fn handle_news(
        &mut self,
        tx_id: Txid,
        tx_status: TransactionStatus,
        context_data: String,
        vout: Option<u32>,
    ) -> Result<bool, BitVMXError> {
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
                        vout,
                        tx_status,
                        context_data,
                        &self.program_context,
                    )?;
                }
                None => {
                    warn!("handle_news: Program {} not found", program_id);
                }
            },
            Context::RequestId(request_id, from) => {
                info!("Sending News: {:?} for context: {:?}", tx_id, context);
                // Only a UTXO subscription carries a vout.
                let response = match vout {
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
        Ok(true)
    }

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

            let news = self.program_context.bitcoin_coordinator.get_news()?;
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

        let had_monitor_news = !monitor_news.is_empty();
        for news in monitor_news {
            self.run_step("monitor news", |this| {
                Self::run_transaction(&store, || this.process_monitor_news(news))
            })?;
        }
        let had_coordinator_news = !coordinator_news.is_empty();
        // Unacknowledged items remain in coordinator storage for the next fetch.
        for news in coordinator_news {
            self.run_step("coordinator news", |this| {
                Self::run_transaction(&store, || this.process_coordinator_news(news))
            })?;
        }
        Ok(had_monitor_news || had_coordinator_news)
    }

    fn process_monitor_news(&mut self, news: MonitorNews) -> Result<(), BitVMXError> {
        let ack_news = match news {
            MonitorNews::Transaction(n) => {
                self.handle_news(n.tx_id, n.status, n.context.clone(), None)?;
                //TODO: Handle reorg case with n.resent_due_to_reorg
                AckMonitorNews::Transaction(n.tx_id, n.context)
            }
            MonitorNews::SpendingUTXOTransaction(tx_id, output_index, tx_status, context_data) => {
                self.handle_news(tx_id, tx_status, context_data.clone(), Some(output_index))?;
                AckMonitorNews::SpendingUTXOTransaction(tx_id, output_index, context_data)
            }
            MonitorNews::OutputPatternTransaction(tx_id, tx_status, tag) => {
                if tag == RSK_PEGIN_TAG {
                    let legacy =
                        OutgoingBitVMXApiMessages::PeginTransactionFound(tx_id, tx_status.clone());
                    let data = serde_json::to_string(&legacy)?;
                    self.program_context
                        .broker_channel
                        .send_service(&self.config.components.l2, data)?;
                }
                let outgoing = OutgoingBitVMXApiMessages::OutputPatternTransactionFound(
                    tx_id,
                    tx_status,
                    tag.clone(),
                );
                let data = serde_json::to_string(&outgoing)?;
                self.program_context
                    .broker_channel
                    .send_service(&self.config.components.l2, data)?;
                AckMonitorNews::OutputPatternTransaction(tx_id, tag)
            }
            MonitorNews::NewBlock(block_height, block_hash) => {
                debug!("New block: {} {}", block_height, block_hash);
                if self.send_new_block_news(&self.program_context) {
                    let data = serde_json::to_string(&OutgoingBitVMXApiMessages::NewBlock(
                        block_hash,
                        block_height,
                    ))?;
                    self.program_context
                        .broker_channel
                        .send_service(&self.config.components.l2, data)?;
                }
                AckMonitorNews::NewBlock
            }
        };

        self.program_context
            .bitcoin_coordinator
            .ack_news(AckNews::Monitor(ack_news))?;
        Ok(())
    }

    fn process_coordinator_news(
        &mut self,
        coordinator_news: CoordinatorNews,
    ) -> Result<(), BitVMXError> {
        match coordinator_news.clone() {
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
                        available,
                        required,
                    },
                    &self.program_context.broker_channel,
                )?;
            }
            CoordinatorNews::DispatchError { txid, context } => {
                error!("Dispatch Transaction Error: {:?} {:?}", txid, context);
                if let Some(wallet) = self.wallet.as_mut() {
                    if let Some(wallet_tx) = wallet.get_wallet_tx(txid)? {
                        wallet.cancel_tx(&wallet_tx.tx_node.tx)?;
                    }
                }
                self.reporter.coordinator_news(
                    Some(&context),
                    ErrorReportKind::TransactionDispatchFailed { txid },
                    &self.program_context.broker_channel,
                )?;
            }
            CoordinatorNews::SpeedupDispatchError { txid, context } => {
                error!("Speedup dispatch error: {:?} {:?}", txid, context);
                self.reporter.coordinator_news(
                    Some(&context),
                    ErrorReportKind::SpeedupDispatchFailed { txid },
                    &self.program_context.broker_channel,
                )?;
            }
            CoordinatorNews::TransactionStuckInMempool { txid, context } => {
                warn!("Transaction stuck in mempool: {:?} {:?}", txid, context);
                self.reporter.coordinator_news(
                    Some(&context),
                    ErrorReportKind::TransactionStuckInMempool { txid },
                    &self.program_context.broker_channel,
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
                    Some(&context),
                    ErrorReportKind::MaxFeeRateReached {
                        txid,
                        effective_fee_rate,
                    },
                    &self.program_context.broker_channel,
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
                        estimated: estimated_fee_rate,
                        max: max_fee_rate,
                    },
                    &self.program_context.broker_channel,
                )?;
            }
            CoordinatorNews::FundingNotAvailable => {
                error!("No funding UTXO is available");
                self.reporter.coordinator_news(
                    None,
                    ErrorReportKind::FundingNotAvailable,
                    &self.program_context.broker_channel,
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
                        amount,
                        min_required,
                    },
                    &self.program_context.broker_channel,
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

        self.program_context
            .bitcoin_coordinator
            .ack_news(AckNews::Coordinator(coordinator_news))?;
        Ok(())
    }

    fn send_new_block_news(&self, context: &ProgramContext<BC>) -> bool {
        context
            .globals
            .get_var(&CLIENT_GLOBAL_SETTINGS_UUID, SEND_NEW_BLOCK_NEWS)
            .unwrap_or(None)
            .unwrap_or(VariableTypes::Bool(false))
            .bool()
            .unwrap_or(false)
    }
}
