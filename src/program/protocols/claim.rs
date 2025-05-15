use bitcoin::{hashes::Hash, PublicKey, Sequence};
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    scripts::{self, SignMode},
    types::{
        input::{InputSpec, SighashType},
        output::SpendMode,
        OutputType,
    },
};

use crate::errors::BitVMXError;

pub struct ClaimGate {
    name: String,
    from: String,
    vout: usize,
    stop_count: u8,
    pub cost: u64,
}

impl ClaimGate {
    pub fn new(
        protocol: &mut Protocol,
        from: &str,
        claim_name: &str,
        aggregated: &PublicKey,
        amount: u64,
        stop_count: u8,
        timelock_blocks: u16,
        actions: Vec<&PublicKey>,
    ) -> Result<Self, BitVMXError> {
        //TODO: this script should check a claimer secret (or be signed only by the claimer)
        let verify_aggregated =
            scripts::check_aggregated_signature(&aggregated, SignMode::Aggregate);
        let claim_start = OutputType::taproot(
            amount,
            aggregated,
            &vec![verify_aggregated.clone()],
            &SpendMode::All {
                key_path_sign: SignMode::Aggregate,
            },
            &vec![],
        )?;

        let vout_idx = protocol.transaction_by_name(from)?.output.len();
        let stx = format!("{}_START", claim_name);
        protocol.add_connection(
            &format!("{}__{}", from, &stx),
            from,
            &stx,
            &claim_start,
            &SighashType::taproot_all(),
        )?;

        let timeout = scripts::timelock(timelock_blocks, &aggregated, SignMode::Aggregate);

        let start_tx_output = OutputType::taproot(
            amount,
            aggregated,
            &vec![verify_aggregated, timeout],
            &SpendMode::All {
                key_path_sign: SignMode::Aggregate,
            },
            &vec![],
        )?;

        protocol.add_transaction_output(&stx, &start_tx_output)?;

        let pb = ProtocolBuilder {};

        for i in 0..stop_count {
            let stopname = format!("{}_STOP_{}", claim_name, i);
            protocol.add_connection(
                &format!("{}__{}", from, &stopname),
                from,
                &stopname,
                &claim_start,
                &SighashType::taproot_all(),
            )?;
            protocol.add_transaction_input(
                Hash::all_zeros(),
                0,
                &stopname,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                &SighashType::taproot_all(),
            )?;
            protocol.connect(
                &format!("CANCEL_CLAIM_{}_BY_{}", claim_name, i),
                &stx,
                0,
                &stopname,
                InputSpec::Index(1),
            )?;

            pb.add_speedup_output(protocol, &stopname, amount, aggregated)?;
        }

        let success = format!("{}_SUCCESS", claim_name);
        protocol.add_connection_with_timelock(
            &format!("{}_TL_{}", from, &success),
            &stx,
            &success,
            &claim_start,
            &SighashType::taproot_all(),
            timelock_blocks,
        )?;

        for action in &actions {
            let verify_aggregated_action =
                scripts::check_aggregated_signature(action, SignMode::Aggregate);
            let output_action = OutputType::taproot(
                amount,
                action,
                &vec![verify_aggregated_action],
                &SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
                &vec![],
            )?;

            protocol.add_transaction_output(&success, &output_action)?;
        }

        pb.add_speedup_output(protocol, &success, amount, aggregated)?;
        pb.add_speedup_output(protocol, &stx, amount, aggregated)?;

        let cost = (actions.len() as u64 + 4 + (2 * stop_count as u64)) * amount;

        Ok(Self {
            name: claim_name.to_string(),
            from: from.to_string(),
            vout: vout_idx,
            stop_count,
            cost,
        })
    }

    pub fn add_claimer_win_connection(
        &self,
        protocol: &mut Protocol,
        to: &str,
    ) -> Result<(), BitVMXError> {
        for i in 0..self.stop_count {
            protocol.add_transaction_input(
                Hash::all_zeros(),
                self.vout,
                to,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                &SighashType::taproot_all(),
            )?;

            let input_index = protocol.transaction_by_name(to)?.input.len() - 1;
            protocol.connect(
                &format!("CLAIMER_WINS_{}_STOP_{}__{}", self.name, i, to),
                &self.from,
                self.vout + 1,
                &to,
                InputSpec::Index(input_index),
            )?;
        }

        Ok(())
    }
}
