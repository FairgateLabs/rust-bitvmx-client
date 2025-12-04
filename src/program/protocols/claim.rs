use bitcoin::{hashes::Hash, PublicKey, Sequence};
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    scripts::{self, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        OutputType,
    },
};

use crate::errors::BitVMXError;

pub const CLAIM_GATE_START: &str = "START";
pub const CLAIM_GATE_STOP: &str = "STOP";
pub const CLAIM_GATE_SUCCESS: &str = "SUCCESS";

pub struct ClaimGate {
    name: String,
    from: String,
    pub vout: usize,
    stop_count: u8,
    pub cost: u64,
    pub exclusive_success_vout: Option<usize>,
    pub stoppers: Vec<OutputType>,
}

impl ClaimGate {
    pub fn tx_start(claim_name: &str) -> String {
        format!("{}_{}", claim_name, CLAIM_GATE_START)
    }
    pub fn tx_stop(claim_name: &str, stopper: u8) -> String {
        format!("{}_{}_{}", claim_name, CLAIM_GATE_STOP, stopper)
    }
    pub fn tx_success(claim_name: &str) -> String {
        format!("{}_{}", claim_name, CLAIM_GATE_SUCCESS)
    }

    pub fn cost(
        amount_fee: u64,
        amount_dust: u64,
        stop_count: u8,
        actions: usize,
        add_exclusive_success: bool,
    ) -> u64 {
        let fees = (2 + stop_count as u64) * amount_fee;
        let exclusive_success = if add_exclusive_success { 1 } else { 0 };
        let dust = (2 + actions as u64 + stop_count as u64 + exclusive_success) * amount_dust;
        fees + dust
    }

    pub fn output_from_aggregated(
        aggregated: &PublicKey,
        dust: u64,
    ) -> Result<OutputType, BitVMXError> {
        let verify_aggregated_action =
            scripts::check_aggregated_signature(aggregated, SignMode::Aggregate);
        let output_action = OutputType::taproot(dust, aggregated, &[verify_aggregated_action])?;
        Ok(output_action)
    }

    pub fn new(
        protocol: &mut Protocol,
        from: &str,
        claim_name: &str,
        claimer: (&PublicKey, SignMode),
        aggregated: &PublicKey,
        amount_fee: u64,
        amount_dust: u64,
        stoppers_pub: Vec<&PublicKey>,
        subset_cov: Option<Vec<&PublicKey>>,
        timelock_blocks: u16,
        action_count: u64,
        outputs: Vec<OutputType>,
        add_exclusive_success: bool,
        exclusive_success_vout: Option<usize>,
    ) -> Result<Self, BitVMXError> {
        // if exclusive vout will be added create the output for it
        let exclusive_success_vout = if add_exclusive_success {
            let verify_aggregated =
                scripts::check_aggregated_signature(&aggregated, SignMode::Aggregate);
            let exclusive_output =
                OutputType::taproot(amount_dust, aggregated, &vec![verify_aggregated.clone()])?;

            let vout_idx = protocol.transaction_by_name(from)?.output.len();
            protocol.add_transaction_output(&from, &exclusive_output)?;
            Some(vout_idx)
        } else {
            exclusive_success_vout
        };

        // Add the claim start transaction
        // This transaction will verify onlye the claimer's signature
        // as the claimer is the one who will be able to spend it
        let claim_start_check = scripts::check_signature(claimer.0, claimer.1);
        let claim_start = OutputType::taproot(
            amount_fee + amount_fee + ((2 + (outputs.len() as u64 + action_count)) * amount_dust),
            aggregated,
            &vec![claim_start_check],
        )?;

        let vout_idx = protocol.transaction_by_name(from)?.output.len();
        let stx = Self::tx_start(claim_name);
        protocol.add_connection(
            &format!("{}__{}", from, &stx),
            from,
            claim_start.clone().into(),
            &stx,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
            None,
            None,
        )?;

        // Add the output to the claim transaction that contains two leaves:
        // 1. The aggregated signature for the stoppers
        // 2. The timelock script that will be used by the claimer if he succeeds the claim
        let verify_aggregated =
            scripts::check_aggregated_signature(&aggregated, SignMode::Aggregate);
        let timeout = scripts::timelock(timelock_blocks, &aggregated, SignMode::Aggregate);

        let start_tx_output = OutputType::taproot(
            amount_fee + ((1 + outputs.len() as u64 + action_count) * amount_dust),
            aggregated,
            &vec![verify_aggregated.clone(), timeout],
        )?;
        protocol.add_transaction_output(&stx, &start_tx_output)?;

        let pb = ProtocolBuilder {};

        let mut claim_stoppers = vec![];

        // add stoppers transactions consuming the stop vout in the origin transaction and the output on the start tx
        // to penalize the claimer if he tries to start the claim before winning (consuming all the stops)
        for (i, stopper_pub) in stoppers_pub.iter().enumerate() {
            let mut leaves = vec![verify_aggregated.clone()];
            // if a covenant of the subset is provided, add the signature check for the subset
            if let Some(subset_cov) = &subset_cov {
                if let Some(subset_pub) = subset_cov.get(i) {
                    leaves.push(scripts::check_signature(subset_pub, SignMode::Aggregate));
                }
            }

            let claim_stop = OutputType::taproot(amount_fee + amount_dust, aggregated, &leaves)?;
            claim_stoppers.push(claim_stop.clone());

            let stopname = Self::tx_stop(claim_name, i as u8);
            protocol.add_connection(
                &format!("{}__{}", from, &stopname),
                from,
                claim_stop.into(),
                &stopname,
                InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
                None,
                None,
            )?;

            protocol.add_connection(
                &format!("CANCEL_CLAIM_{}_BY_{}", claim_name, i as u8),
                &stx,
                0.into(),
                &stopname,
                InputSpec::Auto(
                    SighashType::taproot_all(),
                    SpendMode::All {
                        key_path_sign: SignMode::Aggregate,
                    },
                ),
                None,
                None,
            )?;

            pb.add_speedup_output(protocol, &stopname, amount_dust, &stopper_pub)?;
        }

        // add the claimer success tx that is able to fullfill the claim is he was not stopped after TL
        let success = Self::tx_success(claim_name);
        protocol.add_connection(
            &format!("{}_TL_{}", from, &success),
            &stx,
            OutputSpec::Last,
            &success,
            InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 1 }),
            Some(timelock_blocks),
            None,
        )?;

        if exclusive_success_vout.is_some() {
            protocol.add_connection(
                &format!("{}_EXCLUSIVE_{}", from, &success),
                &from,
                OutputSpec::Index(exclusive_success_vout.unwrap()),
                &success,
                InputSpec::Auto(SighashType::taproot_all(), SpendMode::Script { leaf: 0 }),
                None,
                None,
            )?;
        }

        // add action/enablers as the vouts in the success transaction
        let aggregated_output = Self::output_from_aggregated(aggregated, amount_dust)?;
        let action_outputs = (0..action_count)
            .map(|_x| aggregated_output.clone())
            .collect::<Vec<OutputType>>();

        for action in action_outputs.iter().chain(outputs.iter()) {
            if action.get_value().to_sat() != amount_dust {
                return Err(BitVMXError::InvalidParameter(format!(
                    "Error building claimage {}, All claim gates outputs must have DUST={} as amount in output={}",
                    claim_name,
                    amount_dust,
                    action.get_value().to_sat()
                )));
            }

            protocol.add_transaction_output(&success, action)?;
        }

        // claimer speedup output for the claim success transaction
        pb.add_speedup_output(protocol, &success, amount_dust, claimer.0)?;

        // claimer speedup output for the claim start transaction
        pb.add_speedup_output(protocol, &stx, amount_dust, claimer.0)?;

        let cost = Self::cost(
            amount_fee,
            amount_dust,
            stoppers_pub.len() as u8,
            outputs.len(),
            add_exclusive_success,
        );

        Ok(Self {
            name: claim_name.to_string(),
            from: from.to_string(),
            vout: vout_idx,
            stop_count: stoppers_pub.len() as u8,
            cost,
            exclusive_success_vout,
            stoppers: claim_stoppers,
        })
    }

    // Add the connections to the protocol to allow the claimer to spend the stops if he wins
    pub fn add_claimer_win_connection(
        &self,
        protocol: &mut Protocol,
        to: &str,
    ) -> Result<(), BitVMXError> {
        for i in 0..self.stop_count {
            protocol.add_transaction_input(
                Hash::all_zeros(),
                self.vout + 1,
                to,
                Sequence::ENABLE_RBF_NO_LOCKTIME,
                &SpendMode::All {
                    key_path_sign: SignMode::Aggregate,
                },
                &SighashType::taproot_all(),
            )?;

            let input_index = protocol.transaction_by_name(to)?.input.len() - 1;
            protocol.add_connection(
                &format!("CLAIMER_WINS_{}_STOP_{}__{}", self.name, i, to),
                &self.from,
                (self.vout + 1).into(),
                to,
                input_index.into(),
                None,
                None,
            )?;
        }

        Ok(())
    }
}
