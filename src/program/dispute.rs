use std::{collections::HashMap, path::PathBuf};

use bitcoin::{Amount, Transaction, Txid};
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder, SpendingArgs},
    errors::ProtocolBuilderError,
    graph::{
        input::{InputSpendingInfo, SighashType, Signature},
        output::OutputSpendingType,
    },
    scripts,
};

use super::participant::ParticipantKeys;
pub struct SearchParams {
    search_intervals: u8,
    max_steps: u32,
}

impl SearchParams {
    pub fn new(search_intervals: u8, max_steps: u32) -> Self {
        Self {
            search_intervals,
            max_steps,
        }
    }
}

#[derive(Clone)]
pub struct Funding {
    txid: Txid,
    vout: u32,
    amount: Amount,
    protocol: u64,
    timelock: u64,
    speedup: u64,
}

impl Funding {
    pub fn new(
        txid: Txid,
        vout: u32,
        amount: u64,
        protocol: u64,
        timelock: u64,
        speedup: u64,
    ) -> Self {
        Self {
            txid,
            vout,
            amount: Amount::from_sat(amount),
            protocol,
            timelock,
            speedup,
        }
    }

    pub fn txid(&self) -> Txid {
        self.txid
    }

    pub fn vout(&self) -> u32 {
        self.vout
    }

    pub fn amount(&self) -> Amount {
        self.amount
    }

    pub fn protocol(&self) -> u64 {
        self.protocol
    }

    pub fn timelock(&self) -> u64 {
        self.timelock
    }

    pub fn speedup(&self) -> u64 {
        self.speedup
    }
}

#[derive(Clone)]
pub struct DisputeResolutionProtocol {
    protocol: Protocol,
    funding: Funding,
}

const PREKICKOFF: &str = "pre_kickoff";
const KICKOFF: &str = "kickoff";
const PROTOCOL: &str = "protocol";

impl DisputeResolutionProtocol {
    pub fn new(
        protocol_name: &str,
        protocol_storage: PathBuf,
        funding: Funding,
        prover: &ParticipantKeys,
        _verifier: &ParticipantKeys,
        _search: SearchParams,
    ) -> Result<DisputeResolutionProtocol, ProtocolBuilderError> {
        let ecdsa_sighash_type = SighashType::ecdsa_all();
        let tr_sighash_type = SighashType::taproot_all();

        let mut builder = ProtocolBuilder::new(protocol_name, protocol_storage)?;
        let output_spending_type =
            OutputSpendingType::new_segwit_key_spend(&prover.prekickoff_key(), funding.amount);
        builder.connect_with_external_transaction(
            funding.txid(),
            funding.vout(),
            output_spending_type,
            PREKICKOFF,
            &ecdsa_sighash_type,
        )?;

        let kickoff_spending = scripts::kickoff(
            &prover.protocol_key(),
            &prover.program_ending_state_key(),
            &prover.program_ending_step_number_key(),
        )?;

        builder.add_taproot_script_spend_connection(
            PROTOCOL,
            PREKICKOFF,
            funding.protocol + funding.timelock,
            &prover.internal_key(),
            &[kickoff_spending],
            "kickoff",
            &tr_sighash_type,
        )?;
        builder.add_speedup_output(PREKICKOFF, funding.speedup, &prover.speedup_key())?;

        let protocol = builder.build()?;
        Ok(Self { protocol, funding })
    }

    pub fn prekickoff_transaction(&self) -> Result<Transaction, ProtocolBuilderError> {
        let signature = self.protocol.input_ecdsa_signature(PREKICKOFF, 0)?;
        let mut ecdsa_arg = SpendingArgs::new_args();
        ecdsa_arg.push_ecdsa_signature(signature);

        self.protocol.transaction_to_send(PREKICKOFF, &[ecdsa_arg])
    }

    pub fn kickoff_transaction(&self) -> Result<Transaction, ProtocolBuilderError> {
        self.protocol.transaction_to_send(KICKOFF, &[])
    }

    pub fn spending_infos(
        &self,
    ) -> Result<HashMap<String, Vec<InputSpendingInfo>>, ProtocolBuilderError> {
        self.protocol.spending_infos()
    }

    pub fn update_input_signatures(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        signatures: Vec<Signature>,
    ) -> Result<(), ProtocolBuilderError> {
        self.protocol
            .update_input_signatures(transaction_name, input_index, signatures)?;
        Ok(())
    }

    pub fn funding(&self) -> &Funding {
        &self.funding
    }
}
