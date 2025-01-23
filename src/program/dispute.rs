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
    _search_intervals: u8,
    _max_steps: u32,
}

impl SearchParams {
    pub fn new(search_intervals: u8, max_steps: u32) -> Self {
        Self {
            _search_intervals: search_intervals,
            _max_steps: max_steps,
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
    protocol: Option<Protocol>,
    funding: Funding,
}

const PREKICKOFF: &str = "pre_kickoff";
const KICKOFF: &str = "kickoff";
const PROTOCOL: &str = "protocol";

impl DisputeResolutionProtocol {
    pub fn new(funding: Funding) -> Result<DisputeResolutionProtocol, ProtocolBuilderError> {
        Ok(Self {
            protocol: None,
            funding,
        })
    }

    pub fn build_protocol(
        &mut self,
        protocol_name: &str,
        protocol_storage: PathBuf,
        prover: &ParticipantKeys,
        _verifier: &ParticipantKeys,
        _search: SearchParams,
    ) -> Result<(), ProtocolBuilderError> {
        let ecdsa_sighash_type = SighashType::ecdsa_all();
        let tr_sighash_type = SighashType::taproot_all();

        let mut builder = ProtocolBuilder::new(protocol_name, protocol_storage)?;
        let output_spending_type =
            OutputSpendingType::new_segwit_key_spend(prover.prekickoff_key(), self.funding.amount);
        builder.connect_with_external_transaction(
            self.funding.txid(),
            self.funding.vout(),
            output_spending_type,
            PREKICKOFF,
            &ecdsa_sighash_type,
        )?;

        let kickoff_spending = scripts::kickoff(
            prover.protocol_key(),
            prover.program_ending_state_key(),
            prover.program_ending_step_number_key(),
        )?;

        builder.add_taproot_script_spend_connection(
            PROTOCOL,
            PREKICKOFF,
            self.funding.protocol + self.funding.timelock,
            prover.internal_key(),
            &[kickoff_spending],
            "kickoff",
            &tr_sighash_type,
        )?;
        builder.add_speedup_output(PREKICKOFF, self.funding.speedup, prover.speedup_key())?;

        let protocol = builder.build()?;
        self.protocol = Some(protocol);

        Ok(())
    }

    pub fn prekickoff_transaction(&self) -> Result<Transaction, ProtocolBuilderError> {
        let signature = self.protocol()?.input_ecdsa_signature(PREKICKOFF, 0)?;
        let mut ecdsa_arg = SpendingArgs::new_args();
        ecdsa_arg.push_ecdsa_signature(signature);

        self.protocol()?
            .transaction_to_send(PREKICKOFF, &[ecdsa_arg])
    }

    pub fn kickoff_transaction(&self) -> Result<Transaction, ProtocolBuilderError> {
        self.protocol()?.transaction_to_send(KICKOFF, &[])
    }

    pub fn spending_infos(
        &self,
    ) -> Result<HashMap<String, Vec<InputSpendingInfo>>, ProtocolBuilderError> {
        self.protocol()?.spending_infos()
    }

    pub fn update_input_signatures(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        signatures: Vec<Signature>,
    ) -> Result<(), ProtocolBuilderError> {
        self.protocol_mut()?
            .update_input_signatures(transaction_name, input_index, signatures)?;
        Ok(())
    }

    pub fn funding(&self) -> &Funding {
        &self.funding
    }

    fn protocol(&self) -> Result<&Protocol, ProtocolBuilderError> {
        let protocol = match self.protocol {
            Some(ref p) => p,
            None => return Err(ProtocolBuilderError::MissingProtocol),
        };

        Ok(protocol)
    }

    fn protocol_mut(&mut self) -> Result<&mut Protocol, ProtocolBuilderError> {
        let protocol = match self.protocol {
            Some(ref mut p) => p,
            None => return Err(ProtocolBuilderError::MissingProtocol),
        };

        Ok(protocol)
    }
}
