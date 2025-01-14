use std::str::FromStr;

use anyhow::Result;
use bitcoin::{OutPoint, PublicKey};
use bitvmx_client::{
    bitvmx::BitVMX,
    config::Config,
    program::participant::{P2PAddress, ParticipantRole},
};
use p2p_handler::PeerId;
use tracing::info;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

fn config_trace() {
    let filter = EnvFilter::builder()
        .parse("info,libp2p=off") // Include everything at "info" except `libp2p`
        .expect("Invalid filter");

    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_env_filter(filter)
        .init();
}

type FundingAddress = String;

fn init_bitvmx(role: &str) -> Result<(BitVMX, FundingAddress, PublicKey, P2PAddress)> {
    let config = Config::new(Some(role.to_string()))?;
    let mut bitvmx = BitVMX::new(&config)?;
    //TODO: Pre-kickoff only prover ?? make independent ??
    let funds = bitvmx.add_funds()?;
    let address = P2PAddress::new(&bitvmx.address(), PeerId::from_str(&bitvmx.peer_id())?);
    Ok((bitvmx, format!("{}:{}", funds.0, funds.1), funds.2, address))
}

pub fn main() -> Result<()> {
    config_trace();

    info!("start prover");
    let (mut prover_bitvmx, prover_funds, prover_pre_pub_key, prover_address) =
        init_bitvmx("prover")?;
    info!("start verifier");
    let (mut verifier_bitvmx, verifier_funds, verifier_pre_pub_key, verifier_address) =
        init_bitvmx("verifier")?;

    let id = Uuid::new_v4();

    let prover_pub_keys = prover_bitvmx.setup_program(
        &id,
        ParticipantRole::Prover,
        OutPoint::from_str(&prover_funds)?,
        &prover_pre_pub_key,
        &verifier_address,
    )?;

    let verifier_pub_keys = verifier_bitvmx.setup_program(
        &id,
        ParticipantRole::Verifier,
        OutPoint::from_str(&verifier_funds)?,
        &verifier_pre_pub_key,
        &prover_address,
    )?;

    //TODO: Serializer / Deserialize keys
    prover_bitvmx.setup_counterparty_keys(&id, verifier_pub_keys)?;
    verifier_bitvmx.setup_counterparty_keys(&id, prover_pub_keys)?;

    prover_bitvmx.partial_sign(&id)?;
    //TODO: Partial signs by counterparty
    prover_bitvmx.deploy_program(&id)?;

    //TODO: Push witness and then claim
    //prover_bitvmx.claim_program(&id)?;

    //TODO: Verifier waiting for any claim

    //sleep for 2 secs
    std::thread::sleep(std::time::Duration::from_secs(2));

    Ok(())
}
