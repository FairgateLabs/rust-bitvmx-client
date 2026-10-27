//! F3: real broker + BitVMX event loop + Bitcoin regtest, without internal scheduling calls.
//! Committee keys/settings are fixtures; request and rejection transactions are real.
//!
//! Run from the repository root (requires Docker and exclusive regtest/broker ports):
//! ```text
//! cargo test --locked --test union_test operational_reject_lookup -- --ignored --test-threads=1 --nocapture
//! ```
//! Included by `tests/union_test.rs` when the `union` feature is enabled.
#![cfg(feature = "union")]
use crate::{common, fixtures};
use anyhow::{ensure, Result};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    absolute, transaction, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClientApi;
use bitvmx_broker::RemoteChannel;
use bitvmx_client::program::participant::ParticipantRole;
use bitvmx_client::program::protocols::union::types::{
    Committee, MemberData, PacketSettings, RejectPeginData, DUST_VALUE, REJECT_PEGIN_TX,
};
use bitvmx_client::program::variables::VariableTypes;
use bitvmx_client::{bitvmx::BitVMX, types::*};
use protocol_builder::scripts::{
    build_taproot_spend_info, op_return_script, timelock, verify_signature, SignMode,
};
use std::time::{Duration, Instant};
use uuid::Uuid;

fn send(node: &BitVMX, channel: &RemoteChannel, msg: IncomingBitVMXApiMessages) -> Result<()> {
    channel.send(&node.get_components_config().bitvmx, msg.to_string()?)?;
    Ok(())
}

fn wait_for(
    node: &mut BitVMX,
    channel: &RemoteChannel,
    predicate: impl Fn(&OutgoingBitVMXApiMessages) -> bool,
) -> Result<OutgoingBitVMXApiMessages> {
    let deadline = Instant::now() + Duration::from_secs(90);
    while Instant::now() < deadline {
        node.tick()?;
        if let Some((raw, _)) = channel.recv()? {
            let msg = OutgoingBitVMXApiMessages::from_string(&raw)?;
            if predicate(&msg) {
                return Ok(msg);
            }
            ensure!(
                !matches!(msg, OutgoingBitVMXApiMessages::Error(_)),
                "unexpected BitVMX error: {msg:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    anyhow::bail!("timed out waiting for BitVMX response")
}

fn rejection_setup_and_lookup(early_lookup: bool) -> Result<()> {
    common::config_trace();
    let (bitcoin, _guard, _wallet) = common::prepare_bitcoin_guarded()?;
    let (mut node, address, channel, _) = common::init_bitvmx("op_1", false)?;
    let mut keys = vec![];
    {
        let id = Uuid::new_v4();
        send(
            &node,
            &channel,
            IncomingBitVMXApiMessages::GetPubKey(id, true),
        )?;
        let msg = wait_for(
            &mut node,
            &channel,
            |m| matches!(m, OutgoingBitVMXApiMessages::PubKey(got, _) if *got == id),
        )?;
        let OutgoingBitVMXApiMessages::PubKey(_, key) = msg else {
            unreachable!()
        };
        keys.push(key);
    }
    // Only the rejecting member's secret is held by this node. The other
    // committee public keys are fixtures, not keys imported into its signer.
    for byte in [41_u8, 42, 43] {
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&[byte; 32])?;
        keys.push(PublicKey::new(
            bitcoin::secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &secret),
        ));
    }
    keys.rotate_right(2);
    let aggregate_path = std::env::temp_dir().join(format!("f3-aggregate-{}", Uuid::new_v4()));
    let aggregate: key_manager::musig2::secp::Point = {
        let storage = storage_backend::storage::Storage::new(
            &storage_backend::storage_config::StorageConfig {
                path: aggregate_path.to_string_lossy().into_owned(),
                password: None,
                sync_writes: true,
            },
        )?;
        key_manager::musig2::musig::MuSig2Signer::new(std::rc::Rc::new(storage))
            .get_key_agg_context_aux(keys.clone(), None)?
            .aggregated_pubkey()
    };
    std::fs::remove_dir_all(aggregate_path)?;
    let take_key = PublicKey::from_slice(&aggregate.serialize())?;
    let settings = PacketSettings::default();
    let committee = Committee {
        members: keys
            .iter()
            .map(|key| MemberData {
                role: ParticipantRole::Prover,
                take_key: *key,
                dispute_key: *key,
            })
            .collect(),
        take_aggregated_key: take_key,
        dispute_aggregated_key: take_key,
        packet_size: 1,
        stream_denomination: 100_000,
        settings: settings.clone(),
    };
    let committee_id = Uuid::new_v4();
    send(
        &node,
        &channel,
        IncomingBitVMXApiMessages::SetVar(
            committee_id,
            Committee::name(),
            VariableTypes::String(serde_json::to_string(&committee)?),
        ),
    )?;

    let secp = Secp256k1::new();
    let (user_address, user_key, user_secret) =
        fixtures::emulated_user_keypair(&secp, &bitcoin, Network::Regtest)?;
    let input_value = 102_080;
    let (funding, vout) = bitcoin.fund_address(&user_address, Amount::from_sat(input_value))?;
    let rsk_address = [0x21; 20];
    let metadata = [rsk_address.as_slice(), 100_000_u64.to_be_bytes().as_slice()].concat();
    let main_tree = build_taproot_spend_info(
        &secp,
        &take_key.into(),
        &[
            timelock(settings.request_pegin_timelock, &user_key, SignMode::Single),
            op_return_script(metadata)?,
        ],
    )?;
    let reject_scripts = keys
        .iter()
        .map(|key| verify_signature(key, SignMode::Single))
        .collect::<Result<Vec<_>, _>>()?;
    let reject_tree = build_taproot_spend_info(&secp, &take_key.into(), &reject_scripts)?;
    let mut request = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(funding.compute_txid(), vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::new_p2tr(
                    &secp,
                    main_tree.internal_key(),
                    main_tree.merkle_root(),
                ),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return_script(request_pegin_op_return_data(
                    0,
                    rsk_address,
                    &user_key,
                )?)?
                .get_script()
                .clone(),
            },
            TxOut {
                value: Amount::from_sat(2 * DUST_VALUE),
                script_pubkey: ScriptBuf::new_p2tr(
                    &secp,
                    reject_tree.internal_key(),
                    reject_tree.merkle_root(),
                ),
            },
        ],
    };
    let request = fixtures::sign_p2wpkh_transaction_single_input(
        &secp,
        Network::Regtest,
        &mut request,
        &user_key,
        user_secret,
        input_value,
    )?;
    let request_id = bitcoin.send_transaction(&request)?;
    bitcoin.mine_blocks_to_address(u64::from(settings.pegin_confirmations), &user_address)?;

    let program_id = Uuid::new_v4();
    let data = RejectPeginData {
        committee_id,
        member_index: 2,
        txid: request_id,
    };
    send(
        &node,
        &channel,
        IncomingBitVMXApiMessages::SetVar(
            program_id,
            RejectPeginData::name(),
            VariableTypes::String(serde_json::to_string(&data)?),
        ),
    )?;
    send(
        &node,
        &channel,
        IncomingBitVMXApiMessages::Setup(
            program_id,
            PROGRAM_TYPE_REJECT_PEGIN.into(),
            vec![address.clone()],
            0,
        ),
    )?;
    if early_lookup {
        // Identical ordering to the coordinator; only normal tick() drives the node.
        send(
            &node,
            &channel,
            IncomingBitVMXApiMessages::GetTransactionInfoByName(program_id, REJECT_PEGIN_TX.into()),
        )?;
        wait_for(&mut node, &channel, |m| {
            matches!(m,
                OutgoingBitVMXApiMessages::NotFound(id, _) if *id == program_id
            )
        })?;
    }
    wait_for(
        &mut node,
        &channel,
        |m| matches!(m, OutgoingBitVMXApiMessages::SetupCompleted(id) if *id == program_id),
    )?;
    send(
        &node,
        &channel,
        IncomingBitVMXApiMessages::GetTransactionInfoByName(program_id, REJECT_PEGIN_TX.into()),
    )?;
    let outcome = wait_for(
        &mut node,
        &channel,
        |m| matches!(m, OutgoingBitVMXApiMessages::TransactionInfo(id, name, _) if *id == program_id && name == REJECT_PEGIN_TX),
    )?;
    let OutgoingBitVMXApiMessages::TransactionInfo(_, _, tx) = outcome else {
        unreachable!()
    };
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.input[0].previous_output, OutPoint::new(request_id, 2));
    assert!(!tx.input[0].witness.is_empty());
    // The setup hook dispatches automatically. Drive the real coordinator until
    // Bitcoin has accepted the signed transaction, then verify it can be mined.
    let deadline = Instant::now() + Duration::from_secs(90);
    while bitcoin.get_tx_confirmations(&tx.compute_txid())?.is_none() {
        ensure!(Instant::now() < deadline, "rejection was not broadcast");
        node.tick()?;
        std::thread::sleep(Duration::from_millis(10));
    }
    bitcoin.mine_blocks(1)?;
    assert!(
        bitcoin
            .get_tx_confirmations(&tx.compute_txid())?
            .unwrap_or(0)
            > 0
    );
    println!(
        "F3: early_lookup={early_lookup}, setup completed, rejection {} mined",
        tx.compute_txid()
    );
    node.shutdown()?;
    Ok(())
}

#[test]
#[ignore = "requires isolated Bitcoin regtest and broker ports"]
fn operational_f3_early_lookup() -> Result<()> {
    rejection_setup_and_lookup(true)
}

#[test]
#[ignore = "requires isolated Bitcoin regtest and broker ports"]
fn operational_f3_no_early_lookup_control() -> Result<()> {
    rejection_setup_and_lookup(false)
}
