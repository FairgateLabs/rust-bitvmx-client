use anyhow::Result;

use bitvmx_client::types::{IncomingBitVMXApiMessages, OutgoingBitVMXApiMessages};
use std::net::IpAddr;
use uuid::Uuid;

mod common;

const PEER: &str = "aa11bb22cc33dd44ee55ff6677889900aabbccddeeff00112233445566778899";
const KEPT: &str = "bb22cc33dd44ee55ff6677889900aabbccddeeff001122334455667788990011";

/// Drive one allow list request through a real client and return the reply.
fn request(
    bitvmx: &mut bitvmx_client::bitvmx::BitVMX,
    channel: &bitvmx_broker::RemoteChannel,
    msg: IncomingBitVMXApiMessages,
) -> Result<OutgoingBitVMXApiMessages> {
    channel.send(&bitvmx.get_components_config().bitvmx, msg.to_string()?)?;
    let msg = common::wait_message_from_channel(channel, &mut vec![bitvmx], true)?;
    Ok(OutgoingBitVMXApiMessages::from_string(&msg.0)?)
}

fn list(
    bitvmx: &mut bitvmx_client::bitvmx::BitVMX,
    channel: &bitvmx_broker::RemoteChannel,
) -> Result<(Vec<(String, Option<IpAddr>)>, bool)> {
    match request(
        bitvmx,
        channel,
        IncomingBitVMXApiMessages::ListAllowList(Uuid::new_v4()),
    )? {
        OutgoingBitVMXApiMessages::AllowListEntries(_, entries, allow_all) => {
            Ok((entries, allow_all))
        }
        other => panic!("expected AllowListEntries, got {:?}", other),
    }
}

fn expect_updated(reply: OutgoingBitVMXApiMessages) {
    match reply {
        OutgoingBitVMXApiMessages::AllowListUpdated(_, persisted) => {
            assert!(persisted, "the change should have been persisted");
        }
        other => panic!("expected AllowListUpdated, got {:?}", other),
    }
}

/// A peer added through the API is still honoured by a client that restarts on
/// the same storage, and the YAML no longer overrides it.
#[test]
#[ignore]
fn added_peer_survives_a_restart() -> Result<()> {
    common::config_trace();
    let addr: IpAddr = "10.1.2.3".parse().unwrap();

    {
        let (mut bitvmx, _addr, channel, _emulator) = common::init_bitvmx("op_1", false)?;

        expect_updated(request(
            &mut bitvmx,
            &channel,
            IncomingBitVMXApiMessages::AddToAllowList(Uuid::new_v4(), PEER.to_string(), Some(addr)),
        )?);

        let (entries, _) = list(&mut bitvmx, &channel)?;
        assert!(
            entries.contains(&(PEER.to_string(), Some(addr))),
            "the peer should be listed before the restart, got {:?}",
            entries,
        );

        bitvmx.shutdown()?;
    }

    let (mut bitvmx, _addr, channel, _emulator) = common::restart_bitvmx("op_1", false)?;
    let (entries, _) = list(&mut bitvmx, &channel)?;

    assert!(
        entries.contains(&(PEER.to_string(), Some(addr))),
        "the peer must survive the restart, got {:?}",
        entries,
    );

    bitvmx.shutdown()?;
    Ok(())
}

/// A peer removed through the API stays removed: the YAML that seeded the list
/// is not consulted again once the API has been used.
#[test]
#[ignore]
fn removed_peer_does_not_come_back_after_a_restart() -> Result<()> {
    common::config_trace();

    {
        let (mut bitvmx, _addr, channel, _emulator) = common::init_bitvmx("op_1", false)?;

        // KEPT is the control: without it, an empty list would satisfy the
        // assertion below for the wrong reason, since op_1's yaml is allow_all
        // and so contributes no entries at all.
        for peer in [PEER, KEPT] {
            expect_updated(request(
                &mut bitvmx,
                &channel,
                IncomingBitVMXApiMessages::AddToAllowList(Uuid::new_v4(), peer.to_string(), None),
            )?);
        }
        expect_updated(request(
            &mut bitvmx,
            &channel,
            IncomingBitVMXApiMessages::RemoveFromAllowList(Uuid::new_v4(), PEER.to_string()),
        )?);

        bitvmx.shutdown()?;
    }

    let (mut bitvmx, _addr, channel, _emulator) = common::restart_bitvmx("op_1", false)?;
    let (entries, _) = list(&mut bitvmx, &channel)?;

    assert!(
        entries.iter().any(|(hash, _)| hash == KEPT),
        "the peer that was not removed must survive, got {:?}",
        entries,
    );
    assert!(
        !entries.iter().any(|(hash, _)| hash == PEER),
        "a removed peer must not reappear after a restart, got {:?}",
        entries,
    );

    bitvmx.shutdown()?;
    Ok(())
}

/// The shipped YAML says `allow_all`. Turning it off through the API must stick
/// across a restart rather than being reopened by the YAML.
#[test]
#[ignore]
fn allow_all_stays_disabled_after_a_restart() -> Result<()> {
    common::config_trace();

    {
        let (mut bitvmx, _addr, channel, _emulator) = common::init_bitvmx("op_1", false)?;

        let (_, allow_all) = list(&mut bitvmx, &channel)?;
        assert!(allow_all, "op_1 ships an allow_all comms allow list");

        expect_updated(request(
            &mut bitvmx,
            &channel,
            IncomingBitVMXApiMessages::SetAllowAll(Uuid::new_v4(), false),
        )?);

        bitvmx.shutdown()?;
    }

    let (mut bitvmx, _addr, channel, _emulator) = common::restart_bitvmx("op_1", false)?;
    let (_, allow_all) = list(&mut bitvmx, &channel)?;

    assert!(
        !allow_all,
        "the YAML must not reopen blanket mode after it was disabled",
    );

    bitvmx.shutdown()?;
    Ok(())
}
