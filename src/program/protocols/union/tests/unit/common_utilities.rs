
use super::super::helpers::{
    assert_all_unique, generate_channel_configs, generate_consecutive_values,
    generate_edge_slots, generate_index_pairs, generate_key_labels, generate_network_labels,
    generate_slot_range, generate_symmetric_pairs, generate_test_committee_labels,
    generate_test_key_seeds, generate_test_slots, generate_unicode_strings,
    generate_variable_length_seeds, test_committee, test_key, test_pubkey,
};
use crate::program::protocols::union::common::{
    get_accept_pegin_pid, get_dispute_aggregated_key_pid, get_dispute_channel_pid,
    get_dispute_core_pid, get_dispute_pair_aggregated_key_pid, get_full_penalization_pid,
    get_take_aggreated_key_pid, get_user_take_pid,
};
use uuid::Uuid;

/// Determinism is critical here - same inputs must always give same ID
#[test]
fn dispute_core_is_deterministic() {
    let committee = test_committee("alpha");
    let pubkey = test_pubkey(&test_key("operator", 1));

    let first = get_dispute_core_pid(committee, &pubkey);
    let second = get_dispute_core_pid(committee, &pubkey);

    assert_eq!(first, second);
}

#[test]
fn dispute_core_committee_matters() {
    let pubkey = test_pubkey("wt_a");
    let pid_a = get_dispute_core_pid(test_committee("committee_a"), &pubkey);
    let pid_b = get_dispute_core_pid(test_committee("committee_b"), &pubkey);

    assert_ne!(pid_a, pid_b);
}

#[test]
fn dispute_core_pubkey_matters() {
    let committee = test_committee("main");
    let alice = get_dispute_core_pid(committee, &test_pubkey("alice"));
    let bob = get_dispute_core_pid(committee, &test_pubkey("bob"));

    assert_ne!(alice, bob);
}

#[test]
fn dispute_core_operator_types_distinct() {
    let committee = test_committee("test");
    let seeds = generate_test_key_seeds();

    let pids: Vec<_> = seeds
        .iter()
        .map(|s| get_dispute_core_pid(committee, &test_pubkey(s.as_str())))
        .collect();

    assert_all_unique(&pids, "Key type protocol IDs");
}

#[test]
fn dispute_core_stability_over_calls() {
    let committee = test_committee("prod");
    let pubkey = test_pubkey("node_op");

    let results: Vec<_> = (0..10)
        .map(|_| get_dispute_core_pid(committee, &pubkey))
        .collect();

    for (i, pid) in results.iter().enumerate().skip(1) {
        assert_eq!(results[0], *pid, "Call {} inconsistent", i);
    }
}

#[test]
fn dispute_core_empty_committee_valid() {
    let empty = test_committee("");
    let op = test_pubkey("op");
    let pid = get_dispute_core_pid(empty, &op);

    assert_ne!(pid, Uuid::nil());
}

#[test]
fn dispute_core_variable_length_seeds() {
    let committee = test_committee("encoding");
    let seeds = generate_variable_length_seeds();

    let pids: Vec<_> = seeds
        .iter()
        .map(|s| get_dispute_core_pid(committee, &test_pubkey(s)))
        .collect();

    assert_all_unique(&pids, "Variable length seeds");
}

#[test]
fn dispute_core_unicode_labels() {
    let labels = generate_unicode_strings();
    let key = test_pubkey("operator");

    let pids: Vec<_> = labels.iter()
        .map(|label| get_dispute_core_pid(test_committee(label.as_str()), &key))
        .collect();

    assert_all_unique(&pids, "Unicode committee labels");
}

#[test]
fn dispute_core_hash_distribution() {
    let committee = test_committee("distribution");
    let key1 = test_pubkey("test_a");
    let key2 = test_pubkey("test_b"); // Very similar seed

    let pid1 = get_dispute_core_pid(committee, &key1);
    let pid2 = get_dispute_core_pid(committee, &key2);

    assert_ne!(pid1, pid2);

    // Check that the UUIDs are substantially different, not just one bit flip
    let differing_bytes = pid1
        .as_bytes()
        .iter()
        .zip(pid2.as_bytes().iter())
        .filter(|(b1, b2)| b1 != b2)
        .count();

    // A good hash function should change at least a quarter of the bytes for a small input change.
    assert!(
        differing_bytes > 4,
        "UUIDs are too similar; only {} bytes differ",
        differing_bytes
    );
}

#[test]
fn accept_pegin_consistent() {
    let committee = test_committee("pegin");
    let slot = 5;

    let first = get_accept_pegin_pid(committee, slot);
    let second = get_accept_pegin_pid(committee, slot);

    assert_eq!(first, second);
}

#[test]
fn accept_pegin_slots_unique() {
    let committee = test_committee("bridge");
    let slots = generate_test_slots();

    let pids: Vec<_> = slots.iter()
        .map(|&s| get_accept_pegin_pid(committee, s))
        .collect();

    assert_all_unique(&pids, "Slot IDs");
}

#[test]
fn accept_pegin_min_max_differ() {
    let committee = test_committee("edge");
    let min_slot = get_accept_pegin_pid(committee, 0);
    let max_slot = get_accept_pegin_pid(committee, usize::MAX);

    assert_ne!(min_slot, max_slot);
}

#[test]
fn accept_pegin_committee_isolation() {
    let slot = 7;
    let labels = generate_test_committee_labels();

    let pids: Vec<_> = labels
        .iter()
        .map(|l| get_accept_pegin_pid(test_committee(l.as_str()), slot))
        .collect();

    assert_all_unique(&pids, "Committee isolation");
}

#[test]
fn accept_pegin_consecutive_slots() {
    let committee = test_committee("consecutive");

    let pids: Vec<_> = (0..200)
        .map(|s| get_accept_pegin_pid(committee, s))
        .collect();

    assert_all_unique(&pids, "Consecutive slots");
}

#[test]
fn accept_pegin_near_max_boundary() {
    let committee = test_committee("large");
    let offsets = [10, 5, 1, 0];

    let pids: Vec<_> = offsets.iter()
        .map(|&off| get_accept_pegin_pid(committee, usize::MAX - off))
        .collect();

    assert_all_unique(&pids, "Near-max slots");
}

#[test]
fn user_take_deterministic() {
    let committee = test_committee("withdrawal");
    let slot = 3;

    let first = get_user_take_pid(committee, slot);
    let second = get_user_take_pid(committee, slot);

    assert_eq!(first, second);
}

#[test]
fn user_take_vs_pegin_differ() {
    let committee = test_committee("shared");
    let slot = 7;

    let pegin = get_accept_pegin_pid(committee, slot);
    let take = get_user_take_pid(committee, slot);

    assert_ne!(pegin, take);
}

#[test]
fn user_take_slots_unique() {
    let committee = test_committee("multi");
    let slots = [0, 1, 10, 50, 100];

    let pids: Vec<_> = slots.iter()
        .map(|&s| get_user_take_pid(committee, s))
        .collect();

    assert_all_unique(&pids, "Take slots");
}

#[test]
fn user_take_committee_isolation() {
    let slot = 12;
    let committees = generate_test_committee_labels();

    let ids: Vec<_> = committees
        .iter()
        .map(|c| get_user_take_pid(test_committee(c.as_str()), slot))
        .collect();

    assert_all_unique(&ids, "Committee take IDs");
}

#[test]
fn user_take_never_collides_with_pegin() {
    let committee = test_committee("collision_check");

    for s in 0..100 {
        let take_id = get_user_take_pid(committee, s);
        let pegin_id = get_accept_pegin_pid(committee, s);
        assert_ne!(take_id, pegin_id, "Collision at slot {}", s);
    }
}

#[test]
fn user_take_max_slot() {
    let committee = test_committee("max");
    let max_slot = usize::MAX;

    let first = get_user_take_pid(committee, max_slot);
    let second = get_user_take_pid(committee, max_slot);
    let near = get_user_take_pid(committee, max_slot - 1);

    assert_eq!(first, second);
    assert_ne!(first, near);
}

#[test]
fn take_aggregated_key_stable() {
    let committee = test_committee("agg_test");

    let first = get_take_aggreated_key_pid(committee);
    let second = get_take_aggreated_key_pid(committee);

    assert_eq!(first, second);
}

#[test]
fn dispute_aggregated_key_stable() {
    let committee = test_committee("dispute_agg");

    let first = get_dispute_aggregated_key_pid(committee);
    let second = get_dispute_aggregated_key_pid(committee);

    assert_eq!(first, second);
}

#[test]
fn aggregated_keys_differ_by_type() {
    let committee = test_committee("combined");

    let take = get_take_aggreated_key_pid(committee);
    let dispute = get_dispute_aggregated_key_pid(committee);

    assert_ne!(take, dispute);
}

#[test]
fn aggregated_keys_differ_by_committee() {
    let committees = generate_test_committee_labels();

    let take_keys: Vec<_> = committees
        .iter()
        .map(|c| get_take_aggreated_key_pid(test_committee(c.as_str())))
        .collect();

    let dispute_keys: Vec<_> = committees
        .iter()
        .map(|c| get_dispute_aggregated_key_pid(test_committee(c.as_str())))
        .collect();

    assert_all_unique(&take_keys, "Take keys");
    assert_all_unique(&dispute_keys, "Dispute keys");
}

#[test]
fn pair_aggregated_key_symmetric() {
    let committee = test_committee("pairwise");

    let forward = get_dispute_pair_aggregated_key_pid(committee, 2, 8);
    let reverse = get_dispute_pair_aggregated_key_pid(committee, 8, 2);

    assert_eq!(forward, reverse);
}

#[test]
fn pair_aggregated_key_normalized() {
    let committee = test_committee("norm");

    let p1 = get_dispute_pair_aggregated_key_pid(committee, 1, 10);
    let p2 = get_dispute_pair_aggregated_key_pid(committee, 10, 1);
    let same = get_dispute_pair_aggregated_key_pid(committee, 5, 5);
    let same2 = get_dispute_pair_aggregated_key_pid(committee, 5, 5);

    assert_eq!(p1, p2);
    assert_eq!(same, same2);
}

/// Order shouldn't matter: key(A,B) == key(B,A)
#[test]
fn pair_aggregated_key_commutative() {
    let committee = test_committee("ordering");

    for i in 0..5 {
        for j in 0..5 {
            let ij = get_dispute_pair_aggregated_key_pid(committee, i, j);
            let ji = get_dispute_pair_aggregated_key_pid(committee, j, i);
            assert_eq!(ij, ji, "Symmetry failed for ({}, {})", i, j);
        }
    }
}

#[test]
fn pair_aggregated_key_distinct_pairs() {
    let committee = test_committee("multi_pair");
    let pairs = [(0, 0), (0, 1), (1, 2), (5, 10), (100, 200)];

    let ids: Vec<_> = pairs
        .iter()
        .map(|&(a, b)| get_dispute_pair_aggregated_key_pid(committee, a, b))
        .collect();

    assert_all_unique(&ids, "Pair IDs");
}

#[test]
fn pair_aggregated_key_self_pair() {
    let committee = test_committee("self");
    let idx = 5;

    let first = get_dispute_pair_aggregated_key_pid(committee, idx, idx);
    let second = get_dispute_pair_aggregated_key_pid(committee, idx, idx);

    assert_eq!(first, second);
}

#[test]
fn pair_aggregated_key_boundaries() {
    let committee = test_committee("bounds");

    let zero = get_dispute_pair_aggregated_key_pid(committee, 0, 0);
    let mixed = get_dispute_pair_aggregated_key_pid(committee, 0, 1000);
    let extreme = get_dispute_pair_aggregated_key_pid(committee, usize::MAX - 1, usize::MAX);

    assert_ne!(zero, mixed);
    assert_ne!(mixed, extreme);
    assert_ne!(zero, extreme);
}

#[test]
fn pair_aggregated_key_various_pairs() {
    let committee = test_committee("symmetry");
    let pairs = [(1, 5), (10, 20), (0, 100), (50, 50)];

    for (l, r) in pairs {
        let forward = get_dispute_pair_aggregated_key_pid(committee, l, r);
        let reverse = get_dispute_pair_aggregated_key_pid(committee, r, l);
        assert_eq!(forward, reverse, "Pair ({},{}) asymmetric", l, r);
    }
}

#[test]
fn pair_aggregated_key_extreme_diff() {
    let committee = test_committee("extreme");

    let min_max = get_dispute_pair_aggregated_key_pid(committee, 0, usize::MAX);
    let max_min = get_dispute_pair_aggregated_key_pid(committee, usize::MAX, 0);

    assert_eq!(min_max, max_min);
}

#[test]
fn pair_aggregated_key_sequential() {
    let committee = test_committee("seq");
    let mut seen = std::collections::HashSet::new();

    for i in 0..20 {
        for j in i..20 {
            let pid = get_dispute_pair_aggregated_key_pid(committee, i, j);
            assert!(seen.insert(pid), "Duplicate at ({}, {})", i, j);
        }
    }
}

#[test]
fn pair_aggregated_key_order_insensitivity_for_generated_pairs() {
    let committee = test_committee("gen_pairs_symmetry");
    for (a, b) in generate_index_pairs() {
        let fwd = get_dispute_pair_aggregated_key_pid(committee, a, b);
        let rev = get_dispute_pair_aggregated_key_pid(committee, b, a);
        assert_eq!(fwd, rev, "Order-insensitivity failed for pair ({},{})", a, b);
    }
}

#[test]
fn dispute_channel_directional() {
    let committee = test_committee("channel");

    let forward = get_dispute_channel_pid(committee, 1, 2);
    let reverse = get_dispute_channel_pid(committee, 2, 1);

    assert_ne!(forward, reverse);
}

#[test]
fn dispute_channel_deterministic() {
    let committee = test_committee("stability");

    let first = get_dispute_channel_pid(committee, 4, 7);
    let second = get_dispute_channel_pid(committee, 4, 7);

    assert_eq!(first, second);
}

#[test]
fn dispute_channel_pairs_distinct() {
    let committee = test_committee("multichannel");
    let channels = [(0, 1), (0, 2), (1, 2), (1, 0), (2, 0), (3, 4)];

    let pids: Vec<_> = channels
        .iter()
        .map(|&(a, b)| get_dispute_channel_pid(committee, a, b))
        .collect();

    assert_all_unique(&pids, "Channel configurations");
}

#[test]
fn dispute_channel_bidirectional() {
    let committee = test_committee("bidir");

    let op_wt = get_dispute_channel_pid(committee, 0, 1);
    let wt_op = get_dispute_channel_pid(committee, 1, 0);

    assert_ne!(op_wt, wt_op);
}

#[test]
fn dispute_channel_committee_isolation() {
    let committees = generate_test_committee_labels();
    let mut all = Vec::new();

    for label in &committees {
        let cid = test_committee(label.as_str());
        all.push(get_dispute_channel_pid(cid, 0, 1));
        all.push(get_dispute_channel_pid(cid, 1, 0));
    }

    assert_all_unique(&all, "Committee channels");
}

#[test]
fn dispute_channel_self_channels() {
    let committee = test_committee("self_ch");

    let pids: Vec<_> = (0..10)
        .map(|i| get_dispute_channel_pid(committee, i, i))
        .collect();

    assert_all_unique(&pids, "Self-channels");
}

#[test]
fn dispute_channel_large_indices() {
    let committee = test_committee("large");
    let large = usize::MAX / 2;

    let forward = get_dispute_channel_pid(committee, large, large + 1);
    let reverse = get_dispute_channel_pid(committee, large + 1, large);
    let same = get_dispute_channel_pid(committee, large, large + 1);

    assert_ne!(forward, reverse);
    assert_eq!(forward, same);
}

#[test]
fn full_penalization_stable() {
    let committee = test_committee("penalty");

    let first = get_full_penalization_pid(committee);
    let second = get_full_penalization_pid(committee);

    assert_eq!(first, second);
}

#[test]
fn full_penalization_per_committee() {
    let a = test_committee("pen_a");
    let b = test_committee("pen_b");

    let pid_a = get_full_penalization_pid(a);
    let pid_b = get_full_penalization_pid(b);

    assert_ne!(pid_a, pid_b);
}

#[test]
fn full_penalization_differs_from_others() {
    let committee = test_committee("comparison");

    let pen = get_full_penalization_pid(committee);
    let core = get_dispute_core_pid(committee, &test_pubkey("test"));
    let take = get_take_aggreated_key_pid(committee);

    assert_ne!(pen, core);
    assert_ne!(pen, take);
}

#[test]
fn no_cross_protocol_collisions() {
    let committee = test_committee("collision");
    let op = test_pubkey("test_op");

    let ids = vec![
        get_dispute_core_pid(committee, &op),
        get_take_aggreated_key_pid(committee),
        get_dispute_aggregated_key_pid(committee),
        get_accept_pegin_pid(committee, 0),
        get_user_take_pid(committee, 0),
        get_dispute_pair_aggregated_key_pid(committee, 0, 1),
        get_dispute_channel_pid(committee, 0, 1),
        get_full_penalization_pid(committee),
    ];

    assert_all_unique(&ids, "Protocol types");
}

#[test]
fn committee_namespace_isolation() {
    let op = test_pubkey("shared_op");
    let names = ["fed_1", "fed_2", "fed_3", "testing", "staging"];

    let ids: Vec<_> = names
        .iter()
        .map(|n| get_dispute_core_pid(test_committee(n), &op))
        .collect();

    assert_all_unique(&ids, "Committee namespaces");
}

#[test]
fn slot_protocols_separated() {
    let committee = test_committee("slot_test");
    let slots = [0, 5, 25, 100, 500];

    for s in slots {
        let pegin = get_accept_pegin_pid(committee, s);
        let take = get_user_take_pid(committee, s);
        assert_ne!(pegin, take, "Protocols collided at slot {}", s);
    }
}

#[test]
fn mixed_protocol_behaviors() {
    let committee = test_committee("integration");

    let disp_agg = get_dispute_aggregated_key_pid(committee);
    let take_agg = get_take_aggreated_key_pid(committee);
    let pair_fwd = get_dispute_pair_aggregated_key_pid(committee, 0, 1);
    let pair_rev = get_dispute_pair_aggregated_key_pid(committee, 1, 0);
    let chan_fwd = get_dispute_channel_pid(committee, 0, 1);
    let chan_rev = get_dispute_channel_pid(committee, 1, 0);

    assert_ne!(disp_agg, take_agg);
    assert_eq!(pair_fwd, pair_rev);
    assert_ne!(chan_fwd, chan_rev);
    assert_ne!(pair_fwd, chan_fwd);
}

#[test]
fn pubkey_committee_cartesian() {
    let committees = ["net_a", "net_b", "net_c"];
    let keys = ["op_1", "op_2", "wt_1"];
    let mut ids = Vec::new();

    for committee in &committees {
        for key in &keys {
            ids.push(get_dispute_core_pid(
                test_committee(committee),
                &test_pubkey(key),
            ));
        }
    }

    assert_all_unique(&ids, "Committee-key matrix");
}

