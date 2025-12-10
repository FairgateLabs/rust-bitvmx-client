use bitcoin::secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey};
use bitcoin::PublicKey;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::program::protocols::union::common::{
    get_accept_pegin_pid, get_dispute_aggregated_key_pid, get_dispute_channel_pid,
    get_dispute_core_pid, get_dispute_pair_aggregated_key_pid, get_take_aggreated_key_pid,
    get_user_take_pid,
};

fn committee_id(label: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"test_committee:");
    hasher.update(label.as_bytes());
    let hash = hasher.finalize();
    Uuid::from_bytes(hash[..16].try_into().unwrap())
}

fn make_pubkey(identifier: &str) -> PublicKey {
    let secp = Secp256k1::new();
    let mut hasher = Sha256::new();
    hasher.update(b"pubkey:");
    hasher.update(identifier.as_bytes());
    let hash = hasher.finalize();

    let secret_key = SecretKey::from_slice(&hash).expect("valid key");
    let secp_pubkey = Secp256k1PublicKey::from_secret_key(&secp, &secret_key);
    PublicKey::new(secp_pubkey)
}

mod dispute_core {
    use super::*;

    #[test]
    fn produces_stable_id_for_same_inputs() {
        let committee = committee_id("alpha");
        let pubkey = make_pubkey("operator_1");

        let first = get_dispute_core_pid(committee, &pubkey);
        let second = get_dispute_core_pid(committee, &pubkey);

        assert_eq!(first, second);
    }

    #[test]
    fn distinguishes_committees() {
        let pubkey = make_pubkey("watchtower_a");

        let pid_a = get_dispute_core_pid(committee_id("committee_a"), &pubkey);
        let pid_b = get_dispute_core_pid(committee_id("committee_b"), &pubkey);

        assert_ne!(pid_a, pid_b);
    }

    #[test]
    fn distinguishes_pubkeys() {
        let committee = committee_id("main");

        let pid1 = get_dispute_core_pid(committee, &make_pubkey("alice"));
        let pid2 = get_dispute_core_pid(committee, &make_pubkey("bob"));

        assert_ne!(pid1, pid2);
    }

    #[test]
    fn handles_various_key_types() {
        let committee = committee_id("test");

        let keys = ["op_0", "op_1", "wt_0", "verifier_key", "prover_key"];
        let mut pids = Vec::new();

        for key in &keys {
            let pid = get_dispute_core_pid(committee, &make_pubkey(key));
            pids.push(pid);
        }

        for i in 0..pids.len() {
            for j in (i + 1)..pids.len() {
                assert_ne!(pids[i], pids[j]);
            }
        }
    }

    #[test]
    fn consistent_across_multiple_calls() {
        let committee = committee_id("prod");
        let pubkey = make_pubkey("node_operator");

        let calls: Vec<_> = (0..10).map(|_| get_dispute_core_pid(committee, &pubkey)).collect();

        for pid in &calls[1..] {
            assert_eq!(calls[0], *pid);
        }
    }
}

mod accept_pegin {
    use super::*;

    #[test]
    fn repeatable_for_same_slot() {
        let committee = committee_id("pegin_committee");
        let slot_idx = 5;

        let first = get_accept_pegin_pid(committee, slot_idx);
        let second = get_accept_pegin_pid(committee, slot_idx);

        assert_eq!(first, second);
    }

    #[test]
    fn differentiates_slots() {
        let committee = committee_id("bridge_v1");

        let slots = [0, 1, 10, 42, 100];
        let pids: Vec<_> = slots.iter().map(|&s| get_accept_pegin_pid(committee, s)).collect();

        for i in 0..pids.len() {
            for j in (i + 1)..pids.len() {
                assert_ne!(pids[i], pids[j]);
            }
        }
    }

    #[test]
    fn handles_edge_case_slots() {
        let committee = committee_id("edge_test");

        let pid_first = get_accept_pegin_pid(committee, 0);
        let pid_last = get_accept_pegin_pid(committee, usize::MAX);

        assert_ne!(pid_first, pid_last);
    }

    #[test]
    fn committee_separation() {
        let slot = 7;

        let pid_a = get_accept_pegin_pid(committee_id("committee_x"), slot);
        let pid_b = get_accept_pegin_pid(committee_id("committee_y"), slot);

        assert_ne!(pid_a, pid_b);
    }
}

mod user_take {
    use super::*;

    #[test]
    fn stable_across_calls() {
        let committee = committee_id("withdrawal_committee");
        let slot_idx = 3;

        let first = get_user_take_pid(committee, slot_idx);
        let second = get_user_take_pid(committee, slot_idx);

        assert_eq!(first, second);
    }

    #[test]
    fn distinct_from_accept_pegin() {
        let committee = committee_id("shared_committee");
        let slot_idx = 7;

        let accept_pid = get_accept_pegin_pid(committee, slot_idx);
        let take_pid = get_user_take_pid(committee, slot_idx);

        assert_ne!(accept_pid, take_pid);
    }

    #[test]
    fn varies_per_slot() {
        let committee = committee_id("multi_slot");

        let slots = vec![0, 1, 50, 100];
        let pids: Vec<_> = slots.iter().map(|&s| get_user_take_pid(committee, s)).collect();

        for i in 0..pids.len() {
            for j in (i + 1)..pids.len() {
                assert_ne!(pids[i], pids[j]);
            }
        }
    }

    #[test]
    fn same_slot_different_committees() {
        let slot = 12;

        let pid_dev = get_user_take_pid(committee_id("dev"), slot);
        let pid_staging = get_user_take_pid(committee_id("staging"), slot);
        let pid_prod = get_user_take_pid(committee_id("prod"), slot);

        assert_ne!(pid_dev, pid_staging);
        assert_ne!(pid_staging, pid_prod);
        assert_ne!(pid_dev, pid_prod);
    }
}

mod aggregated_keys {
    use super::*;

    #[test]
    fn take_key_is_deterministic() {
        let committee = committee_id("aggregation_test");

        let first = get_take_aggreated_key_pid(committee);
        let second = get_take_aggreated_key_pid(committee);

        assert_eq!(first, second);
    }

    #[test]
    fn dispute_key_is_deterministic() {
        let committee = committee_id("dispute_aggregation");

        let first = get_dispute_aggregated_key_pid(committee);
        let second = get_dispute_aggregated_key_pid(committee);

        assert_eq!(first, second);
    }

    #[test]
    fn take_and_dispute_differ() {
        let committee = committee_id("combined");

        let take_pid = get_take_aggreated_key_pid(committee);
        let dispute_pid = get_dispute_aggregated_key_pid(committee);

        assert_ne!(take_pid, dispute_pid);
    }

    #[test]
    fn different_committees_yield_different_keys() {
        let committees = ["primary", "secondary", "tertiary"];
        let mut take_pids = Vec::new();
        let mut dispute_pids = Vec::new();

        for label in &committees {
            let cid = committee_id(label);
            take_pids.push(get_take_aggreated_key_pid(cid));
            dispute_pids.push(get_dispute_aggregated_key_pid(cid));
        }

        for i in 0..take_pids.len() {
            for j in (i + 1)..take_pids.len() {
                assert_ne!(take_pids[i], take_pids[j]);
                assert_ne!(dispute_pids[i], dispute_pids[j]);
            }
        }
    }
}

mod pairwise_keys {
    use super::*;

    #[test]
    fn symmetric_for_index_order() {
        let committee = committee_id("pairwise");

        let pid_forward = get_dispute_pair_aggregated_key_pid(committee, 2, 8);
        let pid_reverse = get_dispute_pair_aggregated_key_pid(committee, 8, 2);

        assert_eq!(pid_forward, pid_reverse);
    }

    #[test]
    fn normalization_works_correctly() {
        let committee = committee_id("normalization");

        let small_large = get_dispute_pair_aggregated_key_pid(committee, 1, 10);
        let large_small = get_dispute_pair_aggregated_key_pid(committee, 10, 1);
        let equal = get_dispute_pair_aggregated_key_pid(committee, 5, 5);

        assert_eq!(small_large, large_small);

        let equal_reversed = get_dispute_pair_aggregated_key_pid(committee, 5, 5);
        assert_eq!(equal, equal_reversed);
    }

    #[test]
    fn validates_min_max_ordering() {
        let committee = committee_id("ordering");

        for i in 0..5 {
            for j in 0..5 {
                let pid_ij = get_dispute_pair_aggregated_key_pid(committee, i, j);
                let pid_ji = get_dispute_pair_aggregated_key_pid(committee, j, i);
                assert_eq!(pid_ij, pid_ji, "Symmetry failed for ({}, {})", i, j);
            }
        }
    }

    #[test]
    fn distinct_pairs_yield_distinct_ids() {
        let committee = committee_id("multi_pair");

        let pairs = [(1, 2), (1, 3), (2, 3), (0, 5), (4, 7)];
        let mut pids = Vec::new();

        for (a, b) in pairs {
            pids.push(get_dispute_pair_aggregated_key_pid(committee, a, b));
        }

        for i in 0..pids.len() {
            for j in (i + 1)..pids.len() {
                assert_ne!(pids[i], pids[j]);
            }
        }
    }

    #[test]
    fn same_index_pair_is_valid() {
        let committee = committee_id("self_pair");

        let first = get_dispute_pair_aggregated_key_pid(committee, 5, 5);
        let second = get_dispute_pair_aggregated_key_pid(committee, 5, 5);

        assert_eq!(first, second);
    }

    #[test]
    fn boundary_indices_handled() {
        let committee = committee_id("boundaries");

        let pid_zero = get_dispute_pair_aggregated_key_pid(committee, 0, 0);
        let pid_mixed = get_dispute_pair_aggregated_key_pid(committee, 0, 1000);
        let pid_large = get_dispute_pair_aggregated_key_pid(committee, usize::MAX - 1, usize::MAX);

        assert_ne!(pid_zero, pid_mixed);
        assert_ne!(pid_mixed, pid_large);
        assert_ne!(pid_zero, pid_large);
    }

    #[test]
    fn symmetry_across_various_pairs() {
        let committee = committee_id("symmetry_check");
        let pairs = [(0, 1), (3, 7), (15, 20), (100, 200)];

        for (a, b) in pairs {
            let forward = get_dispute_pair_aggregated_key_pid(committee, a, b);
            let reverse = get_dispute_pair_aggregated_key_pid(committee, b, a);
            assert_eq!(forward, reverse);
        }
    }
}

mod dispute_channels {
    use super::*;

    #[test]
    fn directional_ordering_matters() {
        let committee = committee_id("channel_test");

        let forward = get_dispute_channel_pid(committee, 1, 2);
        let reverse = get_dispute_channel_pid(committee, 2, 1);

        assert_ne!(forward, reverse);
    }

    #[test]
    fn deterministic_for_same_direction() {
        let committee = committee_id("stability");

        let first = get_dispute_channel_pid(committee, 4, 7);
        let second = get_dispute_channel_pid(committee, 4, 7);

        assert_eq!(first, second);
    }

    #[test]
    fn different_pairs_are_distinct() {
        let committee = committee_id("multichannel");

        let channels = vec![
            (0, 1), (0, 2), (1, 2), (1, 0), (2, 0), (3, 4),
        ];

        let pids: Vec<_> = channels
            .iter()
            .map(|&(a, b)| get_dispute_channel_pid(committee, a, b))
            .collect();

        for i in 0..pids.len() {
            for j in (i + 1)..pids.len() {
                assert_ne!(pids[i], pids[j]);
            }
        }
    }

    #[test]
    fn bidirectional_channels_differ() {
        let committee = committee_id("bidirectional");

        let op_to_wt = get_dispute_channel_pid(committee, 0, 1);
        let wt_to_op = get_dispute_channel_pid(committee, 1, 0);

        assert_ne!(op_to_wt, wt_to_op);
    }

    #[test]
    fn committee_isolation() {
        let committees = ["network_a", "network_b", "network_c"];

        let mut all_pids = Vec::new();
        for label in &committees {
            let cid = committee_id(label);
            all_pids.push(get_dispute_channel_pid(cid, 0, 1));
            all_pids.push(get_dispute_channel_pid(cid, 1, 0));
        }

        for i in 0..all_pids.len() {
            for j in (i + 1)..all_pids.len() {
                assert_ne!(all_pids[i], all_pids[j]);
            }
        }
    }
}

mod full_penalization {
    use super::*;

    #[test]
    fn generates_deterministic_id() {
        let committee = committee_id("penalty");

        let first = crate::program::protocols::union::common::get_full_penalization_pid(committee);
        let second = crate::program::protocols::union::common::get_full_penalization_pid(committee);

        assert_eq!(first, second);
    }

    #[test]
    fn differs_across_committees() {
        let committee_a = committee_id("penalty_a");
        let committee_b = committee_id("penalty_b");

        let pid_a = crate::program::protocols::union::common::get_full_penalization_pid(committee_a);
        let pid_b = crate::program::protocols::union::common::get_full_penalization_pid(committee_b);

        assert_ne!(pid_a, pid_b);
    }

    #[test]
    fn distinct_from_other_protocol_types() {
        let committee = committee_id("comparison");

        let penalization = crate::program::protocols::union::common::get_full_penalization_pid(committee);
        let dispute_core = get_dispute_core_pid(committee, &make_pubkey("test"));
        let take_key = crate::program::protocols::union::common::get_take_aggreated_key_pid(committee);

        assert_ne!(penalization, dispute_core);
        assert_ne!(penalization, take_key);
    }
}

mod cross_function_properties {
    use super::*;

    #[test]
    fn no_collisions_across_protocol_types() {
        let committee = committee_id("collision_test");
        let pubkey = make_pubkey("test_operator");

        let ids = vec![
            get_dispute_core_pid(committee, &pubkey),
            get_take_aggreated_key_pid(committee),
            get_dispute_aggregated_key_pid(committee),
            get_accept_pegin_pid(committee, 0),
            get_user_take_pid(committee, 0),
            get_dispute_pair_aggregated_key_pid(committee, 0, 1),
            get_dispute_channel_pid(committee, 0, 1),
        ];

        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "Protocol types should not collide");
            }
        }
    }

    #[test]
    fn multiple_committees_stay_distinct() {
        let pubkey = make_pubkey("shared_operator");
        let committees = ["federation_1", "federation_2", "federation_3", "testing", "staging"];

        let pids: Vec<_> = committees
            .iter()
            .map(|label| get_dispute_core_pid(committee_id(label), &pubkey))
            .collect();

        for i in 0..pids.len() {
            for j in (i + 1)..pids.len() {
                assert_ne!(pids[i], pids[j]);
            }
        }
    }

    #[test]
    fn slot_variations_across_protocols() {
        let committee = committee_id("slot_test");
        let slots = [0, 5, 25, 100, 500];

        for slot in slots {
            let accept = get_accept_pegin_pid(committee, slot);
            let take = get_user_take_pid(committee, slot);
            assert_ne!(accept, take);
        }
    }

    #[test]
    fn mixed_protocol_interactions() {
        let committee = committee_id("integration");

        let dispute_agg = get_dispute_aggregated_key_pid(committee);
        let take_agg = get_take_aggreated_key_pid(committee);
        let pair_0_1 = get_dispute_pair_aggregated_key_pid(committee, 0, 1);
        let pair_1_0 = get_dispute_pair_aggregated_key_pid(committee, 1, 0);
        let channel_0_1 = get_dispute_channel_pid(committee, 0, 1);
        let channel_1_0 = get_dispute_channel_pid(committee, 1, 0);

        assert_ne!(dispute_agg, take_agg);
        assert_eq!(pair_0_1, pair_1_0);
        assert_ne!(channel_0_1, channel_1_0);
        assert_ne!(pair_0_1, channel_0_1);
    }

    #[test]
    fn pubkey_uniqueness_across_committees() {
        let committees = ["net_a", "net_b", "net_c"];
        let keys = ["op_1", "op_2", "wt_1"];

        let mut all_pids = Vec::new();
        for committee_label in &committees {
            for key_label in &keys {
                let pid = get_dispute_core_pid(
                    committee_id(committee_label),
                    &make_pubkey(key_label),
                );
                all_pids.push(pid);
            }
        }

        for i in 0..all_pids.len() {
            for j in (i + 1)..all_pids.len() {
                assert_ne!(all_pids[i], all_pids[j]);
            }
        }
    }
}

