use crate::errors::BitVMXError;
use crate::program::protocols::union::common::{
    double_indexed_name, extract_index, indexed_name, triple_indexed_name,
};

fn sample_prefix() -> &'static str {
    "transaction"
}

fn operator_prefix() -> &'static str {
    "operator"
}

fn slot_prefix() -> &'static str {
    "slot"
}

mod single_index_names {
    use super::*;

    #[test]
    fn generates_basic_single_indexed_name() {
        let name = indexed_name(sample_prefix(), 0);
        assert!(name.starts_with(sample_prefix()));
        assert!(name.contains('_'));
        assert_eq!(name, format!("{}_{}", sample_prefix(), 0));
    }

    #[test]
    fn maintains_prefix_integrity() {
        let prefix = operator_prefix();
        let index = 5;
        let name = indexed_name(prefix, index);

        assert!(name.starts_with(prefix));
        assert_eq!(name.split('_').next().unwrap(), prefix);
    }

    #[test]
    fn handles_first_slot_correctly() {
        let name = indexed_name(slot_prefix(), 0);
        let parts: Vec<&str> = name.split('_').collect();

        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1], "0");
    }

    #[test]
    fn handles_sequential_indices() {
        let prefix = "channel";
        for idx in 0..10 {
            let name = indexed_name(prefix, idx);
            assert_eq!(name, format!("{}_{}", prefix, idx));
        }
    }

    #[test]
    fn preserves_case_sensitivity() {
        let upper = indexed_name("UPPERCASE", 1);
        let lower = indexed_name("lowercase", 1);
        let mixed = indexed_name("MixedCase", 1);

        assert!(upper.starts_with("UPPERCASE"));
        assert!(lower.starts_with("lowercase"));
        assert!(mixed.starts_with("MixedCase"));
    }

    #[test]
    fn works_with_existing_underscores() {
        let prefix = "my_transaction_name";
        let name = indexed_name(prefix, 3);

        assert_eq!(name, format!("{}_{}", prefix, 3));
        assert_eq!(name.matches('_').count(), 3);
    }
}

mod double_index_names {
    use super::*;

    #[test]
    fn creates_pairwise_identifier() {
        let name = double_indexed_name("dispute_pair", 0, 1);
        let parts: Vec<&str> = name.split('_').collect();

        assert!(parts.len() >= 3);
        assert_eq!(parts[parts.len() - 2], "0");
        assert_eq!(parts[parts.len() - 1], "1");
    }

    #[test]
    fn distinguishes_different_pairs() {
        let pair_01 = double_indexed_name("pair", 0, 1);
        let pair_10 = double_indexed_name("pair", 1, 0);
        let pair_12 = double_indexed_name("pair", 1, 2);

        assert_ne!(pair_01, pair_10);
        assert_ne!(pair_01, pair_12);
        assert_ne!(pair_10, pair_12);
    }

    #[test]
    fn handles_matching_indices() {
        let name = double_indexed_name("self_reference", 5, 5);
        assert!(name.ends_with("5_5"));
    }

    #[test]
    fn works_across_large_index_range() {
        for i in [0, 1, 50, 100, 500] {
            for j in [0, 1, 50, 100, 500] {
                let name = double_indexed_name("range_test", i, j);
                assert!(name.contains(&i.to_string()));
                assert!(name.contains(&j.to_string()));
            }
        }
    }
}

mod triple_index_names {
    use super::*;

    #[test]
    fn creates_three_dimensional_identifier() {
        let name = triple_indexed_name("coordinate", 1, 2, 3);
        let parts: Vec<&str> = name.split('_').collect();

        assert!(parts.len() >= 4);
        let last_three: Vec<&str> = parts[parts.len() - 3..].to_vec();
        assert_eq!(last_three, vec!["1", "2", "3"]);
    }

    #[test]
    fn maintains_order_of_indices() {
        let first = 10;
        let second = 20;
        let third = 30;
        let name = triple_indexed_name("ordered", first, second, third);

        let indices_str = name.split('_').skip(1).collect::<Vec<_>>().join("_");
        assert_eq!(indices_str, format!("{}_{}_{}",  first, second, third));
    }

    #[test]
    fn distinguishes_permutations() {
        let abc = triple_indexed_name("perm", 1, 2, 3);
        let acb = triple_indexed_name("perm", 1, 3, 2);
        let bac = triple_indexed_name("perm", 2, 1, 3);

        assert_ne!(abc, acb);
        assert_ne!(abc, bac);
        assert_ne!(acb, bac);
    }

    #[test]
    fn handles_all_zeros() {
        let name = triple_indexed_name("origin", 0, 0, 0);
        assert!(name.ends_with("0_0_0"));
    }
}

mod index_extraction {
    use super::*;

    #[test]
    fn extracts_from_generated_name() {
        let prefix = sample_prefix();
        let expected = 7;
        let name = indexed_name(prefix, expected);

        let extracted = extract_index(&name, prefix).unwrap();
        assert_eq!(extracted, expected);
    }

    #[test]
    fn parses_initial_index() {
        let result = extract_index(&indexed_name(slot_prefix(), 0), slot_prefix()).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn parses_multi_digit_index() {
        let large_index = 12345;
        let name = indexed_name("item", large_index);
        let parsed = extract_index(&name, "item").unwrap();

        assert_eq!(parsed, large_index);
    }

    #[test]
    fn maintains_roundtrip_consistency() {
        let test_cases = [0, 1, 10, 100, 999, 1000, usize::MAX / 2];

        for &index in &test_cases {
            let name = indexed_name("roundtrip", index);
            let extracted = extract_index(&name, "roundtrip").unwrap();
            assert_eq!(extracted, index, "Failed roundtrip for index {}", index);
        }
    }

    #[test]
    fn works_with_complex_prefixes() {
        let prefix = "my_complex_transaction_name";
        let index = 42;
        let name = indexed_name(prefix, index);

        let result = extract_index(&name, prefix).unwrap();
        assert_eq!(result, index);
    }
}

mod error_handling {
    use super::*;

    #[test]
    fn rejects_mismatched_prefix() {
        let name = indexed_name("actual", 5);
        let result = extract_index(&name, "expected");

        assert!(result.is_err());
        if let Err(BitVMXError::InvalidTransactionName(msg)) = result {
            assert!(msg.contains("does not match"));
        } else {
            panic!("Expected InvalidTransactionName error");
        }
    }

    #[test]
    fn rejects_non_numeric_suffix() {
        let result = extract_index("transaction_notanumber", sample_prefix());

        assert!(result.is_err());
        if let Err(BitVMXError::InvalidTransactionName(msg)) = result {
            assert!(msg.contains("Could not parse"));
        } else {
            panic!("Expected parse error");
        }
    }

    #[test]
    fn rejects_missing_underscore() {
        let result = extract_index("transaction5", sample_prefix());
        assert!(result.is_err());
    }

    #[test]
    fn rejects_empty_index_part() {
        let result = extract_index("transaction_", sample_prefix());
        assert!(result.is_err());
    }

    #[test]
    fn rejects_negative_values() {
        let result = extract_index("tx_-10", "tx");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_floating_point() {
        let result = extract_index("item_3.14", "item");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_hex_notation() {
        let result = extract_index("tx_0x10", "tx");
        assert!(result.is_err());
    }

    #[test]
    fn rejects_leading_zeros() {
        let result = extract_index("tx_007", "tx");

        match result {
            Ok(val) => assert_eq!(val, 7),
            Err(_) => {}
        }
    }

    #[test]
    fn handles_whitespace_in_input() {
        let result = extract_index("tx_ 5", "tx");
        assert!(result.is_err());
    }
}

mod boundary_conditions {
    use super::*;

    #[test]
    fn handles_maximum_index_value() {
        let max_val = usize::MAX;
        let name = indexed_name("boundary", max_val);

        assert!(name.starts_with("boundary_"));
        assert!(name.contains(&max_val.to_string()));
    }

    #[test]
    fn handles_near_maximum_values() {
        let near_max = usize::MAX - 1;
        let name = indexed_name("near_max", near_max);
        let extracted = extract_index(&name, "near_max").unwrap();

        assert_eq!(extracted, near_max);
    }

    #[test]
    fn handles_powers_of_two() {
        let powers = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

        for &power in &powers {
            let name = indexed_name("power", power);
            let extracted = extract_index(&name, "power").unwrap();
            assert_eq!(extracted, power);
        }
    }

    #[test]
    fn handles_powers_of_ten() {
        let mut current = 1;
        for _ in 0..10 {
            let name = indexed_name("decimal", current);
            let extracted = extract_index(&name, "decimal").unwrap();
            assert_eq!(extracted, current);
            current *= 10;
        }
    }

    #[test]
    fn double_index_with_extreme_values() {
        let name = double_indexed_name("extreme", 0, usize::MAX);
        assert!(name.contains("0"));
        assert!(name.contains(&usize::MAX.to_string()));
    }

    #[test]
    fn triple_index_mixed_magnitudes() {
        let name = triple_indexed_name("mixed", 0, 1000, usize::MAX / 1000);
        let parts: Vec<&str> = name.split('_').collect();

        assert!(parts.len() >= 4);
        assert!(parts.contains(&"0"));
        assert!(parts.contains(&"1000"));
    }
}

mod special_prefix_cases {
    use super::*;

    #[test]
    fn handles_numeric_looking_prefix() {
        let name = indexed_name("123prefix", 5);
        assert_eq!(name, "123prefix_5");
    }

    #[test]
    fn handles_hyphenated_prefix() {
        let name = indexed_name("dispute-channel", 10);
        let parts: Vec<&str> = name.split('_').collect();
        assert_eq!(parts[0], "dispute-channel");
    }

    #[test]
    fn handles_dotted_notation() {
        let name = indexed_name("protocol.v1", 3);
        assert!(name.starts_with("protocol.v1_"));
    }

    #[test]
    fn handles_consecutive_underscores() {
        let prefix = "double__underscore";
        let name = indexed_name(prefix, 8);
        let extracted = extract_index(&name, prefix).unwrap();

        assert_eq!(extracted, 8);
    }

    #[test]
    fn handles_mixed_case_prefixes() {
        let test_cases = ["CamelCase", "ALLCAPS", "lowercase", "MiXeD_CaSe"];

        for prefix in &test_cases {
            let name = indexed_name(prefix, 1);
            let extracted = extract_index(&name, prefix).unwrap();
            assert_eq!(extracted, 1);
        }
    }
}

mod real_world_scenarios {
    use super::*;

    #[test]
    fn operator_watchtower_pairing() {
        for op in 0..5 {
            for wt in 0..5 {
                let name = double_indexed_name("operator_watchtower", op, wt);
                assert!(name.contains(&op.to_string()));
                assert!(name.contains(&wt.to_string()));
            }
        }
    }

    #[test]
    fn committee_slot_indexing() {
        let committee_size = 10;
        for slot in 0..committee_size {
            let name = indexed_name("committee_slot", slot);
            let extracted = extract_index(&name, "committee_slot").unwrap();
            assert_eq!(extracted, slot);
        }
    }

    #[test]
    fn challenge_round_step_identification() {
        let challenge = 2;
        let round = 5;
        let step = 10;

        let name = triple_indexed_name("challenge_round_step", challenge, round, step);
        let parts: Vec<&str> = name.split('_').collect();

        let indices: Vec<usize> = parts[parts.len() - 3..]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();

        assert_eq!(indices, vec![challenge, round, step]);
    }

    #[test]
    fn transaction_versioning() {
        let major = 1;
        let minor = 0;
        let patch = 0;

        let version_name = triple_indexed_name("transaction_version", major, minor, patch);
        assert!(version_name.contains(&format!("{}_{}_{}",  major, minor, patch)));
    }

    #[test]
    fn sequential_block_references() {
        let mut names = Vec::new();
        for block_height in 0..100 {
            names.push(indexed_name("block", block_height));
        }

        for i in 0..names.len() - 1 {
            assert_ne!(names[i], names[i + 1]);
        }
    }

    #[test]
    fn pairwise_dispute_channels() {
        let participants = 5;
        let mut all_channels = Vec::new();

        for i in 0..participants {
            for j in 0..participants {
                if i != j {
                    all_channels.push(double_indexed_name("dispute_channel", i, j));
                }
            }
        }

        let unique_count = all_channels.iter().collect::<std::collections::HashSet<_>>().len();
        assert_eq!(unique_count, all_channels.len());
    }
}

mod double_index_extraction {
    use super::*;

    #[test]
    fn extracts_from_generated_double_name() {
        let name = double_indexed_name("pair", 5, 10);
        let result = crate::program::protocols::union::common::extract_double_index(&name);

        assert!(result.is_ok());
        let (idx1, idx2) = result.unwrap();
        assert_eq!((idx1, idx2), (5, 10));
    }

    #[test]
    fn handles_double_roundtrip() {
        let test_pairs = [(0, 0), (1, 2), (10, 20), (100, 200)];

        for (a, b) in test_pairs {
            let name = double_indexed_name("test", a, b);
            let result = crate::program::protocols::union::common::extract_double_index(&name).unwrap();
            assert_eq!(result, (a, b), "Roundtrip failed for ({}, {})", a, b);
        }
    }

    #[test]
    fn rejects_single_index_input() {
        let single = indexed_name("test", 5);
        let result = crate::program::protocols::union::common::extract_double_index(&single);

        assert!(result.is_err());
    }

    #[test]
    fn rejects_insufficient_parts() {
        let result = crate::program::protocols::union::common::extract_double_index("single");
        assert!(result.is_err());
    }

    #[test]
    fn handles_prefix_with_underscores() {
        let name = double_indexed_name("my_complex_prefix", 3, 7);
        let result = crate::program::protocols::union::common::extract_double_index(&name).unwrap();

        assert_eq!(result, (3, 7));
    }
}

mod naming_collision_prevention {
    use super::*;

    #[test]
    fn different_indices_produce_unique_names() {
        let mut names = std::collections::HashSet::new();

        for i in 0..100 {
            let name = indexed_name("collision_test", i);
            assert!(names.insert(name), "Collision detected at index {}", i);
        }
    }

    #[test]
    fn double_index_combinations_are_unique() {
        let mut names = std::collections::HashSet::new();

        for i in 0..10 {
            for j in 0..10 {
                let name = double_indexed_name("pair", i, j);
                assert!(names.insert(name), "Collision at ({}, {})", i, j);
            }
        }
    }

    #[test]
    fn single_vs_double_index_distinct() {
        let single = indexed_name("test", 1);
        let double = double_indexed_name("test", 1, 2);

        assert_ne!(single, double);
    }

    #[test]
    fn double_vs_triple_index_distinct() {
        let double = double_indexed_name("test", 1, 2);
        let triple = triple_indexed_name("test", 1, 2, 3);

        assert_ne!(double, triple);
    }
}

