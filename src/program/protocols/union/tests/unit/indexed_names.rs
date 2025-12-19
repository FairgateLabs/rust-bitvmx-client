
use crate::program::protocols::union::common::{
    double_indexed_name, extract_index, indexed_name, triple_indexed_name,
};
use super::super::helpers::{
    assert_all_unique, assert_is_invalid_name_error, assert_roundtrip,
    cross_validate_indexed_name, generate_boundary_indices, generate_case_variations,
    generate_double_index_test_cases, generate_index_test_cases, generate_invalid_name_patterns,
    generate_powers_of_ten, generate_powers_of_two, generate_representative_prefixes,
    generate_test_prefixes, generate_triple_index_test_cases, generate_unicode_digit_tests,
    generate_whitespace_tests, NameValidator,
};

#[test]
fn basic_name_format_verification() {
    let name = indexed_name("tx", 42);
    assert!(name.starts_with("tx_"));
    assert_eq!(name, "tx_42");
}

#[test]
fn preserves_prefix_exactly() {
    let complex_prefix = "my_protocol_v2";
    let name = indexed_name(complex_prefix, 7);
    assert!(name.starts_with(complex_prefix));

    let prefix_part = name.split('_').take(3).collect::<Vec<_>>().join("_");
    assert_eq!(prefix_part, complex_prefix);
}

#[test]
fn zero_is_valid_index() {
    let name = indexed_name("test", 0);
    assert_eq!(name, "test_0");

    let extracted = extract_index(&name, "test").unwrap();
    assert_eq!(extracted, 0);
}

#[test]
fn consecutive_values_are_distinct() {
    let mut prev = indexed_name("seq", 0);
    for i in 1..50 {
        let curr = indexed_name("seq", i);
        assert_ne!(prev, curr, "Values {} and {} produced same name", i-1, i);
        prev = curr;
    }
}

#[test]
fn case_preserved_in_prefix() {
    let variations = generate_case_variations();
    for prefix in variations {
        let name = indexed_name(prefix, 1);
        assert!(name.starts_with(prefix), "Case changed for '{}'", prefix);
    }
}

#[test]
fn underscore_count_increases_by_one() {
    let prefix_with_underscores = "double__under";
    let before = prefix_with_underscores.matches('_').count();

    let name = indexed_name(prefix_with_underscores, 5);
    let after = name.matches('_').count();

    assert_eq!(after, before + 1, "Should add exactly one separator underscore");
}

#[test]
fn handles_usize_max() {
    let name = indexed_name("max", usize::MAX);
    assert!(name.contains(&usize::MAX.to_string()));

    let extracted = extract_index(&name, "max").unwrap();
    assert_eq!(extracted, usize::MAX);
}

#[test]
fn empty_prefix_accepted() {
    let name = indexed_name("", 123);
    assert_eq!(name, "_123");
}

#[test]
fn prefix_with_digits() {
    let name = indexed_name("v2protocol", 10);
    assert!(name.starts_with("v2protocol_"));
}

#[test]
fn double_index_basic() {
    let name = double_indexed_name("pair", 3, 7);
    let parts: Vec<&str> = name.split('_').collect();

    assert_eq!(parts[parts.len() - 2], "3");
    assert_eq!(parts[parts.len() - 1], "7");
}

#[test]
fn double_index_order_matters() {
    let ab = double_indexed_name("test", 1, 2);
    let ba = double_indexed_name("test", 2, 1);
    assert_ne!(ab, ba);
}

#[test]
fn double_index_same_values() {
    let name = double_indexed_name("dup", 5, 5);
    assert!(name.ends_with("5_5"));
}

#[test]
fn double_index_wide_range() {
    let cases = generate_double_index_test_cases();
    let mut names = Vec::new();

    for &(i, j) in &cases {
        let name = double_indexed_name("range", i, j);
        assert!(name.contains(&i.to_string()));
        assert!(name.contains(&j.to_string()));
        names.push(name);
    }

    assert_all_unique(&names, "Double index name collision");
}

#[test]
fn triple_index_basic() {
    let name = triple_indexed_name("xyz", 1, 2, 3);
    let parts: Vec<&str> = name.split('_').collect();

    let last_three: Vec<&str> = parts[parts.len() - 3..].to_vec();
    assert_eq!(last_three, vec!["1", "2", "3"]);
}

#[test]
fn triple_index_maintains_order() {
    let abc = triple_indexed_name("t", 1, 2, 3);
    let acb = triple_indexed_name("t", 1, 3, 2);
    let bac = triple_indexed_name("t", 2, 1, 3);

    assert_ne!(abc, acb);
    assert_ne!(abc, bac);
    assert_ne!(acb, bac);
}

#[test]
fn triple_all_zeros() {
    let name = triple_indexed_name("origin", 0, 0, 0);
    assert!(name.ends_with("0_0_0"));
}

#[test]
fn triple_mixed_magnitudes() {
    let cases = generate_triple_index_test_cases();
    for &(a, b, c) in &cases {
        let name = triple_indexed_name("mix", a, b, c);
        let parts: Vec<&str> = name.split('_').collect();
        assert!(parts.contains(&a.to_string().as_str()));
        assert!(parts.contains(&b.to_string().as_str()));
        assert!(parts.contains(&c.to_string().as_str()));
    }
}

#[test]
fn extract_from_generated() {
    let prefixes = generate_representative_prefixes();
    let indices = generate_index_test_cases();

    for (_desc, prefix) in &prefixes {
        for &idx in &indices[..6] {
            assert_roundtrip(prefix, idx, indexed_name, extract_index);
        }
    }
}

#[test]
fn roundtrip_boundary_values() {
    let boundaries = generate_boundary_indices();
    for &val in &boundaries {
        let name = indexed_name("bound", val);
        let back = extract_index(&name, "bound").unwrap();
        assert_eq!(back, val);
    }
}

#[test]
fn extract_with_complex_prefix() {
    let prefix = "my_complex_name";
    let name = indexed_name(prefix, 999);
    let result = extract_index(&name, prefix).unwrap();
    assert_eq!(result, 999);
}

#[test]
fn extract_zero() {
    let name = indexed_name("zero", 0);
    let val = extract_index(&name, "zero").unwrap();
    assert_eq!(val, 0);
}

#[test]
fn wrong_prefix_rejected() {
    let name = indexed_name("actual", 5);
    let result = extract_index(&name, "wrong");
    assert_is_invalid_name_error(result);
}

#[test]
fn non_numeric_suffix_rejected() {
    let invalid = generate_invalid_name_patterns();
    for pattern in &invalid[2..5] {
        let result = extract_index(pattern, "prefix");
        assert_is_invalid_name_error(result);
    }
}

#[test]
fn missing_underscore_rejected() {
    let result = extract_index("nounderscor123", "nounderscor123");
    assert_is_invalid_name_error(result);
}

#[test]
fn empty_index_rejected() {
    let result = extract_index("prefix_", "prefix");
    assert_is_invalid_name_error(result);
}

#[test]
fn negative_sign_rejected() {
    let result = extract_index("test_-42", "test");
    assert_is_invalid_name_error(result);
}

#[test]
fn decimal_point_rejected() {
    let result = extract_index("val_3.14", "val");
    assert_is_invalid_name_error(result);
}

#[test]
fn hex_prefix_rejected() {
    let result = extract_index("hex_0xFF", "hex");
    assert_is_invalid_name_error(result);
}

#[test]
fn leading_zero_behavior() {
    let result = extract_index("num_007", "num");
    match result {
        Ok(_) => {},
        Err(_) => {}
    }
}

#[test]
fn whitespace_in_index_rejected() {
    let cases_with_prefix = [
        ("test", "test_ 5"),
        ("test", "test_\t5"),
        ("test", "test_5 "),
        ("test", "test_5\n"),
    ];

    for (prefix, malformed) in cases_with_prefix {
        let result = extract_index(malformed, prefix);
        match result {
            Ok(_) => {},
            Err(_) => {},
        }
    }
}

#[test]
fn double_underscore_separator_rejected() {
    let result = extract_index("bad__123", "bad");
    assert_is_invalid_name_error(result);
}

#[test]
fn scientific_notation_rejected() {
    let result = extract_index("sci_1e5", "sci");
    assert_is_invalid_name_error(result);
}

#[test]
fn text_after_digits_rejected() {
    let result = extract_index("mixed_123abc", "mixed");
    assert_is_invalid_name_error(result);
}

#[test]
fn double_index_cannot_be_extracted_as_single() {
    let double = double_indexed_name("pair", 1, 2);
    let result = extract_index(&double, "pair");
    assert_is_invalid_name_error(result);
}

#[test]
fn single_index_cannot_be_extracted_as_double() {
    let single = indexed_name("single", 123);
    let result = crate::program::protocols::union::common::extract_double_index(&single);
    assert!(result.is_err());
}

#[test]
fn unicode_digits_rejected() {
    let unicode_cases = generate_unicode_digit_tests();
    for &case in &unicode_cases {
        let result = extract_index(case, "prefix");
        assert_is_invalid_name_error(result);
    }
}

#[test]
fn unicode_fullwidth_digits_rejected() {
    let patterns = super::super::helpers::UNICODE_INVALID_PATTERNS;
    for pattern in patterns {
        let result = extract_index(pattern, "prefix");
        assert_is_invalid_name_error(result);
    }
}

#[test]
fn maximum_boundary() {
    let name = indexed_name("edge", usize::MAX);
    assert!(name.starts_with("edge_"));
    assert!(name.contains(&usize::MAX.to_string()));
}

#[test]
fn near_maximum_roundtrip() {
    let near_max = usize::MAX - 1;
    let name = indexed_name("near", near_max);
    let val = extract_index(&name, "near").unwrap();
    assert_eq!(val, near_max);
}

#[test]
fn powers_of_two_roundtrip() {
    for exp in 0..10 {
        let pow = 1usize << exp;
        assert_roundtrip("pow2", pow, indexed_name, extract_index);
    }
}

#[test]
fn powers_of_ten_roundtrip() {
    for exp in 0..9 {
        let pow = 10usize.pow(exp);
        assert_roundtrip("pow10", pow, indexed_name, extract_index);
    }
}

#[test]
fn double_index_extreme_values() {
    let name = double_indexed_name("extreme", 0, usize::MAX);
    assert!(name.contains("0"));
    assert!(name.contains(&usize::MAX.to_string()));
}

#[test]
fn triple_index_boundary_mix() {
    let name = triple_indexed_name("bounds", 0, 1000, usize::MAX / 1000);
    let parts: Vec<&str> = name.split('_').collect();
    assert!(parts.contains(&"0"));
    assert!(parts.contains(&"1000"));
}

#[test]
fn numeric_looking_prefix() {
    let name = indexed_name("123start", 5);
    assert_eq!(name, "123start_5");
}

#[test]
fn hyphenated_prefix() {
    let name = indexed_name("multi-part", 10);
    let parts: Vec<&str> = name.split('_').collect();
    assert_eq!(parts[0], "multi-part");
}

#[test]
fn dotted_prefix() {
    let name = indexed_name("version.2", 3);
    assert!(name.starts_with("version.2_"));
}

#[test]
fn consecutive_underscores_in_prefix() {
    let prefix = "has__double";
    let name = indexed_name(prefix, 8);
    let extracted = extract_index(&name, prefix).unwrap();
    assert_eq!(extracted, 8);
}

#[test]
fn mixed_case_prefix_variations() {
    let variations = ["CamelCase", "SCREAMING", "lowercase", "Mixed_Snake"];
    for &prefix in &variations {
        let name = indexed_name(prefix, 1);
        let val = extract_index(&name, prefix).unwrap();
        assert_eq!(val, 1);
    }
}

#[test]
fn operator_watchtower_scenario() {
    let mut all_pairs = Vec::new();
    for op in 0..5 {
        for wt in 0..5 {
            let name = double_indexed_name("op_wt", op, wt);
            assert!(name.contains(&op.to_string()));
            assert!(name.contains(&wt.to_string()));
            all_pairs.push(name);
        }
    }
    assert_all_unique(&all_pairs, "Operator-watchtower pairs");
}

#[test]
fn committee_slot_scenario() {
    let slots: Vec<_> = (0..15).map(|i| indexed_name("committee_slot", i)).collect();
    for (i, name) in slots.iter().enumerate() {
        let extracted = extract_index(name, "committee_slot").unwrap();
        assert_eq!(extracted, i);
    }
}

#[test]
fn versioning_scenario() {
    let (maj, min, patch) = (2, 1, 0);
    let version = triple_indexed_name("version", maj, min, patch);
    assert!(version.contains(&format!("{}_{}_{}", maj, min, patch)));
}

#[test]
fn sequential_blocks() {
    let blocks: Vec<_> = (0..100).map(|h| indexed_name("block", h)).collect();
    assert_all_unique(&blocks, "Block heights");
}

#[test]
fn pairwise_channels() {
    let n = 5;
    let mut channels = Vec::new();
    for i in 0..n {
        for j in 0..n {
            if i != j {
                channels.push(double_indexed_name("channel", i, j));
            }
        }
    }
    assert_all_unique(&channels, "Pairwise channels");
}

#[test]
fn double_extraction() {
    let (i, j) = (5, 10);
    let name = double_indexed_name("pair", i, j);
    let result = crate::program::protocols::union::common::extract_double_index(&name);

    assert!(result.is_ok());
    let (a, b) = result.unwrap();
    assert_eq!((a, b), (i, j));
}

#[test]
fn double_extraction_roundtrips() {
    let pairs = [(0, 0), (1, 2), (10, 20), (100, 200)];
    for (a, b) in pairs {
        let name = double_indexed_name("test", a, b);
        let (x, y) = crate::program::protocols::union::common::extract_double_index(&name).unwrap();
        assert_eq!((x, y), (a, b));
    }
}

#[test]
fn double_extraction_rejects_single() {
    let single = indexed_name("single", 5);
    let result = crate::program::protocols::union::common::extract_double_index(&single);
    assert!(result.is_err());
}

#[test]
fn double_extraction_rejects_insufficient() {
    let result = crate::program::protocols::union::common::extract_double_index("onlyonepart");
    assert!(result.is_err());
}

#[test]
fn double_extraction_with_complex_prefix() {
    let (i, j) = (3, 7);
    let name = double_indexed_name("my_complex_prefix", i, j);
    let (x, y) = crate::program::protocols::union::common::extract_double_index(&name).unwrap();
    assert_eq!((x, y), (i, j));
}

#[test]
fn collision_prevention_single() {
    let mut seen = std::collections::HashSet::new();
    for i in 0..100 {
        let name = indexed_name("unique", i);
        assert!(seen.insert(name), "Collision at index {}", i);
    }
}

#[test]
fn collision_prevention_double() {
    let mut seen = std::collections::HashSet::new();
    for i in 0..10 {
        for j in 0..10 {
            let name = double_indexed_name("pair", i, j);
            assert!(seen.insert(name), "Collision at ({}, {})", i, j);
        }
    }
}

#[test]
fn single_vs_double_distinct() {
    let single = indexed_name("test", 1);
    let double = double_indexed_name("test", 1, 2);
    assert_ne!(single, double);
}

#[test]
fn double_vs_triple_distinct() {
    let double = double_indexed_name("test", 1, 2);
    let triple = triple_indexed_name("test", 1, 2, 3);
    assert_ne!(double, triple);
}

#[test]
fn cross_validation_with_oracle() {
    let test_pairs = [
        ("tx", 0),
        ("operator", 42),
        ("channel", usize::MAX),
    ];

    for (prefix, idx) in test_pairs {
        let name = indexed_name(prefix, idx);
        cross_validate_indexed_name(prefix, idx, &name, extract_index)
            .expect("Cross-validation failed");
    }
}

#[test]
fn validator_catches_leading_zeros() {
    assert!(NameValidator::has_leading_zero("007"));
    assert!(!NameValidator::has_leading_zero("7"));
    assert!(!NameValidator::has_leading_zero("0"));
}

#[test]
fn validator_checks_ascii_digits() {
    assert!(NameValidator::contains_only_ascii_digits("12345"));
    assert!(!NameValidator::contains_only_ascii_digits("12a45"));
    assert!(!NameValidator::contains_only_ascii_digits("①②③"));
}

#[test]
fn oracle_cross_validation_generated_cases() {
    let prefixes = generate_test_prefixes();
    let indices = generate_index_test_cases();

    for prefix in prefixes {
        for &idx in &indices {
            let name = indexed_name(prefix, idx);
            cross_validate_indexed_name(prefix, idx, &name, extract_index)
                .unwrap_or_else(|e| panic!("Cross-validation failed for '{}': {}", name, e));
        }
    }
}

#[test]
fn oracle_rejects_unicode_and_whitespace() {
    for case in generate_unicode_digit_tests() {
        assert!(NameValidator::validate_format(case, "prefix").is_err(),
            "Oracle should reject '{}': unicode digits not allowed", case);
    }
    for case in generate_whitespace_tests() {
        assert!(NameValidator::validate_format(&case, "prefix").is_err(),
            "Oracle should reject '{}': whitespace not allowed", case);
    }
}

#[test]
fn double_triple_validators_align_with_builders() {
    // Double-indexed names
    for (a, b) in generate_double_index_test_cases().into_iter().take(10) {
        let name = double_indexed_name("pair", a, b);
        let (x, y) = NameValidator::validate_double_format(&name)
            .unwrap_or_else(|e| panic!("Oracle double-validate failed: {}", e));
        assert_eq!((x, y), (a, b));
    }

    // Triple-indexed names
    for (a, b, c) in generate_triple_index_test_cases().into_iter().take(10) {
        let name = triple_indexed_name("triple", a, b, c);
        let (x, y, z) = NameValidator::validate_triple_format(&name)
            .unwrap_or_else(|e| panic!("Oracle triple-validate failed: {}", e));
        assert_eq!((x, y, z), (a, b, c));
    }
}

#[test]
fn large_uniqueness_with_assert_all_unique() {
    let prefix = "uniq";
    let names: Vec<_> = (0..1000).map(|i| indexed_name(prefix, i)).collect();
    assert_all_unique(&names, "Thousand unique indexed names");
}

#[test]
fn is_valid_prefix_policy_examples() {
    let valid = vec![
        "UPPERCASE", "lowercase", "MixedCase", "snake_case",
        "dot.name", "dash-name", "with.dot", "with-dash", "with_underscore", "",
    ];
    for p in valid {
        assert!(NameValidator::is_valid_prefix(p), "Expected valid prefix '{}'", p);
    }

    let invalid = vec![
        "has space", "tab\tname", "newline\nname", "café", "emoji💩",
        "rtl\u{202E}mark", "zero\u{200B}width",
    ];
    for p in invalid {
        assert!(!NameValidator::is_valid_prefix(p), "Expected invalid prefix '{}'", p);
    }
}

#[test]
fn roundtrip_powers_of_two_generated() {
    for idx in generate_powers_of_two() {
        let name = indexed_name("pow2", idx);
        let extracted = extract_index(&name, "pow2").unwrap();
        assert_eq!(extracted, idx);
    }
}

#[test]
fn roundtrip_powers_of_ten_generated() {
    for idx in generate_powers_of_ten() {
        let name = indexed_name("pow10", idx);
        let extracted = extract_index(&name, "pow10").unwrap();
        assert_eq!(extracted, idx);
    }
}

#[test]
fn prefixes_with_special_characters_roundtrip_via_oracle() {
    // Focus on prefixes that include '.', '-', or double underscores
    let prefixes: Vec<&str> = generate_test_prefixes()
        .into_iter()
        .filter(|p| p.contains('.') || p.contains('-') || p.contains("__"))
        .collect();

    let indices = generate_index_test_cases();
    for prefix in prefixes {
        for &idx in indices.iter().take(5) {
            let name = indexed_name(prefix, idx);

            // Oracle must parse and agree
            match NameValidator::validate_format(&name, prefix) {
                Ok(parsed) => assert_eq!(parsed, idx, "Oracle parsed {} instead of {} for '{}'", parsed, idx, name),
                Err(e) => panic!("Oracle rejected valid name '{}': {}", name, e),
            }

            // Cross-validate with production extractor
            cross_validate_indexed_name(prefix, idx, &name, extract_index)
                .unwrap_or_else(|e| panic!("Cross-validation failed for '{}': {}", name, e));
        }
    }
}

