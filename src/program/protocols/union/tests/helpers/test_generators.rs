use super::test_enums::{INVALID_PATTERNS, TEST_PREFIXES};
use super::test_helpers::{DUST_THRESHOLD, MAX_BITCOIN_SUPPLY};

const MIN_COMMITTEES: usize = 6;
const SLOT_STEP: usize = 10;
const MAX_SLOT: usize = 100;

pub fn generate_test_slots() -> Vec<usize> {
    (0..=1).chain((SLOT_STEP..=MAX_SLOT).step_by(SLOT_STEP)).collect()
}

pub fn generate_test_committee_labels() -> Vec<String> {
    (0..MIN_COMMITTEES).map(|i| format!("committee_{}", i)).collect()
}

pub fn generate_variable_length_seeds() -> Vec<&'static str> {
    vec!["a", "b", "short", "a_much_longer_seed_for_testing"]
}

pub fn generate_test_key_seeds() -> Vec<String> {
    (0..3)
        .map(|i| format!("operator_{}", i))
        .chain(["watchtower_0", "verifier", "prover"].iter().map(|s| s.to_string()))
        .collect()
}

pub fn generate_index_pairs() -> Vec<(usize, usize)> {
    (0..5)
        .flat_map(|base| (0..=2).map(move |offset| (base, base + offset)))
        .chain([(15, 20), (100, 200)])
        .collect()
}

pub fn generate_boundary_indices() -> Vec<usize> {
    (0..=3)
        .map(|i| 10_usize.pow(i))
        .chain([usize::MAX - 1, usize::MAX])
        .collect()
}

pub fn generate_representative_prefixes() -> Vec<(&'static str, &'static str)> {
    vec![
        ("simple", "tx"),
        ("complex", "my_complex_name_with_underscores"),
        ("empty", ""),
        ("numeric", "v2_protocol"),
    ]
}

pub fn generate_test_prefix(name: &str) -> String {
    format!("{}_test", name)
}

pub fn generate_sequential_range(from: usize, to: usize) -> Vec<usize> {
    (from..to).collect()
}

pub fn generate_test_amounts() -> Vec<u64> {
    [0, 1, 100, 500]
        .iter()
        .map(|&m| DUST_THRESHOLD.saturating_mul(m))
        .chain(std::iter::once(MAX_BITCOIN_SUPPLY))
        .collect()
}

pub fn generate_timelock_values() -> Vec<u16> {
    (1..=4).map(|n| n * 100).collect()
}

pub fn generate_fee_rates() -> Vec<u64> {
    (0..=10)
        .step_by(2)
        .chain([50, 100, 1000])
        .collect()
}

pub fn generate_io_counts() -> Vec<(usize, usize)> {
    (0..=1)
        .map(|n| (n, n))
        .chain((2..=10).step_by(2).flat_map(|n| vec![(n, n), (n, 1), (1, n)]))
        .collect()
}

pub fn generate_test_prefixes() -> Vec<&'static str> {
    TEST_PREFIXES.to_vec()
}

pub fn generate_index_test_cases() -> Vec<usize> {
    [0, 1, 5, 10, 42]
        .iter()
        .cloned()
        .chain(generate_boundary_indices())
        .collect()
}

pub fn generate_double_index_test_cases() -> Vec<(usize, usize)> {
    let bounds = generate_boundary_indices();
    (0..3)
        .flat_map(|i| (0..3).map(move |j| (i, j)))
        .chain(bounds.windows(2).map(|w| (w[0], w[1])))
        .chain(std::iter::once((bounds[0], bounds[bounds.len() - 1])))
        .chain(std::iter::once((bounds[bounds.len() - 1], bounds[0])))
        .collect()
}

pub fn generate_triple_index_test_cases() -> Vec<(usize, usize, usize)> {
    let bounds = generate_boundary_indices();
    let mut cases = vec![(0, 0, 0)];

    cases.extend((1..4).map(|i| (i, i + 1, i + 2)));

    // Avoid overflow on 32-bit
    cases.extend(
        bounds.iter().take(bounds.len() / 2).filter_map(|&v| {
            if v <= usize::MAX / 3 {
                Some((v, v * 2, v * 3))
            } else {
                None
            }
        }),
    );

    cases.push((bounds[0], bounds[bounds.len() - 1], bounds[1]));
    cases
}

pub fn generate_invalid_name_patterns() -> Vec<&'static str> {
    INVALID_PATTERNS.to_vec()
}

pub fn generate_case_variations() -> Vec<&'static str> {
    vec!["UPPERCASE", "lowercase", "MixedCase", "CamelCase"]
}

pub fn generate_unicode_strings() -> Vec<String> {
    vec![
        "committee_a".to_string(),
        "committee_NFC_café".to_string(),
        "committee_NFD_cafe\u{0301}".to_string(),
        "committee_rtl_\u{202E}reversed".to_string(),
        "committee_zwsp_a\u{200B}b".to_string(),
        "committee_emoji_🚀".to_string(),
    ]
}

pub fn generate_unicode_digit_tests() -> Vec<&'static str> {
    // char::is_numeric() accepts these but parse::<usize>() rejects them
    vec![
        "prefix_\u{0660}",
        "prefix_\u{0967}",
        "prefix_\u{FF15}",
        "prefix_①",
    ]
}

pub fn generate_whitespace_tests() -> Vec<String> {
    [" 5", "\t5", "\n5", " _5", "5 ", "5\t"]
        .iter()
        .map(|s| format!("prefix_{}", s))
        .collect()
}

pub fn generate_powers_of_two() -> Vec<usize> {
    (0..10).map(|i| 1 << i).collect()
}

pub fn generate_powers_of_ten() -> Vec<usize> {
    (0..10).map(|i| 10_usize.pow(i as u32)).collect()
}

pub fn generate_fee_test_cases() -> Vec<(usize, usize, u64)> {
    let rates = generate_fee_rates();
    let mut cases = Vec::new();

    for inputs in 0..3 {
        for outputs in 0..3 {
            for &rate in rates.iter().take(3) {
                cases.push((inputs, outputs, rate));
            }
        }
    }

    let mid_rate = rates[rates.len() / 2];
    cases.extend([50, 100, 200].iter().map(|&n| (n, n / 2, mid_rate)));

    cases
}

pub fn generate_symmetric_pairs() -> Vec<(usize, usize)> {
    let bases = [1, 5, 10, 20, 50, 100];
    let mut pairs: Vec<(usize, usize)> = bases.iter().map(|&i| (i, i)).collect();

    for i in 0..bases.len() {
        for j in (i + 1)..bases.len() {
            pairs.push((bases[i], bases[j]));
            pairs.push((bases[j], bases[i]));
        }
    }

    pairs
}

pub fn generate_channel_configs() -> Vec<(usize, usize)> {
    (0..4)
        .flat_map(|i| (0..4).filter_map(move |j| if i != j { Some((i, j)) } else { None }))
        .chain([(100, 101), (101, 100)])
        .collect()
}

pub fn generate_slot_range() -> impl Iterator<Item = usize> {
    0..200
}

pub fn generate_edge_slots() -> Vec<usize> {
    let offsets = [0, 1, 5, 10];
    offsets.iter().map(|&off| usize::MAX - off).collect()
}

pub fn generate_consecutive_values(start: usize, count: usize) -> Vec<usize> {
    (start..start + count).collect()
}

pub fn generate_network_labels() -> Vec<String> {
    (1..=5).map(|i| format!("fed_{}", i)).collect()
}

pub fn generate_key_labels() -> Vec<String> {
    (1..=3).flat_map(|i| {
        vec![format!("op_{}", i), format!("wt_{}", i)]
    }).collect()
}

