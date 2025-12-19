
use crate::program::protocols::union::common::estimate_fee;
use super::super::helpers::{
    generate_fee_test_cases, BASE_TX_WEIGHT, INPUT_WEIGHT, OUTPUT_WEIGHT,
};

#[test]
fn empty_transaction_costs_base_weight() {
    let rate = 5;
    let fee = estimate_fee(0, 0, rate);
    assert_eq!(fee, BASE_TX_WEIGHT * rate);
}

#[test]
fn adding_input_increases_cost() {
    let rate = 10;
    let before = estimate_fee(3, 2, rate);
    let after = estimate_fee(4, 2, rate);
    assert!(after > before);
}

#[test]
fn adding_output_increases_cost() {
    let rate = 10;
    let before = estimate_fee(2, 3, rate);
    let after = estimate_fee(2, 4, rate);
    assert!(after > before);
}

#[test]
fn monotonic_input_growth() {
    let rate = 5;
    let mut prev = estimate_fee(0, 2, rate);

    for inputs in 1..10 {
        let curr = estimate_fee(inputs, 2, rate);
        assert!(curr > prev, "Fee decreased when adding input {}", inputs);
        prev = curr;
    }
}

#[test]
fn monotonic_output_growth() {
    let rate = 5;
    let mut prev = estimate_fee(2, 0, rate);

    for outputs in 1..10 {
        let curr = estimate_fee(2, outputs, rate);
        assert!(curr > prev, "Fee decreased when adding output {}", outputs);
        prev = curr;
    }
}

#[test]
fn rate_scales_linearly() {
    let (inputs, outputs) = (5, 3);
    let base_rate = 2;
    let base_fee = estimate_fee(inputs, outputs, base_rate);

    for multiplier in 2..=5 {
        let scaled_rate = base_rate * multiplier;
        let scaled_fee = estimate_fee(inputs, outputs, scaled_rate);
        let expected = base_fee * multiplier;
        assert_eq!(scaled_fee, expected, "Rate {} didn't scale properly", scaled_rate);
    }
}

#[test]
fn input_heavier_than_output() {
    let rate = 1;
    let base = estimate_fee(0, 0, rate);
    let with_input = estimate_fee(1, 0, rate);
    let with_output = estimate_fee(0, 1, rate);

    let input_delta = with_input - base;
    let output_delta = with_output - base;

    assert_eq!(input_delta, INPUT_WEIGHT);
    assert_eq!(output_delta, OUTPUT_WEIGHT);
    assert!(input_delta > output_delta);
}

#[test]
fn weight_formula_matches_generated_cases() {
    let cases = generate_fee_test_cases();
    for (inputs, outputs, rate) in cases {
        let fee = estimate_fee(inputs, outputs, rate);
        let weight = BASE_TX_WEIGHT
            + (inputs as u64 * INPUT_WEIGHT)
            + (outputs as u64 * OUTPUT_WEIGHT);
        let expected = weight * rate;

        assert_eq!(
            fee, expected,
            "Formula failed for inputs={}, outputs={}, rate={}",
            inputs, outputs, rate
        );
    }
}

#[test]
fn single_input_weight_increment() {
    let rate = 3;
    let base = estimate_fee(0, 0, rate);
    let one_in = estimate_fee(1, 0, rate);

    let delta = (one_in - base) / rate;
    assert_eq!(delta, INPUT_WEIGHT);
}

#[test]
fn single_output_weight_increment() {
    let rate = 3;
    let base = estimate_fee(0, 0, rate);
    let one_out = estimate_fee(0, 1, rate);

    let delta = (one_out - base) / rate;
    assert_eq!(delta, OUTPUT_WEIGHT);
}

#[test]
fn zero_rate_gives_zero_fee() {
    let fee = estimate_fee(10, 10, 0);
    assert_eq!(fee, 0);
}

#[test]
fn high_rate_still_calculates() {
    let (inputs, outputs) = (1, 1);
    let safe_max_rate = u64::MAX / (BASE_TX_WEIGHT + INPUT_WEIGHT + OUTPUT_WEIGHT);

    let fee = estimate_fee(inputs, outputs, safe_max_rate);
    assert!(fee > 0);
}

#[test]
fn large_io_counts() {
    let count = 1000;
    let rate = 1;

    let fee = estimate_fee(count, count, rate);
    let expected = BASE_TX_WEIGHT + (count as u64 * (INPUT_WEIGHT + OUTPUT_WEIGHT));

    assert_eq!(fee, expected);
}

#[test]
#[should_panic]
fn overflow_panics() {
    estimate_fee(usize::MAX, usize::MAX, u64::MAX);
}

#[test]
#[should_panic]
fn fee_rate_max_overflows() {
    // This should panic as the multiplication will overflow
    estimate_fee(1, 1, u64::MAX);
}

#[test]
fn high_value_overflow_test() {
    let rate = 1;
    let max_variable_weight = u64::MAX - BASE_TX_WEIGHT;
    let max_combined_io = (max_variable_weight / (INPUT_WEIGHT + OUTPUT_WEIGHT)) as usize;

    let fee_max_minus_1 = estimate_fee(max_combined_io - 1, 0, rate);
    assert!(fee_max_minus_1 > 0);

    let fee_max = estimate_fee(max_combined_io, 0, rate);
    assert!(fee_max > fee_max_minus_1);

    let result = std::panic::catch_unwind(|| {
        let huge_value = usize::MAX / 2;
        estimate_fee(huge_value, huge_value, 1000);
    });
    assert!(result.is_err(), "Calculation should have panicked on overflow");
}

#[test]
fn deterministic_results() {
    let (inputs, outputs, rate) = (7, 4, 15);
    let first = estimate_fee(inputs, outputs, rate);
    let second = estimate_fee(inputs, outputs, rate);

    assert_eq!(first, second);
}

#[test]
fn swapping_io_affects_result() {
    let rate = 10;
    let fee_5_2 = estimate_fee(5, 2, rate);
    let fee_2_5 = estimate_fee(2, 5, rate);

    assert_ne!(fee_5_2, fee_2_5);
}

#[test]
fn zero_inputs_non_zero_outputs() {
    let rate = 8;
    let fee = estimate_fee(0, 5, rate);
    let expected = (BASE_TX_WEIGHT + 5 * OUTPUT_WEIGHT) * rate;

    assert_eq!(fee, expected);
}

#[test]
fn zero_outputs_non_zero_inputs() {
    let rate = 8;
    let fee = estimate_fee(5, 0, rate);
    let expected = (BASE_TX_WEIGHT + 5 * INPUT_WEIGHT) * rate;

    assert_eq!(fee, expected);
}

#[test]
fn symmetric_io_counts() {
    let rate = 3;

    for n in 1..=10 {
        let fee = estimate_fee(n, n, rate);
        let expected = (BASE_TX_WEIGHT + n as u64 * (INPUT_WEIGHT + OUTPUT_WEIGHT)) * rate;
        assert_eq!(fee, expected, "Symmetric case n={} failed", n);
    }
}

#[test]
fn incremental_consistency() {
    let rate = 7;

    for i in 0..5 {
        for o in 0..5 {
            let fee = estimate_fee(i, o, rate);
            let weight = BASE_TX_WEIGHT + (i as u64 * INPUT_WEIGHT) + (o as u64 * OUTPUT_WEIGHT);
            assert_eq!(fee, weight * rate, "Inconsistent at {}/{}", i, o);
        }
    }
}

#[test]
fn doubling_rate_doubles_fee() {
    let (inputs, outputs) = (3, 2);
    let base_rate = 10;

    let base_fee = estimate_fee(inputs, outputs, base_rate);
    let double_fee = estimate_fee(inputs, outputs, base_rate * 2);

    assert_eq!(double_fee, base_fee * 2);
}

#[test]
fn doubling_inputs_doubles_variable_cost() {
    let rate = 5;
    let base = estimate_fee(0, 2, rate);

    let fee_5 = estimate_fee(5, 2, rate);
    let fee_10 = estimate_fee(10, 2, rate);

    let delta_5 = fee_5 - base;
    let delta_10 = fee_10 - base;

    assert_eq!(delta_10, delta_5 * 2);
}

#[test]
fn boundary_input_counts() {
    let rate = 1;
    let boundaries = [0, 1, 10, 100, 1000];

    for &n in &boundaries {
        let fee = estimate_fee(n, 0, rate);
        let expected = BASE_TX_WEIGHT + n as u64 * INPUT_WEIGHT;
        assert_eq!(fee, expected, "Boundary {} failed", n);
    }
}

#[test]
fn boundary_output_counts() {
    let rate = 1;
    let boundaries = [0, 1, 10, 100, 1000];

    for &n in &boundaries {
        let fee = estimate_fee(0, n, rate);
        let expected = BASE_TX_WEIGHT + n as u64 * OUTPUT_WEIGHT;
        assert_eq!(fee, expected, "Boundary {} failed", n);
    }
}

#[test]
fn rate_one_equals_weight() {
    let (inputs, outputs) = (7, 3);
    let fee = estimate_fee(inputs, outputs, 1);
    let weight = BASE_TX_WEIGHT + (inputs as u64 * INPUT_WEIGHT) + (outputs as u64 * OUTPUT_WEIGHT);

    assert_eq!(fee, weight);
}
