
use bitcoin::ScriptBuf;
use bitcoin::PublicKey;
use protocol_builder::{
    scripts::{timelock, SignMode},
    types::OutputType,
};
use crate::program::protocols::union::common::{
    get_initial_deposit_output_type, get_operator_output_type,
};
use super::super::helpers::{
    dust_amount, generate_test_amounts, generate_timelock_values, test_pubkey, DUST_THRESHOLD,
    MAX_BITCOIN_SUPPLY,
};

fn is_p2wpkh_output(output: &OutputType, expected_amount: u64, expected_key: &PublicKey) -> bool {
    match output {
        OutputType::SegwitPublicKey {
            value,
            public_key,
            script_pubkey,
        } => {
            if value.to_sat() != expected_amount || public_key != expected_key {
                return false;
            }
            // Deep script validation
            let expected_script = ScriptBuf::new_p2wpkh(&expected_key.wpubkey_hash().unwrap());
            script_pubkey == &expected_script
        }
        _ => false,
    }
}

fn is_taproot_output(
    output: &OutputType,
    expected_amount: u64,
    expect_scripts: bool,
) -> bool {
    match output {
        OutputType::Taproot {
            value,
            leaves,
            ..
        } => {
            if value.to_sat() != expected_amount {
                return false;
            }
            let has_scripts = !leaves.is_empty();
            has_scripts == expect_scripts
        }
        _ => false,
    }
}

#[test]
fn operator_output_basic_p2wpkh() {
    let key = test_pubkey("operator");
    let amount = dust_amount(200);

    let output = get_operator_output_type(&key, amount).unwrap();

    assert!(is_p2wpkh_output(&output, amount, &key));
}

#[test]
fn operator_output_various_amounts() {
    let key = test_pubkey("amounts");
    let amounts = generate_test_amounts();

    for amt in amounts {
        let output = get_operator_output_type(&key, amt).unwrap();
        assert!(is_p2wpkh_output(&output, amt, &key));
    }
}

#[test]
fn operator_output_deterministic() {
    let key = test_pubkey("stable");
    let amount = dust_amount(100);

    let first = get_operator_output_type(&key, amount).unwrap();
    let second = get_operator_output_type(&key, amount).unwrap();

    assert_eq!(format!("{:?}", first), format!("{:?}", second));
}

#[test]
fn operator_output_key_sensitivity() {
    let amount = dust_amount(200);
    let key_a = test_pubkey("alice");
    let key_b = test_pubkey("bob");

    let out_a = get_operator_output_type(&key_a, amount).unwrap();
    let out_b = get_operator_output_type(&key_b, amount).unwrap();

    assert_ne!(format!("{:?}", out_a), format!("{:?}", out_b));
}

#[test]
fn operator_output_zero_amount() {
    let key = test_pubkey("zero");

    let output = get_operator_output_type(&key, 0).unwrap();

    assert!(is_p2wpkh_output(&output, 0, &key));
}

#[test]
fn operator_output_amount_changes() {
    let key = test_pubkey("change");

    let small = get_operator_output_type(&key, DUST_THRESHOLD).unwrap();
    let large = get_operator_output_type(&key, MAX_BITCOIN_SUPPLY).unwrap();

    assert_ne!(format!("{:?}", small), format!("{:?}", large));
}

#[test]
fn deposit_taproot_keypath_only() {
    let key = test_pubkey("keypath");
    let amount = dust_amount(400);

    let output = get_initial_deposit_output_type(amount, &key, &[]).unwrap();

    assert!(is_taproot_output(&output, amount, false));
}

#[test]
fn deposit_taproot_amount_range() {
    let key = test_pubkey("taproot");
    let amounts = generate_test_amounts();

    for amt in amounts {
        let output = get_initial_deposit_output_type(amt, &key, &[]).unwrap();
        assert!(is_taproot_output(&output, amt, false));
    }
}

#[test]
fn deposit_taproot_with_scripts() {
    let key = test_pubkey("scripted");
    let amount = dust_amount(300);
    let timelock_value = generate_timelock_values()[0];

    let script = timelock(timelock_value, &key, SignMode::Single);
    let output = get_initial_deposit_output_type(amount, &key, &[script]).unwrap();

    assert!(is_taproot_output(&output, amount, true));
}

#[test]
fn deposit_taproot_script_count_matters() {
    let key = test_pubkey("scripts");
    let amount = dust_amount(200);
    let timelocks = generate_timelock_values();

    let one_script = vec![timelock(timelocks[0], &key, SignMode::Single)];
    let two_scripts = vec![
        timelock(timelocks[0], &key, SignMode::Single),
        timelock(timelocks[1], &key, SignMode::Single),
    ];

    let out1 = get_initial_deposit_output_type(amount, &key, &one_script).unwrap();
    let out2 = get_initial_deposit_output_type(amount, &key, &two_scripts).unwrap();

    assert_ne!(format!("{:?}", out1), format!("{:?}", out2));
}

#[test]
fn deposit_taproot_deterministic() {
    let key = test_pubkey("stable");
    let amount = dust_amount(150);
    let script = timelock(generate_timelock_values()[0], &key, SignMode::Single);

    let first = get_initial_deposit_output_type(amount, &key, &[script.clone()]).unwrap();
    let second = get_initial_deposit_output_type(amount, &key, &[script]).unwrap();

    assert_eq!(format!("{:?}", first), format!("{:?}", second));
}

#[test]
fn deposit_taproot_internal_key_matters() {
    let amount = dust_amount(200);
    let key_a = test_pubkey("intern_a");
    let key_b = test_pubkey("intern_b");

    let out_a = get_initial_deposit_output_type(amount, &key_a, &[]).unwrap();
    let out_b = get_initial_deposit_output_type(amount, &key_b, &[]).unwrap();

    assert_ne!(format!("{:?}", out_a), format!("{:?}", out_b));
}

#[test]
fn deposit_taproot_empty_scripts() {
    let key = test_pubkey("empty");
    let amount = dust_amount(10);

    let output = get_initial_deposit_output_type(amount, &key, &[]).unwrap();

    assert!(is_taproot_output(&output, amount, false));
}

#[test]
fn deposit_taproot_timelock_variations() {
    let key = test_pubkey("timelocks");
    let amount = dust_amount(240);
    let timelocks = generate_timelock_values();

    let lock_a = timelock(timelocks[0], &key, SignMode::Single);
    let lock_b = timelock(timelocks[1], &key, SignMode::Single);

    let out_a = get_initial_deposit_output_type(amount, &key, &[lock_a]).unwrap();
    let out_b = get_initial_deposit_output_type(amount, &key, &[lock_b]).unwrap();

    assert_ne!(format!("{:?}", out_a), format!("{:?}", out_b));
}

#[test]
fn operator_vs_deposit_structure_differs() {
    let key = test_pubkey("compare");
    let amount = dust_amount(200);

    let operator = get_operator_output_type(&key, amount).unwrap();
    let deposit = get_initial_deposit_output_type(amount, &key, &[]).unwrap();

    assert_ne!(format!("{:?}", operator), format!("{:?}", deposit));
}

#[test]
fn operator_output_dust_threshold() {
    let key = test_pubkey("dust");

    let output = get_operator_output_type(&key, DUST_THRESHOLD).unwrap();

    assert!(is_p2wpkh_output(&output, DUST_THRESHOLD, &key));
}

#[test]
fn deposit_output_max_supply() {
    let key = test_pubkey("max");

    let output = get_initial_deposit_output_type(MAX_BITCOIN_SUPPLY, &key, &[]).unwrap();

    assert!(is_taproot_output(&output, MAX_BITCOIN_SUPPLY, false));
}

#[test]
fn multiple_scripts_with_different_keys() {
    let key_internal = test_pubkey("internal");
    let key_script_a = test_pubkey("script_a");
    let key_script_b = test_pubkey("script_b");

    let amount = dust_amount(300);
    let timelocks = generate_timelock_values();

    let scripts = vec![
        timelock(timelocks[0], &key_script_a, SignMode::Single),
        timelock(timelocks[1], &key_script_b, SignMode::Single),
    ];

    let output = get_initial_deposit_output_type(amount, &key_internal, &scripts).unwrap();

    assert!(is_taproot_output(&output, amount, true));
}

#[test]
fn operator_consecutive_amounts() {
    let key = test_pubkey("consecutive");
    let base = dust_amount(20);

    let mut prev = None;
    for i in 0..10 {
        let amount = base + i * 1000;
        let output = get_operator_output_type(&key, amount).unwrap();

        if let Some(previous) = prev {
            assert_ne!(format!("{:?}", output), format!("{:?}", previous));
        }
        prev = Some(output);
    }
}

#[test]
fn deposit_consecutive_timelocks() {
    let key = test_pubkey("consecutive_locks");
    let amount = dust_amount(200);

    let mut prev = None;
    for lock in (100..110).step_by(1) {
        let script = timelock(lock, &key, SignMode::Single);
        let output = get_initial_deposit_output_type(amount, &key, &[script]).unwrap();

        if let Some(previous) = prev {
            assert_ne!(format!("{:?}", output), format!("{:?}", previous));
        }
        prev = Some(output);
    }
}
