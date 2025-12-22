use crate::errors::BitVMXError;
use std::collections::HashSet;
use super::test_validators::{NameValidator, cross_validate_indexed_name};

pub fn assert_valid_indexed_name(name: &str, prefix: &str, idx: usize) {
    assert!(name.starts_with(prefix), "Name '{}' should start with prefix '{}'", name, prefix);
    assert!(name.contains('_'), "Name '{}' missing underscore separator", name);

    let expected = format!("{}_{}", prefix, idx);
    assert_eq!(name, expected, "Name format mismatch");
}

pub fn assert_is_invalid_name_error(result: Result<usize, BitVMXError>) {
    match result {
        Err(BitVMXError::InvalidTransactionName(_)) => {},
        Err(other) => panic!("Expected InvalidTransactionName, got {:?}", other),
        Ok(val) => panic!("Expected error, got Ok({})", val),
    }
}

pub fn assert_error_with_context(result: Result<usize, BitVMXError>, context: &str) {
    match result {
        Err(BitVMXError::InvalidTransactionName(msg)) => {
            assert!(!msg.is_empty(), "Error message should not be empty");
        },
        Err(other) => panic!("{}: Expected InvalidTransactionName, got {:?}", context, other),
        Ok(val) => panic!("{}: Expected error, got Ok({})", context, val),
    }
}

pub fn assert_underscore_count(name: &str, expected_count: usize) {
    let actual = name.matches('_').count();
    assert_eq!(actual, expected_count,
        "Expected {} underscores in '{}', found {}", expected_count, name, actual);
}

pub fn assert_all_unique<T: Eq + std::hash::Hash + Clone>(items: &[T], context: &str) {
    let unique: HashSet<_> = items.iter().cloned().collect();
    assert_eq!(unique.len(), items.len(),
        "{}: Found {} duplicates in {} items", context, items.len() - unique.len(), items.len());
}

pub fn assert_roundtrip<F, P>(prefix: &str, idx: usize, make_fn: F, parse_fn: P)
where
    F: Fn(&str, usize) -> String,
    P: Fn(&str, &str) -> Result<usize, BitVMXError>,
{
    let generated = make_fn(prefix, idx);
    match parse_fn(&generated, prefix) {
        Ok(extracted) => assert_eq!(extracted, idx,
            "Roundtrip failed: generated '{}', extracted {} instead of {}",
            generated, extracted, idx),
        Err(e) => panic!("Roundtrip parse failed for '{}': {:?}", generated, e),
    }
}

pub fn assert_indexed_name_oracle(
    prefix: &str,
    idx: usize,
    generated: &str,
    extractor: impl Fn(&str, &str) -> Result<usize, BitVMXError>,
) {
    match NameValidator::validate_format(generated, prefix) {
        Ok(parsed) => assert_eq!(parsed, idx,
            "Oracle parsed different index: got {}, expected {} for '{}'",
            parsed, idx, generated),
        Err(e) => panic!("Oracle rejected '{}': {}", generated, e),
    }
    if let Err(e) = cross_validate_indexed_name(prefix, idx, generated, extractor) {
        panic!("Cross validation failed: {}", e);
    }
}

