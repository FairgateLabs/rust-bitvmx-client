use super::test_validators::NameValidationError;

pub const TEST_PREFIXES: &[&str] = &[
    "transaction",
    "operator",
    "slot",
    "channel",
    "UPPERCASE",
    "lowercase",
    "MixedCase",
    "my_complex_name",
    "tx",
    "",
    "tx123",
    "dispute_pair",
    "op_wt",
    "triple",
    "CHALLENGE",
    "kick_off",
    "op.disabler",
    "tx-name",
    "prefix__double",
    "123numeric",
];

pub const INVALID_PATTERNS: &[&str] = &[
    "prefix__123",
    "prefix_",
    "prefix_abc",
    "prefix_-5",
    "prefix_1.5",
    "prefix_0x10",
    "prefix_1e10",
    "prefix_01",
    "prefix_123abc",
    "no_underscore123",
    "wrong_prefix_5",
    "prefix_+5",
    "prefix_005",
    "prefix_00",
];

pub const INVALID_NAME_CASES: &[(&str, NameValidationError)] = &[
    ("prefix_", NameValidationError::EmptyIndex),
    ("prefix_01", NameValidationError::LeadingZero),
    ("prefix_abc", NameValidationError::NonAsciiDigit),
    ("prefix_ 5", NameValidationError::NonAsciiDigit),
    ("no_underscore", NameValidationError::MissingSeparator),
];

pub const UNICODE_INVALID_PATTERNS: &[&str] = &[
    "prefix_①",
    "prefix_\u{0660}",
    "prefix_\u{FF15}",
    "prefix_５",
];
