
use crate::errors::BitVMXError;
use std::num::ParseIntError;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum NameValidationError {
    MissingPrefix,
    MissingSeparator,
    EmptyIndex,
    LeadingZero,
    NonAsciiDigit,
    ParseError(ParseIntError),
    InsufficientParts,
}

impl fmt::Display for NameValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<NameValidationError> for String {
    fn from(e: NameValidationError) -> Self {
        e.to_string()
    }
}

pub struct NameValidator;

impl NameValidator {
    pub fn validate_format(name: &str, prefix: &str) -> Result<usize, NameValidationError> {
        // Exact prefix match
        if !name.starts_with(prefix) {
            return Err(NameValidationError::MissingPrefix);
        }

        let remainder = &name[prefix.len()..];
        if !remainder.starts_with('_') {
            return Err(NameValidationError::MissingSeparator);
        }

        let index_str = &remainder[1..];
        if index_str.is_empty() {
            return Err(NameValidationError::EmptyIndex);
        }

        if Self::has_leading_zero(index_str) {
            return Err(NameValidationError::LeadingZero);
        }

        if !Self::contains_only_ascii_digits(index_str) {
            return Err(NameValidationError::NonAsciiDigit);
        }

        index_str
            .parse::<usize>()
            .map_err(NameValidationError::ParseError)
    }

    pub fn validate_double_format(name: &str) -> Result<(usize, usize), NameValidationError> {
        // Parse last two numeric suffixes separated by underscores, allowing underscores in prefix
        let Some(last_us) = name.rfind('_') else {
            return Err(NameValidationError::MissingSeparator);
        };
        let Some(prev_us) = name[..last_us].rfind('_') else {
            return Err(NameValidationError::InsufficientParts);
        };

        let idx1_str = &name[(prev_us + 1)..last_us];
        let idx2_str = &name[(last_us + 1)..];

        if idx1_str.is_empty() || idx2_str.is_empty() {
            return Err(NameValidationError::EmptyIndex);
        }
        if Self::has_leading_zero(idx1_str) || Self::has_leading_zero(idx2_str) {
            return Err(NameValidationError::LeadingZero);
        }
        if !Self::contains_only_ascii_digits(idx1_str) || !Self::contains_only_ascii_digits(idx2_str) {
            return Err(NameValidationError::NonAsciiDigit);
        }

        let i1 = idx1_str.parse::<usize>().map_err(NameValidationError::ParseError)?;
        let i2 = idx2_str.parse::<usize>().map_err(NameValidationError::ParseError)?;
        Ok((i1, i2))
    }

    pub fn validate_triple_format(name: &str) -> Result<(usize, usize, usize), NameValidationError> {
        // Grab the last three underscore-separated numeric parts
        let mut it = name.rsplitn(4, '_');
        let idx3_str = it.next().ok_or(NameValidationError::InsufficientParts)?;
        let idx2_str = it.next().ok_or(NameValidationError::InsufficientParts)?;
        let idx1_str = it.next().ok_or(NameValidationError::InsufficientParts)?;

        for s in [idx1_str, idx2_str, idx3_str] {
            if s.is_empty() {
                return Err(NameValidationError::EmptyIndex);
            }
            if Self::has_leading_zero(s) {
                return Err(NameValidationError::LeadingZero);
            }
            if !Self::contains_only_ascii_digits(s) {
                return Err(NameValidationError::NonAsciiDigit);
            }
        }

        let i1 = idx1_str.parse::<usize>().map_err(NameValidationError::ParseError)?;
        let i2 = idx2_str.parse::<usize>().map_err(NameValidationError::ParseError)?;
        let i3 = idx3_str.parse::<usize>().map_err(NameValidationError::ParseError)?;
        Ok((i1, i2, i3))
    }

    pub fn is_valid_prefix(prefix: &str) -> bool {
        // Allow empty prefix (as tests use "")
        if prefix.is_empty() {
            return true;
        }
        // Accept alnum, underscore, hyphen, dot; reject whitespace/control
        prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    }

    pub fn contains_only_ascii_digits(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
    }

    pub fn has_leading_zero(s: &str) -> bool {
        s.len() > 1 && s.starts_with('0')
    }
}

pub fn cross_validate_indexed_name(
    prefix: &str,
    index: usize,
    generated: &str,
    extractor: impl Fn(&str, &str) -> Result<usize, BitVMXError>
) -> Result<(), String> {
    let oracle_result = NameValidator::validate_format(generated, prefix)?;
    if oracle_result != index {
        return Err(format!("Oracle validation failed: expected {}, got {}", index, oracle_result));
    }

    let extracted = extractor(generated, prefix)
        .map_err(|e| format!("Extractor failed: {:?}", e))?;

    if extracted != index {
        return Err(format!("Extractor mismatch: expected {}, got {}", index, extracted));
    }

    Ok(())
}
