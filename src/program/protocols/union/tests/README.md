# Union Protocol Tests

Comprehensive unit tests for the union protocol implementation covering protocol ID generation, name formatting, fee estimation, and output construction.

## Project Structure

```
tests/
├── helpers/                      # Shared test utilities
│   ├── test_helpers.rs              - Core functions (test_pubkey, test_committee)
│   ├── test_generators.rs           - Test data generators
│   ├── test_enums.rs                - Type-safe test data enums
│   └── test_assertions.rs           - Reusable assertion helpers
├── unit/                         # Unit tests by functionality
│   ├── common_utilities.rs          - Protocol ID tests (51 tests)
│   ├── indexed_names.rs             - Name formatting tests (64 tests)
│   ├── fee_estimation.rs            - Fee calculation tests (18 tests)
│   └── output_builders.rs           - Output construction tests (13 tests)
├── scripts/                      # Test automation
│   └── run_union_tests.sh           - Test runner with formatted output
└── Documentation
    ├── README.md                    - This file
    └── TEST_GUIDE.md                - Detailed test explanations
```

**Total: 142 tests, all passing ✅**

---

## Quick Start

### Run All Tests (Formatted Output)
```bash
./scripts/run_union_tests.sh
```

### Run All Tests (Standard Output)
```bash
cargo test --lib program::protocols::union::tests
```

### Run Specific Test Suite
```bash
# Common utilities (protocol ID generation)
cargo test --lib program::protocols::union::tests::unit::common_utilities

# Indexed names (name formatting)
cargo test --lib program::protocols::union::tests::unit::indexed_names

# Fee estimation
cargo test --lib program::protocols::union::tests::unit::fee_estimation

# Output builders
cargo test --lib program::protocols::union::tests::unit::output_builders
```

### Run Specific Test
```bash
cargo test --lib program::protocols::union::tests::unit::common_utilities::dispute_core::same_inputs_yield_same_id
```

---

## Test Suites Overview

### 1. Common Utilities
**Location:** `unit/common_utilities.rs`

Validates protocol ID generation functions that create unique, deterministic identifiers for various protocol types. Each protocol type has dedicated tests ensuring proper behavior across different inputs and edge cases.

**Covered protocols:**
- Dispute Core protocols
- Accept Peg-in protocols  
- User Take protocols
- Aggregated key protocols (take & dispute)
- Pairwise aggregated keys (with symmetry)
- Dispute channels (directional)
- Full penalization protocols

**Key validations:**
- Determinism: identical inputs produce identical IDs
- Uniqueness: different inputs produce different IDs
- Committee namespace isolation
- No cross-protocol collisions

### 2. Indexed Names
**Location:** `unit/indexed_names.rs`

Validates name formatting and parsing for transaction identifiers with support for single, double, and triple indices.

**Formats:**
- Single: `"transaction_5"`
- Double: `"channel_3_7"`
- Triple: `"challenge_1_2_3"`

**Coverage:**
- Basic formatting and extraction
- Roundtrip consistency (format → parse → format)
- Error handling for malformed inputs
- Boundary values (0, usize::MAX)
- Unicode digit rejection
- Whitespace rejection
- Collision prevention
- Real-world usage scenarios

### 3. Fee Estimation (18 tests)
**Location:** `unit/fee_estimation.rs`

Validates transaction fee calculation logic:
- ✅ Monotonicity (more inputs/outputs → higher fee)
- ✅ Formula correctness
- ✅ Fee rate scaling
- ✅ Determinism
- ✅ Edge cases (zero rate, overflow)

**Formula:** `(base_weight + inputs×input_weight + outputs×output_weight) × fee_rate`

### 4. Output Builders (13 tests)
**Location:** `unit/output_builders.rs`

Validates Bitcoin output construction:
- ✅ P2WPKH (Operator payments)
- ✅ Taproot (Initial deposits)
- ✅ Amount preservation
- ✅ Script correctness
- ✅ Determinism
- ✅ Key sensitivity

**Output types:**
- SegWit P2WPKH for standard payments
- Taproot for deposits (keypath + scriptpath)

---

## Test Helpers

### Core Helpers (`helpers/test_helpers.rs`)
```rust
test_pubkey(seed)           // Generate deterministic public keys
test_committee(label)       // Generate deterministic committee UUIDs
test_key(name, index)       // Format key identifiers
dust_amount(multiplier)     // Calculate dust-based amounts
```

### Data Generators (`helpers/test_generators.rs`)
```rust
generate_test_slots()           // Test slot indices
generate_boundary_indices()     // Edge values (0, 1, MAX)
generate_test_amounts()         // Bitcoin amounts
generate_fee_rates()            // Fee rate samples
generate_io_counts()            // Input/output combinations
// ... and 15+ more
```

### Type-Safe Enums (`helpers/test_enums.rs`)
```rust
TestPrefix::Transaction.as_str()    // "transaction"
InvalidPattern::Negative.as_str()   // "prefix_-5"
```

### Assertion Helpers (`helpers/test_assertions.rs`)
```rust
assert_valid_indexed_name()     // Validate format
assert_extraction_error()       // Verify error messages
assert_all_unique()             // Check uniqueness
assert_roundtrip_index()        // Encode/decode consistency
```

---

## Design Principles

1. **Parametrizable:** Tests use generators, not hardcoded data
2. **Deterministic:** Same inputs always produce same outputs
3. **Domain-Driven:** Only Bitcoin protocol constants (no magic numbers)
4. **Self-Documenting:** Clear test and variable names
5. **Organized:** Helpers separated from tests

---

## Documentation

- **TEST_GUIDE.md** - Detailed explanations of what each test validates and why
---

## Development

### Adding New Tests

1. Choose appropriate test file in `unit/`
2. Import helpers: `use super::super::helpers::*;`
3. Use generators for test data
4. Name tests descriptively
5. Add assertions with clear messages

### Adding New Helpers

1. **Core utilities** → `helpers/test_helpers.rs`
2. **Data generators** → `helpers/test_generators.rs`
3. **Test enums** → `helpers/test_enums.rs`
4. **Assertions** → `helpers/test_assertions.rs`

### Running Tests During Development
```bash
# Run specific module
cargo test --lib program::protocols::union::tests::unit::common_utilities

# Run with verbose output
cargo test --lib program::protocols::union::tests -- --nocapture
```

---

## Key Properties Tested

1. **Determinism**: identical inputs always produce identical outputs
2. **Collision resistance**: different inputs produce different outputs
3. **Symmetry**: pairwise keys are order-insensitive
4. **Directionality**: channel IDs respect ordering
5. **Boundary handling**: edge cases (0, MAX) handled correctly
6. **Error detection**: invalid inputs properly rejected
7. **Unicode safety**: non-ASCII digits rejected in parsing

---

## Contributing

When adding tests, ensure they follow these principles:
- Use generators instead of hardcoded values
- Test one behavior per test function
- Use descriptive test names
- Add edge cases for boundary conditions
- Verify both positive and negative cases

This folder is self-contained and portable.

