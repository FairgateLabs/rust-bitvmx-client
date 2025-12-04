# Union Protocol Tests

Unit tests for protocol ID generation functions in the union protocol implementation.

## Overview

These tests validate union protocol functionality:

### Common Utilities Tests
Deterministic ID generation for various union protocol components:
- Dispute Core protocols
- Accept Peg-in protocols  
- User Take protocols
- Aggregated key protocols (take & dispute)
- Pairwise aggregated keys
- Dispute channels

### Indexed Names Tests
Name formatting and parsing helpers:
- Single, double, and triple indexed name generation
- Index extraction and validation
- Error handling for invalid formats
- Edge cases and boundary conditions

## Running Tests

From this directory:
```bash
./run_union_tests.sh
```

From the workspace root:
```bash
cargo test --lib program::protocols::union::tests::common_utilities
```

Run specific test module:
```bash
cargo test --lib program::protocols::union::tests::common_utilities::dispute_core
```

## Test Structure

### common_utilities.rs (37 tests)
Protocol ID generation tests organized by type:
- `dispute_core` - Core dispute protocol ID tests
- `accept_pegin` - Accept peg-in protocol ID tests
- `user_take` - User take protocol ID tests
- `aggregated_keys` - Aggregated key protocol tests
- `pairwise_keys` - Pairwise key protocol tests (symmetric)
- `dispute_channels` - Dispute channel protocol tests (directional)
- `full_penalization` - Full penalization protocol ID tests
- `cross_function_properties` - Cross-cutting validation tests

### indexed_names.rs (57 tests)
Comprehensive name helper function tests:
- `single_index_names` - Basic single-index formatting and validation
- `double_index_names` - Pairwise indexing for operator/watchtower pairs
- `triple_index_names` - Three-dimensional indexing for complex scenarios
- `index_extraction` - Parsing and roundtrip consistency validation
- `double_index_extraction` - Double index parsing and validation
- `error_handling` - Robust error detection for invalid inputs
- `boundary_conditions` - Edge cases with extreme values
- `special_prefix_cases` - Complex prefix patterns and special characters
- `real_world_scenarios` - Practical use cases and protocol patterns
- `naming_collision_prevention` - Uniqueness guarantees across all combinations

## Key Properties Tested

1. **Determinism**: Same inputs always produce same output
2. **Collision resistance**: Different inputs produce different outputs
3. **Symmetry**: Pairwise keys are order-insensitive
4. **Directionality**: Channel IDs respect ordering
5. **Boundary handling**: Edge cases handled correctly

## Documentation

For detailed explanations of what each test module validates, see [TEST_GUIDE.md](./TEST_GUIDE.md).

## Folder Structure

```
tests/
├── README.md                  # This file
├── TEST_GUIDE.md              # Detailed explanation of each test
├── run_union_tests.sh         # Test runner script
├── common_utilities.rs        # Protocol ID tests (37 tests)
├── indexed_names.rs           # Name helper tests (57 tests)
└── mod.rs                     # Module declaration
```

This folder is self-contained and portable.

