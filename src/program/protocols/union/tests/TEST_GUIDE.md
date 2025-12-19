# Test Guide - Union Protocol

This guide explains what we're actually testing and why it matters. If you're reviewing these tests or adding new ones, this doc will help you understand the reasoning behind design decisions.

**TL;DR:** These tests caught real bugs during development. They're not just checking "does it work?" but "does it work correctly in edge cases that will bite us in production?"

## Structure

```
tests/
├── helpers/
│   ├── test_helpers.rs      - Core utilities (pubkey, committee, amounts)
│   ├── test_generators.rs   - Test data generators
│   ├── test_validators.rs   - Independent validators
│   ├── test_enums.rs        - Test constants
│   └── test_assertions.rs   - Custom assertions
├── unit/
│   ├── common_utilities.rs  - Protocol ID generation
│   ├── indexed_names.rs     - Name formatting & parsing
│   ├── fee_estimation.rs    - Fee calculation
│   └── output_builders.rs   - Output construction
├── scripts/
│   └── run_union_tests.sh   - Test runner
└── Documentation
    ├── README.md            - Quick start
    └── TEST_GUIDE.md        - This file
```

## Design Principles

**Why these tests exist:**
- Caught real bugs during development (Unicode parsing, overflow, ID collisions)
- Prevent regressions when refactoring
- Document expected behavior better than comments

**Key patterns we use:**
- **Generator functions over hardcoded arrays:** Makes it easier to add edge cases when bugs appear
- **Oracle pattern:** Independent validators catch bugs in both production code and tests
- **Bitcoin protocol constants:** Real values (dust threshold, max supply) not made-up test numbers
- **Security focus:** Unicode homograph attacks, overflow, collision resistance
- **Speed matters:** Few representative cases > exhaustive coverage (tests run in <30s)

**Running tests:** See [README.md](./README.md)

---

## Common Utilities (Protocol ID Generation)

**The problem:** Every protocol instance (dispute, peg-in, withdrawal) needs a unique ID that all parties can independently calculate. If Alice and Bob calculate different IDs for the same protocol, they can't coordinate. If two different protocols get the same ID, their state gets mixed up.

**What we test:**
- **Determinism:** Call the function twice with same inputs → get same ID
- **Uniqueness:** Different inputs (committee, slot, keys) → different IDs
- **No collisions:** Dispute IDs never collide with peg-in IDs, even with same inputs

### Dispute Core IDs

IDs for the main dispute protocol between operators/watchtowers.

**Key properties tested:**
- Committee changes → ID changes (federation "alpha" ≠ "beta")
- Participant key changes → ID changes (operator_1 ≠ operator_2)
- Same inputs called multiple times → same ID every time
- Unicode committee labels work correctly (important for internationalization)

**Why this matters:** If two operators calculate different IDs for the same dispute, they'll be looking at different on-chain protocols and fail to coordinate.

### Peg-In IDs

IDs for deposits coming from other chains (like Ethereum → Bitcoin).

**Key properties:**
- Each slot gets a unique ID (slot 0 ≠ slot 1)
- Same slot always generates same ID (deterministic)
- Different committees get different IDs (mainnet ≠ testnet)
- Edge cases work: slot 0, slot MAX, consecutive slots (0..200)

**Real scenario:** User deposits 1 BTC in slot 42. All committee members need to independently compute the same ID for slot 42 to track this deposit. If one member gets a different ID, they won't see the deposit.

### Take IDs (User Withdrawals)

IDs for users withdrawing funds back to other chains.

**Critical distinction:** A take in slot 5 MUST have a different ID than a peg-in in slot 5, even with the same committee. Otherwise we'd confuse deposits with withdrawals.

**Tests verify:**
- Takes and peg-ins in same slot have different IDs (collision prevention)
- Different slots → different take IDs
- 100 consecutive slots all get unique IDs (no accidental patterns)

### Aggregated Key IDs

IDs for multi-signature protocols.

**Tests:**
- Take key stability
- Dispute key stability
- Take vs dispute distinction
- Committee separation

**Why:** Normal operations and disputes need separate ID spaces.

### Pairwise Key IDs

IDs for protocols between two specific operators (used in multi-signature schemes).

**Symmetry is critical:** pair(operator_3, operator_7) MUST equal pair(operator_7, operator_3) because it doesn't matter who initiates the protocol. If these produced different IDs, operators 3 and 7 would be trying to use different on-chain protocols and fail.

**Tests cover:**
- Order independence: (A,B) == (B,A) for all combinations
- Self-pairs work: (5,5) is valid and distinct from (5,6)
- Edge cases: (0,0), (MAX, MAX), (0, MAX)
- Large numbers of pairs are all unique (no accidental collisions)

### Dispute Channel IDs

Directional communication for challenges (operator A challenges operator B).

**Asymmetry is required:** channel(A→B) MUST be different from channel(B→A) because:
- A challenging B is a different protocol than B challenging A
- They need separate on-chain state
- If they had the same ID, challenges would get confused

**Real scenario:** Operator 3 catches operator 7 cheating and opens a challenge. This uses channel(3→7). If operator 7 later challenges operator 3, that's a completely separate dispute using channel(7→3).

**Tests verify:** All (i,j) pairs where i≠j get unique IDs, and (i,j) ≠ (j,i).

### Penalization IDs

IDs for full penalization protocols.

**Tests:**
- Committee consistency
- Committee isolation
- No collisions with other protocols

**Why:** Separate ID space prevents confusion with disputes.

### Integration

System-wide validation.

**Tests:**
- No cross-protocol collisions
- Committee isolation maintained
- Slot uniqueness preserved
- Mixed scenarios work
- Proper separation across all dimensions

**Why:** All ID types must coexist without conflicts.

---

## Indexed Names (Transaction Name Formatting)

**The problem:** Bitcoin transactions need human-readable names that encode indices. We use formats like `"transaction_5"`, `"pair_3_7"`, etc. These names must be:
- Parseable back to the original index (roundtrip)
- Unique (no collisions)
- Secure (reject Unicode tricks)

**Why security matters:** An attacker could try `"tx_①"` (circled digit 1) instead of `"tx_1"`. If we parse this incorrectly, they could confuse the system about which transaction is which.

### Single Index Names

Format: `"prefix_42"`

**What we test:**
- Roundtrip: `indexed_name("tx", 5)` → `"tx_5"` → `extract_index()` → `5`
- Zero works: `"tx_0"` is valid
- Large numbers work: `"tx_18446744073709551615"` (usize::MAX on 64-bit)
- Case preserved: `"MixedCase_5"` keeps the case
- Empty prefix works: `"_5"` is technically valid

### Double Index

Pair names like `"channel_3_7"`.

**Tests:** Format, uniqueness, self-pairs (5,5), large ranges

**Example:** `double_indexed_name("pair", 0, 1)` → `"pair_0_1"`

### Triple Index

Complex names like `"challenge_1_2_3"`.

**Tests:** Format, order sensitivity, zero handling

**Example:** `triple_indexed_name("coord", 1, 2, 3)` → `"coord_1_2_3"`

### Extraction

Parse names back to indices.

**Tests:** Extraction, roundtrips, zero, multi-digit, complex prefixes

**Example:** `extract_index("slot_42", "slot")` → `42`

### Double Extraction

Parse pair indices.

**Tests:** Both indices, roundtrips, rejects singles, malformed input, complex prefixes

**Example:** `extract_double_index("pair_3_7")` → `(3, 7)`

### Error Handling (Security-Critical)

**Philosophy:** Reject early and loudly. Better to fail a test than silently parse garbage.

**What we reject and why:**

| Input | Why it's dangerous |
|-------|-------------------|
| `"prefix_①"` | Unicode circled digit (homograph attack) |
| `"prefix_\u{0660}"` | Arabic-Indic digit (looks like 0 to humans) |
| `"prefix_01"` | Leading zero (could be interpreted as octal) |
| `"prefix_5.5"` | Decimal point (not an integer) |
| `"prefix_0x10"` | Hex notation (ambiguous) |
| `"prefix_-5"` | Negative (indices are unsigned) |
| `"prefix_"` | Empty index (ambiguous) |
| `"prefix_ 5"` | Whitespace (invisible to users) |

**Real attack vector:** Rust's `char::is_numeric()` returns true for Unicode digits, but `str::parse::<usize>()` rejects them. If we used the wrong check, we'd accept `"tx_①"` as valid but fail to parse it later.

### Boundaries

Extreme value testing.

**Tests:** usize::MAX, near-max, powers of 2/10, mixed magnitudes

**Why:** Must handle full range without overflow.

### Special Prefixes

Unusual but valid prefixes.

**Tests:** Numeric start (`"123prefix"`), hyphens, dots, multiple underscores, mixed case

**Why:** Support various naming conventions.

### Real Scenarios

Production usage patterns.

**Tests:** Operator-watchtower pairs, committee slots, challenge rounds, versioning, block references, dispute channels

**Why:** Verify realistic complex scenarios.

### Collision Prevention

Uniqueness guarantees.

**Tests:** 100 consecutive unique, 10×10 grid unique, type separation (single/double/triple)

**Why:** Prevent transaction confusion.



---

## Fee Estimation

**Formula:** `fee = (BASE_WEIGHT + inputs×INPUT_WEIGHT + outputs×OUTPUT_WEIGHT) × rate`

**Real-world impact:**
- Too low → transaction stuck in mempool forever
- Too high → wasting user funds (overpaying miners)
- Wrong formula → all transactions broken

### What We Test

**Monotonicity (fees should increase predictably):**
- Adding an input increases the fee
- Adding an output increases the fee
- Increasing rate multiplies the fee proportionally
- Inputs cost more than outputs (INPUT_WEIGHT > OUTPUT_WEIGHT)

**Formula correctness:**
- Empty transaction (0 inputs, 0 outputs) costs exactly `BASE_WEIGHT × rate`
- Single input adds exactly `INPUT_WEIGHT × rate`
- Single output adds exactly `OUTPUT_WEIGHT × rate`
- We test this across multiple rate values to catch scaling bugs

**Edge cases:**
- Zero rate → zero fee (technically valid, though useless)
- Very high rates don't overflow
- Large transaction (1000+ inputs/outputs) calculates correctly
- Overflow with extreme values panics safely (we verify the panic happens)

**Determinism:**
- Call it twice → same result
- All operators must calculate identical fees for coordination

---

## Output Builders (Bitcoin Transaction Outputs)

**What we're building:** Bitcoin transaction outputs that either:
1. Pay operators (P2WPKH - standard SegWit)
2. Lock deposits in Taproot (with optional dispute paths)

**Why this is critical:** Get this wrong → funds locked forever or unspendable.

### Operator Outputs (P2WPKH)

Standard SegWit outputs for paying operators their share.

**What we validate:**
- Script is exactly `OP_0 <20-byte-pubkey-hash>` (P2WPKH format)
- Amount is encoded correctly
- Different keys → different scripts (no collisions)
- Same key+amount called twice → identical output (deterministic)
- Works with dust amounts (546 sats) and max supply (21M BTC)

**Deep validation:** We don't just check the output type, we verify the actual script bytes match what Bitcoin Core would generate.

### Taproot Deposits

Taproot outputs that lock user deposits. Can have dispute scripts for slashing.

**Two modes:**
1. **Keypath-only:** Just a public key (looks like a normal send, privacy-preserving)
2. **With scripts:** Includes timelock paths for disputes (visible when spent via script)

**Tests cover:**
- Keypath-only outputs work (empty script array)
- Adding scripts changes the output (script tree affects Taproot commitment)
- Different timelock values → different outputs
- Multiple scripts with different keys all work
- Deterministic: same inputs → same output

**JSON comparison workaround:** `OutputType` doesn't implement `PartialEq` (probably to avoid footguns with script comparison), so we serialize to JSON and compare strings. Not elegant, but reliable.

---

## Helper Architecture

### Core Utilities (`test_helpers.rs`)

**Deterministic fixtures:**
- `test_pubkey("alice")` → Always the same secp256k1 key for "alice"
- `test_committee("mainnet")` → Always the same UUID for "mainnet"
- Why deterministic? Tests must be reproducible across machines/runs

**Bitcoin constants:**
- `DUST_THRESHOLD = 546` (smallest economical output)
- `BASE_TX_WEIGHT = 46` (empty transaction overhead)
- `INPUT_WEIGHT = 68`, `OUTPUT_WEIGHT = 34` (P2WPKH weights)
- These are Bitcoin protocol specs, not arbitrary test values

### Generators (`test_generators.rs`)

**Design philosophy:** Generate cases algorithmically, don't hardcode arrays.

**Key generators:**
- `generate_test_slots()` → [0, 1, 10, 20, ..., 100] (edge cases + sampling)
- `generate_boundary_indices()` → [1, 10, 100, 1000, MAX-1, MAX]
- `generate_unicode_digit_tests()` → Unicode digits that must be rejected
- `generate_fee_test_cases()` → Combinations of (inputs, outputs, rate)

**Why generators?** When we find a new bug, we add one line to the generator instead of updating 20 hardcoded test arrays.

### Test Constants (`test_enums.rs`)

**Curated edge cases discovered through:**
- Real bugs found in development
- Security research on Unicode attacks
- Bitcoin protocol corner cases

Examples:
- `INVALID_PATTERNS`: `"prefix_01"` (leading zero), `"prefix_0x10"` (hex)
- `UNICODE_INVALID_PATTERNS`: `"prefix_①"` (circled digit), `"prefix_\u{0660}"` (Arabic)

### Custom Assertions (`test_assertions.rs`)

**Better error messages than bare `assert!`:**
- `assert_all_unique(ids, "Protocol IDs")` → "Protocol IDs: Found 3 duplicates in 50 items"
- `assert_roundtrip(prefix, idx, make_fn, parse_fn)` → Tests encode→decode is lossless

### Oracle Validators (`test_validators.rs`)

**The oracle pattern:** Independent implementation to verify production code.

`NameValidator` implements name parsing separately from production. If both agree → high confidence. If they disagree → at least one has a bug.

Why? Testing production code against itself can miss systematic errors (both encoder and decoder have same bug).

---

## Future Improvements

**High priority (when Cargo.toml becomes modifiable):**

1. **Property-based testing with `proptest`:**
   - Current: We test ~20 Unicode digits manually
   - With proptest: Test ALL Unicode digit ranges automatically
   - Would catch edge cases we haven't thought of
   - Blocked on: Can't modify Cargo.toml in current phase

2. **Fuzzing with `cargo-fuzz`:**
   - Feed random/malicious inputs to parsers
   - Has found real bugs in Bitcoin Core and other critical systems
   - Would stress test error handling paths

**Medium priority (nice to have):**

3. **Formal grammar for name format:**
   - Document the parsing rules in BNF or similar
   - Make it easier to implement parsers in other languages
   - Reference for security audits

4. **Performance benchmarks:**
   - ID generation happens frequently in protocol execution
   - Benchmark with criterion.rs to catch performance regressions
   - Identify optimization opportunities

5. **Coverage tracking:**
   - Use tarpaulin or similar to measure test coverage
   - Current estimate: ~90% coverage on tested modules
   - Find untested edge cases

**Low priority (probably overkill):**
- Mutation testing (extremely slow, questionable value)
- Snapshot testing for outputs (brittle, hard to maintain)

---

For quick start and running instructions, see [README.md](./README.md)
