# Test Guide - Union Protocol

This guide explains what each test suite validates and why it matters for the union protocol implementation.

---

## Common Utilities Tests

These tests validate the helper functions that generate unique protocol IDs and manage protocol state. Every protocol in the system needs a unique identifier to track its transactions and participants.

### Dispute Core Protocol IDs

These tests verify that dispute protocols get stable, unique identifiers based on their committee and participant.

**What they check:**
- Same committee + same participant → always generates the same ID
- Different committees → different IDs (even with same participant)
- Different participants in same committee → different IDs
- Multiple key types (operators, watchtowers, verifiers) → all get unique IDs
- Calling the function multiple times → returns consistent results

**Why it matters:** Dispute protocols need deterministic IDs so all parties can independently derive the same identifier and track the protocol state correctly.

### Accept Peg-In Protocol IDs

Tests for generating IDs when users deposit funds from another chain.

**What they check:**
- Same slot → same ID every time
- Different slots → different IDs
- Edge cases: slot 0 and maximum slot value work correctly
- Same slot on different committees → different IDs

**Why it matters:** Each peg-in needs a unique identifier that's consistent across all committee members so they can coordinate the acceptance process.

### User Take Protocol IDs

Tests for generating IDs when users withdraw their funds.

**What they check:**
- Repeated calls with same parameters → consistent ID
- User take vs accept peg-in → different IDs (even for same slot/committee)
- Each slot → unique ID
- Same slot across committees → different IDs per committee

**Why it matters:** User withdrawals must be distinguishable from deposits and tracked separately for each committee and slot.

### Aggregated Keys Protocol IDs

Tests for IDs used in multi-signature aggregated key protocols.

**What they check:**
- Take key ID generation → stable and deterministic
- Dispute key ID generation → stable and deterministic
- Take keys vs dispute keys → always different
- Different committees → different key IDs

**Why it matters:** The system uses aggregated keys for both normal operations ("take") and disputes. These need separate identifiers to avoid confusion.

### Pairwise Keys Protocol IDs

Tests for IDs representing relationships between two participants.

**What they check:**
- Order doesn't matter: pair(A, B) == pair(B, A)
- Different pairs → different IDs
- Self-pairs (A, A) → valid and stable
- Extreme index values → handled correctly
- Internal normalization logic → works correctly across many combinations

**Why it matters:** Pairwise relationships (like operator-watchtower pairs) need symmetric IDs so both parties derive the same identifier regardless of who initiates.

### Dispute Channels Protocol IDs

Tests for directional communication channels between parties in disputes.

**What they check:**
- Direction matters: channel(A→B) ≠ channel(B→A)
- Same direction → same ID consistently
- All combinations → unique IDs
- Forward vs reverse → different IDs
- Committee isolation → maintained

**Why it matters:** Dispute channels are directional (challenges flow from one party to another), so A→B must differ from B→A to track dispute flow correctly.

### Full Penalization Protocol IDs

Tests for IDs used when fully penalizing a misbehaving party.

**What they check:**
- Same committee → same ID consistently
- Different committees → different IDs
- Doesn't collide with other protocol types

**Why it matters:** Full penalization is a distinct protocol that needs its own identifier space to avoid confusion with partial penalties or disputes.

### Cross-Function Properties

Integration tests that verify the entire ID generation system works together.

**What they check:**
- No collisions across different protocol types
- Multiple committees stay completely isolated
- Slot-based protocols maintain uniqueness across all slots
- Mixed usage scenarios work correctly
- Same public key across committees/protocols → properly separated

**Why it matters:** The real system uses all these ID types together. These tests ensure there are no unexpected collisions or conflicts when everything runs simultaneously.

---

## Indexed Names Tests

These tests validate the helper functions that create and parse transaction names with indices. The protocol uses indexed names like `"transaction_5"` or `"channel_3_7"` to identify specific instances of transactions.

### Single Index Names

Basic name generation with one index, like `"transaction_5"`.

**What they test:**
- Correct format: prefix + underscore + number
- Prefixes stay unchanged (including case)
- Index 0 works without off-by-one errors
- Sequential indices all work
- Prefixes with underscores don't break anything

**Example:** `indexed_name("slot", 42)` → `"slot_42"`

### Double Index Names

Names with two indices for representing pairs, like `"channel_3_7"`.

**What they test:**
- Correct format: prefix_index1_index2
- Different pairs get different names
- Same index twice (like 5_5) is valid
- Works across large index ranges

**Example:** `double_indexed_name("pair", 0, 1)` → `"pair_0_1"`

### Triple Index Names

Names with three indices for complex scenarios, like `"challenge_1_2_3"`.

**What they test:**
- Correct format with three indices
- Order matters (1_2_3 ≠ 1_3_2)
- All zeros works correctly

**Example:** `triple_indexed_name("coord", 1, 2, 3)` → `"coord_1_2_3"`

### Index Extraction

Parsing names back into their components.

**What they test:**
- Can extract index from generated name
- Roundtrip works: generate → extract → matches original
- Handles index 0 correctly
- Works with multi-digit numbers
- Works when prefix has underscores

**Example:** `extract_index("slot_42", "slot")` → `42`

### Double Index Extraction

Parsing names with two indices.

**What they test:**
- Extracts both indices correctly
- Roundtrip works for pairs
- Rejects single-index names (error handling)
- Rejects malformed input
- Works with complex prefixes

**Example:** `extract_double_index("pair_3_7")` → `(3, 7)`

### Error Handling

Tests that bad inputs are properly rejected.

**What gets rejected:**
- Wrong prefix: `extract_index("wrong_5", "expected")` → error
- Non-numeric: `"transaction_abc"` → error
- Missing underscore: `"transaction5"` → error
- Empty index: `"transaction_"` → error
- Negative numbers: `"tx_-5"` → error
- Decimals: `"item_3.14"` → error
- Hex notation: `"tx_0x10"` → error
- Whitespace: `"tx_ 5"` → error

**Why it matters:** The system needs to fail fast on invalid names instead of silently producing wrong results.

### Boundary Conditions

Tests with extreme values to catch edge cases.

**What they test:**
- Maximum possible index (`usize::MAX`)
- Near-maximum values
- Powers of 2 (1, 2, 4, 8, ..., 1024)
- Powers of 10 (1, 10, 100, 1000, ...)
- Double indices with extreme values (0 and MAX)
- Triple indices with mixed magnitudes

**Why it matters:** The system must handle the full range of possible indices without overflows or errors.

### Special Prefix Cases

Tests with unusual but valid prefixes.

**What they handle:**
- Prefixes starting with numbers: `"123prefix"`
- Hyphens: `"tx-name"`
- Dots: `"protocol.v1"`
- Multiple underscores: `"my__name"`
- Mixed case: `"CamelCase"`, `"UPPERCASE"`

**Why it matters:** Real transaction names might use various naming conventions, and the system should handle them all.

### Real World Scenarios

Tests that simulate actual protocol usage patterns.

**Scenarios tested:**
- All operator-watchtower pairs in a network
- Committee slots for a full committee
- Challenge rounds with steps
- Transaction versioning (like semantic versioning)
- Sequential block references
- All possible dispute channels between participants

**Why it matters:** These tests verify the naming system works correctly in realistic, complex scenarios that will actually happen in production.

### Naming Collision Prevention

Tests that ensure names never accidentally collide.

**What they verify:**
- 100 consecutive indices → all unique
- 10×10 grid of double indices → all unique
- Single-indexed vs double-indexed → always different
- Double-indexed vs triple-indexed → always different

**Why it matters:** Name collisions would cause the system to confuse different transactions, leading to serious bugs. These tests provide strong guarantees that collisions won't happen.

---

## Summary

**Common Utilities (37 tests)** - Validates protocol ID generation
- Ensures every protocol gets a unique, deterministic identifier
- Tests all protocol types: disputes, peg-ins, withdrawals, keys, channels, penalties
- Verifies committee isolation and cross-protocol uniqueness

**Indexed Names (57 tests)** - Validates transaction naming
- Tests name generation with 1, 2, or 3 indices
- Tests parsing names back into indices
- Comprehensive error handling for invalid inputs
- Collision prevention across all name types

**Total: 94 tests covering the core helper functions used throughout the union protocol.**

These are unit tests for the foundation layer. Higher-level protocol tests (Accept Peg-in, User Take, Dispute Core, etc.) will be added in future test suites.

