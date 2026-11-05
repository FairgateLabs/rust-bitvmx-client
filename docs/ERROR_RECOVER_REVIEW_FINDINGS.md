# Analysis of the `review/error-recover-findings` branch

**Status: all three findings are now fixed on `error_recover`, covered by `tests/poison_messages.rs`.** The rest of this document describes the code as it was at `a24cd7f`.

Compares `origin/review/error-recover-findings` (`af48ec1`, 2026-10-21) with `error_recover` (`a24cd7f`, 2026-11-04).

## Conclusion

**All three findings are valid and still reproduce on `error_recover`.** None were fixed by the 67 commits made since the review branch forked at `3659d14`.

All three have the same root cause. A deterministic, non-retryable failure comes out of a handler as `Err`. The transaction rolls back, the message returns to the head of its queue, and the next tick takes the same message again. The error is classified as `Severity::Other`, so the node keeps running but that inbox no longer moves.

| Finding | Trigger | Inbox blocked | Clears by itself? | Verdict |
|---|---|---|---|---|
| 2: invalid variable key | API caller sends a key containing `/`, or an empty key | Broker inbox: API requests and dispatcher results | No | Valid, and wider than reported |
| 3: PKCS#1 verification key | A program participant announces its key as PKCS#1, then sends a setup message | Comms inbox: every program on the node | Yes, at that program's setup timeout (default 1h), but the bad key stays stored | Valid, but "every round" overstates its duration |
| 4: conflicting ZKP timeout | API caller reuses a job id with a different timeout | Broker inbox: API requests and dispatcher results | No | Valid |

The branch numbers its findings 2, 3 and 4. It contains no finding 1.

## What the review branch contains

The branch adds no fixes. It adds one file, `src/review_findings.rs`, with one failing test per finding and a passing control test beside each. The tests run the real inbox loop, so the rollback and retry do happen. Finding 3 uses a real second comms node.

`docs/BITVMX_API_ERROR_HANDLING.md` supports the expected behaviour: request errors must become terminal responses, and `Err` should mean that retrying may succeed or that the node must stop.

## How this was checked

The review's test bodies were copied unchanged into a temporary worktree at `a24cd7f`, under `src/bitvmx/`, because `bitvmx.rs` has since been split up. Only the `mod` declaration was added. The worktree has been removed, and nothing in this branch changed except this document.

| Test | Result on `a24cd7f` |
|---|---|
| `set_var_with_valid_key_does_not_block_the_inbox` (control) | pass |
| `set_var_with_invalid_key_is_an_api_error` (finding 2) | **fail**: Ping unanswered after 5 ticks |
| `generate_zkp_repeated_with_same_timeout_does_not_block_the_inbox` (control) | pass |
| `generate_zkp_with_conflicting_timeout_is_an_api_error` (finding 4) | **fail**: Ping unanswered after 5 ticks |
| `bad_signature_from_real_peer_with_spki_key_fails_the_setup` (control) | pass |
| `bad_signature_from_real_peer_with_pkcs1_key_fails_the_setup` (finding 3) | **fail**: 30 non-fatal errors in 30 rounds, no `SetupFailed` |

Temporary probe tests covered the scope questions below. They are marked **tested** where they apply; claims marked **by reading** come from the code only.

The build used the sibling checkouts selected by the workspace `.cargo/config.toml`, not the pinned tags. `RSAKeyPair::verify` is the same in the sibling checkout and in tag `v0.8.7`.

## The shared failure path

1. `process_inputs` runs each input in its own transaction and stops at the first `Err` (`src/bitvmx/steps.rs:93`).
2. `run_transaction` rolls back, which restores the received message (`src/bitvmx/steps.rs:205`).
3. `classify` returns `Severity::Other` for these errors, so `finish_step` reports a non-fatal error and continues (`src/bitvmx/steps.rs:183`).
4. A failed step counts as work (`src/bitvmx/steps.rs:72`), so the throttle stays on its busy interval. L2 gets one report for each cycle: 30 reports in 30 rounds in the finding 3 test.

The docs already describe this risk in general (`docs/BITVMX_API_ERROR_HANDLING.md:162`). These findings are concrete cases of it.

## Finding 2: invalid variable or witness key

**Valid.** `StorageKey::new` rejects segments that are empty or contain `/`, and the key comes straight from the request. `var_key` returns `StorageError::InvalidKey` (`src/program/variables/mod.rs:17`), and the `SetVar` arm passes it on with `?` (`src/bitvmx/api.rs:959`). `InvalidKey` is not in the fatal list (`src/error_handling.rs:112`).

**Wider than the review's test shows:**

- **Tested:** `SetVar` with an empty key, `GetVar` with `a/b` and `GetWitness` with `a/b` all block the inbox.
- **By reading:** `SetWitness` has the same shape (`src/bitvmx/api.rs:964`).

**Impact:**

- The blocked queue is also the one that carries dispatcher results (`src/bitvmx/job_handler.rs:337`). One bad request therefore stalls job results and every later API call, including `Shutdown` and `DiscardDispatcherJob`.
- By reading, no timeout applies and the message is durable, so a restart should not clear it. A restart was not tested.
- The trigger is a client on the broker channel rather than a remote peer, so this is most likely to come from a client bug.

**Documentation conflict:** `docs/BITVMX_API_ERROR_HANDLING.md:306` says `SetVar` and `SetWitness` have no request-level failure after decoding. This finding shows that is wrong, so the section needs correcting along with the fix.

## Finding 4: conflicting ZKP timeout

**Valid.** `register_with_dispatch` compares dispatcher, target and timeout with the existing job, and returns `InvalidState` on a mismatch (`src/expected_job.rs:178-188`). `GenerateZKP` passes that on with `?` (`src/bitvmx/api.rs:1075`).

**Impact:** the same as finding 2. By reading, the check ignores the job's status, so the conflict also applies after the original job has finished.

**The trigger is narrow:** omitting the timeout resolves to `DEFAULT_JOB_TIMEOUT`, so `None` and an explicit 900 seconds do not conflict. A client retrying with a longer timeout is a plausible way to hit this.

**Related gap, not in the review:** input and ELF path are not compared. By reading, reusing a job id with a different input is accepted as an idempotent no-op with no reply, and the caller later receives the proof for the original input. This deserves a separate decision.

## Finding 3: PKCS#1 verification key

**Valid.** The two sides of the key check accept different formats:

- The announcement check accepts SPKI or PKCS#1 (`src/helper.rs:13`), and both give the same fingerprint, so the key is stored as sent (`src/signature_verifier.rs:318`).
- `RSAKeyPair::verify` parses SPKI only, so a stored PKCS#1 key fails. `authenticate_message` passes that failure on with `?` instead of rejecting the message (`src/signature_verifier.rs:216-220`).

**Tested on the review's claim:**

- A message queued behind the blocked one was not processed.
- With an 8s setup timeout, the program failed at the timeout and no further non-fatal errors followed. The block therefore lasts until the setup timeout, not forever, because the lifecycle check runs before authentication (`src/bitvmx/peer_messages.rs:230`).
- The PKCS#1 key was still stored afterwards. Stored keys are global rather than per-program, so by reading the same peer can repeat this in its next setup.

**By reading:**

- The signature's content does not matter, because the key is parsed before the signature is checked. A correctly signed message blocks the inbox too.
- The leader-broadcast path has the same problem (`src/leader_broadcast.rs:448`, `src/leader_broadcast.rs:569`).
- Other programs' setups stall during the block and could reach their own timeouts. This inference was not run.

**Who can trigger it:** only an authenticated participant in a program, and only during setup. Honest nodes export SPKI, so this needs a deliberately or unusually behaving peer. It is still a denial of service: one participant can stall comms for the whole node for up to the setup timeout, repeatedly.

## Proposed fixes

`origin/review/error-recover-fixes` has one commit per finding (`f7ee18f`, `2899431`, `b9bac5b`). They target the old layout (`src/bitvmx_api.rs` no longer exists), so they need porting rather than cherry-picking.

An equivalent port was tried in the temporary worktree. All three failing review tests passed. The full unit suite then gave 345 passed and 2 failed:

- One failure was a temporary probe asserting the key stays PKCS#1, which the fix correctly changes.
- The other is a **real issue with the proposed fix**: `handle_verification_messages_stores_valid_announcement` fails on Windows. The fix re-encodes keys with `LineEnding::LF`, while `export_public_pem` uses the platform default (CRLF on Windows), and the test compares the strings. Using the same line ending, or comparing parsed keys, should resolve it; Linux was not run.

| Finding | Assessment of the proposed fix | Recommendation |
|---|---|---|
| 2 | `answer_invalid_key` converts only `InvalidKey` to `ApiError`, across all four arms. Other storage errors still propagate. | Port as is, and correct the doc section above. |
| 4 | A typed `DispatcherJobConflict` is handled only in the `GenerateZKP` arm, so internal job registrations still propagate. | Port as is. |
| 3 | Re-encoding to SPKI at announcement closes both the direct and broadcast paths, but does not repair PKCS#1 keys already stored. | Port with the line-ending fix, and also treat a peer key that fails to parse in `authenticate_message` as `rejected()`. That second change is untested and covers stored keys. Keep `Err` when the node's own key fails, since that is a local fault and not the peer's. |

The review tests now live in `tests/poison_messages.rs`, with added cases for the `GetVar`, `GetWitness` and `SetWitness` arms. All recommendations above were applied, using the platform-default line ending for finding 3.

## What this does not settle

- These fixes remove three known cases, not the underlying risk: any other permanent `Err` can still block an inbox indefinitely. `docs/BITVMX_API_ERROR_HANDLING.md:162-197` lists other candidates, and there is still no retry limit or API dead-letter path.
- The tests run 5 to 30 rounds, so "permanent" for findings 2 and 4 rests on the code path, not on a long run or a restart.
