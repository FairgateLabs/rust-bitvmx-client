# Agent instructions: repeated process-restart test

Run this with a requested number of rounds, e.g. **"Follow `docs/PROCESS_RESTART_LOOP_AGENT.md` for 20 rounds."** Default to 20 if no count is supplied. Your job is to run the test and report the **first anomaly**, not to investigate or fix it. Stop immediately on an anomaly; do not continue the loop. Keep tool output and context small.

## What is being tested

`tall_process.bat [all|one|random] [seed] [bitcoind_outage_interval_ms]` launches a **new, detached `cmd /k` window** running `cargo test --test independent --release -- --ignored test_all --test-threads 1` with `BITVMX_TEST_EXECUTION=process`, restart interval 5000 ms, downtime 500 ms, and the specified restart target and optional seed. Supplying the third argument also injects randomized bitcoind outages around that interval, with a 3000 ms outage duration and the second argument reused as the outage seed. For example, `tall_process.bat random 42 15000` pauses bitcoind at reproducible intervals between approximately 7500 and 22500 ms.

Bitcoind outages use Docker **pause/unpause**, not container removal. The local test container is auto-removed when stopped, so an actual stop/start would discard the regtest chain. Pause/unpause makes RPC unavailable while preserving the chain, wallet, mempool, and exact container state.

**Do not use the batch file for this loop:** its launcher returns before the test finishes and does not give you the test's exit code. Instead, run the *same test* in the foreground with the corresponding environment variables set, capturing the entire output in a per-round file. This ignored regtest integration test requires Docker/bitcoind and a built BitVMX-CPU emulator. Do not start another round while one is running; the test owns the `bitcoin-regtest` container and local operator state.

## Reusable runner (Git Bash on Windows)

Use the checked-in foreground runner instead of rebuilding the shell loop each time:

```bash
bash docs/run-process-restart-loop.sh --rounds 20
bash docs/run-process-restart-loop.sh --rounds 20 --outages
# Optional: --base-seed 300000 --outage-interval-ms 15000 --outage-downtime-ms 3000
```

The script sets the exact working directory, verifies CPU/Docker prerequisites, creates a unique session under `logs/process-restart/`, runs rounds serially with a **3600-second per-round timeout**, redirects both streams to separate logs, checks the single test result, updates `summary.md` after each round, and appends to `tasks.md` on the first anomaly. It clears inherited outage variables when outages are off and unsets `GITHUB_ACTIONS`. It prints only one result line per round. Give the calling tool a timeout long enough for **all** requested rounds, or run smaller *separate* sessions; an externally aborted tool may leave a test process/container running. If interrupted, stop and check the process/container state before starting again. Do not automatically resume or dismiss an anomaly: follow the stopping rule below.

## Preparation

1. **Run from this exact repository path:** `C:\src\rust-bitvmx-workspace\rust-bitvmx-client` (the directory containing `tall_process.bat`). The CPU check in `tests/common/mod.rs` resolves `../BitVMX-CPU/target/release/emulator.exe` and `../BitVMX-CPU/docker-riscv32/riscv32/build` relative to the **test process's working directory**, not relative to the test executable. Set the working directory explicitly in the shell/process that invokes `cargo`, and verify those two paths there before starting. A missing-CPU message from another working directory is a launch-path mistake: correct the path, do not build the CPU or report it absent. If the paths really are missing from the verified directory, or Docker is unavailable, create an alert as below. Do not run `cargo test` merely to probe readiness.
2. Choose a unique session directory under `logs/process-restart/` in that repository (e.g. a timestamp), and record its absolute path. `logs/` is gitignored. Keep one log file per round; never overwrite a prior log. Use a fresh PowerShell session or explicitly set/unset all eight variables below for each round so inherited values cannot affect the test. In particular, unset all three `BITVMX_TEST_BITCOIND_OUTAGE_*` variables when outages were not requested. Do not set `GITHUB_ACTIONS` locally: it changes how bitcoind is managed and disables control of the locally spawned `bitcoin-regtest` container.
3. Create a compact `summary.md` in the session directory with a table: round, target, interval_ms, downtime_ms, seed, bitcoind_outage_interval_ms, bitcoind_outage_downtime_ms, bitcoind_outage_seed, exit code, status, log path. Use `disabled` for the three outage columns when outages are off. Update it after every round. Pick a numeric base seed (e.g. 100000) and record it in the summary.

## Round schedule

For round `i` (1-based), use `seed = base_seed + i`. Rotate targets `all`, `one`, `random` (rounds 1, 2, 3, then repeat). Use the batch defaults (5000 ms interval, 500 ms downtime) for rounds 1–9. For rounds 10–15 use 3000 ms / 500 ms; for rounds 16–20 use 7000 ms / 1000 ms. For counts greater than 20, repeat the 20-round schedule with **new seeds**. This changes one timing dimension at a time after the baseline; every configuration is reproducible. If a seed/configuration fails, record the exact values rather than trying a different seed.

Bitcoind outages are **disabled by default** for this loop. Enable them only when the user explicitly asks for bitcoind outages, Docker outages, or the third `tall_process.bat` argument. Unless the user provides other values, use a 15000 ms outage interval, 3000 ms outage downtime, and the round's `seed` as `BITVMX_TEST_BITCOIND_OUTAGE_SEED`. The actual interval is randomized between approximately 50% and 150% of the configured interval. Keep these outage settings constant across the rounds so the existing process-restart schedule remains the only changing timing dimension.

## Execution and low-token checks

Run the equivalent of the following **synchronously**, with the working directory explicitly set **inside the same shell that runs `cargo`**, for each round (PowerShell example; substitute the scheduled values and a unique absolute log path). Do not rely on the agent's/tool's default directory or on a previous tool invocation's `cd`:

```powershell
$repoRoot = 'C:\src\rust-bitvmx-workspace\rust-bitvmx-client'
Set-Location -LiteralPath $repoRoot
if ((Get-Location).Path -ne $repoRoot) { throw "Wrong test working directory: $(Get-Location)" }
if (-not (Test-Path -LiteralPath '..\BitVMX-CPU\target\release\emulator.exe') -or
    -not (Test-Path -LiteralPath '..\BitVMX-CPU\docker-riscv32\riscv32\build')) {
    throw 'CPU prerequisites not found relative to the test working directory'
}
$logPath = Join-Path $sessionDir 'round-01.log' # $sessionDir is absolute
$env:BITVMX_TEST_EXECUTION = 'process'
$env:BITVMX_TEST_RESTART_INTERVAL_MS = '5000'
$env:BITVMX_TEST_RESTART_DOWNTIME_MS = '500'
$env:BITVMX_TEST_RESTART_TARGET = 'all'
$env:BITVMX_TEST_RESTART_SEED = '100001'

# Enable these three only when bitcoind outages were requested. Otherwise remove them.
$env:BITVMX_TEST_BITCOIND_OUTAGE_INTERVAL_MS = '15000'
$env:BITVMX_TEST_BITCOIND_OUTAGE_DOWNTIME_MS = '3000'
$env:BITVMX_TEST_BITCOIND_OUTAGE_SEED = '100001'
# Disabled form:
# Remove-Item Env:BITVMX_TEST_BITCOIND_OUTAGE_INTERVAL_MS -ErrorAction SilentlyContinue
# Remove-Item Env:BITVMX_TEST_BITCOIND_OUTAGE_DOWNTIME_MS -ErrorAction SilentlyContinue
# Remove-Item Env:BITVMX_TEST_BITCOIND_OUTAGE_SEED -ErrorAction SilentlyContinue

cargo test --test independent --release -- --ignored test_all --test-threads 1 *> $logPath
$exitCode = $LASTEXITCODE
```

Do **not** call `tall_process.bat`, use `start`, background the test, pipe its output into the agent context, or run rounds concurrently. The command above redirects both streams to the log; ensure `$logPath` points to the unique session/round file. If using an execution tool with a timeout, give each round a generous bound (e.g. 60 minutes) and treat a timeout or lost process as an anomaly, not a pass. A killed harness may leave subprocesses or Docker state behind, including a paused `bitcoin-regtest` container. Stop, report it, and do not start a new round until cleanup has been handled. If cleanup is authorized, check the container state first and use `docker unpause bitcoin-regtest` when it is paused; do not remove it while a test is still running.

On completion check only the exit code and a **small final test-result excerpt** (at most ~20 lines, or search for `test result:` without printing other matches). Expect a zero exit code **and** `test result: ok. 1 passed; 0 failed` for the selected test. A missing/ambiguous result, nonzero exit, timeout, unexpected extra tests, missing log, or inability to start a round is an anomaly. Do not classify normal intentional crash/restart messages as failures. Do not read or print the whole log, even on failure; if clarification is indispensable, search for one specific string and print only a small bounded excerpt. Do not change code, retry, or diagnose during this loop.

## Alert and stopping rule

At the **first** anomaly, update the summary, then create or append `tasks.md` in the repository root with a short actionable entry containing: session/round, process restart target/interval/downtime/seed, bitcoind outage interval/downtime/seed (or `disabled`), exit code (or timeout/start failure), the exact log path, a one-line symptom from the bounded check, and a request to analyze that log later and reproduce with the same settings. Do not paste the log into `tasks.md`. If the test did not create a log, say so. Stop the loop immediately and tell the user the alert location and rounds completed. For a clean run, do not create `tasks.md`; report the number of passes and the summary/log directory only.
