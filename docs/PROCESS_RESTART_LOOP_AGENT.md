# Agent instructions: repeated process-restart test

Run this with a requested number of rounds, e.g. **"Follow `docs/PROCESS_RESTART_LOOP_AGENT.md` for 20 rounds."** Default to 20 if no count is supplied. Your job is to run the test and report the **first anomaly**, not to investigate or fix it. Stop immediately on an anomaly; do not continue the loop. Keep tool output and context small.

## What is being tested

`tall_process.bat [all|one|random] [seed]` launches a **new, detached `cmd /k` window** running `cargo test --test independent --release -- --ignored test_all --test-threads 1` with `BITVMX_TEST_EXECUTION=process`, restart interval 5000 ms, downtime 500 ms, and the specified restart target and optional seed. **Do not use the batch file for this loop:** its launcher returns before the test finishes and does not give you the test's exit code. Instead, run the *same test* in the foreground with those environment variables set, capturing the entire output in a per-round file. This ignored regtest integration test requires Docker/bitcoind and a built BitVMX-CPU emulator. Do not start another round while one is running; the test owns the `bitcoin-regtest` container and local operator state.

## Preparation

1. **Run from this exact repository path:** `C:\src\rust-bitvmx-workspace\rust-bitvmx-client` (the directory containing `tall_process.bat`). The CPU check in `tests/common/mod.rs` resolves `../BitVMX-CPU/target/release/emulator.exe` and `../BitVMX-CPU/docker-riscv32/riscv32/build` relative to the **test process's working directory**, not relative to the test executable. Set the working directory explicitly in the shell/process that invokes `cargo`, and verify those two paths there before starting. A missing-CPU message from another working directory is a launch-path mistake: correct the path, do not build the CPU or report it absent. If the paths really are missing from the verified directory, or Docker is unavailable, create an alert as below. Do not run `cargo test` merely to probe readiness.
2. Choose a unique session directory under `logs/process-restart/` in that repository (e.g. a timestamp), and record its absolute path. `logs/` is gitignored. Keep one log file per round; never overwrite a prior log. Use a fresh PowerShell session or explicitly set/unset all five variables below for each round so inherited values cannot affect the test. Do not set `GITHUB_ACTIONS` locally: it changes how bitcoind is managed.
3. Create a compact `summary.md` in the session directory with a table: round, target, interval_ms, downtime_ms, seed, exit code, status, log path. Update it after every round. Pick a numeric base seed (e.g. 100000) and record it in the summary.

## Round schedule

For round `i` (1-based), use `seed = base_seed + i`. Rotate targets `all`, `one`, `random` (rounds 1, 2, 3, then repeat). Use the batch defaults (5000 ms interval, 500 ms downtime) for rounds 1–9. For rounds 10–15 use 3000 ms / 500 ms; for rounds 16–20 use 7000 ms / 1000 ms. For counts greater than 20, repeat the 20-round schedule with **new seeds**. This changes one timing dimension at a time after the baseline; every configuration is reproducible. If a seed/configuration fails, record the exact values rather than trying a different seed.

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
cargo test --test independent --release -- --ignored test_all --test-threads 1 *> $logPath
$exitCode = $LASTEXITCODE
```

Do **not** call `tall_process.bat`, use `start`, background the test, pipe its output into the agent context, or run rounds concurrently. The command above redirects both streams to the log; ensure `$logPath` points to the unique session/round file. If using an execution tool with a timeout, give each round a generous bound (e.g. 60 minutes) and treat a timeout or lost process as an anomaly, not a pass. A killed harness may leave subprocesses or Docker state behind: stop, report it, and do not start a new round until cleanup has been handled.

On completion check only the exit code and a **small final test-result excerpt** (at most ~20 lines, or search for `test result:` without printing other matches). Expect a zero exit code **and** `test result: ok. 1 passed; 0 failed` for the selected test. A missing/ambiguous result, nonzero exit, timeout, unexpected extra tests, missing log, or inability to start a round is an anomaly. Do not classify normal intentional crash/restart messages as failures. Do not read or print the whole log, even on failure; if clarification is indispensable, search for one specific string and print only a small bounded excerpt. Do not change code, retry, or diagnose during this loop.

## Alert and stopping rule

At the **first** anomaly, update the summary, then create or append `tasks.md` in the repository root with a short actionable entry containing: session/round, target, interval/downtime, seed, exit code (or timeout/start failure), the exact log path, a one-line symptom from the bounded check, and a request to analyze that log later and reproduce with the same settings. Do not paste the log into `tasks.md`. If the test did not create a log, say so. Stop the loop immediately and tell the user the alert location and rounds completed. For a clean run, do not create `tasks.md`; report the number of passes and the summary/log directory only.
