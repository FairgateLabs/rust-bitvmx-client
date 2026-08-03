@echo off
REM coverage.bat - Local LLVM coverage for rust-bitvmx-client (Windows)
REM
REM Equivalent to: ./scripts/coverage.sh --unit --no-open --summary
REM Runs unit/doc tests only (no #[ignore], no bitcoind needed),
REM generates the HTML report, and prints a text summary.
REM
REM USAGE:
REM   scripts\coverage.bat

setlocal EnableDelayedExpansion

REM Resolve repo root (parent of this script's directory)
set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "REAL_DIR=%%~fI"

set "OUT_DIR=target\coverage"

REM Paths excluded from coverage measurement.
REM Regex passed to --ignore-filename-regex (LLVM regex: matching files are excluded).
REM Excludes: test/example files, workspace dependencies (all workspace members except
REM rust-bitvmx-client itself), and crates.io registry deps.
REM Uses [/\\] instead of / so paths match with both separators on Windows.
set "EXCLUDE_REGEX=cardinal[/\\]|tests[/\\]|examples[/\\]|build\.rs|src[/\\]main\.rs|BitVMX-CPU[/\\]|rust-bitcoin-coordinator[/\\]|rust-bitcoin-indexer[/\\]|rust-bitcoind[/\\]|rust-bitvmx-bitcoin-rpc[/\\]|rust-bitvmx-broker[/\\]|rust-bitvmx-job-dispatcher[/\\]|rust-bitvmx-key-manager[/\\]|rust-bitvmx-protocol-builder[/\\]|rust-bitvmx-settings[/\\]|rust-bitvmx-storage-backend[/\\]|rust-bitvmx-transaction-monitor[/\\]|rust-bitvmx-wallet[/\\]|rust-bitvmx-gc[/\\]|\.cargo[/\\]registry[/\\]"

echo.
echo === rust-bitvmx-client coverage ===
echo.
echo [cov] Mode: unit tests (no #[ignore])
echo [cov] Exclude regex: !EXCLUDE_REGEX!
echo [cov] Output: %REAL_DIR%\%OUT_DIR%\html\index.html
echo.

cd /d "%REAL_DIR%"

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

cargo llvm-cov ^
    --release ^
    --features testpanic ^
    --ignore-filename-regex "%EXCLUDE_REGEX%" ^
    --output-dir "%REAL_DIR%\%OUT_DIR%" ^
    --html ^
    -- --test-threads=1
if errorlevel 1 (
    echo [cov] Coverage run failed.
    exit /b 1
)

echo.
echo [cov] Coverage summary:
cargo llvm-cov report --release --ignore-filename-regex "%EXCLUDE_REGEX%"

echo.
echo [cov] Report: %REAL_DIR%\%OUT_DIR%\html\index.html
echo [cov] Done.

endlocal
