@echo off
rem Usage: tall_process.bat [all|one|random] [seed]
set TARGET=%~1
if "%TARGET%"=="" set TARGET=all
set SEED_CMD=
if not "%~2"=="" set SEED_CMD=set BITVMX_TEST_RESTART_SEED=%~2^&^&
start "BitVMX process restart test (%TARGET%)" /D "%~dp0" cmd /k "set BITVMX_TEST_EXECUTION=process&& set BITVMX_TEST_RESTART_INTERVAL_MS=5000&& set BITVMX_TEST_RESTART_DOWNTIME_MS=500&& set BITVMX_TEST_RESTART_TARGET=%TARGET%&& %SEED_CMD%cargo test --test independent --release -- --ignored test_all --test-threads 1"
