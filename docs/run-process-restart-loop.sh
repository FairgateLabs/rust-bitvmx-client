#!/usr/bin/env bash
# Run from Git Bash on Windows. Synchronous; stops and alerts at the first anomaly.
set -u

rounds=20
base_seed=100000
outages=false
outage_interval=15000
outage_downtime=3000
while (($#)); do
    case "$1" in
        --rounds|--base-seed|--outage-interval-ms|--outage-downtime-ms)
            (($# >= 2)) || { echo "Missing value for $1" >&2; exit 2; }
            [[ "$2" =~ ^[0-9]+$ ]] || { echo "Expected nonnegative integer for $1" >&2; exit 2; }
            case "$1" in
                --rounds) rounds=$((10#$2));;
                --base-seed) base_seed=$((10#$2));;
                --outage-interval-ms) outage_interval=$((10#$2));;
                --outage-downtime-ms) outage_downtime=$((10#$2));;
            esac
            shift 2;;
        --outages) outages=true; shift;;
        *) echo "Unknown option: $1" >&2; exit 2;;
    esac
done
((rounds > 0 && outage_interval > 0 && outage_downtime > 0)) || { echo 'Round count and outage timings must be positive' >&2; exit 2; }

repo_root='/c/src/rust-bitvmx-workspace/rust-bitvmx-client'
cd "$repo_root" || exit 2
[[ "$PWD" == "$repo_root" ]] || { echo "Wrong test working directory: $PWD" >&2; exit 2; }
mkdir -p logs/process-restart || exit 2
session_dir=$(mktemp -d "$repo_root/logs/process-restart/$(date +%Y%m%d-%H%M%S)-XXXXXX") || exit 2
summary="$session_dir/summary.md"
printf '# Process restart loop\n\nBase seed: `%s`\nBitcoind outages: `%s`\n\n| round | target | interval_ms | downtime_ms | seed | bitcoind_outage_interval_ms | bitcoind_outage_downtime_ms | bitcoind_outage_seed | exit code | status | log path |\n|---:|---|---:|---:|---:|---|---|---|---|---|---|\n' "$base_seed" "$outages" > "$summary"
printf 'Session: %s\n' "$session_dir"

record() {
    local status=$1 exit_code=$2 symptom=$3 log_path=$4
    printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | `%s` |\n' \
        "$round" "$target" "$interval" "$downtime" "$seed" \
        "$out_interval" "$out_downtime" "$out_seed" "$exit_code" "$status" "$log_path" >> "$summary"
    printf 'round=%s exit=%s status=%s %s\n' "$round" "$exit_code" "$status" "$symptom"
    if [[ $status == anomaly ]]; then
        printf '\n- Process-restart alert: session `%s`, round %s; target=%s interval_ms=%s downtime_ms=%s seed=%s; bitcoind outage interval_ms=%s downtime_ms=%s seed=%s; exit=%s; log `%s`; symptom: %s. Analyze that log later and reproduce with the same settings.\n' \
            "$session_dir" "$round" "$target" "$interval" "$downtime" "$seed" \
            "$out_interval" "$out_downtime" "$out_seed" "$exit_code" "$log_path" "$symptom" >> "$repo_root/tasks.md"
    fi
}

for ((round=1; round<=rounds; round++)); do
    case $(((round - 1) % 3)) in
        0) target=all;; 1) target=one;; 2) target=random;;
    esac
    slot=$(((round - 1) % 20 + 1))
    if ((slot <= 9)); then interval=5000; downtime=500
    elif ((slot <= 15)); then interval=3000; downtime=500
    else interval=7000; downtime=1000; fi
    seed=$((base_seed + round))
    out_interval=disabled; out_downtime=disabled; out_seed=disabled
    if $outages; then
        out_interval=$outage_interval; out_downtime=$outage_downtime; out_seed=$seed
    fi
    printf -v round_name 'round-%02d.log' "$round"
    log_path="$session_dir/$round_name"
    failure=''
    [[ -f ../BitVMX-CPU/target/release/emulator.exe && -d ../BitVMX-CPU/docker-riscv32/riscv32/build ]] || failure='CPU prerequisites missing relative to verified working directory'
    command -v timeout >/dev/null 2>&1 || failure='timeout command unavailable'
    if ! docker info >/dev/null 2>&1; then failure='Docker unavailable'; fi
    if [[ -e "$log_path" ]]; then failure='round log already exists'; fi
    if [[ -n $failure ]]; then
        record anomaly 'start failure' "$failure (log not created)" 'not created'
        exit 1
    fi

    env_args=(-u GITHUB_ACTIONS
        -u BITVMX_TEST_BITCOIND_OUTAGE_INTERVAL_MS
        -u BITVMX_TEST_BITCOIND_OUTAGE_DOWNTIME_MS
        -u BITVMX_TEST_BITCOIND_OUTAGE_SEED
        BITVMX_TEST_EXECUTION=process
        BITVMX_TEST_RESTART_INTERVAL_MS="$interval"
        BITVMX_TEST_RESTART_DOWNTIME_MS="$downtime"
        BITVMX_TEST_RESTART_TARGET="$target"
        BITVMX_TEST_RESTART_SEED="$seed")
    if $outages; then
        env_args+=(BITVMX_TEST_BITCOIND_OUTAGE_INTERVAL_MS="$out_interval"
            BITVMX_TEST_BITCOIND_OUTAGE_DOWNTIME_MS="$out_downtime"
            BITVMX_TEST_BITCOIND_OUTAGE_SEED="$out_seed")
    fi
    timeout 3600 env "${env_args[@]}" cargo test --test independent --release -- --ignored test_all --test-threads 1 > "$log_path" 2>&1
    exit_code=$?
    results=$(grep -F 'test result:' "$log_path" || true)
    result=$(printf '%s\n' "$results" | tail -n 1)
    result_count=$(printf '%s\n' "$results" | grep -c . || true)
    if [[ $exit_code -eq 0 && $result_count -eq 1 && $result == 'test result: ok. 1 passed; 0 failed;'* ]]; then
        record pass "$exit_code" "$result" "$log_path"
    else
        symptom=${result:-missing test result}
        [[ $result_count -gt 1 ]] && symptom='ambiguous test result (multiple matches)'
        [[ $exit_code -eq 124 ]] && symptom='test timed out after 3600 seconds'
        [[ -f $log_path ]] || { log_path='not created'; symptom='test did not create a log'; }
        record anomaly "$exit_code" "$symptom" "$log_path"
        exit 1
    fi
done
