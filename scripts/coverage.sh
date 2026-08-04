#!/usr/bin/env bash
# coverage.sh — Local LLVM coverage for rust-bitvmx-client
#
# USAGE:
#   ./scripts/coverage.sh [OPTIONS]
#
# OPTIONS:
#   --unit              Run only unit/doc tests (default, fast, no bitcoind needed)
#   --nightly           Run all tests including #[ignore] ones (test_full, test_drp)
#                       Requires bitcoind running via docker-compose
#   --test <spec>       Run one or more #[ignore] tests. Repeatable. Use file:name syntax:
#                         --test fulltest:test_full
#                         --test union_test:test_union_fund
#                         --test fulltest:test_full --test union_test:test_union_fund
#                       Coverage is merged across all specified tests.
#                       Without file: prefix, matches any test with that name.
#   --open              Open HTML report in browser after generation (default: true)
#   --no-open           Do not open the browser
#   --out <dir>         Output directory for the report (default: target/coverage)
#   --exclude <regex>   Additional paths to exclude (appended to defaults)
#   --summary           Print text summary to stdout (in addition to HTML)
#   --help              Show this help
#
# EXAMPLES:
#   ./scripts/coverage.sh                                           # unit tests coverage
#   ./scripts/coverage.sh --test fulltest:test_full --summary       # 1 client test
#   ./scripts/coverage.sh --test union_test:test_union_fund         # 1 union test
#   ./scripts/coverage.sh \
#     --test fulltest:test_full \
#     --test integration:test_drp \
#     --test union_test:test_union_fund \
#     --summary                                                      # N tests merged
#   ./scripts/coverage.sh --no-open --summary                       # unit tests, no browser

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
MODE="unit"
OPEN=true
OUT_DIR="target/coverage"
EXTRA_EXCLUDE=""
SUMMARY=false
TESTS=()  # accumulates multiple --test specs

# Paths excluded from coverage measurement.
# Regex passed to --ignore-filename-regex (LLVM regex: matching files are excluded).
# Excludes: test/example files, workspace dependencies (all workspace members except
# rust-bitvmx-client itself), and crates.io registry deps.
DEFAULT_EXCLUDE="cardinal/|tests/|examples/|build\.rs|src/main\.rs|BitVMX-CPU/|rust-bitcoin-coordinator/|rust-bitcoin-indexer/|rust-bitcoind/|rust-bitvmx-bitcoin-rpc/|rust-bitvmx-broker/|rust-bitvmx-job-dispatcher/|rust-bitvmx-key-manager/|rust-bitvmx-protocol-builder/|rust-bitvmx-settings/|rust-bitvmx-storage-backend/|rust-bitvmx-transaction-monitor/|rust-bitvmx-wallet/|rust-bitvmx-gc/|\.cargo/registry/"

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --unit)       MODE="unit"        ; shift ;;
        --nightly)    MODE="nightly"     ; shift ;;
        --test)       MODE="multi"; TESTS+=("$2"); shift 2 ;;
        --open)       OPEN=true          ; shift ;;
        --no-open)    OPEN=false         ; shift ;;
        --out)        OUT_DIR="$2"       ; shift 2 ;;
        --exclude)    EXTRA_EXCLUDE="$2" ; shift 2 ;;
        --summary)    SUMMARY=true       ; shift ;;
        --help|-h)
            # Print only the header block (lines 2..first blank line after header)
            sed -n '2,/^[^#]/{ /^#/p }' "$0" | sed 's/^# \{0,2\}//'
            exit 0
            ;;
        *) echo "Unknown option: $1  (use --help)"; exit 1 ;;
    esac
done

# Build exclude regex
EXCLUDE_REGEX="$DEFAULT_EXCLUDE"
if [[ -n "$EXTRA_EXCLUDE" ]]; then
    EXCLUDE_REGEX="${EXCLUDE_REGEX}|${EXTRA_EXCLUDE}"
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[cov]${RESET} $*"; }
success() { echo -e "${GREEN}[cov]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[cov]${RESET} $*"; }

require_bitcoind() {
    if ! docker ps --format "{{.Names}}" 2>/dev/null | grep -q "^bitcoind$"; then
        warn "bitcoind container is not running."
        warn "Start it first:"
        warn "  cd tests/docker && docker-compose up -d"
        exit 1
    fi
}

REAL_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ── Base cargo-llvm-cov flags ─────────────────────────────────────────────────
BASE_FLAGS=(
    --release
    --features testpanic
    --ignore-filename-regex "$EXCLUDE_REGEX"
    --output-dir "${REAL_DIR}/${OUT_DIR}"
)

# ── Modes ─────────────────────────────────────────────────────────────────────

run_unit() {
    info "Mode: unit tests (no #[ignore])"
    info "Exclude regex: ${EXCLUDE_REGEX}"
    info "Output: ${REAL_DIR}/${OUT_DIR}/html/index.html"
    echo ""
    cd "$REAL_DIR"
    cargo llvm-cov \
        "${BASE_FLAGS[@]}" \
        --html \
        -- --test-threads=1
}

run_nightly() {
    require_bitcoind
    info "Mode: nightly — merging coverage from test_full + test_drp"
    info "Exclude regex: ${EXCLUDE_REGEX}"
    info "Output: ${OUT_DIR}/html/index.html"
    echo ""

    export GITHUB_ACTIONS=true

    NIGHTLY_TESTS=(
        "fulltest:test_full"
        "integration:test_drp"
    )

    local count=0
    local total=${#NIGHTLY_TESTS[@]}

    for spec in "${NIGHTLY_TESTS[@]}"; do
        local file="${spec%%:*}"
        local name="${spec##*:}"
        count=$((count + 1))

        info "($count/$total) Running ${name} from ${file}..."

        # --no-report: accumulate profdata without generating the report yet
        cd "$REAL_DIR"
        cargo llvm-cov \
            "${BASE_FLAGS[@]}" \
            --no-report \
            --test "$file" \
            -- "$name" --ignored --test-threads=1 --nocapture

        success "  $name done"

        # Restart bitcoind between tests (same logic as run_sequential_tests.sh)
        if [[ $count -lt $total ]]; then
            info "Restarting bitcoind between tests..."
            restart_bitcoind
        fi
    done

    generate_report
}

run_multi() {
    local total=${#TESTS[@]}

    if [[ $total -eq 0 ]]; then
        warn "No tests specified. Use --test <file:name>"
        exit 1
    fi

    info "Mode: ${total} test(s) — coverage merged"
    info "Exclude regex: ${EXCLUDE_REGEX}"
    info "Output: ${REAL_DIR}/${OUT_DIR}/html/index.html"
    echo ""

    local count=0
    for spec in "${TESTS[@]}"; do
        local test_file=""
        local test_name="$spec"
        if [[ "$spec" == *:* ]]; then
            test_file="${spec%%:*}"
            test_name="${spec##*:}"
        fi
        count=$((count + 1))

        info "($count/$total) Running ${test_name}${test_file:+ (from $test_file)}..."

        cd "$REAL_DIR"
        local extra_flags=()
        [[ -n "$test_file" ]] && extra_flags+=(--test "$test_file")

        if [[ $total -eq 1 ]]; then
            # Single test: generate report directly
            cargo llvm-cov \
                "${BASE_FLAGS[@]}" \
                --html \
                "${extra_flags[@]}" \
                -- "$test_name" --ignored --test-threads=1 --nocapture
        elif [[ $count -lt $total ]]; then
            # Not the last: accumulate profdata only
            cargo llvm-cov \
                "${BASE_FLAGS[@]}" \
                --no-report \
                "${extra_flags[@]}" \
                -- "$test_name" --ignored --test-threads=1 --nocapture
        else
            # Last test: accumulate then generate report
            cargo llvm-cov \
                "${BASE_FLAGS[@]}" \
                --no-report \
                "${extra_flags[@]}" \
                -- "$test_name" --ignored --test-threads=1 --nocapture
            generate_report
        fi

        success "  ${test_name} done"
    done
}

restart_bitcoind() {
    if docker ps --format "{{.Names}}" | grep -q "^bitcoind$"; then
        docker stop bitcoind > /dev/null 2>&1
        docker start bitcoind > /dev/null 2>&1
        sleep 15
        for i in {1..30}; do
            if docker exec bitcoind bitcoin-cli -regtest -rpcuser=foo -rpcpassword=rpcpassword \
               -rpcport=18443 -rpcwallet=test_wallet getbalance > /dev/null 2>&1; then
                success "bitcoind ready"
                return 0
            fi
            sleep 3
        done
        warn "bitcoind did not become ready after restart"
        return 1
    fi
}

generate_report() {
    info "Generating HTML report..."
    cd "$REAL_DIR"
    cargo llvm-cov report \
        --html \
        --ignore-filename-regex "$EXCLUDE_REGEX" \
        --output-dir "${REAL_DIR}/${OUT_DIR}"
}

print_summary() {
    info "Coverage summary:"
    cd "$REAL_DIR"
    cargo llvm-cov report \
        --ignore-filename-regex "$EXCLUDE_REGEX" 2>/dev/null || true
}

open_report() {
    local html="${REAL_DIR}/${OUT_DIR}/html/index.html"
    if [[ ! -f "$html" ]]; then
        warn "Report not found at $html"
        return
    fi
    success "Report: file://$(realpath "$html")"
    if [[ "$OPEN" == "true" ]]; then
        if command -v xdg-open &>/dev/null; then
            xdg-open "$html" &
        elif command -v open &>/dev/null; then
            open "$html"
        fi
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}=== rust-bitvmx-client coverage ===${RESET}"
echo ""

mkdir -p "${REAL_DIR}/${OUT_DIR}"

case "$MODE" in
    unit)    run_unit    ;;
    nightly) run_nightly ;;
    multi)   run_multi   ;;
esac

if [[ "$SUMMARY" == "true" ]]; then
    echo ""
    print_summary
fi

open_report

echo ""
success "Done."
