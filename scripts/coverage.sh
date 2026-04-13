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
#   --test <name>       Run a single #[ignore] test by name (e.g. --test test_full)
#                       Use file:name syntax to target a specific test file:
#                         --test fulltest:test_full   (runs test_full from fulltest.rs only)
#                         --test test_full            (runs any test matching "test_full")
#   --open              Open HTML report in browser after generation (default: true)
#   --no-open           Do not open the browser
#   --out <dir>         Output directory for the report (default: target/coverage)
#   --exclude <regex>   Additional paths to exclude (appended to defaults)
#   --summary           Print text summary to stdout (in addition to HTML)
#   --help              Show this help
#
# EXAMPLES:
#   ./scripts/coverage.sh                                    # unit tests coverage
#   ./scripts/coverage.sh --test fulltest:test_full --summary  # test_full with summary
#   ./scripts/coverage.sh --no-open --summary                # unit tests, no browser

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
MODE="unit"
OPEN=true
OUT_DIR="target/coverage"
EXTRA_EXCLUDE=""
SUMMARY=false
SINGLE_TEST=""

# Paths excluded from coverage measurement (mirrors CI coverage_exclude)
# Regex passed to --ignore-filename-regex
DEFAULT_EXCLUDE="tests/|examples/|build\.rs|src/main\.rs"

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --unit)       MODE="unit"        ; shift ;;
        --nightly)    MODE="nightly"     ; shift ;;
        --test)       MODE="single"; SINGLE_TEST="$2"; shift 2 ;;
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

run_single() {
    # Parse optional file:name syntax (e.g. "fulltest:test_full")
    local test_file=""
    local test_name="$SINGLE_TEST"
    if [[ "$SINGLE_TEST" == *:* ]]; then
        test_file="${SINGLE_TEST%%:*}"
        test_name="${SINGLE_TEST##*:}"
    fi

    info "Mode: single test — ${test_name}${test_file:+ (from $test_file)}"
    info "Exclude regex: ${EXCLUDE_REGEX}"
    info "Output: ${REAL_DIR}/${OUT_DIR}/html/index.html"
    echo ""

    cd "$REAL_DIR"
    if [[ -n "$test_file" ]]; then
        cargo llvm-cov \
            "${BASE_FLAGS[@]}" \
            --html \
            --test "$test_file" \
            -- "$test_name" --ignored --test-threads=1 --nocapture
    else
        cargo llvm-cov \
            "${BASE_FLAGS[@]}" \
            --html \
            -- "$test_name" --ignored --test-threads=1 --nocapture
    fi
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
    unit)    run_unit   ;;
    nightly) run_nightly ;;
    single)  run_single  ;;
esac

if [[ "$SUMMARY" == "true" ]]; then
    echo ""
    print_summary
fi

open_report

echo ""
success "Done."
