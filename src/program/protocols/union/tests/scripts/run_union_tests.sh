#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_ROOT="$(cd "$SCRIPT_DIR/../../../../.." && pwd)"
cd "$CLIENT_ROOT"

TEMP_TXT=$(mktemp)
TEMP_JSON=$(mktemp)
trap 'rm -f "$TEMP_TXT" "$TEMP_JSON"' EXIT

echo ""
echo "Union Protocol Tests"
echo ""

have_jq=false
if command -v jq >/dev/null 2>&1; then
  have_jq=true
fi

run_tests_plain() {
  # Limit to bitvmx-client crate and filter to union tests only (filter passed after --)
  cargo test -p bitvmx-client --lib -- program::protocols::union::tests > "$TEMP_TXT" 2>&1 || true
}

run_tests_json() {
  # Try JSON output; if unsupported by toolchain, fall back to plain
  if ! cargo test -p bitvmx-client --lib -- --format json program::protocols::union::tests > "$TEMP_JSON" 2>/dev/null; then
    return 1
  fi
  return 0
}

if $have_jq && run_tests_json; then
  # Pretty print JSON results by suite
  echo "=== JSON summary (jq) ==="
  total_pass=$(jq -r 'select(.type=="test") | select(.event=="ok") | .name' "$TEMP_JSON" | wc -l | tr -d ' ')
  total_fail=$(jq -r 'select(.type=="test") | select(.event=="failed") | .name' "$TEMP_JSON" | wc -l | tr -d ' ')
  for suite in common_utilities indexed_names fee_estimation output_builders; do
    echo ""
    echo "=== $(echo "$suite" | sed 's/_/ /g' | sed 's/\b./\U&/g') ==="
    jq -r --arg s "$suite" '
      select(.type=="test")
      | select(.name | contains($s))
      | [.event, (.name | split("::") | .[-1])] 
      | @tsv' "$TEMP_JSON" \
      | sort \
      | awk '{ status=$1; name=$2; if(status=="ok"){printf "  ✓ %-55s [PASSED]\n", name} else if(status=="failed"){printf "  ✗ %-55s [FAILED]\n", name} else {printf "  • %-55s [OTHER]\n", name} }'
  done
  echo ""
  echo "Result: $total_pass passed, $total_fail failed"
  test $total_fail -eq 0 || exit 1
else
  run_tests_plain

  print_suite_tests() {
      local suite_title=$1
      local pattern=$2

      local matches=$(grep "^test " "$TEMP_TXT" | grep "$pattern" || true)

      if [ -z "$matches" ]; then
          return
      fi

      echo "=== $suite_title ==="
      echo ""

      echo "$matches" | sort | awk '
      BEGIN { prev_module = "" }
      {
          status = $NF

          full_path = $2
          gsub(/\.{3}$/, "", full_path)

          n = split(full_path, parts, "::")

          module = parts[n-1]
          test_name = parts[n]

          if (module != prev_module) {
              if (prev_module != "") print ""
              print "Module: " module
              prev_module = module
          }

          if (status == "ok") {
              printf "  ✓ %-55s [PASSED]\n", test_name
          } else if (status == "FAILED") {
              printf "  ✗ %-55s [FAILED]\n", test_name
          } else {
              printf "  • %-55s [IGNORED]\n", test_name
          }
      }
      '
      echo ""
  }

  print_suite_tests "Common Utilities" "unit::common_utilities"
  print_suite_tests "Indexed Names" "unit::indexed_names"
  print_suite_tests "Fee Estimation" "unit::fee_estimation"
  print_suite_tests "Output Builders" "unit::output_builders"

  grep "test result:" "$TEMP_TXT" || true
  echo ""

  if grep -q " passed" "$TEMP_TXT" && ! grep -q "FAILED" "$TEMP_TXT"; then
      echo "✓ All tests passed"
  else
      echo "✗ Tests failed"
      grep -A 20 "failures:" "$TEMP_TXT" || true
      exit 1
  fi
fi

echo ""


