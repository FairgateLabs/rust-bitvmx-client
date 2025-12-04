#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_ROOT="$(cd "$SCRIPT_DIR/../../../../.." && pwd)"
cd "$CLIENT_ROOT"

TEMP=$(mktemp)
trap 'rm -f "$TEMP"' EXIT

echo ""
echo "Union Protocol Tests"
echo ""

cargo test --lib program::protocols::union::tests > "$TEMP" 2>&1

print_module_tests() {
    local suite_name=$1
    local pattern=$2

    echo "=== $suite_name ==="
    echo ""

    grep "$pattern" "$TEMP" | grep "test program::" | sort | awk '
    BEGIN { prev_module = "" }
    {
        # Extract status (last word)
        status = $NF

        # Split by :: to get components
        n = split($0, parts, "::")

        # Module is second to last, test name is part before " ..."
        module = parts[n-1]

        # Extract test name from the last part (remove " ... status")
        split(parts[n], last_parts, " ")
        test_name = last_parts[1]

        # Print module header when it changes
        if (module != prev_module) {
            if (prev_module != "") print ""
            print "Module: " module
            prev_module = module
        }

        # Format output based on status
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

print_module_tests "Common Utilities" "::common_utilities::"
print_module_tests "Indexed Names" "::indexed_names::"

grep "test result:" "$TEMP"
echo ""

if grep -q " passed" "$TEMP" && ! grep -q "FAILED" "$TEMP"; then
    echo "✓ All tests passed"
else
    echo "✗ Tests failed"
    grep -A 20 "failures:" "$TEMP"
fi

echo ""


