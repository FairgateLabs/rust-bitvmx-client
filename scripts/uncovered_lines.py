#!/usr/bin/env python3
"""List uncovered lines from a cargo-llvm-cov HTML report.

Usage:
    python scripts/uncovered_lines.py <source-file-name> [--html-root DIR] [--context]

Examples:
    python scripts/uncovered_lines.py comms_helper.rs
    python scripts/uncovered_lines.py src/program/variables.rs --context

Finds the per-file HTML page under the coverage HTML root (default:
target/coverage/html), extracts the line numbers marked as uncovered
(red), and prints them. With --context, also prints the source text of
each uncovered line and groups consecutive lines into ranges.
"""

import argparse
import html as html_mod
import re
import sys
from pathlib import Path


def find_report(html_root: Path, source_name: str) -> Path:
    # Match by file name (and optional trailing path components).
    needle = source_name.replace("\\", "/").lstrip("./")
    candidates = [
        p
        for p in html_root.rglob("*.html")
        if p.name != "index.html"
        and p.as_posix().replace(".html", "").endswith(needle)
    ]
    if not candidates:
        sys.exit(f"error: no coverage page matching '{source_name}' under {html_root}")
    if len(candidates) > 1:
        names = "\n  ".join(str(c) for c in candidates)
        sys.exit(f"error: ambiguous source name '{source_name}', matches:\n  {names}")
    return candidates[0]


def uncovered_lines(report: Path) -> list[tuple[int, str]]:
    text = report.read_text(encoding="utf-8")
    result = []
    for row in re.findall(r"<tr>(.*?)</tr>", text, re.S):
        m = re.search(r"name='L(\d+)'", row)
        if not m or "class='uncovered-line'" not in row:
            continue
        # Source text is in the last <td> cell; strip tags.
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        src = html_mod.unescape(re.sub(r"<[^>]+>", "", cells[-1])) if cells else ""
        result.append((int(m.group(1)), src.rstrip("\n")))
    return result


def as_ranges(nums: list[int]) -> str:
    parts = []
    start = prev = nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
            continue
        parts.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = n
    parts.append(f"{start}-{prev}" if start != prev else str(start))
    return ", ".join(parts)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("source", help="source file name, e.g. comms_helper.rs")
    ap.add_argument(
        "--html-root",
        type=Path,
        default=Path("target/coverage/html"),
        help="coverage HTML root (default: target/coverage/html)",
    )
    ap.add_argument(
        "--context", action="store_true", help="print source text of uncovered lines"
    )
    args = ap.parse_args()

    report = find_report(args.html_root, args.source)
    lines = uncovered_lines(report)
    if not lines:
        print(f"{args.source}: fully covered (no red lines)")
        return

    nums = [n for n, _ in lines]
    print(f"{args.source}: {len(nums)} uncovered lines: {as_ranges(nums)}")
    if args.context:
        for n, src in lines:
            print(f"{n:6}  {src}")


if __name__ == "__main__":
    main()
