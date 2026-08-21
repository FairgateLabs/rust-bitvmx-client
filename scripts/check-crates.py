#!/usr/bin/env python3

import os
import re
import sys

# Exact versions: matching versions are errors; other versions are warnings.
EXACT_DEPENDENCIES = {
    "append-only-vec": "0.1.9",
    "arrayref": "0.3.10",
    "internment": "0.8.7",
}

# Any version of these packages is considered an error.
ANY_VERSION_ERRORS = {
    "proc-macro1",
    "proc-macro-en",
    "aovine",
    "arone",
    "aronenao",
    "tinymember",
}

# Generated/vendor locations that are not standalone projects.
SKIP_DIRECTORIES = {
    ".git",
    "target",
    "node_modules",
}

PACKAGE_HEADER = re.compile(r"^\s*\[\[package]]\s*$")
NAME_FIELD = re.compile(r'^\s*name\s*=\s*"([^"]+)"')
VERSION_FIELD = re.compile(r'^\s*version\s*=\s*"([^"]+)"')


def read_packages(lockfile):
    packages = []
    current = None

    with open(lockfile, "r", encoding="utf-8", errors="replace") as file:
        for line in file:
            if PACKAGE_HEADER.match(line):
                if current and "name" in current and "version" in current:
                    packages.append(current)
                current = {}
                continue

            if current is None:
                continue

            name_match = NAME_FIELD.match(line)
            if name_match:
                current["name"] = name_match.group(1)
                continue

            version_match = VERSION_FIELD.match(line)
            if version_match:
                current["version"] = version_match.group(1)

    if current and "name" in current and "version" in current:
        packages.append(current)

    return packages


def inspect_lockfile(lockfile):
    errors = []
    warnings = []

    for package in read_packages(lockfile):
        name = package["name"]
        version = package["version"]

        if name in ANY_VERSION_ERRORS:
            errors.append(f"{name} {version}")

        elif name in EXACT_DEPENDENCIES:
            dangerous_version = EXACT_DEPENDENCIES[name]

            if version == dangerous_version:
                errors.append(f"{name} {version}")
            else:
                warnings.append(
                    f"{name} {version} "
                    f"(listed version of concern: {dangerous_version})"
                )

    return sorted(set(errors)), sorted(set(warnings))


def find_lockfiles(roots):
    for root in roots:
        root = os.path.abspath(os.path.expanduser(root))

        for directory, subdirectories, filenames in os.walk(
            root,
            followlinks=False,
            onerror=lambda error: None,
        ):
            subdirectories[:] = [
                name for name in subdirectories
                if name not in SKIP_DIRECTORIES
            ]

            if "Cargo.lock" in filenames:
                yield os.path.join(directory, "Cargo.lock")


def main():
    roots = sys.argv[1:] or [os.path.expanduser("~")]

    infected = []
    warning_only = []
    clean = []
    scan_errors = []

    for lockfile in sorted(set(find_lockfiles(roots))):
        try:
            errors, warnings = inspect_lockfile(lockfile)
        except OSError as error:
            scan_errors.append((lockfile, str(error)))
            continue

        if errors:
            infected.append((lockfile, errors, warnings))
        elif warnings:
            warning_only.append((lockfile, warnings))
        else:
            clean.append(lockfile)

    print("Infected projects:")
    if not infected:
        print("  None")

    for lockfile, errors, warnings in infected:
        print(f"\n{lockfile}")

        for dependency in errors:
            print(f"  ERROR:   {dependency}")

        for dependency in warnings:
            print(f"  WARNING: {dependency}")

    print("\nProjects with dependency warnings:")
    if not warning_only:
        print("  None")

    for lockfile, warnings in warning_only:
        print(f"\n{lockfile}")

        for dependency in warnings:
            print(f"  WARNING: {dependency}")

    if scan_errors:
        print("\nProjects that could not be inspected:")

        for lockfile, error in scan_errors:
            print(f"\n{lockfile}")
            print(f"  SCAN ERROR: {error}")

    print("\nNo listed dependecies project:")
    if not clean:
        print("  None")
    else:
        for lockfile in clean:
            print(f"  {lockfile}")

    # Exit 1 when an infected project or unreadable lockfile is found.
    return 1 if infected or scan_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())