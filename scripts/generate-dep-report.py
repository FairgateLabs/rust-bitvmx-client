#!/usr/bin/env python3
"""Generate dep.html for Rust repositories that are sibling Git submodules.

The report aggregates Cargo crate dependencies to repository-level edges. By
 default, paths are inferred from this script's location:

    python scripts/generate-dep-report.py

Use --workspace-root or --output to override them.
"""

from __future__ import annotations

import argparse
import json
import os
import tomllib
from pathlib import Path
from typing import Any, Iterator

SKIP_DIRECTORIES = {".git", "target", "node_modules", ".venv", "venv"}
DEPENDENCY_TABLES = (
    ("dependencies", "normal"),
    ("build-dependencies", "build"),
    ("dev-dependencies", "dev"),
)


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=project_root.parent,
        help="directory containing .gitmodules and the sibling repositories",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=project_root / "dep.html",
        help="output HTML path (default: PROJECT_ROOT/dep.html)",
    )
    return parser.parse_args()


def sibling_repositories(workspace_root: Path) -> list[str]:
    gitmodules = workspace_root / ".gitmodules"
    if not gitmodules.is_file():
        raise FileNotFoundError(f"Git submodule list not found: {gitmodules}")

    repositories = []
    for line in gitmodules.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("path ="):
            repositories.append(line.split("=", 1)[1].strip())
    return repositories


def cargo_manifests(repository: Path) -> Iterator[Path]:
    for base, directories, files in os.walk(repository):
        directories[:] = [d for d in directories if d not in SKIP_DIRECTORIES]
        if "Cargo.toml" in files:
            yield Path(base) / "Cargo.toml"


def dependency_tables(manifest: dict[str, Any]) -> Iterator[tuple[str, str | None, dict[str, Any]]]:
    for table_name, kind in DEPENDENCY_TABLES:
        table = manifest.get(table_name)
        if isinstance(table, dict):
            yield kind, None, table

    for target, target_data in manifest.get("target", {}).items():
        if not isinstance(target_data, dict):
            continue
        for table_name, kind in DEPENDENCY_TABLES:
            table = target_data.get(table_name)
            if isinstance(table, dict):
                yield kind, target, table


def find_workspace_dependencies(
    manifest_path: Path,
    workspace_root: Path,
    manifests_by_path: dict[Path, dict[str, Any]],
) -> dict[str, Any]:
    for parent in (manifest_path.parent, *manifest_path.parents):
        candidate = parent / "Cargo.toml"
        manifest = manifests_by_path.get(candidate)
        if manifest:
            dependencies = manifest.get("workspace", {}).get("dependencies")
            if isinstance(dependencies, dict):
                return dependencies
        if parent == workspace_root:
            break
    return {}


def release_cycle_count(repositories: list[str], edges: list[dict[str, Any]]) -> int:
    adjacency = {repository: set() for repository in repositories}
    for edge in edges:
        if edge["kind"] != "dev":
            adjacency[edge["src"]].add(edge["dst"])

    indexes: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def visit(repository: str) -> None:
        indexes[repository] = lowlinks[repository] = len(indexes)
        stack.append(repository)
        on_stack.add(repository)
        for dependency in adjacency[repository]:
            if dependency not in indexes:
                visit(dependency)
                lowlinks[repository] = min(lowlinks[repository], lowlinks[dependency])
            elif dependency in on_stack:
                lowlinks[repository] = min(lowlinks[repository], indexes[dependency])
        if lowlinks[repository] == indexes[repository]:
            component = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == repository:
                    break
            components.append(component)

    for repository in repositories:
        if repository not in indexes:
            visit(repository)
    return sum(len(component) > 1 for component in components)


def collect_graph(workspace_root: Path) -> dict[str, Any]:
    repositories = sibling_repositories(workspace_root)
    manifests_by_path: dict[Path, dict[str, Any]] = {}
    packages: list[tuple[str, Path, dict[str, Any], str]] = []
    package_repository: dict[str, str] = {}

    for repository in repositories:
        repository_path = workspace_root / repository
        for manifest_path in cargo_manifests(repository_path):
            try:
                manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError) as error:
                print(f"warning: skipping {manifest_path}: {error}")
                continue
            manifests_by_path[manifest_path] = manifest
            package_name = manifest.get("package", {}).get("name")
            if not package_name:
                continue
            previous = package_repository.get(package_name)
            if previous and previous != repository:
                raise ValueError(
                    f"crate {package_name!r} occurs in both {previous!r} and {repository!r}"
                )
            package_repository[package_name] = repository
            packages.append((repository, manifest_path, manifest, package_name))

    edges: list[dict[str, Any]] = []
    seen_edges: set[tuple[Any, ...]] = set()
    for repository, manifest_path, manifest, package_name in packages:
        workspace_dependencies = find_workspace_dependencies(
            manifest_path, workspace_root, manifests_by_path
        )
        for kind, target, dependencies in dependency_tables(manifest):
            for alias, original_specification in dependencies.items():
                specification = original_specification
                dependency_name = alias
                optional = False
                if isinstance(specification, dict):
                    if specification.get("workspace") is True and alias in workspace_dependencies:
                        specification = workspace_dependencies[alias]
                    if isinstance(specification, dict):
                        dependency_name = specification.get("package", alias)
                        optional = bool(specification.get("optional", False))

                dependency_repository = package_repository.get(dependency_name)
                if not dependency_repository or dependency_repository == repository:
                    continue
                edge = {
                    "src": repository,
                    "dst": dependency_repository,
                    "source_crate": package_name,
                    "dependency": dependency_name,
                    "alias": alias,
                    "kind": kind,
                    "target": target,
                    "optional": optional,
                    "manifest": str(manifest_path.relative_to(workspace_root / repository)),
                }
                edge_key = tuple(edge.items())
                if edge_key not in seen_edges:
                    seen_edges.add(edge_key)
                    edges.append(edge)

    return {
        "root": str(workspace_root),
        "repos": repositories,
        "packages": [
            {
                "repo": repository,
                "crate": package_name,
                "manifest": str(manifest_path.relative_to(workspace_root / repository)),
            }
            for repository, manifest_path, _, package_name in packages
        ],
        "edges": edges,
    }


def main() -> None:
    args = parse_args()
    workspace_root = args.workspace_root.resolve()
    output = args.output.resolve()
    graph = collect_graph(workspace_root)

    template_path = Path(__file__).with_name("dep-report-template.html")
    template = template_path.read_text(encoding="utf-8")
    if template.count("__DATA__") != 1:
        raise ValueError(f"expected one __DATA__ placeholder in {template_path}")

    serialized_graph = json.dumps(graph, separators=(",", ":")).replace("</", "<\\/")
    cycle_count = release_cycle_count(graph["repos"], graph["edges"])
    report = template.replace("__DATA__", serialized_graph).replace(
        '<b id="cycleCount">0</b>', f'<b id="cycleCount">{cycle_count}</b>'
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")

    release_links = len(
        {
            (edge["src"], edge["dst"])
            for edge in graph["edges"]
            if edge["kind"] != "dev"
        }
    )
    print(
        f"wrote {output} ({len(graph['repos'])} repositories, "
        f"{len(graph['packages'])} crates, {release_links} release links, "
        f"{cycle_count} release cycles)"
    )


if __name__ == "__main__":
    main()
