"""Publishes the client's contract files into a mirror tree, verbatim.

No parsing, no regex on Rust, no AST, no line scanning, no markers: this script
only copies whole files listed in mirror_files.txt and prepends a header. That
restraint is the point -- Stage 1 restructured the crate precisely so the
wire contract lives in files that can be copied byte for byte.
"""
import argparse
import pathlib

HEADER_TEMPLATE = (
    "// GENERATED FILE - DO NOT EDIT\n"
    "// Source: rust-bitvmx-client @ {tag}\n"
    "// Regenerate with scripts/mirror.py\n"
)


def parse_file_list(file_list: pathlib.Path) -> list[str]:
    lines = file_list.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def split_header(content: bytes) -> tuple[bytes, bytes]:
    marker = b"// Regenerate with scripts/mirror.py\n"
    idx = content.index(marker) + len(marker)
    return content[:idx], content[idx:]


def run(client_dir: pathlib.Path, file_list: pathlib.Path, out_dir: pathlib.Path, tag: str) -> None:
    rel_paths = parse_file_list(file_list)
    header = HEADER_TEMPLATE.format(tag=tag).encode("utf-8")
    line_counts = {}
    for rel_path in rel_paths:
        src = client_dir / rel_path
        if not src.is_file():
            raise FileNotFoundError(f"listed file not found: {rel_path}")
        body = src.read_bytes()
        dest = out_dir / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(header + body)
        line_counts[rel_path] = body.count(b"\n")

    toml_lines = [f'source_tag = "{tag}"', "", "[files]"]
    toml_lines += [f'"{rel_path}" = {count}' for rel_path, count in line_counts.items()]
    (out_dir / "mirror.toml").write_text("\n".join(toml_lines) + "\n", encoding="utf-8")


def main() -> None:
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--client-dir", type=pathlib.Path, default=repo_root)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()

    file_list = args.client_dir / "scripts" / "mirror_files.txt"
    run(args.client_dir, file_list, args.out, args.tag)


if __name__ == "__main__":
    main()
