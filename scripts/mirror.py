"""Publishes the client's contract files into a mirror tree, verbatim.

No parsing, no regex on Rust, no AST, no line scanning, no markers: this script
only copies whole files listed in mirror_files.txt and prepends a header. That
restraint is the point -- Stage 1 restructured the crate precisely so the
wire contract lives in files that can be copied byte for byte.
"""
import argparse
import pathlib
import re

# One git dependency's inline table. Nothing nests braces inside one, so `[^}]`
# is enough to keep a match from swallowing the next dep.
GIT_DEP_RE = re.compile(r'\{[^}]*?git = "(?P<url>[^"]+)"[^}]*\}', re.DOTALL)
# How a dep names its git ref. Only `tag` survives into the mirror.
REF_RE = re.compile(r'(?:tag|branch|rev) = "[^"]*"')
LEFTOVER_REF_RE = re.compile(r',?\s*(?:branch|rev) = "[^"]*"')

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


def _normalize_url(url: str) -> str:
    return url.rstrip("/").removesuffix(".git")


def _client_tags(client_cargo: pathlib.Path) -> dict[str, str]:
    tags = {}
    for entry in GIT_DEP_RE.finditer(client_cargo.read_text(encoding="utf-8")):
        ref = REF_RE.search(entry.group(0))
        if ref and ref.group(0).startswith("tag"):
            tags[_normalize_url(entry.group("url"))] = ref.group(0).split('"')[1]
    return tags


def sync_dep_tags(client_cargo: pathlib.Path, mirror_cargo: pathlib.Path, release_tag: str) -> None:
    """Repin every git dep in the mirror to a tag.

    The mirror shares its dependency set with the client, so a mirror left on
    last release's tags compiles the copied files against the wrong types. Tags
    are copied per-URL, not blanket-set: deps the client holds back
    (bitcoin-script at v0.6.0) must stay held back.

    A published crate must not float, so a dep the client tracks by branch, by
    rev, or by nothing at all does not carry that over -- it is pinned to the
    release tag, which the sibling repos cut in lockstep with the client.
    """
    client_tags = _client_tags(client_cargo)

    def repin(match: re.Match) -> str:
        entry = match.group(0)
        tag = f'tag = "{client_tags.get(_normalize_url(match.group("url")), release_tag)}"'
        entry, replaced = REF_RE.subn(tag, entry, count=1)
        if not replaced:
            entry = entry[:-1].rstrip().rstrip(",") + f", {tag} }}"
        # A dep may name both a branch and a rev; the leftover would conflict.
        return LEFTOVER_REF_RE.sub("", entry)

    text = mirror_cargo.read_text(encoding="utf-8")
    mirror_cargo.write_text(GIT_DEP_RE.sub(repin, text), encoding="utf-8")


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

    mirror_cargo = out_dir / "Cargo.toml"
    if mirror_cargo.is_file():
        sync_dep_tags(client_dir / "Cargo.toml", mirror_cargo, tag)


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
