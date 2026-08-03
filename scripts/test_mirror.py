"""Tests for mirror.py. Run with: python -m unittest test_mirror -v"""
import pathlib
import tempfile
import unittest

import mirror


def _write(path: pathlib.Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


class MirrorTest(unittest.TestCase):
    def _make_source_tree(self, tmp: pathlib.Path):
        client_dir = tmp / "client"
        a_content = b"pub struct A {\r\n    x: u8,\r\n}\r\n"
        b_content = b"pub struct B;\n"
        _write(client_dir / "src" / "a" / "b.rs", a_content)
        _write(client_dir / "src" / "c.rs", b_content)
        file_list = client_dir / "scripts" / "mirror_files.txt"
        _write(
            file_list,
            b"# a comment\n\nsrc/a/b.rs\nsrc/c.rs\n",
        )
        return client_dir, file_list, a_content, b_content

    def test_copies_files_to_same_relative_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            client_dir, file_list, _, _ = self._make_source_tree(tmp)
            out_dir = tmp / "out"
            mirror.run(client_dir, file_list, out_dir, "v0.0.1-test")
            self.assertTrue((out_dir / "src" / "a" / "b.rs").exists())
            self.assertTrue((out_dir / "src" / "c.rs").exists())

    def test_header_is_prepended_naming_tag(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            client_dir, file_list, _, _ = self._make_source_tree(tmp)
            out_dir = tmp / "out"
            mirror.run(client_dir, file_list, out_dir, "v0.0.1-test")
            generated = (out_dir / "src" / "c.rs").read_bytes().decode("utf-8")
            self.assertIn("GENERATED FILE - DO NOT EDIT", generated)
            self.assertIn("v0.0.1-test", generated)

    def test_body_after_header_is_byte_identical_to_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            client_dir, file_list, a_content, b_content = self._make_source_tree(tmp)
            out_dir = tmp / "out"
            mirror.run(client_dir, file_list, out_dir, "v0.0.1-test")

            generated_a = (out_dir / "src" / "a" / "b.rs").read_bytes()
            header, body = mirror.split_header(generated_a)
            self.assertEqual(body, a_content)

            generated_b = (out_dir / "src" / "c.rs").read_bytes()
            header, body = mirror.split_header(generated_b)
            self.assertEqual(body, b_content)

    def test_mirror_toml_records_tag_files_and_line_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            client_dir, file_list, a_content, b_content = self._make_source_tree(tmp)
            out_dir = tmp / "out"
            mirror.run(client_dir, file_list, out_dir, "v0.0.1-test")

            toml_text = (out_dir / "mirror.toml").read_text(encoding="utf-8")
            self.assertIn('source_tag = "v0.0.1-test"', toml_text)
            self.assertIn("src/a/b.rs", toml_text)
            self.assertIn("src/c.rs", toml_text)
            self.assertIn(str(a_content.count(b"\n")), toml_text)
            self.assertIn(str(b_content.count(b"\n")), toml_text)

    def test_missing_file_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            client_dir, file_list, _, _ = self._make_source_tree(tmp)
            _write(file_list, b"src/a/b.rs\nsrc/does_not_exist.rs\n")
            out_dir = tmp / "out"
            with self.assertRaises(FileNotFoundError):
                mirror.run(client_dir, file_list, out_dir, "v0.0.1-test")

    def test_comments_and_blank_lines_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            client_dir, file_list, _, _ = self._make_source_tree(tmp)
            paths = mirror.parse_file_list(file_list)
            self.assertEqual(paths, ["src/a/b.rs", "src/c.rs"])


if __name__ == "__main__":
    unittest.main()
