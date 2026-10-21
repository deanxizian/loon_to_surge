"""Remote JQ comments must not swallow code when embedded in Surge."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import convert_kelee_to_surge as converter
from jq_program import compact_jq_program
from surge_syntax import tokenize_surge_line
from validate_surge_modules import validate_surge_modules

FIXTURE = Path(__file__).parent / "fixtures" / "jq-comments" / "amap-detail-minimal.jq"
URL = "https://example.com/fixture.jq"


@unittest.skipUnless(shutil.which("jq"), "real jq is required for semantic comparisons")
class JQProgramTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.network_guard = patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected network"))
        self.network_guard.start()
        self.addCleanup(self.network_guard.stop)

    def evaluate(self, program, value):
        path = self.root / "program.jq"
        path.write_text(program)
        result = subprocess.run(["jq", "-c", "-f", str(path)], input=json.dumps(value),
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [json.loads(line) for line in result.stdout.split("\n") if line]

    def assert_equivalent(self, program, value, expected):
        compacted = compact_jq_program(program)
        self.assertEqual(len(compacted.splitlines()), 1)
        self.assertEqual(self.evaluate(program, value), [expected])
        self.assertEqual(self.evaluate(compacted, value), [expected])
        return compacted

    def test_amap_comment_layout_preserves_filtering_and_order(self):
        value = {"data": {"modules": {"baseInfo": {"name": "A # place"}, "ad": 1, "anchor": {}},
                          "regions": ["baseInfo", "ad", None, 7, {"other": 1}, "anchor"]}}
        expected = {"data": {"modules": {"baseInfo": {"name": "A # place"}, "anchor": {}},
                             "regions": ["baseInfo", None, 7, {"other": 1}, "anchor"]}}
        compacted = self.assert_equivalent(FIXTURE.read_text(), value, expected)
        self.assertNotIn("#", compacted)
        for value in ({}, {"data": None}, {"data": "unchanged"}, {"data": []}, None):
            with self.subTest(value=value):
                self.assert_equivalent(FIXTURE.read_text(), value, value)

    def test_string_hashes_quotes_backslashes_and_whitespace_are_literal(self):
        values = ["https://example.com/#fragment", '  quote " # and spaces  ',
                  "backslash \\ # and \\( are literal", "trailing slash \\"]
        program = json.dumps(values) + " # remove the comment\n"
        self.assert_equivalent(program, None, values)

    def test_real_line_separators_inside_strings_are_preserved_as_escapes(self):
        value = "before\n# still a string\r\n  after\u2028line\u2029paragraph\x85next\vpage\f"
        program = '"' + value + '" # actual comment\n'
        self.assert_equivalent(program, None, value)

    def test_nested_interpolation_comments_and_strings(self):
        program = r'''"outer # \(
            ("inner # \(1 + # comment with misleading ) \" [
                2)")
        ) end" # trailing comment'''
        self.assert_equivalent(program, None, "outer # inner # 3 end")

    def test_interpolation_tracks_arrays_objects_and_parentheses(self):
        program = r'''"value \(({a: [1, # ) \" ] } are comment text
                                   2]}.a | add)) # literal"'''
        self.assert_equivalent(program, None, "value 3 # literal")

    def test_ambiguous_comment_continuations_are_rejected(self):
        for newline in ("\n", "\r\n"):
            for slashes in (1, 2, 3, 4):
                with self.subTest(newline=newline, slashes=slashes):
                    program = "[1, # continued " + "\\" * slashes + newline + "2," + newline + "3]"
                    if slashes % 2:
                        with self.assertRaisesRegex(ValueError, "version-dependent"):
                            compact_jq_program(program)
                    else:
                        # JQ 1.7 rejects raw CR outside comments; use LF for
                        # the cross-version execution oracle, then check CRLF
                        # produces exactly the same one-line program.
                        reference = program.replace("\r\n", "\n")
                        self.assert_equivalent(reference, None, [1, 2, 3])
                        self.assertEqual(compact_jq_program(program), compact_jq_program(reference))
        self.assert_equivalent("[1, 3] # EOF \\", None, [1, 3])

    def test_comment_only_and_existing_comment_free_layout(self):
        self.assertEqual(compact_jq_program("# comment\n # more\n"), "")
        original = '  def keep:  .;\n\n  keep | {"two spaces": "a  b"}  \n'
        self.assertEqual(compact_jq_program(original), 'def keep:  .; keep | {"two spaces": "a  b"}')

    def test_unterminated_or_mismatched_sources_are_rejected(self):
        for program in ('"unterminated', '"escape\\', '[1, # missing close', '[1)',
                        '"\\(1"', '"bad\\\nstring"', '.\u2028| .'):
            with self.subTest(program=program):
                with self.assertRaises(ValueError):
                    compact_jq_program(program)

    def source(self, syntax):
        folder = self.root / "Loon"
        folder.mkdir(exist_ok=True)
        rule = ('response if ${url} ~= /^https:\\/\\/example\\.com/ then response.json.jq_file("' + URL + '")'
                if syntax == "v2" else '^https://example.com response-body-json-jq jq-path=' + URL)
        path = folder / "Sample.lpx"
        path.write_text("#!name=Sample\n[Rewrite]\n" + rule + "\n")
        return path

    def publish(self):
        with contextlib.chdir(self.root), contextlib.redirect_stdout(io.StringIO()):
            converter.convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json", require_jq=True)

    def test_remote_download_cache_and_both_syntaxes_publish_equivalent_programs(self):
        raw = FIXTURE.read_bytes()
        value = {"data": {"modules": {"baseInfo": {}, "ad": {}}, "regions": ["ad", 0, "baseInfo"]}}
        for syntax in ("legacy", "v2"):
            with self.subTest(syntax=syntax), patch.dict(converter.JQ_PATH_CACHE, {}, clear=True):
                source = self.source(syntax)
                source_bytes = source.read_bytes()
                with patch("urllib.request.urlopen", return_value=io.BytesIO(raw)) as download:
                    self.publish()
                    self.assertEqual(download.call_count, 1)
                    self.assertEqual(converter.JQ_PATH_CACHE[URL], raw.decode())
                # The next conversion must also compact cached raw text.
                self.publish()
                output = (self.root / "Surge" / "Sample.sgmodule").read_text()
                line = next(line for line in output.splitlines() if line.startswith("http-response-jq "))
                expression = tokenize_surge_line(line)[2]
                self.assertEqual(self.evaluate(expression, value), self.evaluate(raw.decode(), value))
                self.assertEqual(source.read_bytes(), source_bytes)
                summary = validate_surge_modules(str(self.root / "Loon"), str(self.root / "Surge"),
                                                 str(self.root / "Surge" / "convert-report.json"), require_jq=True)
                self.assertEqual(summary["modules"], 1)
                self.assertTrue(summary["jq_compiled"])

    def test_invalid_remote_jq_preserves_previous_publication(self):
        for syntax in ("legacy", "v2"):
            with self.subTest(syntax=syntax), patch.dict(converter.JQ_PATH_CACHE, {}, clear=True):
                self.source(syntax)
                converter.JQ_PATH_CACHE[URL] = "."
                self.publish()
                before = {p.name: p.read_bytes() for p in (self.root / "Surge").iterdir()}
                # The lexer must not substitute for full JQ grammar validation.
                for invalid in ('[1, # missing close', 'if true then . else end', '[1, # ambiguous \\\n2,\n3]'):
                    converter.JQ_PATH_CACHE[URL] = invalid
                    with self.assertRaises(RuntimeError):
                        self.publish()
                    self.assertEqual(before, {p.name: p.read_bytes() for p in (self.root / "Surge").iterdir()})


if __name__ == "__main__":
    unittest.main()
