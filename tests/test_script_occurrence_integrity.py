from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from convert_kelee_to_surge import convert_file, convert_kelee_to_surge
from validate_surge_modules import validate_surge_modules


class ScriptOccurrenceIntegrityTest(unittest.TestCase):
    def test_twelve_current_sources_preserve_all_explicit_http_tags_in_order(self):
        fixture = Path(__file__).parent / "fixtures" / "kelee-v2-quality" / "shared-http-names.json"
        cases = json.loads(fixture.read_text())["cases"]
        self.assertEqual(len(cases), 12)
        for case in cases:
            with self.subTest(source=case["source"]):
                output, report = self.convert("\n".join(case["script_lines"]))
                self.assertIsNotNone(output)
                script_lines = output.split("[Script]\n", 1)[1].strip().splitlines()
                self.assertEqual([line.partition(" = ")[0] for line in script_lines], case["expected_tags"])
                self.assertEqual([item["kind"] for item in report], ["script-http-name-shared"])

    def convert(self, scripts: str, arguments: str = ""):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "Sample.lpx"
            source.write_text("#!name=Sample\n" + arguments + "[Script]\n" + scripts + "\n")
            report = []
            result = convert_file(source, root, report, {})
            return (root / result["output"]).read_text() if result else None, report

    def test_duplicate_untagged_v2_lines_keep_distinct_occurrences(self):
        for trigger in ("request", "response"):
            with self.subTest(trigger=trigger):
                line = trigger + ' if ${url} ~= /example/ then script("https://example.com/a.js")'
                output, report = self.convert(line + "\n" + line)
                self.assertIn(f"{trigger} 1 = type=http-{trigger}", output)
                self.assertIn(f"{trigger} 2 = type=http-{trigger}", output)
                self.assertEqual(output.count("script-path=https://example.com/a.js"), 2)
                self.assertEqual(report, [])

    def test_mixed_legacy_and_repeated_v2_lines_keep_original_order(self):
        line = 'request if ${url} ~= /example/ then script("https://example.com/a.js")'
        legacy = 'http-request ^https://other/ script-path=https://example.com/legacy.js, tag=Legacy'
        output, report = self.convert(line + "\n" + legacy + "\n" + line)
        self.assertLess(output.index("request 1 ="), output.index("Legacy ="))
        self.assertLess(output.index("Legacy ="), output.index("request 3 ="))
        self.assertEqual(report, [])

    def test_repeated_identical_warp_occurrences_are_not_collapsed(self):
        line = 'generic then script("https://raw.githubusercontent.com/VirgilClyne/Cloudflare/main/js/1.1.1.1.panel.js")'
        output, report = self.convert(line + "\n" + line)
        self.assertIsNone(output)
        self.assertEqual([item["kind"] for item in report], ["module-excluded"])
        self.assertIn("multiple WARP", report[0]["message"])

    def test_explicit_http_tags_are_preserved_even_when_shared(self):
        line = 'request if ${url} ~= /example/ then script("https://example.com/a.js")'
        cases = (
            (line + ' with tag="Same"\n' + line + ' with tag="Same"', ""),
            (line + ' with tag="request 2"\n' + line, ""),
            (line + ' with tag="Same", enable=${Enabled}\n' + line + ' with tag="Same"',
             '[Argument]\nEnabled=switch,false,true\n'),
        )
        for scripts, arguments in cases:
            with self.subTest(scripts=scripts):
                output, report = self.convert(scripts, arguments)
                self.assertIsNotNone(output)
                self.assertEqual(output.count("script-path=https://example.com/a.js"), 2)
                expected_name = "request 2" if 'tag="request 2"' in scripts else "Same"
                self.assertEqual(output.count(expected_name + " ="), 2)
                self.assertNotIn("module-excluded", [item["kind"] for item in report])

    def test_staged_validation_preserves_explicit_shared_http_names(self):
        line = 'request if ${url} ~= /example/ then script("https://example.com/a.js") with tag="Same"'
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            (root / "Loon").mkdir()
            (root / "Loon" / "Sample.lpx").write_text("#!name=Sample\n[Script]\n" + line + "\n" + line + "\n")
            before = Path.cwd()
            try:
                os.chdir(root)
                convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
                self.assertEqual(validate_surge_modules("Loon", "Surge", "Surge/convert-report.json")["modules"], 1)
                module = root / "Surge" / "Sample.sgmodule"
                self.assertEqual(module.read_text().count("Same ="), 2)
            finally:
                os.chdir(before)
