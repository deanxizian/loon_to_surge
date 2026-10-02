from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from convert_kelee_to_surge import FATAL_REPORT_KINDS, convert_file, convert_kelee_to_surge
from validate_surge_modules import validate_surge_modules


EMPTY_JQ = '[Rewrite]\nresponse if ${url} ~= /example/ then response.json.jq("")\n'
UNUSED_ARGUMENT = '[Argument]\nUnused=input, value, tag=Unused\n'
DISABLED_SCRIPT = ('[Script]\nresponse if ${url} ~= /example/ then script("https://example.com/a.js") '
                   'with tag="Disabled", enable=false\n')
VALID_RULE = '[Rule]\nDOMAIN,example.com,DIRECT\n'


@contextlib.contextmanager
def in_directory(path: Path):
    previous = Path.cwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(previous)


class EmptyModuleConversionTest(unittest.TestCase):
    def convert(self, body: str, *, metadata: str = "", prior_report=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            source = root / "Sample.lpx"
            source.write_text("#!name=Sample\n" + metadata + body, encoding="utf-8")
            report = list(prior_report or [])
            seen = {}
            with patch("urllib.request.urlopen", side_effect=AssertionError("No remote script execution or fetch needed")):
                result = convert_file(source, output, report, seen)
            files = {path.name: path.read_text(encoding="utf-8") for path in output.iterdir()}
            return result, report, files, seen

    def assert_excluded(self, body: str, *, expected_diagnostic: str | None = None):
        result, report, files, seen = self.convert(body)
        self.assertIsNone(result)
        self.assertEqual(files, {})
        self.assertEqual(seen, {})  # Never reserve a filename for excluded output.
        excluded = [item for item in report if item["kind"] == "module-excluded"]
        self.assertEqual(len(excluded), 1)
        self.assertEqual(excluded[0]["file"], "Sample.lpx")
        self.assertTrue(excluded[0]["message"])
        self.assertFalse(any(item["kind"] in FATAL_REPORT_KINDS for item in report))
        if expected_diagnostic:
            self.assertIn(expected_diagnostic, [item["kind"] for item in report])

    def test_noop_only_jq_is_excluded_after_preserving_skip_evidence(self):
        for body in (
            EMPTY_JQ,
            '[Rewrite]\nresponse if ${url} ~= /example/ then response.json.jq("   ")\n',
            "[Rewrite]\n^https://example.com response-body-json-jq ''\n",
        ):
            with self.subTest(body=body):
                self.assert_excluded(body, expected_diagnostic="rewrite-empty-skipped")

    def test_arguments_only_is_excluded_after_unused_argument_diagnostic(self):
        self.assert_excluded(UNUSED_ARGUMENT, expected_diagnostic="argument-unused-dropped")

    def test_metadata_and_empty_sections_are_excluded(self):
        for body in ("", "#!desc=Metadata only\n", "[Rewrite]\n# No active rules\n[Script]\n"):
            with self.subTest(body=body):
                self.assert_excluded(body)

    def test_static_disabled_script_definitions_remain_supported_output(self):
        legacy = ('[Script]\nhttp-response ^https://example.com script-path=https://example.com/a.js, '
                  'tag=Disabled, enable=false\n')
        for body in (DISABLED_SCRIPT, legacy):
            with self.subTest(body=body):
                result, report, files, _ = self.convert(body)
                self.assertIsNotNone(result)
                self.assertEqual(result["sections"], ["Script"])
                self.assertIn("#Disabled = type=http-response", files["Sample.sgmodule"])
                self.assertNotIn("module-excluded", [item["kind"] for item in report])

    def test_general_or_mitm_only_modules_are_not_metadata_only(self):
        for body, section in (("[General]\nreal-ip=example.com\n", "General"),
                              ("[MitM]\nhostname=example.com\n", "MITM")):
            with self.subTest(section=section):
                result, report, files, _ = self.convert(body)
                self.assertIsNotNone(result)
                self.assertEqual(result["sections"], [section])
                self.assertTrue(files)
                self.assertNotIn("module-excluded", [item["kind"] for item in report])

    def test_fatal_source_is_not_reclassified_as_empty_module_exclusion(self):
        cases = (
            ("[Argument]\nBroken=input\n", "", "argument-default"),
            ("", "#!system=unsupported-platform\n", "unsupported-system"),
            ("[MitM]\nhostname=\n", "", "mitm-unsupported"),
            ("[Unsupported]\nkey=value\n", "", "unsupported-section"),
            ('[Rewrite]\nresponse if ${url} ~= /example/ then response.json.delete("data[")\n', "", "unsupported-rewrite"),
            (EMPTY_JQ + 'response if ${url} ~= /example/ then broken_action()\n', "", "unsupported-rewrite"),
        )
        for body, metadata, fatal_kind in cases:
            with self.subTest(kind=fatal_kind):
                _, report, _, _ = self.convert(body, metadata=metadata)
                # convert_file retains its diagnostic-candidate contract. The
                # public batch entry point must reject these fatal reports;
                # emptiness must never downgrade them to a benign exclusion.
                self.assertIn(fatal_kind, [item["kind"] for item in report])
                self.assertNotIn("module-excluded", [item["kind"] for item in report])
                evidence = [item for item in report if item["kind"] == fatal_kind]
                self.assertTrue(all(item["file"] == "Sample.lpx" and item["line"] for item in evidence))

    def test_prior_invocation_fatal_report_does_not_hide_current_empty_diagnostic(self):
        old = {"file": "Sample.lpx", "kind": "unsupported-rewrite", "message": "prior invocation", "line": "old"}
        result, report, files, _ = self.convert(EMPTY_JQ, prior_report=[old])
        self.assertIsNone(result)
        self.assertEqual(files, {})
        self.assertEqual(report[0], old)
        self.assertEqual(sum(item["kind"] == "module-excluded" for item in report), 1)


class EmptyModulePublicationTest(unittest.TestCase):
    def publish(self, sources: dict[str, str], expected_converted: set[str]):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            (root / "Loon").mkdir()
            for name, body in sources.items():
                (root / "Loon" / name).write_text(f"#!name={Path(name).stem}\n" + body, encoding="utf-8")
            with in_directory(root):
                convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
                manifest = json.loads((root / "Surge/modules.index.json").read_text())
                report = json.loads((root / "Surge/convert-report.json").read_text())
                self.assertEqual({item["source"] for item in manifest}, expected_converted)
                self.assertEqual(report["converted"], len(expected_converted))
                self.assertEqual(report["excluded"], len(sources) - len(expected_converted))
                excluded = [item["file"] for item in report["items"] if item["kind"] == "module-excluded"]
                self.assertEqual(set(excluded), set(sources) - expected_converted)
                self.assertEqual(len(excluded), len(set(excluded)))
                self.assertEqual({path.name for path in (root / "Surge").glob("*.sgmodule")},
                                 {item["output"] for item in manifest})
                checked = validate_surge_modules("Loon", "Surge", "Surge/convert-report.json")
                self.assertEqual(checked["modules"], len(expected_converted))

    def test_mixed_batch_publishes_supported_modules_and_explicit_empty_exclusions(self):
        self.publish({
            "Good.lpx": VALID_RULE,
            "Noop.lpx": EMPTY_JQ,
            "Unused.lpx": UNUSED_ARGUMENT,
            "Metadata.lpx": "#!desc=Metadata only\n",
            "Disabled.lpx": DISABLED_SCRIPT,
        }, {"Good.lpx", "Disabled.lpx"})

    def test_noop_only_batch_publishes_empty_manifest_with_explicit_exclusion(self):
        self.publish({"Noop.lpx": EMPTY_JQ}, set())

    def test_malformed_empty_source_still_aborts_batch_and_preserves_previous_output(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            (root / "Loon").mkdir()
            (root / "Surge").mkdir()
            (root / "Loon/Good.lpx").write_text("#!name=Good\n" + VALID_RULE)
            (root / "Loon/Noop.lpx").write_text("#!name=Noop\n" + EMPTY_JQ)
            (root / "Loon/Broken.lpx").write_text("#!name=Broken\n#!system=unsupported-platform\n")
            sentinel = root / "Surge/previous.sgmodule"
            sentinel.write_bytes(b"last-known-good")
            with in_directory(root):
                with self.assertRaisesRegex(RuntimeError, "unsupported-system"):
                    convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
            self.assertEqual(list((root / "Surge").iterdir()), [sentinel])
            self.assertEqual(sentinel.read_bytes(), b"last-known-good")


if __name__ == "__main__":
    unittest.main()
