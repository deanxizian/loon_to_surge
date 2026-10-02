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

from convert_kelee_to_surge import convert_kelee_to_surge, format_surge_argument_default
from validate_surge_modules import (
    SurgeValidationError, module_argument_features, module_arguments, validate_surge_modules,
)


@contextlib.contextmanager
def in_directory(path: Path):
    previous = Path.cwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(previous)


class ArgumentRequirementParsingTest(unittest.TestCase):
    def test_leading_literal_quotes_are_escaped_without_changing_the_default(self) -> None:
        for default in ('"quoted"', '"unterminated', '  "quoted"', '"folder\\'):
            with self.subTest(default=default):
                formatted = format_surge_argument_default(default)
                self.assertEqual(json.loads(formatted), default)
                errors = []
                self.assertEqual(module_argument_features('#!arguments=Value:' + formatted, 'Sample', errors),
                                 ({'Value'}, True))
                self.assertEqual(errors, [])

    def test_quoted_defaults_handle_embedded_commas_quotes_backslashes_and_colons(self) -> None:
        payloads = (
            r'Value:"one,two",Mode:compact',
            r'Value:"one,\"two\",folder\\",Mode:compact',
            r'Value:"https://example.com/a,b",Capture:#,Run',
            r'Plain:two words, Value: "one,two" ,Tail:end',
            r'Value:"optional quotes without comma",Mode:compact',
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                errors = []
                names, quoted = module_argument_features("#!arguments=" + payload, "Sample", errors)
                self.assertTrue(quoted)
                self.assertIn("Value", names)
                self.assertEqual(errors, [])
                old_api_errors = []
                self.assertEqual(module_arguments("#!arguments=" + payload, "Sample", old_api_errors), names)
                self.assertEqual(old_api_errors, [])

    def test_unquoted_defaults_and_unrelated_script_quotes_keep_old_parity(self) -> None:
        errors = []
        names, quoted = module_argument_features(
            '#!arguments=Mode:two words,URL:https://example.com,Capture:#,Run,Label:someone\'s label\n'
            '[Script]\nExample = type=cron, cronexp="0 0 * * *", argument="one,two"\n',
            "Sample", errors,
        )
        self.assertEqual(names, {"Mode", "URL", "Capture", "Run", "Label"})
        self.assertFalse(quoted)
        self.assertEqual(errors, [])
        self.assertEqual(module_argument_features("#!name=Sample\n", "Sample", []), (set(), False))

    def test_malformed_quoted_defaults_and_duplicate_names_are_rejected(self) -> None:
        for payload in (
            'Value:"one,two',
            'Value:"one,two"junk,Mode:compact',
            'Value:"one,two\\',
            'Value:"one,two",Value:again',
            'Value:plain,',
        ):
            with self.subTest(payload=payload):
                errors = []
                module_argument_features("#!arguments=" + payload, "Sample", errors)
                self.assertTrue(errors)


class ArgumentRequirementPublicationTest(unittest.TestCase):
    def publish(self, default: str, expected_requirement: str) -> None:
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            (root / "Loon").mkdir()
            (root / "Surge").mkdir()
            sentinel = root / "Surge" / "last-known-good.sgmodule"
            sentinel.write_text("last-known-good", encoding="utf-8")
            source = '#!name=ArgumentVersion\n[Argument]\nValue=input, ' + default + ', tag=Value\n'
            source += 'Plain=input, compact, tag=Plain\n[Script]\n'
            source += 'http-request ^https://example.com/value script-path=https://example.com/value.js, tag=ValueScript, argument={Value}\n'
            source += 'http-request ^https://example.com/plain script-path=https://example.com/plain.js, tag=PlainScript, argument={Plain}\n'
            (root / "Loon" / "ArgumentVersion.lpx").write_text(source, encoding="utf-8")
            with in_directory(root):
                # This is the real staged-validation/publication entry point,
                # not convert_file, which previously concealed the regression.
                convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
                self.assertFalse(sentinel.exists())
                module = root / "Surge" / "ArgumentVersion.sgmodule"
                output = module.read_text(encoding="utf-8")
                self.assertIn("#!requirement=" + expected_requirement + "\n", output)
                self.assertNotIn("[Body Rewrite]", output)
                self.assertNotIn("[Rule]", output)
                self.assertEqual(validate_surge_modules("Loon", "Surge", "Surge/convert-report.json")["modules"], 1)
                if expected_requirement == "CORE_VERSION>=6008000":
                    module.write_text(output.replace(expected_requirement, "CORE_VERSION>=20"), encoding="utf-8")
                    with self.assertRaisesRegex(SurgeValidationError, "expected #!requirement=CORE_VERSION>=6008000"):
                        validate_surge_modules("Loon", "Surge", "Surge/convert-report.json")

    def test_top_level_publishes_comma_default_with_modern_requirement(self) -> None:
        for default in ('"one,two"', r'"one,\"two\",folder\\"'):
            with self.subTest(default=default):
                self.publish(default, "CORE_VERSION>=6008000")

    def test_top_level_preserves_base_requirement_for_unquoted_defaults(self) -> None:
        for default in ('"two words"', 'compact', '"https://example.com/path"'):
            with self.subTest(default=default):
                self.publish(default, "CORE_VERSION>=20")

    def test_top_level_preserves_literal_leading_quotes_with_modern_requirement(self) -> None:
        for default in ("'\"quoted\"'", "'\"unterminated'", "'  \"quoted\"'"):
            with self.subTest(default=default):
                self.publish(default, "CORE_VERSION>=6008000")


if __name__ == "__main__":
    unittest.main()
