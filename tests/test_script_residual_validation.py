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

from convert_kelee_to_surge import convert_kelee_to_surge
from validate_surge_modules import SurgeValidationError, validate_surge_modules


class ScriptResidualValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        (self.root / 'Loon').mkdir()
        (self.root / 'Loon' / 'Sample.lpx').write_text('''#!name=Sample
[Script]
cron "0 8 * * *" then script("https://example.com/a.js") with tag="Test"
''', encoding='utf-8')
        with contextlib.redirect_stdout(io.StringIO()):
            convert_kelee_to_surge('Loon', 'Surge', 'Surge/convert-report.json')

    def validate(self, properties: str, script_type: str = 'cron') -> dict:
        prefix = 'Test = type=' + script_type
        if script_type == 'cron':
            prefix += ', cronexp="0 8 * * *"'
        (self.root / 'Surge' / 'Sample.sgmodule').write_text(
            '#!name=Sample\n[Script]\n' + prefix + ', ' + properties + '\n',
            encoding='utf-8',
        )
        return validate_surge_modules('Loon', 'Surge', 'Surge/convert-report.json')

    def test_residual_options_outside_argument_are_detected_even_without_comma(self) -> None:
        for option in ('enable=true', 'enabled?=true', 'data-path=x', 'mock-data-is-base64=true'):
            for argument in ('', ', argument="enable=true,data-path=x"'):
                with self.subTest(option=option, argument=argument), self.assertRaisesRegex(SurgeValidationError, 'missing comma'):
                    self.validate('script-path=https://example.com/a.js ' + option + argument)

    def test_quoted_and_unquoted_argument_values_can_contain_loon_option_text(self) -> None:
        for argument in (
            '"enable=true,enabled?=true,data-path=x,mock-data-is-base64=true"',
            "'enable=true,data-path=x'",
            'enable=true&data-path=x',
            json.dumps('quoted "enable=true", backslash \\, data-path=x'),
        ):
            with self.subTest(argument=argument):
                summary = self.validate('script-path=https://example.com/a.js, argument=' + argument)
                self.assertEqual(summary['modules'], 1)

    def test_text_after_a_quoted_argument_is_not_exempted(self) -> None:
        for argument in ('"payload" enable=true', '"payload" enabled?=true', "'payload' data-path=x"):
            with self.subTest(argument=argument), self.assertRaisesRegex(SurgeValidationError, 'invalid quoted Script property'):
                self.validate('script-path=https://example.com/a.js, argument=' + argument)

    def test_supported_script_values_are_not_mistaken_for_option_keys(self) -> None:
        for text in ('enable=true', 'enabled?=true', 'data-path=x', 'mock-data-is-base64=true'):
            path = 'https://example.com/a.js?' + text
            for value in (path, json.dumps(path)):
                with self.subTest(value=value):
                    self.assertEqual(self.validate('script-path=' + value)['modules'], 1)
            for pattern in ('^' + text, '^GET /path ' + text, json.dumps('^GET /path ' + text)):
                with self.subTest(pattern=pattern):
                    summary = self.validate('script-path=https://example.com/a.js, pattern=' + pattern, 'http-response')
                    self.assertEqual(summary['modules'], 1)

    def test_text_after_other_quoted_properties_is_rejected(self) -> None:
        for suffix in ('enable=true', 'data-path=x'):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(SurgeValidationError, 'invalid quoted Script property'):
                self.validate('script-path="https://example.com/a.js" ' + suffix)

    def test_argument_contents_still_undergo_placeholder_validation(self) -> None:
        with self.assertRaisesRegex(SurgeValidationError, 'bare Loon argument placeholder'):
            self.validate('script-path=https://example.com/a.js, argument="{Mode}"')


if __name__ == '__main__':
    unittest.main()
