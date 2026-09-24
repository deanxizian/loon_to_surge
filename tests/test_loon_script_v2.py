from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from convert_kelee_to_surge import convert_file, convert_kelee_to_surge, prepare_script_v2
from loon_rewrite_v2 import V2Regex, V2UrlCondition
from loon_script_v2 import is_script_v2_line, parse_script_v2_line
from validate_surge_modules import validate_section_line, validate_surge_modules


@contextlib.contextmanager
def working_directory(path: Path):
    previous = Path.cwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(previous)


class ScriptV2Test(unittest.TestCase):
    def convert(self, text: str) -> tuple[str | None, list[dict[str, str]]]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "Sample.lpx"
            source.write_text("#!name=Sample\n" + text, encoding="utf-8")
            report = []
            manifest = convert_file(source, root, report, {})
            return (root / manifest["output"]).read_text(encoding="utf-8") if manifest else None, report

    def test_all_triggers_are_identified_without_misreading_legacy_strings(self) -> None:
        for head in ('request if ${url} == "https://example.com"', 'response if ${url} ~= /ads/',
                     'cron "0 8 * * *"', 'cron ${Cron}', 'generic', 'network-changed'):
            with self.subTest(head=head):
                self.assertTrue(is_script_v2_line(head + ' then script("https://example.com/a.js")'))
        for line in ('cron {Cron} script-path=https://example.com/a.js, argument="text then script(x)"',
                     'generic script-path=https://example.com/a.js, tag="then script(x)"',
                     'http-response ^https://example.com script-path=https://example.com/a.js'):
            self.assertFalse(is_script_v2_line(line))

    def test_http_scripts_keep_order_body_flags_timeout_and_string_type(self) -> None:
        output, report = self.convert(r'''
[Script]
request if ${url} ~= /^https:\/\/example.com\/(ads|banner)$/i then script("https://example.com/a.js", "source=plugin,a=b") with tag="First", requires_body=true, timeout=35, debug=true
response if ${url} == "https://example.com/config?key=a.b" then script(`https://example.com/b.js`) with tag="Second", binary_body_mode=true, requires_body=false
''')
        self.assertEqual(report, [])
        self.assertIn('First = type=http-request, pattern=(?i:^https:\\/\\/example.com\\/(ads|banner)$)', output)
        self.assertIn('timeout=35, requires-body=true, debug=true, argument="source=plugin,a=b"', output)
        self.assertIn('Second = type=http-response, pattern=^https://example\\.com/config\\?key=a\\.b$', output)
        self.assertIn('timeout=20, requires-body=false, binary-body-mode=true', output)
        self.assertLess(output.index('First ='), output.index('Second ='))

    def test_quoted_keywords_commas_and_parentheses_do_not_split_actions(self) -> None:
        script = parse_script_v2_line('cron "0 8 * * *" then script("https://example.com/a.js", `then with (a,b)`) with tag="then with"')
        name, parts = prepare_script_v2(script)
        self.assertEqual(name, 'then with')
        self.assertIn('argument="then with (a,b)"', parts)
        self.assertIn('cronexp="0 8 * * *"', parts)
        self.assertIn('timeout=300', parts)

    def test_cron_preserves_disable_and_explicit_empty_string_argument(self) -> None:
        output, report = self.convert('''
[Script]
cron "0 0 8 * * *" then script("https://example.com/a.js", "") with enable=false, tag="Daily", timeout=400
''')
        self.assertEqual(report, [])
        self.assertIn('#Daily = type=cron, cronexp="0 0 8 * * *"', output)
        self.assertIn('timeout=400, argument=""', output)

    def test_literal_json_argument_is_not_converted_to_plugin_placeholders(self) -> None:
        output, report = self.convert('''
[Script]
cron "0 8 * * *" then script("https://example.com/a.js", `{"key":"value"}`)
''')
        self.assertEqual(report, [])
        self.assertIn('argument="{\\"key\\":\\"value\\"}"', output)
        self.assertNotIn('{{{', output)

    def test_known_unsupported_features_exclude_before_other_conversion(self) -> None:
        cases = (
            'generic then script("https://example.com/a.js")',
            'network-changed then script("https://example.com/a.js")',
            'cron ${Cron} then script("https://example.com/a.js")',
            'cron "0 8 * * *" then script("https://example.com/a.js", {${Region}, ${Enabled}})',
            'cron "0 8 * * *" then script("https://example.com/a.js", "region=${Region}")',
            'cron "0 8 * * *" then script("https://example.com/a.js") with enable=${Enabled}',
            'cron "0 8 * * *" then script("relative.js")',
            'response if ${url} ~= /ads/ && ${response.status} == 200 then script("https://example.com/a.js")',
            'request if ${url} ~= /ads/im then script("https://example.com/a.js")',
            'request if ${url} ~= ${Pattern} then script("https://example.com/a.js")',
        )
        for line in cases:
            with self.subTest(line=line):
                output, report = self.convert('[General]\nfuture=value\n[Script]\n' + line)
                self.assertIsNone(output)
                self.assertEqual([item['kind'] for item in report], ['module-excluded'])
                self.assertEqual(report[0]['line'], line)

    def test_invalid_v2_remains_fatal_instead_of_becoming_an_exclusion(self) -> None:
        cases = (
            'request if ${url} ~= /ads/ then script("https://example.com/a.js") with timeout=0',
            'cron "0 8 * * *" then script("https://example.com/a.js") with debug="true"',
            'cron "0 8 * * *" then script("https://example.com/a.js") with tag="A", tag="A"',
            'cron "0 8 * * *" then script("https://example.com/a.js") with requires_body=true',
            'generic then script("https://example.com/a.js") with unknown=true',
            'network-changed then script("https://example.com/a.js", true)',
            'cron "0 8 * * *" then script("https://example.com/a.js") with',
            'cron "0 8 * * *" then script("https://example.com/a.js"',
            'cron "0 8 * * *" then script("")',
            'cron "0 8 * * *" then script("https://example.com/a.js") with timeout=' + '9' * 400,
            'request if ${url} ~= /ads/ii then script("https://example.com/a.js")',
            'request if ${url} ~= /ads/ as match then script("https://example.com/a.js")',
            'cron "70 8 * * *" then script("https://example.com/a.js")',
            'cron "*/0 8 * * *" then script("https://example.com/a.js")',
            'cron "0 8 * *" then script("https://example.com/a.js")',
        )
        for line in cases:
            with self.subTest(line=line):
                output, report = self.convert('[Script]\n' + line)
                self.assertIsNone(output)
                self.assertEqual([item['kind'] for item in report], ['unsupported-script'])

    def test_invalid_v2_keeps_previous_output_even_with_an_excluded_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(tmp)
            (root / 'Loon').mkdir()
            (root / 'Surge').mkdir()
            sentinel = root / 'Surge' / 'previous.sgmodule'
            sentinel.write_text('previous', encoding='utf-8')
            (root / 'Loon' / 'Invalid.lpx').write_text('''#!name=Invalid
[Script]
generic then script("https://example.com/a.js")
cron "0 8 * * *" then script("https://example.com/b.js") with timeout=-1
''', encoding='utf-8')
            with working_directory(root), self.assertRaisesRegex(RuntimeError, 'Invalid Script V2'):
                convert_kelee_to_surge('Loon', 'Surge', 'Surge/convert-report.json')
            self.assertEqual(sentinel.read_text(encoding='utf-8'), 'previous')

    def test_supported_and_excluded_v2_modules_pass_full_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(tmp)
            (root / 'Loon').mkdir()
            for name, script in {
                'HTTP': 'request if ${url} ~= /ads/i then script("https://example.com/a.js", "enable=true,data-path=x")',
                'Cron': 'cron "0 8 * * *" then script("https://example.com/b.js", `{"key":"value"}`) with enable=false',
                'Generic': 'generic then script("https://example.com/c.js")',
                'Network': 'network-changed then script("https://example.com/d.js")',
            }.items():
                (root / 'Loon' / f'{name}.lpx').write_text(f'#!name={name}\n[Script]\n{script}\n', encoding='utf-8')
            with working_directory(root):
                convert_kelee_to_surge('Loon', 'Surge', 'Surge/convert-report.json')
                summary = validate_surge_modules('Loon', 'Surge', 'Surge/convert-report.json')
            self.assertEqual(summary['modules'], 2)
            report = json.loads((root / 'Surge' / 'convert-report.json').read_text(encoding='utf-8'))
            self.assertEqual(report['excluded'], 2)

    def test_validator_still_rejects_an_actual_enable_option(self) -> None:
        errors = []
        validate_section_line('Test.sgmodule', 1, 'Script',
                              'Test = type=cron, cronexp="0 8 * * *", script-path=https://example.com/a.js, enable=true', errors)
        self.assertTrue(any('enable' in error for error in errors))


class URLIgnoreCaseTest(unittest.TestCase):
    def test_scoped_flag_keeps_matches_and_capture_numbers(self) -> None:
        from convert_kelee_to_surge import v2_url_pattern
        pattern = r'^https:\/\/example\.com\/(Ads|Banner)/(\d+)$'
        converted = v2_url_pattern(V2UrlCondition(V2Regex(pattern, 'i'), None))
        original = re.compile(pattern, re.IGNORECASE)
        result = re.compile(converted)
        for url in ('https://example.com/Ads/12', 'HTTPS://EXAMPLE.COM/bANNER/34', 'https://example.com/other/12'):
            before, after = original.search(url), result.search(url)
            self.assertEqual(bool(before), bool(after))
            if before:
                self.assertEqual(before.groups(), after.groups())

    def test_only_url_i_is_allowed(self) -> None:
        from convert_kelee_to_surge import UnverifiedRewriteV2RegexFlags, v2_regex_pattern, v2_url_pattern
        for flags in ('m', 's', 'im', 'is', 'ims'):
            with self.subTest(flags=flags), self.assertRaises(UnverifiedRewriteV2RegexFlags):
                v2_url_pattern(V2UrlCondition(V2Regex('ads', flags), None))
        with self.assertRaises(UnverifiedRewriteV2RegexFlags):
            v2_regex_pattern(V2Regex('ads', 'i'), 'Body regex')


if __name__ == '__main__':
    unittest.main()
