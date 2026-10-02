from __future__ import annotations

import contextlib
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import convert_kelee_to_surge as converter
import script_v2_compat as compat
from validate_surge_modules import SurgeValidationError, validate_surge_modules


class ScriptQuotedRequirementTest(unittest.TestCase):
    @contextlib.contextmanager
    def publish(self, source: str):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            (root / "Loon").mkdir()
            (root / "Loon/Sample.lpx").write_text("#!name=Sample\n" + source, encoding="utf-8")
            try:
                os.chdir(root)
                converter.convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
                yield root / "Surge/Sample.sgmodule"
            finally:
                os.chdir(previous)

    def assert_modern_requirement(self, module: Path):
        output = module.read_text(encoding="utf-8")
        self.assertIn("#!requirement=CORE_VERSION>=6008000\n", output)
        self.assertEqual(validate_surge_modules("Loon", "Surge", "Surge/convert-report.json")["modules"], 1)
        # Independently reject missing and downgraded metadata on otherwise
        # unchanged output. This must not trust the converter or its report.
        for replacement in ("", "#!requirement=CORE_VERSION>=20\n"):
            module.write_text(output.replace("#!requirement=CORE_VERSION>=6008000\n", replacement), encoding="utf-8")
            with self.assertRaisesRegex(SurgeValidationError, "expected #!requirement=CORE_VERSION>=6008000"):
                validate_surge_modules("Loon", "Surge", "Surge/convert-report.json")
        module.write_text(output, encoding="utf-8")

    def test_v2_string_arguments_preserve_quotes_and_backslashes(self):
        for argument in ('a "quoted" value', r"C:\Proxy", 'one, "two"', 'tail\\'):
            with self.subTest(argument=argument):
                source = '[Script]\ncron "0 8 * * *" then script("https://example.com/a.js", '
                source += json.dumps(argument) + ')\n'
                with self.publish(source) as module:
                    self.assert_modern_requirement(module)
                    script = next(line for line in module.read_text().splitlines() if " = type=" in line)
                    fields = dict(part.strip().split("=", 1) for part in converter.split_top_level(script.split(" = ", 1)[1]))
                    self.assertEqual(json.loads(fields["argument"]), argument)

    def test_legacy_arguments_and_quoted_patterns_are_version_gated(self):
        cases = (
            'http-request ^https://example.com script-path=https://example.com/a.js, argument=\'{"enabled":true}\'',
            'http-request ^https://example.com/a,"b" script-path=https://example.com/a.js',
            r'http-request ^https://example.com script-path=https://example.com/a.js, argument="C:\\Proxy", enable=false',
        )
        for script in cases:
            with self.subTest(script=script), self.publish("[Script]\n" + script + "\n") as module:
                self.assert_modern_requirement(module)

    def test_unescaped_quotes_and_unquoted_regexes_keep_existing_requirements(self):
        cases = (
            ('[Script]\ncron "0 8 * * *" then script("https://example.com/a.js", "one,two")\n', None),
            (r'[Script]' + '\n' + r'http-request ^https://example\.com/\d+ script-path=https://example.com/a.js' + '\n', None),
            ('[Argument]\nValue=input, compact\n[Script]\nhttp-request ^https://example.com script-path=https://example.com/a.js, argument={Value}\n', "CORE_VERSION>=20"),
        )
        for source, requirement in cases:
            with self.subTest(source=source), self.publish(source) as module:
                output = module.read_text()
                requirements = [line for line in output.splitlines() if line.startswith("#!requirement=")]
                self.assertEqual(requirements, ["#!requirement=" + requirement] if requirement else [])

    def test_reviewed_object_arguments_require_modern_core(self):
        url = compat.BASE + "Spotify/Spotify_remove_ads.js"
        probe = b"// synthetic decoder-contract fixture; never executed\n"
        adapters = dict(compat.VERIFIED_OBJECT_ADAPTERS)
        adapters[url] = replace(adapters[url], sha256=hashlib.sha256(probe).hexdigest())
        source = '[Argument]\ntab=switch, false, true\n[Script]\n'
        source += f'response if ${{url}} ~= /ads/ then script("{url}", {{${{tab}}}})\n'
        with patch.object(compat, "VERIFIED_OBJECT_ADAPTERS", adapters), patch.object(converter, "fetch_script_source", return_value=probe):
            with self.publish(source) as module:
                self.assert_modern_requirement(module)
                self.assertIn(r'argument="{\"tab\":{{{tab}}}}"', module.read_text())

    def test_bad_requirement_cannot_replace_last_known_good_publication(self):
        source = '[Script]\ncron "0 8 * * *" then script("https://example.com/a.js", '
        source += json.dumps('a "quoted" value') + ')\n'
        with self.publish(source) as module:
            previous = module.read_bytes()
            with patch.object(converter, "surge_module_requirement", return_value=None):
                with self.assertRaisesRegex(SurgeValidationError, "expected #!requirement=CORE_VERSION>=6008000"):
                    converter.convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
            self.assertEqual(module.read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
