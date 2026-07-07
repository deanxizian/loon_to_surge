from __future__ import annotations

import base64
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from convert_kelee_to_surge import convert_file, convert_mock_response_options  # noqa: E402


class ConvertMockResponseOptionsTest(unittest.TestCase):
    def test_json_mock_body_is_encoded_as_surge_base64_data(self) -> None:
        body = '{"code":0,"msg":""}'
        encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")

        converted = convert_mock_response_options(f'data-type=json data="{body}" status-code=200')

        self.assertEqual(
            converted,
            f'data-type=base64 data="{encoded}" status-code=200 header="Content-Type:application/json"',
        )

    def test_loon_base64_mock_flag_becomes_surge_base64_data_type(self) -> None:
        converted = convert_mock_response_options('data-type=text data="AAAAAAA=" mock-data-is-base64=true')

        self.assertEqual(converted, 'data-type=base64 data="AAAAAAA=" status-code=200')


class ConvertFileTest(unittest.TestCase):
    def convert_lpx(self, content: str) -> tuple[str, list[dict[str, str]]]:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "Sample.lpx"
            output_root = root / "Surge"
            output_root.mkdir()
            input_path.write_text(content, encoding="utf-8")

            report: list[dict[str, str]] = []
            manifest = convert_file(input_path, output_root, report, {})
            output = (output_root / manifest["output"]).read_text(encoding="utf-8")
            return output, report

    def test_proxy_policy_rules_are_preserved_as_external_policy(self) -> None:
        output, report = self.convert_lpx(
            """#!name=Sample

[Rule]
DOMAIN,proxy.example.com,PROXY
DOMAIN,ads.example.com,REJECT
"""
        )

        self.assertIn("DOMAIN,proxy.example.com,PROXY,extended-matching", output)
        self.assertNotIn("DOMAIN,proxy.example.com,PROXY,extended-matching,pre-matching", output)
        self.assertIn("DOMAIN,ads.example.com,REJECT,extended-matching,pre-matching", output)
        self.assertEqual([item["kind"] for item in report], ["external-policy"])

    def test_enable_scripts_use_surge_comment_toggles(self) -> None:
        output, report = self.convert_lpx(
            """#!name=Sample

[Argument]
Capture=select, false, true, tag=Capture
Run=select, true, false, tag=Run
Cron=select, "0 1 * * *", "0 2 * * *", tag=Cron

[Script]
http-request ^https://capture.example.com script-path=https://example.com/capture.js, tag=Capture, enable={Capture}
http-response ^https://run.example.com script-path=https://example.com/run.js, tag=Run, enable={Run}
cron {Cron} script-path=https://example.com/cron.js, tag=Cron, enable={Run}
"""
        )

        self.assertIn("{{{Capture}}}Capture = type=http-request", output)
        self.assertIn("{{{Run}}}Run = type=http-response", output)
        self.assertIn("{{{Run}}}Cron = type=cron, cronexp={{{Cron}}}", output)
        self.assertIn('#!arguments=Capture:#,Run:,Cron:"0 1 * * *"', output)
        self.assertEqual(
            [item["kind"] for item in report],
            ["script-enable-toggle-emitted", "script-enable-toggle-emitted", "script-enable-toggle-emitted"],
        )

    def test_direct_disabled_enable_scripts_are_commented(self) -> None:
        output, report = self.convert_lpx(
            """#!name=Sample

[Script]
http-request ^https://off.example.com script-path=https://example.com/off.js, tag=Off, enable=false
http-response ^https://on.example.com script-path=https://example.com/on.js, tag=On, enable=true
"""
        )

        self.assertIn("#Off = type=http-request", output)
        self.assertIn("On = type=http-response", output)
        self.assertEqual(
            [item["kind"] for item in report],
            ["script-enable-direct-commented", "script-enable-direct-kept"],
        )

    def test_enable_argument_shared_with_script_argument_keeps_boolean_default(self) -> None:
        output, report = self.convert_lpx(
            """#!name=Sample

[Argument]
Feature=switch, false, true, tag=Feature

[Script]
http-request ^https://feature.example.com script-path=https://example.com/feature.js, tag=Feature, enable={Feature}
http-response ^https://main.example.com script-path=https://example.com/main.js, tag=Main, argument=[{Feature}]
"""
        )

        self.assertIn("#Feature = type=http-request", output)
        self.assertIn("Main = type=http-response", output)
        self.assertIn('argument="[{{{Feature}}}]"', output)
        self.assertIn("#!arguments=Feature:false", output)
        self.assertEqual([item["kind"] for item in report], ["script-enable-shared-commented"])


if __name__ == "__main__":
    unittest.main()
