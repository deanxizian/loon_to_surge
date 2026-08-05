from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from convert_kelee_to_surge import convert_file, convert_kelee_to_surge, convert_mock_response_options  # noqa: E402
from loon_rewrite_v2 import RewriteV2Error, parse_rewrite_v2_line  # noqa: E402
from validate_surge_modules import validate_section_line, validate_surge_modules  # noqa: E402


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

    def test_empty_text_mock_gets_explicit_surge_data_and_content_type(self) -> None:
        converted = convert_mock_response_options("data-type=text")

        self.assertEqual(
            converted,
            'data-type=text data="" status-code=200 header="Content-Type:text/plain"',
        )

    def test_json_mock_file_keeps_json_content_type(self) -> None:
        converted = convert_mock_response_options(
            'data-type=json data-path="https://example.com/response.json" status-code=200'
        )

        self.assertEqual(
            converted,
            'data-type=file data="https://example.com/response.json" status-code=200 '
            'header="Content-Type:application/json"',
        )


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
            self.assertIsNotNone(manifest)
            assert manifest is not None
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

    def test_reject_200_maps_to_an_empty_body(self) -> None:
        output, report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
^https:\/\/ads\.example\.com reject-200
'''
        )

        self.assertIn('data-type=text data="" status-code=200', output)
        self.assertNotIn('data=" "', output)
        self.assertEqual(report, [])

    def test_json_replace_jq_guard_handles_missing_parent_paths(self) -> None:
        output, report = self.convert_lpx(
            """#!name=Sample

[Rewrite]
^https://api.example.com/config response-body-json-replace data.flags.enabled true
"""
        )

        self.assertIn(
            'http-response-jq ^https://api.example.com/config '
            '\'if (try (getpath(["data","flags"]) | has("enabled")) catch false) '
            'then (setpath(["data","flags","enabled"]; true)) else . end\'',
            output,
        )
        self.assertEqual(report, [])

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

    def test_generic_script_drops_loon_only_image_url(self) -> None:
        output, report = self.convert_lpx(
            """#!name=Sample
#!openUrl=https://example.com/loon-only-instructions

[Script]
generic script-path=https://kelee.one/Resource/JavaScript/NodeLinkCheck/NodeLinkCheck.js, timeout=10, tag=Panel, img-url=link.circle.system
"""
        )

        self.assertIn(
            "Panel = type=generic, "
            "script-path=https://kelee.one/Resource/JavaScript/NodeLinkCheck/NodeLinkCheck.js, timeout=10, "
            'argument="policy={{{Policy}}}"',
            output,
        )
        self.assertIn("#!arguments=Policy:PROXY", output)
        self.assertIn("#!desc=Checks the proxy chain for a Surge policy using Sub-Store node data.", output)
        self.assertNotIn("#!openUrl=", output)
        self.assertNotIn("img-url", output)
        self.assertEqual([item["kind"] for item in report], ["generic-script-adapted"])

    def test_generic_script_preserves_supported_properties_and_enable_toggle(self) -> None:
        output, report = self.convert_lpx(
            """#!name=Sample

[Argument]
Panel=select, true, false, tag=Panel
Mode=select, compact, full, tag=Mode

[Script]
generic script-path=https://kelee.one/Resource/JavaScript/NodeLinkCheck/NodeLinkCheck.js, tag=Panel, enable={Panel}, argument={Mode}, script-update-interval=3600, debug=true
"""
        )

        self.assertIn(
            '{{{Panel}}}Panel = type=generic, '
            'script-path=https://kelee.one/Resource/JavaScript/NodeLinkCheck/NodeLinkCheck.js, '
            'script-update-interval=3600, debug=true, argument="policy={{{Policy}}}&{{{Mode}}}"',
            output,
        )
        self.assertIn("#!arguments=Panel:,Mode:compact,Policy:PROXY", output)
        self.assertEqual(
            [item["kind"] for item in report],
            ["generic-script-adapted", "script-enable-toggle-emitted"],
        )

    def test_warp_generic_adds_a_linked_surge_panel(self) -> None:
        output, report = self.convert_lpx(
            """#!name=WARP
#!desc=Loon selected-node instructions

[Script]
generic script-path=https://raw.githubusercontent.com/VirgilClyne/Cloudflare/main/js/1.1.1.1.panel.js, timeout=10, tag=WARP INFO
"""
        )

        self.assertIn("#!desc=Displays WARP details for the current Surge route in an information panel.", output)
        self.assertIn("[Panel]", output)
        self.assertIn(
            'WARP INFO = title="WARP INFO", content="Refresh to query the current Surge route.", '
            "style=info, script-name=WARP INFO",
            output,
        )
        self.assertIn(
            "WARP INFO = type=generic, "
            "script-path=https://raw.githubusercontent.com/VirgilClyne/Cloudflare/main/js/1.1.1.1.panel.js, timeout=10",
            output,
        )
        self.assertEqual([item["kind"] for item in report], ["generic-script-adapted"])

    def test_unverified_generic_script_excludes_the_entire_module(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "Unknown.lpx"
            output_root = root / "Surge"
            output_root.mkdir()
            input_path.write_text(
                """#!name=Unknown

[Rule]
DOMAIN,example.com,REJECT

[Script]
generic script-path=https://example.com/unknown.js, tag=Unknown
""",
                encoding="utf-8",
            )
            report: list[dict[str, str]] = []

            manifest = convert_file(input_path, output_root, report, {})

            self.assertIsNone(manifest)
            self.assertEqual(list(output_root.glob("*.sgmodule")), [])
            self.assertEqual([item["kind"] for item in report], ["module-excluded"])
            self.assertIn("https://example.com/unknown.js", report[0]["message"])

    def test_unknown_or_incomplete_script_properties_are_fatal_reports(self) -> None:
        output, report = self.convert_lpx(
            """#!name=Sample

[Script]
http-response ^https://example.com tag=MissingPath, future-option=true
"""
        )

        self.assertNotIn("[Script]", output)
        self.assertEqual([item["kind"] for item in report], ["unsupported-script"])
        self.assertIn("future-option", report[0]["message"])
        self.assertIn("script-path", report[0]["message"])

    def test_identical_duplicate_script_property_is_deduplicated_and_reported(self) -> None:
        output, report = self.convert_lpx(
            """#!name=Sample

[Script]
http-request ^https://example.com script-path=https://example.com/a.js, timeout=300, timeout=300, tag=Sample
"""
        )

        self.assertIn("timeout=300", output)
        self.assertEqual(output.count("timeout=300"), 1)
        self.assertEqual([item["kind"] for item in report], ["script-property-corrected"])

    def test_conflicting_duplicate_script_property_is_a_fatal_report(self) -> None:
        output, report = self.convert_lpx(
            """#!name=Sample

[Script]
http-request ^https://example.com script-path=https://example.com/a.js, timeout=30, timeout=300, tag=Sample
"""
        )

        self.assertNotIn("[Script]", output)
        self.assertEqual([item["kind"] for item in report], ["unsupported-script"])
        self.assertIn("Conflicting duplicate", report[0]["message"])

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

    def test_rewrite_v2_redirect_preserves_arguments_and_url_captures(self) -> None:
        output, report = self.convert_lpx(
            r'''#!name=Telegram Redirect

[Argument]
app=select, "tg", "sg", tag=Client

[Rewrite]
request if ${url} ~= /^https:\/\/t\.me\/([A-Za-z0-9_-]+)\/?$/ as item then redirect(307, "${app}://resolve?domain=${item.1}")

[MitM]
hostname=t.me
'''
        )

        self.assertIn("#!arguments=app:\"tg\"", output)
        self.assertIn(
            r"^https:\/\/t\.me\/([A-Za-z0-9_-]+)\/?$ {{{app}}}://resolve?domain=$1 307",
            output,
        )
        self.assertIn("hostname = %APPEND% t.me", output)
        self.assertEqual(report, [])

    def test_rewrite_v2_header_arrays_preserve_set_and_action_order(self) -> None:
        output, report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
request if ${url} ~= /^https:\/\/api\.example\.com/ then request.header.set(["X-A", "X-B"], ["one", "two words"]) | request.header.del("Cookie")
'''
        )

        expected_lines = [
            r"http-request ^https:\/\/api\.example\.com header-del X-A",
            r"http-request ^https:\/\/api\.example\.com header-add X-A one",
            r"http-request ^https:\/\/api\.example\.com header-del X-B",
            r"http-request ^https:\/\/api\.example\.com header-add X-B 'two words'",
            r"http-request ^https:\/\/api\.example\.com header-del Cookie",
        ]
        positions = [output.index(line) for line in expected_lines]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(report, [])

    def test_rewrite_v2_body_and_json_actions_use_native_body_rewrite(self) -> None:
        body_output, body_report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
response if ${url} ~= /^https:\/\/api\.example\.com/ then response.body.replace(/"state":(false|0)/, "\"state\":true")
'''
        )
        self.assertIn(
            'http-response ^https:\\/\\/api\\.example\\.com \'"state":(false|0)\' \'"state":true\'',
            body_output,
        )
        self.assertEqual(body_report, [])

        json_output, json_report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
response if ${url} ~= /^https:\/\/api\.example\.com/ then response.json.add(["data.a", "data.b"], [1, true]) | response.json.delete(["data.ads", "data.tracking"])
'''
        )
        self.assertIn("'setpath([\"data\",\"a\"]; 1)'", json_output)
        self.assertIn("'setpath([\"data\",\"b\"]; true)'", json_output)
        self.assertIn("'delpaths([[\"data\",\"ads\"]])'", json_output)
        self.assertIn("'delpaths([[\"data\",\"tracking\"]])'", json_output)
        self.assertEqual(json_report, [])

    def test_rewrite_v2_mock_raw_string_keeps_pipes_and_commas(self) -> None:
        body = '{"code":0,"message":"a|b,c"}'
        encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
        output, report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
response if ${url} ~= /^https:\/\/api\.example\.com\/mock$/ then response.body.mock("json", `{"code":0,"message":"a|b,c"}`, 201)
'''
        )

        self.assertIn(
            f'data-type=base64 data="{encoded}" status-code=201 header="Content-Type:application/json"',
            output,
        )
        self.assertEqual(report, [])

    def test_rewrite_v2_complex_conditions_are_reported_instead_of_flattened(self) -> None:
        output, report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
response if ${url} ~= /^https:\/\/api\.example\.com/ && ${response.status} == 200 then response.header.set("X-Test", "true")
'''
        )

        self.assertNotIn("[Header Rewrite]", output)
        self.assertEqual([item["kind"] for item in report], ["unsupported-rewrite"])
        self.assertIn("single URL condition", report[0]["message"])

    def test_rewrite_v2_reject_actions_keep_status_body_and_content_type(self) -> None:
        text_output, text_report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
request if ${url} == "https://api.example.com/blocked" then reject(451, "Unavailable for legal reasons")
'''
        )
        encoded = base64.b64encode(b"Unavailable for legal reasons").decode("ascii")
        self.assertIn(
            f'^https://api\\.example\\.com/blocked$ data-type=base64 data="{encoded}" status-code=451 '
            'header="Content-Type:text/plain"',
            text_output,
        )
        self.assertEqual(text_report, [])

        json_output, json_report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
request if ${url} ~= /^https:\/\/api\.example\.com\/ads/ then reject_dict(204) | reject_array(200)
'''
        )
        self.assertNotIn("[Map Local]", json_output)
        self.assertEqual([item["kind"] for item in json_report], ["unsupported-rewrite"])
        self.assertIn("Multiple terminal", json_report[0]["message"])

    def test_rewrite_v2_parser_rejects_unescaped_string_quotes(self) -> None:
        with self.assertRaisesRegex(RewriteV2Error, "Unescaped double quote"):
            parse_rewrite_v2_line(
                r'request if ${url} ~= /example/ then request.header.set("X-Test", "one" "two")'
            )

    def test_rewrite_v2_capture_name_cannot_shadow_plugin_argument(self) -> None:
        output, report = self.convert_lpx(
            r'''#!name=Sample

[Argument]
item=select, "tg", "sg", tag=Client

[Rewrite]
request if ${url} ~= /^https:\/\/t\.me\/(.+)$/ as item then redirect(307, "${item}://resolve?domain=${item.1}")
'''
        )

        self.assertNotIn("[URL Rewrite]", output)
        self.assertEqual([item["kind"] for item in report], ["unsupported-rewrite"])
        self.assertIn("conflicts with a declared plugin argument", report[0]["message"])

    def test_rewrite_v2_url_capture_index_must_exist(self) -> None:
        output, report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
request if ${url} ~= /^https:\/\/t\.me\/(.+)$/ as item then redirect(307, "tg://resolve?domain=${item.2}")
'''
        )

        self.assertNotIn("[URL Rewrite]", output)
        self.assertEqual([item["kind"] for item in report], ["unsupported-rewrite"])
        self.assertIn("has 1 group", report[0]["message"])

    def test_rewrite_v2_url_action_rejects_legacy_dollar_capture_syntax(self) -> None:
        output, report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
request if ${url} ~= /^https:\/\/old\.example\/(.+)$/ as item then url.replace("https://new.example/$1")
'''
        )

        self.assertNotIn("[URL Rewrite]", output)
        self.assertEqual([item["kind"] for item in report], ["unsupported-rewrite"])
        self.assertIn("uses $n syntax", report[0]["message"])

    def test_empty_legacy_jq_is_skipped_and_reported(self) -> None:
        output, report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
^https:\/\/api\.example\.com response-body-json-jq ''
'''
        )

        self.assertNotIn("[Body Rewrite]", output)
        self.assertEqual([item["kind"] for item in report], ["rewrite-empty-skipped"])

    def test_mislabeled_json_delete_jq_is_preserved_as_one_expression(self) -> None:
        output, report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
^https:\/\/api\.example\.com response-body-json-del 'del(.data[] | select(.type == "guide"))'
'''
        )

        self.assertIn(
            'http-response-jq ^https:\\/\\/api\\.example\\.com \'del(.data[] | select(.type == "guide"))\'',
            output,
        )
        self.assertEqual([item["kind"] for item in report], ["rewrite-action-corrected"])

    def test_known_invalid_jq_binding_is_grouped(self) -> None:
        output, report = self.convert_lpx(
            r'''#!name=Sample

[Rewrite]
^https:\/\/api\.example\.com response-body-json-jq 'def namesToRemove:["A"];def clean:if type=="object"then with_entries(select(.value|(type=="object"and .name as $name|$name|IN(namesToRemove[])|not)))else .end;clean'
'''
        )

        self.assertIn(
            'type=="object" and (.name as $name|$name|IN(namesToRemove[])|not)',
            output,
        )
        self.assertEqual([item["kind"] for item in report], ["jq-expression-corrected"])

    def test_full_conversion_stops_before_replacing_output_on_fatal_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            loon = root / "Loon"
            surge = root / "Surge"
            loon.mkdir()
            surge.mkdir()
            (surge / "sentinel.sgmodule").write_text("existing", encoding="utf-8")
            (loon / "Sample.lpx").write_text(
                r'''#!name=Sample

[Rewrite]
request if ${request.method} == "POST" then reject_dict(200)
''',
                encoding="utf-8",
            )

            previous_cwd = Path.cwd()
            try:
                os.chdir(root)
                with self.assertRaisesRegex(RuntimeError, "Conversion stopped"):
                    convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
            finally:
                os.chdir(previous_cwd)

            self.assertEqual((surge / "sentinel.sgmodule").read_text(encoding="utf-8"), "existing")
            self.assertFalse((surge / "Sample.sgmodule").exists())

    def test_full_conversion_accounts_for_excluded_modules(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            loon = root / "Loon"
            loon.mkdir()
            (loon / "Regular.lpx").write_text(
                """#!name=Regular

[Rule]
DOMAIN,ads.example.com,REJECT
""",
                encoding="utf-8",
            )
            (loon / "Unknown.lpx").write_text(
                """#!name=Unknown

[Script]
generic script-path=https://example.com/unknown.js, tag=Unknown
""",
                encoding="utf-8",
            )

            previous_cwd = Path.cwd()
            try:
                os.chdir(root)
                convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
                summary = validate_surge_modules("Loon", "Surge", "Surge/convert-report.json")
            finally:
                os.chdir(previous_cwd)

            report = json.loads((root / "Surge" / "convert-report.json").read_text(encoding="utf-8"))
            manifest = json.loads((root / "Surge" / "modules.index.json").read_text(encoding="utf-8"))
            self.assertEqual(report["total"], 2)
            self.assertEqual(report["converted"], 1)
            self.assertEqual(report["excluded"], 1)
            self.assertEqual([item["kind"] for item in report["items"]], ["module-excluded"])
            self.assertEqual([item["source"] for item in manifest], ["Regular.lpx"])
            self.assertEqual(summary["modules"], 1)


class ValidateRuleLineTest(unittest.TestCase):
    def validate(self, line: str) -> list[str]:
        errors: list[str] = []
        validate_section_line("Sample.sgmodule", 1, "Rule", line, errors)
        return errors

    def test_rule_markers_accept_project_policy(self) -> None:
        self.assertEqual(self.validate("DOMAIN,proxy.example.com,PROXY,extended-matching"), [])
        self.assertEqual(
            self.validate("DOMAIN,ads.example.com,REJECT,extended-matching,pre-matching"),
            [],
        )
        self.assertEqual(self.validate("IP-CIDR,192.0.2.0/24,REJECT,no-resolve,pre-matching"), [])

    def test_rule_markers_reject_unsafe_combinations(self) -> None:
        self.assertTrue(any("extended-matching" in item for item in self.validate("DOMAIN,x.example,PROXY")))
        self.assertTrue(
            any(
                "non-REJECT" in item
                for item in self.validate("DOMAIN,x.example,PROXY,extended-matching,pre-matching")
            )
        )
        self.assertTrue(any("no-resolve" in item for item in self.validate("IP-CIDR,192.0.2.0/24,REJECT")))


class ValidateMapLocalLineTest(unittest.TestCase):
    def validate(self, line: str) -> list[str]:
        errors: list[str] = []
        validate_section_line("Sample.sgmodule", 1, "Map Local", line, errors)
        return errors

    def test_status_code_must_be_in_http_range(self) -> None:
        self.assertEqual(self.validate('^https://example.com data-type=text data="" status-code=204'), [])
        self.assertTrue(
            any(
                "status-code" in item
                for item in self.validate('^https://example.com data-type=text data="" status-code=999')
            )
        )


class ValidateScriptLineTest(unittest.TestCase):
    def validate(self, line: str) -> list[str]:
        errors: list[str] = []
        validate_section_line("Sample.sgmodule", 1, "Script", line, errors)
        return errors

    def test_script_shape_accepts_supported_properties(self) -> None:
        self.assertEqual(
            self.validate(
                "Filter = type=http-response, pattern=^https://example.com, "
                "script-path=https://example.com/filter.js, requires-body=true"
            ),
            [],
        )
        self.assertEqual(
            self.validate(
                'Job = type=cron, cronexp="0 1 * * *", script-path=https://example.com/job.js, timeout=10'
            ),
            [],
        )
        self.assertEqual(
            self.validate(
                "Panel = type=generic, "
                "script-path=https://raw.githubusercontent.com/VirgilClyne/Cloudflare/main/js/1.1.1.1.panel.js"
            ),
            [],
        )
        self.assertEqual(
            self.validate(
                "Panel = type=generic, "
                "script-path=https://kelee.one/Resource/JavaScript/NodeLinkCheck/NodeLinkCheck.js"
            ),
            [],
        )

    def test_script_shape_rejects_loon_only_or_missing_properties(self) -> None:
        self.assertTrue(
            any(
                "img-url" in item
                for item in self.validate(
                    "Panel = type=generic, script-path=https://example.com/panel.js, img-url=link.circle.system"
                )
            )
        )
        self.assertTrue(
            any("missing pattern" in item for item in self.validate("Filter = type=http-response, script-path=x.js"))
        )
        self.assertTrue(
            any(
                "not verified" in item
                for item in self.validate("Panel = type=generic, script-path=https://example.com/panel.js")
            )
        )

    def test_script_shape_rejects_invalid_boolean_or_engine_values(self) -> None:
        errors = self.validate(
            "Filter = type=http-response, pattern=^https://example.com, script-path=x.js, "
            "debug=yes, engine=node"
        )
        self.assertTrue(any("debug" in item for item in errors))
        self.assertTrue(any("engine" in item for item in errors))


class ValidatePanelLineTest(unittest.TestCase):
    def validate(self, line: str) -> list[str]:
        errors: list[str] = []
        validate_section_line("Sample.sgmodule", 1, "Panel", line, errors)
        return errors

    def test_panel_shape_requires_dynamic_panel_fields(self) -> None:
        self.assertEqual(
            self.validate(
                'WARP INFO = title="WARP INFO", content="Refresh", style=info, script-name=WARP INFO'
            ),
            [],
        )
        self.assertTrue(any("missing Panel" in item for item in self.validate('WARP = title="WARP"')))


if __name__ == "__main__":
    unittest.main()
