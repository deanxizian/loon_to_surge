from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from source_quality import (
    BLOCKING_REPORT_KIND, UNVERIFIED_REPORT_KIND, inspect_source_quality, validate_generated_json_mock,
)

FIXTURE = json.loads((Path(__file__).parent / "fixtures/kelee-v2-quality/source-cases.json").read_text(encoding="utf-8"))
CASES = FIXTURE["cases"]


def inspect(line: str, filename: str = "Sample.lpx") -> list[dict[str, str]]:
    return inspect_source_quality(filename, {"Rewrite": [line]})


def mock_line(body: str, *, encoded: bool = False, content_type: str = "json", phase: str = "response") -> str:
    action_args = [content_type, body]
    if phase == "response":
        action_args.extend([200, encoded])
    else:
        action_args.append(encoded)
    return rf'{phase} if ${{url}} ~= /^https:\/\/example.com/ then {phase}.body.mock(' + ", ".join(
        json.dumps(value, ensure_ascii=False) for value in action_args
    ) + ")"


class JsonMockQualityTest(unittest.TestCase):
    def test_real_sf_truncation_fails_independent_source_string_decoding(self) -> None:
        case = next(case for case in CASES if case["category"] == "invalid-json-mock")
        # The argument list is JSON-compatible. This oracle does not use the
        # Loon parser or converter and proves the corruption is in source bytes.
        arguments = json.loads("[" + case["line"].split("response.body.mock(", 1)[1][:-1] + "]")
        self.assertEqual([arguments[0], arguments[2]], ["json", 200])
        self.assertEqual(len(arguments[1].encode("utf-8")), 446)
        self.assertEqual(case["previous_body"]["utf8_bytes"], 23756)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(arguments[1])
        report = inspect(case["line"], case["file"])
        self.assertEqual(len(report), 1)
        self.assertEqual(report[0]["kind"], BLOCKING_REPORT_KIND)
        self.assertEqual(report[0]["reason"], "invalid-json-mock")
        self.assertIn("Unterminated string", report[0]["message"])

    def test_valid_plain_and_base64_json_are_accepted_for_both_phases(self) -> None:
        for value in ({"name": "中文", "items": []}, [], "string", None, True, 3.5):
            for phase in ("request", "response"):
                text = json.dumps(value, ensure_ascii=False)
                with self.subTest(value=value, phase=phase):
                    self.assertEqual(inspect(mock_line(text, phase=phase)), [])
                    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
                    self.assertEqual(inspect(mock_line(encoded, encoded=True, phase=phase)), [])

    def test_invalid_plain_and_base64_json_fail_closed(self) -> None:
        bodies = ("", "{", '{"broken":', '{"n":NaN}', "Infinity", "-Infinity", '{} trailing', '[1,]')
        for body in bodies:
            for encoded in (False, True):
                with self.subTest(body=body, encoded=encoded):
                    value = base64.b64encode(body.encode()).decode() if encoded else body
                    report = inspect(mock_line(value, encoded=encoded))
                    self.assertEqual(report[0]["kind"], BLOCKING_REPORT_KIND)
                    self.assertEqual(report[0]["reason"], "invalid-json-mock")

    def test_invalid_base64_and_non_utf8_bytes_fail_closed(self) -> None:
        for body in ("%not-base64", "e30", "e3 0=", base64.b64encode(b'\xff').decode()):
            with self.subTest(body=body):
                self.assertEqual(inspect(mock_line(body, encoded=True))[0]["kind"], BLOCKING_REPORT_KIND)

    def test_plain_invalid_utf8_and_corrected_sf_payload(self) -> None:
        self.assertEqual(inspect(mock_line('"\ud800"'))[0]["kind"], BLOCKING_REPORT_KIND)
        case = next(case for case in CASES if case["category"] == "invalid-json-mock")
        corrected = case["line"].split(" then ", 1)[0] + ' then response.body.mock("json", "{}", 200)'
        self.assertEqual(inspect(corrected, case["file"]), [])

    def test_non_json_content_types_are_not_misclassified(self) -> None:
        for content_type in ("text", "html", "png", "plain"):
            self.assertEqual(inspect(mock_line("not JSON {", content_type=content_type)), [])

    def test_raw_string_json_and_dynamic_scope_are_explicit(self) -> None:
        self.assertEqual(inspect('response if ${url} ~= /x/ then response.body.mock("json", `{"a":"${literal}"}`)'), [])
        for line, reason in (
            ('response if ${url} ~= /x/ then response.body.mock("json", "${body}")', "dynamic-json-not-validated"),
            ('response if ${url} ~= /x/ then response.body.mock("json", "{}", 200, ${encoded})', "dynamic-encoding-not-validated"),
            ('response if ${url} ~= /x/ then response.body.mock(${type}, "{}")', "dynamic-mock-content-type"),
        ):
            with self.subTest(line=line):
                report = inspect(line)
                self.assertEqual(report[0]["kind"], UNVERIFIED_REPORT_KIND)
                self.assertEqual(report[0]["reason"], reason)

    def test_remote_json_is_scope_warning_and_never_downloaded(self) -> None:
        with patch("urllib.request.urlopen", side_effect=AssertionError("No network allowed")), patch(
            "subprocess.run", side_effect=AssertionError("No script execution allowed")
        ):
            for location in ("https://example.com/mock.json", "resources/mock.json"):
                report = inspect(f'response if ${{url}} ~= /x/ then response.body.mock_file("json", "{location}")')
                self.assertEqual(report[0]["kind"], UNVERIFIED_REPORT_KIND)
                self.assertEqual(report[0]["reason"], "remote-runtime-not-validated")

    def test_known_chelaile_framing_is_validated_inside_precise_scope(self) -> None:
        cases = [case for case in CASES if case["category"] == "framed-json-protocol"]
        self.assertEqual(len(cases), 6)
        for case in cases:
            with self.subTest(line=case["line_number"]):
                self.assertIn("**YGKJ", case["previous_line"])
                self.assertIn("YGKJ##", case["previous_line"])
                self.assertEqual(inspect(case["line"], case["file"]), [])
                self.assertEqual(inspect(case["line"], "Unrelated.lpx")[0]["kind"], BLOCKING_REPORT_KIND)
                changed_scope = case["line"].replace("chelaile", "different", 1)
                self.assertEqual(inspect(changed_scope, case["file"])[0]["kind"], BLOCKING_REPORT_KIND)
                broken_json = case["line"].replace("**YGKJ", "**YGKJbroken", 1)
                self.assertEqual(inspect(broken_json, case["file"])[0]["kind"], BLOCKING_REPORT_KIND)
                broken_frame = case["line"].replace("YGKJ##", "YGKJ#", 1)
                self.assertEqual(inspect(broken_frame, case["file"])[0]["kind"], BLOCKING_REPORT_KIND)

    def test_chelaile_base64_still_requires_valid_inner_json(self) -> None:
        case = next(case for case in CASES if case["category"] == "framed-json-protocol")
        prefix = case["line"].split(" then ", 1)[0]
        for payload, expected_count in (("**YGKJ{}YGKJ##", 0), ("**YGKJ{YGKJ##", 1)):
            encoded = base64.b64encode(payload.encode()).decode()
            line = prefix + f' then response.body.mock("json", "{encoded}", 200, true)'
            self.assertEqual(len(inspect(line, case["file"])), expected_count)


class KnownMigrationDriftTest(unittest.TestCase):
    def test_all_real_known_replacements_are_blocked_with_baseline_provenance(self) -> None:
        count = 0
        files = set()
        for case in CASES:
            if case["category"] != "known-json-type-drift":
                continue
            with self.subTest(file=case["file"], line=case["line_number"]):
                self.assertEqual(hashlib.sha256(case["previous_line"].encode()).hexdigest(), case["previous_line_sha256"])
                report = inspect(case["line"], case["file"])
                self.assertEqual(len(report), len(case["changes"]))
                legacy_tokens = case["previous_line"].split(" response-body-json-replace ", 1)[1].split()
                legacy_values = dict(zip(legacy_tokens[::2], legacy_tokens[1::2]))
                for item, change in zip(report, case["changes"]):
                    baseline_value = json.loads(legacy_values[change["path"]])
                    self.assertEqual(type(baseline_value), dict if change["before_type"] == "object" else list)
                    self.assertEqual(len(baseline_value), 0)
                    self.assertEqual(item["kind"], BLOCKING_REPORT_KIND)
                    self.assertEqual(item["reason"], "known-json-type-drift")
                    self.assertIn(repr(change["path"]), item["message"])
                    self.assertIn(change["before_type"], item["message"])
                count += len(report)
                files.add(case["file"])
        self.assertEqual(count, 15)
        self.assertEqual(len(files), 8)

    def test_legitimate_string_values_are_not_globally_rejected_or_coerced(self) -> None:
        line = 'response if ${url} ~= /new-endpoint/ then response.json.replace(["data", "label"], ["{}", "[]"])'
        self.assertEqual(inspect(line, "BaiduMap_remove_ads.lpx"), [])
        for case in CASES:
            if case["category"] == "known-json-type-drift":
                self.assertEqual(inspect(case["line"], "NewPlugin.lpx"), [])

    def test_filename_scope_path_and_literal_each_narrow_the_known_match(self) -> None:
        case = next(case for case in CASES if case["file"] == "BaiduMap_remove_ads.lpx")
        for modified in (
            case["line"].replace("mine", "future-endpoint", 1),
            case["line"].replace('"data"', '"description"', 1),
            case["line"].replace('"{}"', '"a legitimate string"', 1),
            case["line"].replace('"{}"', 'null', 1),
        ):
            with self.subTest(line=modified):
                self.assertEqual(inspect(modified, case["file"]), [])

    def test_whitespace_and_raw_string_spelling_do_not_hide_same_known_drift(self) -> None:
        case = next(case for case in CASES if case["file"] == "BaiduMap_remove_ads.lpx")
        for modified in (
            "  " + case["line"] + "  ",
            case["line"].replace(" then ", "   then   ").replace(', ', ',    '),
            case["line"].replace('"{}"', '`{}`'),
        ):
            self.assertEqual(inspect(modified, case["file"])[0]["reason"], "known-json-type-drift")

    def test_corrected_explicit_jq_clears_known_blocker(self) -> None:
        for case in CASES:
            if case["category"] == "known-json-type-drift":
                corrected = case["line"].split(" then ", 1)[0] + ' then response.json.jq(".data = {}")'
                self.assertEqual(inspect(corrected, case["file"]), [])


class GeneratedJsonMockTest(unittest.TestCase):
    def test_plain_str_and_decoded_bytes_are_strictly_validated(self) -> None:
        for body in ('{"data":[]}', b'{"data":[]}', 'null', '"string"'):
            self.assertIsNone(validate_generated_json_mock("Sample.lpx", "^https://example.com", body))
        for body in ('{', b'\xff', 'NaN', '{} trailing'):
            with self.subTest(body_type=type(body).__name__):
                with self.assertRaises(ValueError):
                    validate_generated_json_mock("Sample.lpx", "^https://example.com", body)

    def test_parser_recursion_failure_is_reported_as_value_error(self) -> None:
        with patch("source_quality._validate_json", side_effect=RecursionError("nesting limit")):
            with self.assertRaisesRegex(ValueError, "nesting limit"):
                validate_generated_json_mock("Sample.lpx", "^https://example.com", "[]")

    def test_only_exact_legacy_and_scoped_chelaile_patterns_accept_framing(self) -> None:
        for case in CASES:
            if case["category"] != "framed-json-protocol":
                continue
            pattern = case["line"].split(" ~= /", 1)[1].split("/i then ", 1)[0]
            arguments = json.loads("[" + case["line"].split("response.body.mock(", 1)[1][:-1] + "]")
            for spelling in (pattern, f"(?i:{pattern})"):
                for body in (arguments[1], arguments[1].encode("utf-8")):
                    self.assertIsNone(validate_generated_json_mock(case["file"], spelling, body))
                with self.assertRaises(ValueError):
                    validate_generated_json_mock("Unrelated.lpx", spelling, arguments[1])
            for different in (f"(?s:{pattern})", f"(?i:{pattern})suffix", "new-scope", pattern + "$"):
                with self.assertRaises(ValueError):
                    validate_generated_json_mock(case["file"], different, arguments[1])
            for broken in ("**YGKJ{YGKJ##", "**YGKJ{}YGKJ#"):
                with self.assertRaises(ValueError):
                    validate_generated_json_mock(case["file"], pattern, broken)

    def test_sf_output_is_rejected_independently_of_source_guard_reports(self) -> None:
        case = next(case for case in CASES if case["category"] == "invalid-json-mock")
        arguments = json.loads("[" + case["line"].split("response.body.mock(", 1)[1][:-1] + "]")
        for body in (arguments[1], arguments[1].encode("utf-8")):
            with self.assertRaisesRegex(ValueError, "Unterminated string"):
                validate_generated_json_mock(case["file"], "unimportant-for-ordinary-json", body)


class DiagnosticContractTest(unittest.TestCase):
    def test_exact_line_numbers_duplicate_lines_case_insensitive_sections_no_mutation(self) -> None:
        line = mock_line("{")
        text = "#!name=Sample\n[Script]\n" + line + "\n[rEwRiTe]\n\n  " + line + "\n# comment\n" + line + "\n"
        sections = {"Script": [line], "rEwRiTe": [line, line]}
        before = copy.deepcopy(sections)
        report = inspect_source_quality("Sample.lpx", sections, source_text=text)
        self.assertEqual([item["line_number"] for item in report], ["6", "8"])
        self.assertEqual([item["line"] for item in report], [line, line])
        self.assertEqual(sections, before)

    def test_legacy_syntax_and_invalid_v2_still_belong_to_converter_validation(self) -> None:
        self.assertEqual(inspect('^https://example.com reject-dict'), [])
        self.assertEqual(inspect('response if ${url} ~= /x/ then response.body.mock("json", "unterminated)'), [])


if __name__ == "__main__":
    unittest.main()
