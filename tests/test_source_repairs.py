from __future__ import annotations

import base64
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import source_repairs
from source_repairs import APPLIED_REPORT_KIND, BLOCKING_REPORT_KIND, apply_reviewed_source_repairs
from source_quality import inspect_source_quality, validate_generated_json_mock
from loon_rewrite_v2 import V2Array, parse_rewrite_v2_line, parse_url_only_condition
from convert_kelee_to_surge import (
    SECTION_ORDER, convert_rewrite_line, tokenize_surge_line, v2_constant_string, v2_url_pattern,
)

FIXTURES = Path(__file__).parent / "fixtures/source-repairs"
PROVENANCE = json.loads((FIXTURES / "provenance.json").read_text(encoding="utf-8"))
REPAIRS = PROVENANCE["repairs"]


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def fixture_text(filename: str) -> str:
    return (FIXTURES / "upstream" / filename).read_text(encoding="utf-8")


def sections(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            result.setdefault(current, [])
        elif current and line and not line.startswith(("#", ";")):
            result[current].append(line)
    return result


def rewrite_outputs(filename: str, line: str) -> dict[str, list[str]]:
    output = {section: [] for section in SECTION_ORDER}
    report = []
    convert_rewrite_line(line, output, report, filename)
    if report:
        raise AssertionError(report)
    return output


class RepairPolicyTest(unittest.TestCase):
    def test_all_ten_exact_versions_repair_atomically_with_complete_provenance(self) -> None:
        self.assertEqual(len(REPAIRS), 10)
        changed_lines = 0
        for filename, evidence in REPAIRS.items():
            with self.subTest(file=filename):
                raw = fixture_text(filename)
                before_bytes = (FIXTURES / "upstream" / filename).read_bytes()
                self.assertEqual(digest(raw), evidence["source_sha256"])
                corrected, reports = apply_reviewed_source_repairs(filename, raw)
                self.assertEqual(digest(corrected), evidence["repaired_sha256"])
                self.assertEqual(len(reports), len(evidence["lines"]))
                raw_lines, fixed_lines = raw.splitlines(), corrected.splitlines()
                changed_numbers = {item["number"] for item in evidence["lines"]}
                self.assertEqual(len(raw_lines), len(fixed_lines))
                for number, (old, new) in enumerate(zip(raw_lines, fixed_lines), 1):
                    self.assertEqual(old != new, number in changed_numbers)
                for item, proof in zip(reports, evidence["lines"]):
                    self.assertEqual(item["kind"], APPLIED_REPORT_KIND)
                    self.assertEqual(item["source_sha256"], evidence["source_sha256"])
                    self.assertEqual(item["repaired_sha256"], evidence["repaired_sha256"])
                    self.assertEqual(item["baseline_sha256"], evidence["baseline_sha256"])
                    self.assertEqual(item["baseline_revision"], PROVENANCE["baseline_revision"])
                    self.assertEqual(item["original_line_sha256"], proof["original_sha256"])
                    self.assertEqual(item["replacement_line_sha256"], proof["replacement_sha256"])
                    self.assertEqual(item["line_number"], str(proof["number"]))
                    self.assertEqual(digest(fixed_lines[proof["number"] - 1]), proof["replacement_sha256"])
                self.assertEqual(inspect_source_quality(filename, sections(corrected), source_text=corrected), [])
                self.assertEqual((FIXTURES / "upstream" / filename).read_bytes(), before_bytes)
                self.assertEqual(apply_reviewed_source_repairs(filename, corrected), (corrected, []))
                changed_lines += len(reports)
        self.assertEqual(changed_lines, 15)

    def test_unknown_versions_fail_closed_without_partial_or_stale_repairs(self) -> None:
        for filename in REPAIRS:
            raw = fixture_text(filename)
            for changed in (raw + "\n# newer upstream version\n", raw.replace("#!name=", "#!name=Changed ", 1)):
                corrected, report = apply_reviewed_source_repairs(filename, changed)
                self.assertEqual(corrected, changed)
                self.assertEqual(len(report), 1)
                self.assertEqual(report[0]["kind"], BLOCKING_REPORT_KIND)
                self.assertEqual(report[0]["reason"], "unreviewed-source-version")

    def test_other_files_are_never_inferred_from_content(self) -> None:
        for filename in REPAIRS:
            raw = fixture_text(filename)
            self.assertEqual(apply_reviewed_source_repairs("Unrelated.lpx", raw), (raw, []))

    def test_known_baseline_hash_is_accepted_without_repair(self) -> None:
        filename = next(iter(REPAIRS))
        baseline = "verified baseline bytes for API contract\n"
        policy = replace(source_repairs._REPAIRS[filename], baseline_sha256=digest(baseline))
        with patch.dict(source_repairs._REPAIRS, {filename: policy}):
            self.assertEqual(apply_reviewed_source_repairs(filename, baseline), (baseline, []))

    def test_every_line_and_output_assertion_fails_closed_atomically(self) -> None:
        filename = "DiDi_remove_ads.lpx"  # Two repairs prove no partial application.
        raw = fixture_text(filename)
        original_policy = source_repairs._REPAIRS[filename]
        first, last = original_policy.lines
        bad_policies = (
            replace(original_policy, lines=(first, replace(last, original="wrong evidence"))),
            replace(original_policy, lines=(first, replace(last, original_sha256="0" * 64))),
            replace(original_policy, lines=(first, replace(last, replacement_sha256="0" * 64))),
            replace(original_policy, lines=(first, replace(last, number=99999))),
            replace(original_policy, lines=(first, first)),
            replace(original_policy, repaired_sha256="0" * 64),
        )
        for policy in bad_policies:
            with self.subTest(policy=policy.repaired_sha256):
                with patch.dict(source_repairs._REPAIRS, {filename: policy}):
                    corrected, report = apply_reviewed_source_repairs(filename, raw)
                self.assertEqual(corrected, raw)
                self.assertEqual(report[0]["kind"], BLOCKING_REPORT_KIND)
                self.assertEqual(report[0]["reason"], "repair-policy-mismatch")

    def test_no_network_or_external_program_execution_during_repairs(self) -> None:
        with patch("urllib.request.urlopen", side_effect=AssertionError("No fetching")), patch(
            "subprocess.run", side_effect=AssertionError("No execution")
        ):
            for filename in REPAIRS:
                _, reports = apply_reviewed_source_repairs(filename, fixture_text(filename))
                self.assertTrue(reports)


@unittest.skipUnless(shutil.which("jq"), "jq is required to exercise typed replacement semantics")
class RepairedJsonSemanticsTest(unittest.TestCase):
    def jq(self, program: str, value: object) -> object:
        result = subprocess.run(
            [shutil.which("jq"), "-c", program], input=json.dumps(value, ensure_ascii=False),
            text=True, capture_output=True, timeout=10, check=True,
        )
        return json.loads(result.stdout)

    def test_all_fifteen_type_replacements_preserve_types_and_missing_paths(self) -> None:
        count = 0
        for filename, evidence in REPAIRS.items():
            corrected, _ = apply_reviewed_source_repairs(filename, fixture_text(filename))
            for proof in evidence["lines"]:
                if "changes" not in proof:
                    continue
                line = corrected.splitlines()[proof["number"] - 1]
                rewrite = parse_rewrite_v2_line(line)
                self.assertEqual(rewrite.actions[0].name, "response.json.jq")
                program = v2_constant_string(rewrite.actions[0].arguments[0], "JQ")
                populated = {"untouched": {"keep": 1}}
                for change in proof["changes"]:
                    node = populated
                    parts = change["path"].split(".")
                    for part in parts[:-1]:
                        node = node.setdefault(part, {})
                    node[parts[-1]] = {"advert": 1}
                for value in (populated, {}, {"data": {}}, {"data": None}, {"data": "unchanged"}):
                    expected = copy.deepcopy(value)
                    for change in proof["changes"]:
                        node = expected
                        parts = change["path"].split(".")
                        for part in parts[:-1]:
                            node = node.get(part) if isinstance(node, dict) else None
                        if isinstance(node, dict) and parts[-1] in node:
                            node[parts[-1]] = {} if change["before_type"] == "object" else []
                    with self.subTest(file=filename, line=proof["number"], input=value):
                        self.assertEqual(self.jq(program, value), expected)
                count += len(proof["changes"])
        self.assertEqual(count, 15)

    def test_jiaxiao_restores_correct_guard_and_all_twelve_deletions(self) -> None:
        filename = "JiaXiaoDrive_remove_ads.lpx"
        proof = REPAIRS[filename]["lines"][0]
        corrected, _ = apply_reviewed_source_repairs(filename, fixture_text(filename))
        line = corrected.splitlines()[proof["number"] - 1]
        rewrite = parse_rewrite_v2_line(line)
        condition = parse_url_only_condition(rewrite.condition)
        self.assertEqual(condition.regex.pattern, proof["baseline_line"].split()[1])
        self.assertEqual(condition.regex.flags, "i")
        self.assertEqual(rewrite.actions[0].name, "response.json.delete")
        arguments = rewrite.actions[0].arguments
        self.assertEqual(len(arguments), 1)
        self.assertIsInstance(arguments[0], V2Array)
        actual_paths = [v2_constant_string(value, "path") for value in arguments[0].items]
        self.assertEqual(actual_paths, proof["deleted_paths"])
        self.assertEqual(len(actual_paths), 12)
        output = rewrite_outputs(filename, line)
        programs = [tokenize_surge_line(item)[2] for item in output["Body Rewrite"]]
        self.assertEqual(len(programs), 12)
        payload = {"result": {path.split(".")[-1]: "advert" for path in actual_paths}, "ok": True}
        payload["result"]["keep"] = 42
        self.assertEqual(self.jq(" | ".join(programs), payload), {"result": {"keep": 42}, "ok": True})
        self.assertEqual(self.jq(" | ".join(programs), {"ok": True}), {"ok": True})


class SfPayloadRestorationTest(unittest.TestCase):
    def test_full_verified_payload_replaces_only_its_exact_truncated_prefix(self) -> None:
        filename = "SF-Express_remove_ads.lpx"
        proof = REPAIRS[filename]["lines"][0]
        raw = fixture_text(filename)
        corrected, _ = apply_reviewed_source_repairs(filename, raw)
        before_line = raw.splitlines()[proof["number"] - 1]
        after_line = corrected.splitlines()[proof["number"] - 1]
        # Decode actual source strings independently of the Loon parser.
        before_args = json.loads("[" + before_line.split("response.body.mock(", 1)[1][:-1] + "]")
        after_args = json.loads("[" + after_line.split("response.body.mock(", 1)[1][:-1] + "]")
        self.assertEqual(before_args[::2], after_args[::2])
        self.assertEqual(after_args[::2], ["json", 200])
        self.assertTrue(after_args[1].startswith(before_args[1]))
        self.assertEqual(len(before_args[1].encode()), 446)
        self.assertEqual(len(after_args[1].encode()), 23756)
        self.assertEqual(digest(after_args[1]), proof["baseline_body_sha256"])
        self.assertEqual(len(json.loads(after_args[1])["obj"]), 3)
        self.assertEqual(before_line.split(" then ", 1)[0], after_line.split(" then ", 1)[0])
        output = rewrite_outputs(filename, after_line)
        self.assertEqual(len(output["Map Local"]), 1)
        tokens = tokenize_surge_line(output["Map Local"][0])
        options = dict(token.split("=", 1) for token in tokens[1:])
        self.assertEqual(options["header"], "Content-Type:application/json")
        self.assertEqual(options["status-code"], "200")
        body = base64.b64decode(options["data"], validate=True)
        self.assertEqual(hashlib.sha256(body).hexdigest(), proof["baseline_body_sha256"])
        validate_generated_json_mock(filename, tokens[0], body)


if __name__ == "__main__":
    unittest.main()
