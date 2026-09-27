from __future__ import annotations

import itertools
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from convert_kelee_to_surge import convert_file, module_semantics_problem, v2_body_regex_pattern
from loon_rewrite_v2 import V2Regex
from regex_overlap import patterns_may_overlap
from validate_surge_modules import validate_section_line


class RegexDisjointnessTest(unittest.TestCase):
    def test_disjoint_domains_paths_branches_and_anchors(self) -> None:
        pairs = [
            (r"^https://api\.example\.com/ads", r"^https://other\.example\.com/ads"),
            (r"^https?://api\.example\.com/(ads|banner)/v\d+", r"^https?://api\.example\.com/(account|home)/v\d+"),
            (r"(?i:^https://api\.example\.com/ads$)", r"^https://api\.example\.com/ads/extra"),
            (r"^https://[a-z]+\.example\.com/v[0-9]+/ads", r"^https://[a-z]+\.example\.com/v[0-9]+/home"),
            (r"^https://(?:api-\w+|post)\.example\.com/(?:feed|config)", r"^https://(?:api-\w+|post)\.example\.com/(?:chat|user)"),
        ]
        for first, second in pairs:
            with self.subTest(first=first, second=second):
                self.assertFalse(patterns_may_overlap(first, second))
                self.assertFalse(patterns_may_overlap(second, first))

    def test_overlapping_patterns_are_not_treated_as_disjoint(self) -> None:
        pairs = [
            (r"^https://example\.com/api", r"^https://example\.com/api/v2"),
            (r"api", r"^https://example\.com/api"),
            (r"(?i:^https://example\.com/ADS$)", r"^https://example\.com/ads$"),
            (r"^https://example\.com/(ads|home)$", r"^https://example\.com/(account|ads)$"),
            (r"^https://example\.com/a{2,4}$", r"^https://example\.com/a{3}$"),
            (r"^https://example\.com/ad(?:s)?$", r"^https://example\.com/ad$"),
            (r"^https://example\.com/[^/]+$", r"^https://example\.com/ads$"),
        ]
        for first, second in pairs:
            with self.subTest(first=first, second=second):
                self.assertTrue(patterns_may_overlap(first, second))

    def test_unknown_icu_syntax_parameters_and_limits_fail_closed(self) -> None:
        for pattern in (
            r"^https://other/\p{L}+", r"^https://other/\Qliteral\E", r"^https://other/\v",
            r"^https://other/(?<name>a)\k<name>", r"^https://other/(a)\1",
            r"^https://other/[a-z&&[^x]]", r"^https://other/[a-z[a]]",
            r"^https://other/{{{path}}}", r"(?m)^https://other/", r"(?x)^https://other/",
            r"^https://other/中文", r"^https://other/a{1000}", "[invalid",
        ):
            with self.subTest(pattern=pattern):
                self.assertTrue(patterns_may_overlap(pattern, r"^https://example/api"))
        with patch("regex_overlap.MAX_PAIRS", 0):
            self.assertTrue(patterns_may_overlap(r"^https://example/a", r"^https://example/b"))

    def test_shared_matches_in_a_bounded_corpus_never_prove_disjoint(self) -> None:
        # An independent match oracle catches false safety verdicts across
        # anchors, alternatives, empty branches, repetitions and classes.
        patterns = [r"a", r"^a", r"a$", r"^a$", r"a*", r"a+", r"a?b", r"a{2,3}",
                    r"(a|b)c", r"(|ab)c", r"[ab]+", r"[^b]", r"\w", r"\d", r"\s", r"a.b"]
        samples = ["".join(chars) for n in range(4) for chars in itertools.product("abc1 \n", repeat=n)]
        matches = [{sample for sample in samples if re.search(pattern, sample, re.I)} for pattern in patterns]
        for a, b in itertools.combinations(range(len(patterns)), 2):
            if matches[a] & matches[b]:
                self.assertTrue(patterns_may_overlap(patterns[a], patterns[b]), (patterns[a], patterns[b]))


class ConversionSemanticsTest(unittest.TestCase):
    def convert(self, content: str) -> tuple[str | None, list[dict[str, str]]]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.lpx"
            source.write_text("#!name=Sample\n" + content)
            output = root / "out"
            output.mkdir()
            report: list[dict[str, str]] = []
            result = convert_file(source, output, report, {})
            return (output / result["output"]).read_text() if result else None, report

    def assert_excluded(self, content: str, message: str) -> None:
        output, report = self.convert(content)
        self.assertIsNone(output)
        self.assertEqual([entry["kind"] for entry in report], ["module-excluded"])
        self.assertIn(message, report[0]["message"])
        self.assertTrue(report[0]["line"])

    def test_legacy_http_defaults_and_explicit_timeouts(self) -> None:
        for kind in ("http-request", "http-response"):
            for setting, expected in (("", "10"), (", timeout=0.5", "0.5"), (", timeout=120", "120")):
                with self.subTest(kind=kind, setting=setting):
                    output, report = self.convert(f"[Script]\n{kind} ^https://example/ script-path=https://example/a.js{setting}\n")
                    self.assertEqual(report, [])
                    self.assertIn(f"timeout={expected}", output)
                    self.assertEqual(output.count("timeout="), 1)

    def test_legacy_disabled_script_gets_default_without_becoming_enabled(self) -> None:
        output, report = self.convert("[Script]\nhttp-response ^https://example/ script-path=https://example/a.js, enable=false, tag=Disabled\n")
        self.assertIn("#Disabled = type=http-response", output)
        self.assertIn("timeout=10", output)

    def test_v2_body_regex_flags_are_explicit_and_keep_capture_references(self) -> None:
        for flags in ("", "i", "m", "s", "im", "is", "ms", "ims"):
            with self.subTest(flags=flags):
                source = '[Rewrite]\nresponse if ${url} ~= /example/ then response.body.replace(/^(ad)$/, "$1")\n'
                source = source.replace('/^(ad)$/', '/^(ad)$/' + flags)
                output, report = self.convert(source)
                self.assertEqual(report, [])
                pattern = v2_body_regex_pattern(V2Regex("^(ad)$", flags), "body")
                self.assertIn(f"'{pattern}' '$1'", output)
        self.assertEqual(v2_body_regex_pattern(V2Regex("^ad$", ""), "body"), "(?-ims)^ad$")
        self.assertEqual(v2_body_regex_pattern(V2Regex("^ad$", "m"), "body"), "(?m-is)^ad$")

    def test_body_and_http_script_overlap_excludes_legacy_and_v2(self) -> None:
        for rewrite in (
            "^https://example/api response-body-json-del ads",
            'response if ${url} ~= /^https:\\/\\/example\\/api/ then response.json.delete("ads")',
        ):
            for script in (
                "http-response ^https://example/api/v2 script-path=https://example/a.js",
                'response if ${url} ~= /^https:\\/\\/example\\/api\\/v2/ then script("https://example/a.js")',
            ):
                self.assert_excluded(f"[Rewrite]\n{rewrite}\n[Script]\n{script}\n", "Loon suppresses the script")

    def test_request_body_overlap_and_fallback_scripts_are_excluded(self) -> None:
        self.assert_excluded(r'''[Rewrite]
request if ${url} ~= /^https:\/\/example\/api/ then request.body.replace(/old/, "new")
[Script]
http-request ^https://example/api/post script-path=https://example/post.js
http-request ^https://example/api script-path=https://example/fallback.js
''', "Loon suppresses the script")

    def test_disjoint_and_opposite_phase_scripts_are_kept(self) -> None:
        for kind, path in (("http-response", "account"), ("http-request", "ads")):
            output, report = self.convert(f'''[Rewrite]
^https://example/ads response-body-json-del ads
[Script]
{kind} ^https://example/{path} script-path=https://example/a.js
''')
            self.assertIsNotNone(output)
            self.assertEqual(report, [])

    def test_unknown_overlap_is_excluded_instead_of_using_samples(self) -> None:
        self.assert_excluded(r'''[Rewrite]
^https://example/ads response-body-json-del ads
[Script]
http-response ^https://other/\p{L} script-path=https://example/a.js
''', "disjointness could not be proven")

    def test_fixed_disabled_script_does_not_conflict(self) -> None:
        output, report = self.convert('''[Rewrite]
^https://example/ads response-body-json-del ads
[Script]
http-response ^https://example/ads script-path=https://example/a.js, enable=false
''')
        self.assertIsNotNone(output)
        self.assertEqual([entry["kind"] for entry in report], ["script-enable-direct-commented"])

    def test_parameter_toggled_script_is_checked_even_with_disabled_default(self) -> None:
        output, report = self.convert('''[Argument]
Enabled = switch,false,tag=Enabled
[Rewrite]
^https://example/ads response-body-json-del ads
[Script]
http-response ^https://example/ads script-path=https://example/a.js, enable={Enabled}
''')
        self.assertIsNone(output)
        self.assertIn("module-excluded", [entry["kind"] for entry in report])

    def test_multiple_url_rewrites_and_cross_stage_request_rewrites_are_excluded(self) -> None:
        first = 'request if ${url} ~= /^https:\\/\\/a\\.example/ then url.replace("https://b.example")'
        others = [
            'request if ${url} ~= /^https:\\/\\/b\\.example/ then url.replace("https://c.example")',
            'request if ${url} ~= /^https:\\/\\/b\\.example/ then request.header.set("X-Trace", "yes")',
            'request if ${url} ~= /^https:\\/\\/b\\.example/ then request.body.replace(/old/, "new")',
        ]
        for other in others:
            with self.subTest(other=other):
                self.assert_excluded(f"[Rewrite]\n{first}\n{other}\n", "Surge")
        self.assert_excluded("[Rewrite]\n^https://a.example header https://b.example\n^https://b.example header https://c.example\n", "first match")

    def test_single_url_rewrite_with_response_header_remains_supported(self) -> None:
        output, report = self.convert(r'''[Rewrite]
request if ${url} ~= /^https:\/\/a\.example/ then url.replace("https://b.example")
response if ${url} ~= /^https:\/\/b\.example/ then response.header.set("X-Trace", "yes")
''')
        self.assertIsNotNone(output)
        self.assertEqual(report, [])

    def test_framing_header_edits_exclude_entire_module_including_batches(self) -> None:
        for header in ("Content-Length", "content-length", "TRANSFER-ENCODING"):
            for action in (f'request.header.set("{header}", "0")', f'response.header.del("{header}")',
                           f'response.header.set(["X-Test", "{header}"], ["yes", "0"])'):
                phase = action.split(".")[0]
                self.assert_excluded(f'[Rewrite]\n{phase} if ${{url}} ~= /example/ then {action}\n', "must not change")
        self.assert_excluded("[Rewrite]\n^https://example/ response-header-add Content-Length 0\n", "must not change")
        self.assert_excluded("[Rewrite]\n^https://example/ header-replace-regex Transfer-Encoding old new\n", "must not change")

    def test_dynamic_header_names_cannot_bypass_framing_guard(self) -> None:
        self.assert_excluded('''[Argument]
Header = input,"X-Test",tag=Header
[Rewrite]
request if ${url} ~= /example/ then request.header.set("${Header}", "0")
''', "dynamic header names")

    def test_header_values_can_contain_framing_field_names(self) -> None:
        output, report = self.convert('''[Rewrite]
request if ${url} ~= /example/ then request.header.set("X-Trace", "Content-Length")
''')
        self.assertIsNotNone(output)
        self.assertEqual(report, [])

    def test_output_validator_rejects_only_unsafe_header_fields(self) -> None:
        for name, bad in (("Content-Length", True), ("transfer-encoding", True), ("{{{Header}}}", True), ("X-Test", False)):
            errors = []
            validate_section_line("test", 1, "Header Rewrite", f'http-response ^https://example/ header-add "{name}" Content-Length', errors)
            self.assertEqual(bool(errors), bad)

    def test_ambiguous_quoted_script_pattern_fails_closed(self) -> None:
        problem = module_semantics_problem({
            "Body Rewrite": ["http-response-jq ^https://example/ ."],
            "Script": [r'Job = type=http-response, pattern="^https://other/\\d", script-path=https://example/a.js'],
        })
        self.assertIsNotNone(problem)

    def test_invalid_legacy_rewrite_quote_has_normal_fatal_diagnostic(self) -> None:
        output, report = self.convert('[Rewrite]\n^https://example/ response-header-add X-Test "unfinished\n')
        self.assertIsNone(output)
        self.assertEqual([entry["kind"] for entry in report], ["unsupported-rewrite"])
        self.assertIn("unclosed quote", report[0]["line"])
        self.assertEqual(report[0]["file"], "sample.lpx")


if __name__ == "__main__":
    unittest.main()
