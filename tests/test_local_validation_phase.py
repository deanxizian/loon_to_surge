"""Offline local-before-remote validation and positional WARP linkage matrix."""
from __future__ import annotations

import contextlib
from dataclasses import replace
import hashlib
import io
import itertools
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import convert_kelee_to_surge as converter
import script_v2_compat as compat
from convert_kelee_to_surge import WARP_PANEL_SCRIPT_PATH, convert_file, convert_kelee_to_surge, fatal_report_items
from validate_surge_modules import validate_surge_modules
from loon_script_v2 import parse_script_v2_line

SPOTIFY = compat.BASE + "Spotify/Spotify_remove_ads.js"
PROBE = b"// Offline source-verification fixture. Never execute this text.\n"
OBJECT = (rf'response if ${{url}} ~= /^https:\/\/api\.example\.com\/ads/ then script("{SPOTIFY}", '
          '{${tab}}) with tag="Object", requires_body=true')
DECLARATIONS = "[Argument]\ntab=switch, false, true\n"
NOOP = r'response if ${url} ~= /^https:\/\/api\.example\.com\/ads/ then response.json.jq("")'
PLAIN_LEGACY = "http-request ^https://plain.example.com script-path=https://example.com/plain.js, tag=Legacy"
PLAIN_V2 = 'request if ${url} ~= /plain-v2/ then script("https://example.com/v2.js") with tag="V2"'
JQ_URL = "https://example.com/offline-fixture.jq"
JQ_FILE = (rf'response if ${{url}} ~= /^https:\/\/jq\.example\.com\/payload/ '
           f'then response.json.jq_file("{JQ_URL}")')


@contextlib.contextmanager
def working_directory(path):
    previous = Path.cwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(previous)


class LocalValidationPhaseTest(unittest.TestCase):
    def setUp(self):
        for name in ("urllib.request.urlopen", "socket.create_connection"):
            guard = patch(name, side_effect=AssertionError("Network forbidden in offline matrix"))
            guard.start()
            self.addCleanup(guard.stop)
        adapters = dict(compat.VERIFIED_OBJECT_ADAPTERS)
        adapters[SPOTIFY] = replace(adapters[SPOTIFY], sha256=hashlib.sha256(PROBE).hexdigest())
        self.adapter_patch = patch.object(compat, "VERIFIED_OBJECT_ADAPTERS", adapters)
        self.adapter_patch.start()
        self.addCleanup(self.adapter_patch.stop)

    def source(self, lines=(OBJECT,), extra="", *, reverse_sections=False, extra_argument="", metadata=""):
        script = "[Script]\n" + "\n".join(lines) + "\n" if lines else ""
        pieces = (script, extra) if reverse_sections else (extra, script)
        return "#!name=Matrix\n" + metadata + DECLARATIONS + extra_argument + "".join(pieces)

    def convert(self, source, *, verification="forbidden", source_loader=None):
        if source_loader is not None:
            loader = source_loader
        elif verification == "valid":
            loader = Mock(return_value=PROBE)
        elif verification == "changed":
            loader = Mock(return_value=PROBE + b"changed")
        else:
            loader = Mock(side_effect=TimeoutError("offline source must not be fetched for locally rejected modules"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir()
            path = root / "Matrix.lpx"
            path.write_text(source, encoding="utf-8")
            reports = []
            result = convert_file(path, output, reports, {}, script_source_loader=loader)
            files = {p.name: p.read_text(encoding="utf-8") for p in output.iterdir()}
            return result, reports, files, loader

    def assert_local_exclusion(self, source):
        result, reports, files, loader = self.convert(source)
        self.assertIsNone(result)
        self.assertEqual(files, {})
        self.assertTrue(any(item["kind"] == "module-excluded" for item in reports), reports)
        self.assertFalse(fatal_report_items(reports), reports)
        self.assertNotIn("script-object-adapted", [item["kind"] for item in reports])
        loader.assert_not_called()

    def test_rewrite_flags_and_semantic_exclusions_precede_object_source_fetch(self):
        rewrites = (
            'response if ${url} ~= /other/m then response.json.delete("ads")',
            'request if ${url} ~= /other/ then request.header.replace("X-Test", /old/i, "new")',
            r'response if ${url} ~= /^https:\/\/api\.example\.com\/ads/ then response.json.delete("ads")',
            'request if ${url} ~= /other/ then request.header.set("Content-Length", "0")',
        )
        for line, reverse in itertools.product(rewrites, (False, True)):
            with self.subTest(rewrite=line, script_section_first=reverse):
                self.assert_local_exclusion(self.source(extra="[Rewrite]\n" + line + "\n", reverse_sections=reverse))

    def test_all_local_fatal_categories_precede_object_source_fetch(self):
        cases = (
            ("[Rewrite]\nresponse if ${url} ~= /other/ then response.json.delete(\"data[\")\n", "", "", "unsupported-rewrite"),
            ("[Rule]\nLOON-ONLY,value,REJECT\n", "", "", "unsupported-rule"),
            ("", "Broken=input\n", "", "argument-default"),
            ("", "", "#!system=unknown-platform\n", "unsupported-system"),
            ("[General]\nunknown-option=true\n", "", "", "general-pass-through"),
            ("[MitM]\nhostname=\n", "", "", "mitm-unsupported"),
            ("[Unsupported]\nkey=value\n", "", "", "unsupported-section"),
        )
        for (extra, argument, metadata, kind), reverse in itertools.product(cases, (False, True)):
            with self.subTest(kind=kind, script_section_first=reverse):
                result, reports, files, loader = self.convert(self.source(
                    extra=extra, extra_argument=argument, metadata=metadata, reverse_sections=reverse))
                self.assertIsNone(result)
                self.assertEqual(files, {})
                self.assertIn(kind, [item["kind"] for item in reports], reports)
                self.assertNotIn("script-verification", [item["kind"] for item in reports])
                self.assertNotIn("script-object-adapted", [item["kind"] for item in reports])
                loader.assert_not_called()

    def assert_local_fatal_without_fetch(self, source, kind):
        result, reports, files, loader = self.convert(source)
        self.assertIsNone(result, reports)
        self.assertEqual(files, {})
        self.assertIn(kind, [item["kind"] for item in fatal_report_items(reports)], reports)
        self.assertNotIn("script-verification", [item["kind"] for item in reports])
        self.assertNotIn("script-object-adapted", [item["kind"] for item in reports])
        loader.assert_not_called()

    def test_rewrite_exclusion_cannot_mask_later_fatal_in_either_order(self):
        excluded = 'response if ${url} ~= /other/m then response.json.delete("ads")'
        malformed = 'response if ${url} ~= /broken/ then response.json.delete()'
        for reverse_rewrites, reverse_sections in itertools.product((False, True), repeat=2):
            lines = (malformed, excluded) if reverse_rewrites else (excluded, malformed)
            with self.subTest(malformed_first=reverse_rewrites, script_section_first=reverse_sections):
                self.assert_local_fatal_without_fetch(self.source(
                    extra="[Rewrite]\n" + "\n".join(lines) + "\n",
                    reverse_sections=reverse_sections), "unsupported-rewrite")

    def test_script_exclusions_cannot_mask_malformed_local_source(self):
        unsupported_scripts = (
            'request if ${url} ~= /other/ then script("https://example.com/a.js") with timeout=${Timeout}',
            'request if ${url} ~= /other/m then script("https://example.com/a.js")',
            'generic script-path=https://example.com/unverified.js, tag=Unknown',
        )
        fatal_cases = (
            ("[Rewrite]\nresponse if ${url} ~= /broken/ then response.json.delete()\n", "", "unsupported-rewrite"),
            ("[Argument]\nBroken=input\n", "", "argument-default"),
            ("", "#!system=unknown-platform\n", "unsupported-system"),
        )
        for unsupported in unsupported_scripts:
            # These are valid, unrepresentable features, not malformed fixtures.
            self.assert_local_exclusion(self.source((OBJECT, unsupported)))
            for (extra, metadata, kind), object_first, script_first in itertools.product(
                    fatal_cases, (False, True), (False, True)):
                lines = (OBJECT, unsupported) if object_first else (unsupported, OBJECT)
                with self.subTest(unsupported=unsupported, fatal=kind,
                                  object_first=object_first, script_section_first=script_first):
                    self.assert_local_fatal_without_fetch(self.source(
                        lines, extra=extra, metadata=metadata,
                        reverse_sections=script_first), kind)

    def test_jq_file_local_preflight_never_fetches_rejected_sources(self):
        unsupported = 'request if ${url} ~= /other/m then script("https://example.com/a.js")'
        malformed = 'response if ${url} ~= /broken/ then response.json.delete()'
        for reverse_lines, reverse_sections in itertools.product((False, True), repeat=2):
            with self.subTest(case="excluded-script", reverse_lines=reverse_lines,
                              script_section_first=reverse_sections), patch.object(
                    converter, "fetch_jq_path", side_effect=AssertionError("JQ fetch before local eligibility")) as jq_fetch:
                lines = (OBJECT, unsupported) if reverse_lines else (unsupported, OBJECT)
                self.assert_local_exclusion(self.source(
                    lines, extra="[Rewrite]\n" + JQ_FILE + "\n", reverse_sections=reverse_sections))
                jq_fetch.assert_not_called()
            with self.subTest(case="malformed-rewrite", reverse_lines=reverse_lines,
                              script_section_first=reverse_sections), patch.object(
                    converter, "fetch_jq_path", side_effect=AssertionError("JQ fetch before local eligibility")) as jq_fetch:
                lines = (JQ_FILE, malformed) if reverse_lines else (malformed, JQ_FILE)
                self.assert_local_fatal_without_fetch(self.source(
                    extra="[Rewrite]\n" + "\n".join(lines) + "\n",
                    reverse_sections=reverse_sections), "unsupported-rewrite")
                jq_fetch.assert_not_called()

    def test_eligible_jq_file_resolves_actual_body_before_object_hash(self):
        actual_jq = "del(.ads) | .verified_jq = true"
        for verification, reverse_sections in itertools.product(("valid", "changed"), (False, True)):
            with self.subTest(verification=verification, script_section_first=reverse_sections):
                events = Mock()
                jq_fetch = Mock(return_value=actual_jq)
                object_fetch = Mock(return_value=PROBE if verification == "valid" else PROBE + b"changed")
                events.attach_mock(jq_fetch, "jq")
                events.attach_mock(object_fetch, "object")
                with patch.object(converter, "fetch_jq_path", jq_fetch):
                    result, reports, files, _ = self.convert(self.source(
                        extra="[Rewrite]\n" + JQ_FILE + "\n", reverse_sections=reverse_sections),
                        source_loader=object_fetch)
                self.assertEqual(events.mock_calls, [call.jq(JQ_URL), call.object(SPOTIFY)])
                if verification == "valid":
                    self.assertIsNotNone(result, reports)
                    self.assertFalse(fatal_report_items(reports), reports)
                    body_lines = [line for line in files["Matrix.sgmodule"].splitlines()
                                  if line.startswith("http-response-jq ")]
                    self.assertEqual(len(body_lines), 1)
                    self.assertTrue(body_lines[0].endswith(" '" + actual_jq + "'"), body_lines)
                    self.assertIn("script-object-adapted", [item["kind"] for item in reports])
                else:
                    self.assertIsNone(result, reports)
                    self.assertEqual(files, {})
                    self.assertIn("script-verification", [item["kind"] for item in fatal_report_items(reports)])
                    self.assertNotIn("script-object-adapted", [item["kind"] for item in reports])

    def test_jq_file_fetch_failure_prevents_object_fetch_and_artifacts(self):
        for reverse_sections in (False, True):
            with self.subTest(script_section_first=reverse_sections):
                events = Mock()
                jq_fetch = Mock(side_effect=TimeoutError("offline JQ fixture failure"))
                object_fetch = Mock(return_value=PROBE)
                events.attach_mock(jq_fetch, "jq")
                events.attach_mock(object_fetch, "object")
                with patch.object(converter, "fetch_jq_path", jq_fetch):
                    result, reports, files, _ = self.convert(self.source(
                        extra="[Rewrite]\n" + JQ_FILE + "\n", reverse_sections=reverse_sections),
                        source_loader=object_fetch)
                self.assertEqual(events.mock_calls, [call.jq(JQ_URL)])
                object_fetch.assert_not_called()
                self.assertIsNone(result, reports)
                self.assertEqual(files, {})
                self.assertIn("unsupported-rewrite", [item["kind"] for item in fatal_report_items(reports)])
                self.assertNotIn("script-verification", [item["kind"] for item in reports])
                self.assertNotIn("script-object-adapted", [item["kind"] for item in reports])

    def remote_jq_line(self, syntax, *, overlaps=False):
        pattern = r"^https://api\.example\.com/ads" if overlaps else r"^https://jq\.example\.com/payload"
        if syntax == "legacy":
            return f"{pattern} response-body-json-jq jq-path={JQ_URL}"
        escaped_pattern = pattern.replace("/", r"\/")
        return (f'response if ${{url}} ~= /{escaped_pattern}/ '
                f'then response.json.jq_file("{JQ_URL}")')

    def test_remote_and_local_body_overlap_excludes_before_any_resource_fetch(self):
        plain_response = (r"http-response ^https://api\.example\.com/ads "
                          "script-path=https://example.com/plain.js, tag=Plain")
        matrix = itertools.product(("v2", "legacy"), (False, True), (False, True),
                                   (False, True), (False, True))
        for syntax, has_object, remote_overlaps, reverse_rewrites, reverse_sections in matrix:
            remote = self.remote_jq_line(syntax, overlaps=remote_overlaps)
            local_pattern = r"^https:\/\/local\.example\.com\/ads" if remote_overlaps else r"^https:\/\/api\.example\.com\/ads"
            local = f'response if ${{url}} ~= /{local_pattern}/ then response.json.delete("ads")'
            rewrites = (local, remote) if reverse_rewrites else (remote, local)
            source = self.source((OBJECT if has_object else plain_response,),
                                 extra="[Rewrite]\n" + "\n".join(rewrites) + "\n",
                                 reverse_sections=reverse_sections)
            observed_reports = []
            for resource_state in ("offline", "available", "empty"):
                with self.subTest(syntax=syntax, has_object=has_object, remote_overlaps=remote_overlaps,
                                  reverse_rewrites=reverse_rewrites, script_section_first=reverse_sections,
                                  resource_state=resource_state):
                    jq_fetch = (Mock(side_effect=TimeoutError("offline")) if resource_state == "offline"
                                else Mock(return_value="" if resource_state == "empty" else "del(.remote_ads)"))
                    with patch.object(converter, "fetch_jq_path", jq_fetch):
                        result, reports, files, object_fetch = self.convert(source, verification="valid")
                    observed_reports.append(reports)
                    self.assertIsNone(result, reports)
                    self.assertEqual(files, {})
                    self.assertFalse(fatal_report_items(reports), reports)
                    self.assertTrue(any(item["kind"] == "module-excluded" and "Body Rewrite" in item["message"]
                                        for item in reports), reports)
                    self.assertNotIn("script-object-adapted", [item["kind"] for item in reports])
                    jq_fetch.assert_not_called()
                    object_fetch.assert_not_called()
            with self.subTest(syntax=syntax, has_object=has_object, remote_overlaps=remote_overlaps,
                              reverse_rewrites=reverse_rewrites, script_section_first=reverse_sections,
                              same_diagnostic_without_network=True):
                for reports in observed_reports[1:]:
                    self.assertEqual(observed_reports[0], reports)

    def remote_macro_source(self, syntax, has_object, enabled_is_used, *, reverse_sections=False):
        scripts = [OBJECT if has_object else PLAIN_LEGACY]
        if enabled_is_used:
            scripts.append('cron "0 8 * * *" then script("https://example.com/toggle.js") '
                           'with tag="Toggle", enable=${Enabled}')
        return self.source(scripts, extra="[Rewrite]\n" + self.remote_jq_line(syntax) + "\n",
                           extra_argument="Enabled=switch, true, false\n", reverse_sections=reverse_sections)

    def test_remote_jq_raw_macros_are_fatal_without_creating_argument_usage(self):
        raw_program = '{"literal":"{{{Enabled}}}","ordinary":"kept"}'
        for syntax, has_object, enabled_is_used, reverse_sections, resource_source in itertools.product(
                ("v2", "legacy"), (False, True), (False, True), (False, True), ("loader", "cache")):
            with self.subTest(syntax=syntax, has_object=has_object, enabled_is_used=enabled_is_used,
                              script_section_first=reverse_sections, resource_source=resource_source):
                if resource_source == "cache":
                    cache_context = patch.dict(converter.JQ_PATH_CACHE, {JQ_URL: raw_program}, clear=True)
                    # Spy on the real cached-resource reader, not a fabricated
                    # fetch return, so cached bytes undergo the same rejection.
                    fetch_context = patch.object(converter, "fetch_jq_path", wraps=converter.fetch_jq_path)
                else:
                    cache_context = contextlib.nullcontext()
                    fetch_context = patch.object(converter, "fetch_jq_path", return_value=raw_program)
                with cache_context, fetch_context as jq_fetch:
                    result, reports, files, object_fetch = self.convert(self.remote_macro_source(
                        syntax, has_object, enabled_is_used, reverse_sections=reverse_sections), verification="valid")
                jq_fetch.assert_called_once_with(JQ_URL)
                self.assertTrue(fatal_report_items(reports), reports)
                object_fetch.assert_not_called()
                self.assertNotIn("script-object-adapted", [item["kind"] for item in reports])
                if has_object:
                    self.assertIsNone(result, reports)
                    self.assertEqual(files, {})
                # Non-Object failures may keep a diagnostic candidate, but it
                # cannot contain the rejected program or invent argument use.
                for text in files.values():
                    body_lines = [line for line in text.splitlines() if line.startswith("http-response-jq ")]
                    self.assertFalse(any("{{{Enabled}}}" in line for line in body_lines), body_lines)
                    if not enabled_is_used:
                        arguments = [line for line in text.splitlines() if line.startswith("#!arguments=")]
                        self.assertFalse(any("Enabled" in line for line in arguments), arguments)

    def test_remote_jq_raw_macros_cannot_replace_published_modules(self):
        raw_program = '{"literal":"{{{Enabled}}}"}'
        for syntax, has_object, enabled_is_used in itertools.product(("v2", "legacy"), (False, True), (False, True)):
            with self.subTest(syntax=syntax, has_object=has_object, enabled_is_used=enabled_is_used), \
                    tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
                root = Path(temporary)
                (root / "Loon").mkdir()
                (root / "Surge").mkdir()
                (root / "Loon/Matrix.lpx").write_text(self.remote_macro_source(syntax, has_object, enabled_is_used))
                (root / "Loon/Good.lpx").write_text("#!name=Good\n[Rule]\nDOMAIN,example.com,DIRECT\n")
                sentinel = root / "Surge/previous.sgmodule"
                sentinel.write_bytes(b"last-known-good")
                object_fetch = Mock(return_value=PROBE)
                with working_directory(root), \
                        patch.object(converter, "fetch_jq_path", return_value=raw_program) as jq_fetch, \
                        patch.object(converter, "fetch_script_source", object_fetch):
                    with self.assertRaises(RuntimeError):
                        convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
                jq_fetch.assert_called_once_with(JQ_URL)
                object_fetch.assert_not_called()
                self.assertEqual(list((root / "Surge").iterdir()), [sentinel])
                self.assertEqual(sentinel.read_bytes(), b"last-known-good")

    def test_remote_jq_escaped_braces_preserve_program_and_real_argument_usage(self):
        safe_program = r'{"literal":"\u007b\u007b\u007bEnabled\u007d\u007d\u007d"}'
        for syntax, has_object, enabled_is_used in itertools.product(("v2", "legacy"), (False, True), (False, True)):
            with self.subTest(syntax=syntax, has_object=has_object, enabled_is_used=enabled_is_used):
                with patch.object(converter, "fetch_jq_path", return_value=safe_program) as jq_fetch:
                    result, reports, files, object_fetch = self.convert(self.remote_macro_source(
                        syntax, has_object, enabled_is_used), verification="valid")
                self.assertIsNotNone(result, reports)
                self.assertFalse(fatal_report_items(reports), reports)
                jq_fetch.assert_called_once_with(JQ_URL)
                if has_object:
                    object_fetch.assert_called_once_with(SPOTIFY)
                else:
                    object_fetch.assert_not_called()
                lines = files["Matrix.sgmodule"].splitlines()
                body_lines = [line for line in lines if line.startswith("http-response-jq ")]
                self.assertEqual(len(body_lines), 1)
                self.assertTrue(body_lines[0].endswith(" '" + safe_program + "'"), body_lines)
                arguments = [line for line in lines if line.startswith("#!arguments=")]
                self.assertEqual(any("Enabled" in line for line in arguments), enabled_is_used, arguments)

    def warp(self, syntax, *, tag=None, enable=None):
        if syntax == "legacy":
            return (f"generic script-path={WARP_PANEL_SCRIPT_PATH}, timeout=10"
                    + (f", tag={tag}" if tag is not None else "")
                    + (f", enable={enable}" if enable is not None else ""))
        return (f'generic then script("{WARP_PANEL_SCRIPT_PATH}") with timeout=10'
                + (", tag=" + json.dumps(tag) if tag is not None else "")
                + (f", enable={enable}" if enable is not None else ""))

    def test_generic_and_warp_exclusions_precede_object_fetch_in_both_orders(self):
        exclusions = (
            'generic script-path=https://example.com/unverified.js, tag=Unknown',
            'generic then script("https://example.com/unverified.js") with tag="Unknown"',
            self.warp("legacy", tag="Warp", enable="false"),
            self.warp("v2", tag="Warp", enable="false"),
        )
        for line, reverse in itertools.product(exclusions, (False, True)):
            with self.subTest(line=line, object_first=reverse):
                lines = (OBJECT, line) if reverse else (line, OBJECT)
                self.assert_local_exclusion(self.source(lines))
        for syntax, reverse in itertools.product(("legacy", "v2"), (False, True)):
            lines = [self.warp(syntax, tag="Warp"), self.warp(syntax, tag="OtherWarp"), OBJECT]
            self.assert_local_exclusion(self.source(lines[::-1] if reverse else lines))

    def test_noop_does_not_hide_a_valid_object_or_create_false_body_overlap(self):
        for reverse in (False, True):
            result, reports, files, loader = self.convert(self.source(
                extra="[Rewrite]\n" + NOOP + "\n", reverse_sections=reverse), verification="valid")
            self.assertIsNotNone(result)
            self.assertFalse(fatal_report_items(reports), reports)
            loader.assert_called_once_with(SPOTIFY)
            self.assertIn("rewrite-empty-skipped", [item["kind"] for item in reports])
            self.assertIn("script-object-adapted", [item["kind"] for item in reports])
            self.assertNotIn("[Body Rewrite]", files["Matrix.sgmodule"])
            self.assertIn("{{{tab}}}", files["Matrix.sgmodule"])
        self.assert_local_exclusion(self.source(lines=(), extra="[Rewrite]\n" + NOOP + "\n"))

    def test_valid_object_still_requires_current_bytes_and_exact_hash(self):
        for verification in ("valid", "changed", "offline"):
            with self.subTest(verification=verification):
                result, reports, files, loader = self.convert(self.source(), verification=verification)
                loader.assert_called_once_with(SPOTIFY)
                if verification == "valid":
                    self.assertIsNotNone(result)
                    self.assertFalse(fatal_report_items(reports), reports)
                    self.assertTrue(files)
                    self.assertIn(hashlib.sha256(PROBE).hexdigest(), " ".join(item["message"] for item in reports))
                    script = parse_script_v2_line(OBJECT)
                    context = compat.build_script_v2_context(["tab=switch, false, true"], [OBJECT])
                    plan = compat.plan_script_v2(script, context)
                    _, raw_parts = converter.prepare_script_v2(plan.script)
                    with self.assertRaises(compat.ScriptSourceVerificationError):
                        plan.apply_parts(raw_parts)
                    verified = compat.verify_script_v2_source(plan, source_loader=lambda _: PROBE)
                    expected_line = "Object = " + ", ".join(verified.apply_parts(raw_parts))
                    actual_lines = [line for line in files["Matrix.sgmodule"].splitlines()
                                    if line.startswith("Object = ")]
                    self.assertEqual(actual_lines, [expected_line])
                else:
                    self.assertIsNone(result)
                    self.assertEqual(files, {})
                    self.assertIn("script-verification", [item["kind"] for item in reports])
                    self.assertNotIn("script-object-adapted", [item["kind"] for item in reports])

    def assert_warp_link(self, output, name):
        self.assertIn("script-name=" + name, output)
        self.assertIn(name + " = type=generic", output)
        self.assertEqual(sum(line.startswith(name + " = ") and "type=generic" in line for line in output.splitlines()), 1)

    def test_untagged_legacy_and_v2_warp_use_actual_position_after_mixed_scripts(self):
        prefixes = ((), (PLAIN_LEGACY,), (PLAIN_V2,), (PLAIN_LEGACY, PLAIN_V2),
                    (PLAIN_V2, PLAIN_LEGACY), (OBJECT, PLAIN_LEGACY))
        for syntax, prefix in itertools.product(("legacy", "v2"), prefixes):
            with self.subTest(syntax=syntax, prefix=prefix):
                has_object = OBJECT in prefix
                result, reports, files, loader = self.convert(
                    self.source((*prefix, self.warp(syntax))), verification="valid")
                self.assertIsNotNone(result, reports)
                self.assertFalse(fatal_report_items(reports), reports)
                self.assert_warp_link(files["Matrix.sgmodule"], f"generic {len(prefix) + 1}")
                if has_object:
                    loader.assert_called_once_with(SPOTIFY)
                else:
                    loader.assert_not_called()

    def test_untagged_warp_name_collisions_fail_locally_for_both_syntaxes_and_orders(self):
        for warp_syntax, http_syntax, warp_first in itertools.product(("legacy", "v2"), ("legacy", "v2"), (False, True)):
            name = "generic 1" if warp_first else "generic 2"
            if http_syntax == "legacy":
                collision = f'http-request ^https://example.com script-path=https://example.com/a.js, tag={name}'
            else:
                collision = f'request if ${{url}} ~= /other/ then script("https://example.com/a.js") with tag="{name}"'
            warp = self.warp(warp_syntax)
            pair = (warp, collision) if warp_first else (collision, warp)
            with self.subTest(warp=warp_syntax, http=http_syntax, warp_first=warp_first):
                self.assert_local_exclusion(self.source((*pair, OBJECT)))

    def test_unverified_object_preview_cannot_replace_published_output(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            (root / "Loon").mkdir()
            (root / "Surge").mkdir()
            (root / "Loon/Matrix.lpx").write_text(self.source())
            sentinel = root / "Surge/previous.sgmodule"
            sentinel.write_bytes(b"last-known-good")
            loader = Mock(return_value=PROBE + b"changed")
            with working_directory(root), patch.object(converter, "fetch_script_source", loader):
                with self.assertRaisesRegex(RuntimeError, "script-verification"):
                    convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
            loader.assert_called_once_with(SPOTIFY)
            self.assertEqual(list((root / "Surge").iterdir()), [sentinel])
            self.assertEqual(sentinel.read_bytes(), b"last-known-good")

    def test_mixed_batch_local_exclusion_does_not_require_network(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temporary)
            (root / "Loon").mkdir()
            (root / "Loon/Excluded.lpx").write_text(self.source(
                extra='[Rewrite]\nresponse if ${url} ~= /other/m then response.json.delete("ads")\n'))
            (root / "Loon/Good.lpx").write_text("#!name=Good\n[Rule]\nDOMAIN,example.com,DIRECT\n")
            loader = Mock(side_effect=TimeoutError("offline"))
            with working_directory(root), patch.object(converter, "fetch_script_source", loader):
                convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
                result = validate_surge_modules("Loon", "Surge", "Surge/convert-report.json")
                self.assertEqual(result["modules"], 1)
                report = json.loads((root / "Surge/convert-report.json").read_text())
                self.assertEqual((report["converted"], report["excluded"]), (1, 1))
                loader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
