from __future__ import annotations

import base64
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from convert_kelee_to_surge import convert_kelee_to_surge
from loon_rewrite_v2 import RewriteV2Error, parse_rewrite_v2_line
from validate_surge_modules import (
    SurgeValidationError,
    literal_rewrite_placeholder_spans,
    validate_surge_modules,
)


class LiteralPlaceholderValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        (self.root / "Loon").mkdir()
        self.source = self.root / "Loon" / "Literal.lpx"
        self.output = self.root / "Surge" / "Literal.sgmodule"

    def convert(self, action: str, *, arguments: str = "", condition: str = "${url} ~= /rewrite-only/",
                section_case: str = "title", expected_modules: int = 1, jq_program: str | None = None) -> str:
        source = (
            "#!name=Literal\n[Argument]\nEnabled=switch, false, true\n" + arguments +
            "[Rewrite]\nresponse if " + condition + " then " + action + "\n" +
            '[Script]\ncron "0 8 * * *" then script("https://example.com/a.js") with enable=${Enabled}\n'
        )
        if section_case == "lower":
            source = source.replace("[Argument]", "[argument]").replace("[Rewrite]", "[rewrite]")
        elif section_case == "mixed":
            source = source.replace("[Argument]", "[aRgUmEnT]").replace("[Rewrite]", "[rEwRiTe]")
        self.source.write_text(source, encoding="utf-8")
        with patch("convert_kelee_to_surge.fetch_script_source", side_effect=AssertionError("must not fetch Script")), \
                patch("convert_kelee_to_surge.fetch_jq_path", return_value=jq_program,
                      side_effect=AssertionError("must not fetch JQ") if jq_program is None else None) as jq_loader, \
                contextlib.redirect_stdout(io.StringIO()):
            convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
            self.assertEqual(self.validate()["modules"], expected_modules)
            if jq_program is not None:
                jq_loader.assert_called_once_with("https://example.com/a.jq")
        return self.output.read_text(encoding="utf-8") if self.output.exists() else ""

    def validate(self) -> dict:
        return validate_surge_modules("Loon", "Surge", "Surge/convert-report.json")

    def tamper(self, text: str) -> None:
        self.output.write_text(text, encoding="utf-8")

    def test_lowercase_and_mixed_case_source_sections_keep_provenance(self) -> None:
        for case in ("lower", "mixed"):
            with self.subTest(case=case):
                text = self.convert(r'response.header.set("X-Test", "literal \${Enabled}; mode=${Mode}")',
                                    arguments="Mode=input, compact\n", section_case=case)
                self.assertIn("literal ${Enabled}; mode={{{Mode}}}", text)
                self.assertIn("Enabled:#", text)

    def test_plain_brace_text_is_literal_in_v2_strings(self) -> None:
        text = self.convert('response.body.replace(/ad/, "literal {Enabled}")')
        self.assertIn("literal {Enabled}", text)
        self.assertIn("Enabled:#", text)

    def test_arrays_and_multiple_actions_preserve_literal_occurrences(self) -> None:
        text = self.convert(
            r'response.header.set(["X-A", "X-B"], [`${Enabled}`, "\${Enabled}"])'
            r' | response.header.add("X-C", `again ${Enabled}`)'
        )
        self.assertEqual(text.count("${Enabled}"), 3)

    def test_regex_literals_and_url_condition_keep_literal_provenance(self) -> None:
        text = self.convert('response.body.replace(/${Enabled}/, "safe")',
                            condition='${url} ~= /literal-${Enabled}/')
        self.assertIn("literal-${Enabled}", text)
        self.assertIn("(?-ims)${Enabled}", text)

    def test_json_string_literal_is_proven_without_remote_loading(self) -> None:
        text = self.convert('response.json.replace("message", `literal ${Enabled}`)')
        self.assertIn("literal ${Enabled}", text)

    def test_real_reference_alongside_same_named_literal_is_still_converted(self) -> None:
        text = self.convert(r'response.body.replace(/ad/, "literal \${Mode}; real ${Mode}")',
                            arguments="Mode=input, compact\n")
        self.assertIn("literal ${Mode}; real {{{Mode}}}", text)
        self.tamper(text.replace("real {{{Mode}}}", "real ${Mode}"))
        with self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
            self.validate()

    def test_normalized_argument_name_cannot_collide_with_literal_markers(self) -> None:
        text = self.convert(
            r'response.header.set("X-Test", "literal \${Enabled}; real ${SURGE-LITERAL-PROVENANCE-0-END}")',
            arguments="SURGE-LITERAL-PROVENANCE-0-END=input, compact\n",
        )
        self.assertIn("literal ${Enabled}; real {{{SURGE_LITERAL_PROVENANCE_0_END}}}", text)

    def test_unsupported_unicode_escape_cannot_create_decoded_marker_collision(self) -> None:
        line = (
            r'response if ${url} ~= /rewrite-only/ then response.header.set("X-Test", '
            r'"SURGE_LITERAL_PROVENANC\u0045_0_END literal \${Enabled}")'
        )
        with self.assertRaisesRegex(RewriteV2Error, "Unsupported string escape"):
            parse_rewrite_v2_line(line)
        self.assertEqual(literal_rewrite_placeholder_spans({"Rewrite": [line]}), {})

    def test_real_variable_is_not_exempt_even_if_emitter_regresses(self) -> None:
        text = self.convert(r'response.body.replace(/ad/, "literal \${Mode}; real ${Mode}")',
                            arguments="Mode=input, compact\n")
        self.tamper(text.replace("real {{{Mode}}}", "real ${Mode}"))
        # The validator shares output formatting, but its AST literal mask must
        # not blindly bless an emitter's incorrect handling of real variables.
        with patch("convert_kelee_to_surge.surge_argument_placeholder", return_value="${Mode}"), \
                self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
            self.validate()

    def test_extra_copy_of_valid_literal_output_is_rejected(self) -> None:
        text = self.convert('response.body.replace(/ad/, `literal ${Enabled}`)')
        literal_line = next(line for line in text.splitlines() if "literal ${Enabled}" in line)
        self.tamper(text.replace(literal_line, literal_line + "\n" + literal_line))
        with self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
            self.validate()

    def test_source_duplicate_occurrences_are_counted_exactly(self) -> None:
        action = 'response.body.replace(/ad/, `literal ${Enabled}`)'
        text = self.convert(action + " | " + action)
        self.assertEqual(text.count("literal ${Enabled}"), 2)
        literal_line = next(line for line in text.splitlines() if "literal ${Enabled}" in line)
        self.tamper(text.replace(literal_line, literal_line + "\n" + literal_line, 1))
        with self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
            self.validate()

    def test_literal_cannot_move_to_different_pattern_or_payload(self) -> None:
        text = self.convert('response.header.set("X-Test", `literal ${Enabled}`)')
        for replacement in ("literal ${Other}", "changed ${Enabled}", "literal ${Enabled} ${Enabled}"):
            with self.subTest(replacement=replacement):
                self.tamper(text.replace("literal ${Enabled}", replacement))
                with self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
                    self.validate()
        self.tamper(text.replace("rewrite-only header-add", "another-url header-add"))
        with self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
            self.validate()

    def test_literal_cannot_authorize_script_argument(self) -> None:
        text = self.convert('response.header.set("X-Test", `literal ${Enabled}`)')
        self.tamper(text.replace("timeout=300", 'timeout=300, argument="literal ${Enabled}"'))
        with self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
            self.validate()

    def test_changed_source_reference_does_not_reuse_old_literal_proof(self) -> None:
        self.convert('response.header.set("X-Test", `literal ${Enabled}`)')
        self.source.write_text(self.source.read_text().replace('`literal ${Enabled}`', '"literal ${Enabled}"'))
        with self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
            self.validate()

    def test_comment_literal_cannot_authorize_payload(self) -> None:
        text = self.convert('response.header.set("X-Test", "safe")')
        with self.source.open("a", encoding="utf-8") as handle:
            handle.write("# `literal ${Enabled}`\n")
        self.tamper(text.replace("header-add X-Test safe", "header-add X-Test 'literal ${Enabled}'"))
        with self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
            self.validate()

    def test_other_module_literal_cannot_authorize_payload(self) -> None:
        text = self.convert('response.header.set("X-Test", "safe")')
        other_source = self.source.read_text().replace("#!name=Literal", "#!name=Other")
        other_source = other_source.replace('"safe"', '`literal ${Enabled}`')
        (self.root / "Loon" / "Other.lpx").write_text(other_source, encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            convert_kelee_to_surge("Loon", "Surge", "Surge/convert-report.json")
        self.tamper(text.replace("header-add X-Test safe", "header-add X-Test 'literal ${Enabled}'"))
        with self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
            self.validate()

    def test_undeclared_surge_placeholders_are_never_literal_exemptions(self) -> None:
        text = self.convert('response.header.set("X-Test", "${Mode}")', arguments="Mode=input, compact\n")
        self.tamper(text.replace("{{{Mode}}}", "{{{Missing}}}"))
        with self.assertRaisesRegex(SurgeValidationError, "undeclared module arguments.*Missing"):
            self.validate()

    def test_literal_surge_macros_are_excluded_before_publication(self) -> None:
        for literal in ('`literal {{{Enabled}}}`', '"literal {{{Enabled}}}"', r'"literal \${{{Enabled}}}"'):
            for action in ('response.body.replace(/ad/, VALUE)', 'response.header.set("X-Test", VALUE)'):
                with self.subTest(literal=literal, action=action):
                    self.assertEqual(self.convert(action.replace("VALUE", literal), expected_modules=0), "")

    def test_base64_mock_preserves_literal_surge_macro(self) -> None:
        text = self.convert('response.body.mock("text", `literal {{{Enabled}}}`)')
        self.assertIn(base64.b64encode(b"literal {{{Enabled}}}").decode(), text)
        self.assertIn("Enabled:#", text)

    def test_independent_validation_rejects_declared_source_literal_surge_macro(self) -> None:
        for action in ('response.body.replace(/ad/, `literal ${Enabled}`)',
                       'response.header.set("X-Test", `literal ${Enabled}`)'):
            with self.subTest(action=action):
                text = self.convert(action)
                self.source.write_text(self.source.read_text().replace("literal ${Enabled}", "literal {{{Enabled}}}"))
                self.tamper(text.replace("literal ${Enabled}", "literal {{{Enabled}}}"))
                with self.assertRaisesRegex(SurgeValidationError, "literal source text would be expanded"):
                    self.validate()

    def test_remote_jq_source_never_fetches_or_proves_literals(self) -> None:
        with patch("convert_kelee_to_surge.fetch_jq_path", side_effect=AssertionError("must not fetch")):
            proof = literal_rewrite_placeholder_spans({
                "Rewrite": ['response if ${url} ~= /${Enabled}/ then response.json.jq_file("https://example.com/a.jq")'],
            })
        self.assertEqual(proof, {})

    def test_remote_jq_pipeline_retains_adjacent_local_literal_provenance(self) -> None:
        for literal in ('`literal ${Enabled}`', r'"literal \${Enabled}"'):
            with self.subTest(literal=literal):
                text = self.convert(
                    'response.json.jq_file("https://example.com/a.jq") | '
                    'response.json.replace("message", ' + literal + ')', jq_program=".",
                )
                self.assertIn("literal ${Enabled}", text)
                self.assertIn("Enabled:#", text)

    def test_remote_jq_literal_url_pattern_is_excluded_without_fetch(self) -> None:
        for action in (
            'response.json.jq_file("https://example.com/a.jq")',
            'response.json.jq_file("https://example.com/a.jq") | response.json.replace("message", `local ${Enabled}`)',
        ):
            with self.subTest(action=action):
                self.assertEqual(self.convert(action, condition='${url} ~= /literal-${Enabled}/',
                                              expected_modules=0), "")

    def test_downloaded_jq_literal_has_no_local_provenance(self) -> None:
        with self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
            self.convert(
                'response.json.jq_file("https://example.com/a.jq") | '
                'response.json.replace("message", `local ${Enabled}`)',
                jq_program='setpath(["remote"]; "unproven ${Enabled}")',
            )

    def test_downloaded_copy_of_local_literal_does_not_gain_extra_occurrence(self) -> None:
        with self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
            self.convert(
                'response.json.jq_file("https://example.com/a.jq") | '
                'response.json.add("message", `literal ${Enabled}`)',
                jq_program='setpath(["message"]; "literal ${Enabled}")',
            )

    def test_tampered_remote_jq_cannot_borrow_local_literal_allowance(self) -> None:
        text = self.convert(
            'response.json.jq_file("https://example.com/a.jq") | '
            'response.json.replace("message", `literal ${Enabled}`)', jq_program=".",
        )
        self.assertIn("http-response-jq rewrite-only '.'", text)
        self.tamper(text.replace("http-response-jq rewrite-only '.'",
                                 "http-response-jq rewrite-only '\"remote ${Enabled}\"'"))
        with patch("convert_kelee_to_surge.fetch_jq_path", side_effect=AssertionError("must not fetch")), \
                self.assertRaisesRegex(SurgeValidationError, "residual bare Loon argument placeholder"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
