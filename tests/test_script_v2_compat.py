from __future__ import annotations

import base64
import contextlib
import io
import os
from dataclasses import replace
import hashlib
import itertools
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import script_v2_compat as compat
from loon_script_v2 import parse_script_v2_line
from loon_rewrite_v2 import V2String, V2Variable
from convert_kelee_to_surge import convert_file, convert_kelee_to_surge, prepare_script_v2, UnverifiedScriptV2, WARP_PANEL_SCRIPT_PATH
from validate_surge_modules import validate_surge_modules


SPOTIFY = compat.BASE + 'Spotify/Spotify_remove_ads.js'
YOUTUBE = compat.BASE + 'YouTube/YouTube_remove_ads/YouTube_remove_ads_response.js'
SUBTITLES = compat.BASE + 'YouTube/YouTube_Subtitles_Translate/YouTube_Subtitles_request.js'
PROBE_BYTES = b'// Synthetic static parser-contract test fixture; never executed.\n'


class ScriptV2CompatibilityTest(unittest.TestCase):
    def context(self, arguments, lines=(), other=()):
        return compat.build_script_v2_context(arguments, lines, other)

    def line(self, path=SPOTIFY, variables=('tab', 'useractivity')):
        values = ', '.join('${' + name + '}' for name in variables)
        return f'response if ${{url}} ~= /ads/ then script("{path}", {{{values}}})'

    def adapt_with_probe(self, line, arguments):
        """Exercise codecs without executing JS or relying on mutable network."""
        script = parse_script_v2_line(line)
        path = ''.join(script.path.parts)
        adapters = dict(compat.VERIFIED_OBJECT_ADAPTERS)
        adapters[path] = replace(adapters[path], sha256=hashlib.sha256(PROBE_BYTES).hexdigest())
        with patch.object(compat, 'VERIFIED_OBJECT_ADAPTERS', adapters):
            return compat.adapt_script_v2(script, self.context(arguments, [line]), source_loader=lambda _: PROBE_BYTES)

    def expand(self, value, values):
        for name, replacement in values.items():
            text = json.dumps(replacement) if type(replacement) is bool else replacement
            value = value.replace(compat.placeholder(name), text)
        return value

    def test_review_manifest_matches_every_pinned_adapter(self):
        rows = json.loads((Path(__file__).parent / 'fixtures/script-v2-compat/source-review.json').read_text())
        by_url = {item['url']: item for item in rows}
        for url, adapter in compat.VERIFIED_OBJECT_ADAPTERS.items():
            with self.subTest(url=url):
                self.assertEqual(adapter.sha256, by_url[url]['sha256'])
                self.assertEqual(by_url[url]['reviewed_at'], '2026-10-02')
                self.assertEqual(len(adapter.sha256), 64)
                self.assertIn('$argument', ''.join(by_url[url]['excerpts']))

    def test_json_booleans_remain_booleans_for_every_combination(self):
        line = self.line()
        adapted = self.adapt_with_probe(line, ['tab=switch, false, true', 'useractivity=switch, true, false'])
        for tab, useractivity in itertools.product([False, True], repeat=2):
            values = dict(tab=tab, useractivity=useractivity)
            self.assertEqual(json.loads(self.expand(adapted.argument_override, values)), values)
        self.assertIsNone(adapted.script.argument)
        self.assertEqual(adapted.argument_codec, 'json')

    def test_json_strings_have_different_placeholders_from_booleans(self):
        line = self.line(YOUTUBE, ['captionLang', 'blockUpload'])
        adapted = self.adapt_with_probe(line, ['captionLang=select, "zh-Hans", "off"', 'blockUpload=switch, true, false'])
        self.assertEqual(adapted.argument_override, '{"captionLang":"{{{captionLang}}}","blockUpload":{{{blockUpload}}}}')
        for language, enabled in itertools.product(['zh-Hans', 'off'], [True, False]):
            expected = {'captionLang': language, 'blockUpload': enabled}
            self.assertEqual(json.loads(self.expand(adapted.argument_override, expected)), expected)

    def test_apply_parts_escapes_surge_argument_exactly_once(self):
        adapted = self.adapt_with_probe(self.line(), ['tab=switch, false, true', 'useractivity=switch, true, false'])
        _, parts = prepare_script_v2(adapted.script)
        actual = adapted.apply_parts(parts)
        argument = next(part.partition('=')[2] for part in actual if part.startswith('argument='))
        self.assertEqual(json.loads(argument), adapted.argument_override)
        self.assertEqual(len([part for part in actual if part.startswith('argument=')]), 1)
        self.assertFalse(any(part.startswith('argument=') for part in parts))

    def test_subtitles_query_values_preserve_common_normalized_settings(self):
        line = self.line(SUBTITLES, ['Type', 'AutoCC', 'ShowOnly', 'Position'])
        adapted = self.adapt_with_probe(line, ['Type=select, "Official", "Translate"', 'AutoCC=switch, true, false',
                                             'ShowOnly=switch, false, true', 'Position=select, "Forward", "Reverse"'])
        for type_, auto, show, position in itertools.product(['Official', 'Translate'], [True, False], [True, False], ['Forward', 'Reverse']):
            values = dict(Type=type_, AutoCC=auto, ShowOnly=show, Position=position)
            query = dict(part.split('=') for part in self.expand(adapted.argument_override, values).split('&'))
            normalized = {k: json.loads(v) if v in {'true', 'false'} else v for k, v in query.items()}
            self.assertEqual(normalized, values)
        self.assertEqual(adapted.argument_codec, 'query-normalized')

    def test_unreviewed_url_cannot_reuse_a_familiar_filename(self):
        for url in ['https://example.com/Spotify_remove_ads.js', SPOTIFY + '?version=1', SPOTIFY.replace('https:', 'http:')]:
            with self.subTest(url=url), self.assertRaisesRegex(compat.UnverifiedScriptArgument, 'no reviewed'):
                compat.adapt_script_v2(parse_script_v2_line(self.line(url)), self.context([]), source_loader=lambda _: PROBE_BYTES)

    def test_missing_unavailable_or_changed_source_is_fatal_not_exclusion(self):
        script = parse_script_v2_line(self.line())
        context = self.context(['tab=switch, false, true', 'useractivity=switch, true, false'])
        for loader in [None, lambda _: b'changed', lambda _: 'not bytes']:
            with self.subTest(loader=loader), self.assertRaises(compat.ScriptSourceVerificationError):
                compat.adapt_script_v2(script, context, source_loader=loader)
        def unavailable(_):
            raise TimeoutError('offline')
        with self.assertRaisesRegex(compat.ScriptSourceVerificationError, 'TimeoutError'):
            compat.adapt_script_v2(script, context, source_loader=unavailable)
        self.assertFalse(issubclass(compat.ScriptSourceVerificationError, compat.UnverifiedScriptArgument))

    def test_known_non_lossless_adapters_remain_excluded(self):
        for path, reason in compat.UNSUPPORTED_OBJECT_REASONS.items():
            with self.subTest(path=path), self.assertRaises(compat.UnverifiedScriptArgument) as caught:
                compat.adapt_script_v2(parse_script_v2_line(self.line(path)), self.context([]), source_loader=lambda _: PROBE_BYTES)
            self.assertEqual(str(caught.exception), reason)

    def test_boolean_looking_strings_and_type_metadata_are_not_booleans(self):
        for declaration in ['tab=select, "false", "true"', 'tab=input, "false"', 'tab=switch, false, true, type=number', 'tab=switch, false, true, future_type=number']:
            with self.subTest(declaration=declaration), self.assertRaises(compat.UnverifiedScriptArgument):
                self.adapt_with_probe(self.line(variables=['tab']), [declaration])

    def test_dynamic_enable_rejects_unrecognized_fields_after_metadata(self):
        line = 'cron "0 8 * * *" then script("https://example.com/a.js") with enable=${Enabled}'
        tails = ['tag=Toggle, bogus', 'desc=Description, bogus',
                 'tag=Toggle, bogus, desc=Description', 'tag=Toggle, true',
                 'tag=Toggle, ', 'tag=Toggle, future=number',
                 'future=number, tag=Toggle', 'desc=Description, type=number']
        for tail in tails:
            declaration = 'Enabled=switch, false, true, ' + tail
            with self.subTest(declaration=declaration), self.assertRaises(compat.UnverifiedScriptArgument):
                context = self.context([declaration], [line])
                self.assertIn('Enabled', context.declaration_errors)
                compat.adapt_script_v2(parse_script_v2_line(line), context)

    def test_object_adapter_rejects_unrecognized_fields_after_metadata(self):
        line = self.line(variables=['tab'])
        for tail in ['tag=Tab, bogus', 'desc=Description, bogus, tag=Tab',
                     'tag=Tab, future=number', 'future=number, desc=Description']:
            declaration = 'tab=switch, false, true, ' + tail
            with self.subTest(declaration=declaration), self.assertRaises(compat.UnverifiedScriptArgument):
                self.adapt_with_probe(line, [declaration])

    def test_recognized_metadata_fields_remain_supported(self):
        line = 'cron "0 8 * * *" then script("https://example.com/a.js") with enable=${Enabled}'
        for tail in ['tag=Toggle, desc=Description', 'desc=Description, tag=Toggle',
                     'tag="Toggle, with comma", desc=', 'TAG = Toggle, DESC = Description']:
            with self.subTest(tail=tail):
                declaration = 'Enabled=switch, false, true, ' + tail
                adapted = compat.adapt_script_v2(parse_script_v2_line(line), self.context([declaration], [line]))
                self.assertEqual(adapted.enable_prefix, '{{{Enabled}}}')
        adapted = self.adapt_with_probe(self.line(variables=['tab']), ['tab=switch, false, true, tag=Tab, desc=Description'])
        self.assertEqual(adapted.argument_override, '{"tab":{{{tab}}}}')

    def test_string_choice_safety_checks_all_options_not_only_default(self):
        options = ['a&b', 'a=b', 'a,b', 'a\\"b', 'a\\\\b', '${Other}', '{{{Other}}}', 'a\\nb', 'a%20b', 'a b']
        for option in options:
            with self.subTest(option=option), self.assertRaises(compat.UnverifiedScriptArgument):
                self.adapt_with_probe(self.line(YOUTUBE, ['captionLang']), [f'captionLang=select, "off", "{option}"'])
        for declaration in ['captionLang=input, "off"', 'captionLang=select, "off", "zh-Hans", type=number']:
            with self.subTest(declaration=declaration), self.assertRaises(compat.UnverifiedScriptArgument):
                self.adapt_with_probe(self.line(YOUTUBE, ['captionLang']), [declaration])

    def test_unknown_object_property_and_undeclared_variables_are_excluded(self):
        with self.assertRaisesRegex(compat.UnverifiedScriptArgument, 'not reviewed'):
            self.adapt_with_probe(self.line(variables=['other']), ['other=switch, false, true'])
        with self.assertRaisesRegex(compat.UnverifiedScriptArgument, 'not declared'):
            self.adapt_with_probe(self.line(variables=['tab']), [])

    def test_duplicate_and_colliding_declarations_are_not_adapted(self):
        for declarations in [ ['tab=switch, false, true', 'tab=switch, true, false'],
                              ['a.b=switch, false, true', 'a-b=switch, false, true'] ]:
            context = self.context(declarations)
            self.assertTrue(context.declaration_errors)
        with self.assertRaisesRegex(compat.UnverifiedScriptArgument, 'duplicate'):
            self.adapt_with_probe(self.line(variables=['tab']), ['tab=switch, false, true', 'tab=switch, true, false'])

    def test_dynamic_enable_emits_toggle_defaults_for_both_orders(self):
        line = 'cron "0 8 * * *" then script("https://example.com/a.js") with enable=${CaptureCookie}'
        for first, second, expected in [('false', 'true', '#'), ('true', 'false', '')]:
            with self.subTest(first=first):
                context = self.context([f'CaptureCookie=switch, {first}, {second}'], [line])
                adapted = compat.adapt_script_v2(parse_script_v2_line(line), context)
                self.assertEqual(adapted.enable_prefix, '{{{CaptureCookie}}}')
                self.assertEqual(dict(adapted.toggle_defaults), {'CaptureCookie': expected})
                self.assertNotIn('enable', adapted.script.properties)
                prepare_script_v2(adapted.script)

    def test_dynamic_enable_shared_with_other_semantics_is_excluded(self):
        line = 'cron "0 8 * * *" then script("https://example.com/a.js") with enable=${Enabled}'
        other_scripts = [self.line(variables=['Enabled']),
                         'cron "0 8 * * *" then script("https://example.com/a.js", "value=${Enabled}")',
                         'cron "0 8 * * *" then script("https://example.com/a.js") with debug=${Enabled}',
                         'cron ${Enabled} then script("https://example.com/a.js")',
                         'http-response ^https://example.com script-path=https://example.com/a.js, argument="x={Enabled}"']
        for other in other_scripts:
            with self.subTest(other=other), self.assertRaisesRegex(compat.UnverifiedScriptArgument, 'shared'):
                context = self.context(['Enabled=switch, false, true'], [line, other])
                compat.adapt_script_v2(parse_script_v2_line(line), context)
        for other in ['hostname={Enabled}', 'request if ${url} ~= /ads/ then response.body.replace("x", "${Enabled}")']:
            with self.subTest(other=other), self.assertRaisesRegex(compat.UnverifiedScriptArgument, 'shared'):
                context = self.context(['Enabled=switch, false, true'], [line], [other])
                compat.adapt_script_v2(parse_script_v2_line(line), context)

    def test_v2_action_literals_do_not_share_enable_argument(self):
        # Official Rewrite V2: raw strings and Regex never interpolate; \${
        # is literal in double-quoted Strings. These are parsed-value tests.
        enable = 'cron "0 8 * * *" then script("https://example.com/a.js") with enable=${Enabled}'
        actions = [
            'response.body.mock("text", `literal ${Enabled}`)',
            r'response.body.mock("text", "literal \${Enabled}")',
            'response.body.mock("text", `literal `` ${Enabled}`)',
            'response.body.mock("text", "literal {Enabled}")',
            r'response.body.replace(/\$\{Enabled\}/, "safe")',
            r'response.header.set(["X-A", "X-B"], [`${Enabled}`, "\${Enabled}"])',
            r'response.header.set("X-A", `${Enabled}`) | response.header.set("X-B", "\${Enabled}")',
        ]
        for action in actions:
            with self.subTest(action=action):
                rewrite = 'response if ${url} ~= /ads/ then ' + action
                context = self.context(['Enabled=switch, false, true'], [enable], [rewrite])
                self.assertNotIn('Enabled', context.non_enable_names)
                self.assertEqual(compat.plan_script_v2(parse_script_v2_line(enable), context).enable_prefix, '{{{Enabled}}}')

    def test_v2_condition_literals_do_not_share_enable_argument(self):
        enable = 'cron "0 8 * * *" then script("https://example.com/a.js") with enable=${Enabled}'
        conditions = [
            '${url} == `literal ${Enabled}`',
            r'${url} == "literal \${Enabled}"',
            '${url} ~= /${Enabled}/',
            r"(${request.header['X-Test']} == `literal ${Enabled}` || ${url} ~= /\$\{Enabled\}/) && ${response.status} == 200",
            r'(( ${url} == "escaped quote \" and \${Enabled}" ))',
            '${url} ~= /literal as ${Enabled}/ as match',
        ]
        for condition in conditions:
            with self.subTest(condition=condition):
                rewrite = 'response if ' + condition + ' then response.header.set("X-Test", "safe")'
                other_script = 'response if ' + condition + ' then script("https://example.com/b.js")'
                for scripts, other in [([enable], [rewrite]), ([enable, other_script], [])]:
                    context = self.context(['Enabled=switch, false, true'], scripts, other)
                    self.assertNotIn('Enabled', context.non_enable_names)

    def test_real_v2_references_remain_shared_through_arrays_templates_and_conditions(self):
        enable = 'cron "0 8 * * *" then script("https://example.com/a.js") with enable=${Enabled}'
        rewrites = [
            'response if ${url} ~= /ads/ then response.json.replace("enabled", ${Enabled})',
            'response if ${url} ~= /ads/ then response.header.set("X-Test", "value=${Enabled}")',
            r'response if ${url} ~= /ads/ then response.header.set("X-Test", "backslash \\${Enabled}")',
            'response if ${url} ~= /ads/ then response.header.set(["X-A", "X-B"], ["safe", "${Enabled}"])',
            'response if ${url} ~= /ads/ then response.json.replace(["a"], [[${Enabled}]])',
            'response if ${Enabled} == true then response.header.set("X-Test", "safe")',
            'response if (${url} == "${Enabled}" || ${response.status} == 200) then response.header.set("X-Test", "safe")',
            'response if ${url} ~= ${Enabled} then response.header.set("X-Test", "safe")',
            'response if ${url} ~= /ads/ then response.header.set("X-A", `${Enabled}`) | response.header.set("X-B", "${Enabled}")',
        ]
        for rewrite in rewrites:
            with self.subTest(rewrite=rewrite), self.assertRaisesRegex(compat.UnverifiedScriptArgument, 'shared'):
                context = self.context(['Enabled=switch, false, true'], [enable], [rewrite])
                self.assertIn('Enabled', context.non_enable_names)
                compat.plan_script_v2(parse_script_v2_line(enable), context)

    def test_legacy_reference_collection_retains_conservative_behavior(self):
        enable = 'cron "0 8 * * *" then script("https://example.com/a.js") with enable=${Enabled}'
        for line in ['hostname={Enabled}', 'hostname=`${Enabled}`', r'legacy "\${Enabled}"',
                     'http-response ^https://example.com script-path=https://example.com/b.js, argument="{Enabled}"']:
            with self.subTest(line=line):
                context = self.context(['Enabled=switch, false, true'], [enable], [line])
                self.assertIn('Enabled', context.non_enable_names)

    def test_raw_mock_minimal_reproduction_keeps_literal_and_enable_toggle(self):
        for literal in ['`literal ${Enabled}`', r'"literal \${Enabled}"']:
            with self.subTest(literal=literal), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                path = root / 'Literal.lpx'
                path.write_text('#!name=Literal\n[Argument]\nEnabled=switch, false, true\n[Rewrite]\n' +
                                'response if ${url} ~= /ads/ then response.body.mock("text", ' + literal + ')\n' +
                                '[Script]\ncron "0 8 * * *" then script("https://example.com/a.js") with enable=${Enabled}\n')
                loader = Mock(side_effect=AssertionError('must not fetch'))
                report = []
                result = convert_file(path, root, report, {}, script_source_loader=loader)
                self.assertIsNotNone(result, report)
                output = (root / result['output']).read_text()
                self.assertIn('#!arguments=Enabled:#', output)
                self.assertIn('{{{Enabled}}}cron 1 =', output)
                self.assertIn(base64.b64encode(b'literal ${Enabled}').decode(), output)
                self.assertNotIn('module-excluded', [item['kind'] for item in report])
                loader.assert_not_called()

    def test_literal_reference_regression_passes_full_staged_and_independent_validation(self):
        for literal in ['`literal ${Enabled}`', r'"literal \${Enabled}"']:
            for action in ['response.body.mock("text", VALUE)',
                           'response.body.replace(/ad/, VALUE)',
                           'response.header.set("X-Test", VALUE)']:
                with self.subTest(literal=literal, action=action), tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
                    root = Path(tmp)
                    (root / 'Loon').mkdir()
                    (root / 'Loon' / 'Literal.lpx').write_text(
                        '#!name=Literal\n[Argument]\nEnabled=switch, false, true\n[Rewrite]\n' +
                        'response if ${url} ~= /rewrite-only/ then ' + action.replace('VALUE', literal) + '\n' +
                        '[Script]\ncron "0 8 * * *" then script("https://example.com/a.js") with enable=${Enabled}\n')
                    previous = Path.cwd()
                    try:
                        os.chdir(root)
                        with patch('convert_kelee_to_surge.fetch_script_source', side_effect=AssertionError('must not fetch')) as loader:
                            convert_kelee_to_surge('Loon', 'Surge', 'Surge/convert-report.json')
                            summary = validate_surge_modules('Loon', 'Surge', 'Surge/convert-report.json')
                        self.assertEqual(summary['modules'], 1)
                        loader.assert_not_called()
                        output = (root / 'Surge' / 'Literal.sgmodule').read_text()
                        self.assertIn('#!arguments=Enabled:#', output)
                        self.assertIn('{{{Enabled}}}cron 1 =', output)
                        expected = base64.b64encode(b'literal ${Enabled}').decode() if '.mock(' in action else 'literal ${Enabled}'
                        self.assertIn(expected, output)
                    finally:
                        os.chdir(previous)

    def test_dynamic_enable_can_be_shared_between_only_enable_properties(self):
        lines = [f'cron "0 {hour} * * *" then script("https://example.com/a.js") with enable=${{Enabled}}' for hour in [8, 9]]
        context = self.context(['Enabled=switch, false, true'], lines)
        for line in lines:
            self.assertEqual(compat.adapt_script_v2(parse_script_v2_line(line), context).enable_prefix, '{{{Enabled}}}')

    def test_dynamic_enable_rejects_string_default_and_missing_declaration(self):
        line = 'cron "0 8 * * *" then script("https://example.com/a.js") with enable=${Enabled}'
        for arguments in [[], ['Enabled=input, "true"'], ['Enabled=switch, "true", "false"'], ['Enabled=select, true, false']]:
            with self.subTest(arguments=arguments), self.assertRaises(compat.UnverifiedScriptArgument):
                compat.adapt_script_v2(parse_script_v2_line(line), self.context(arguments, [line]))

    def test_dynamic_cron_default_validated_but_placeholder_preserved(self):
        line = 'cron ${CRONEXP} then script("https://example.com/a.js")'
        for declaration in ['CRONEXP=input, "0 8 * * *"', 'CRONEXP=select, "0 0 8 * * *", "0 5,17 * * *"']:
            with self.subTest(declaration=declaration):
                adapted = compat.adapt_script_v2(parse_script_v2_line(line), self.context([declaration], [line]))
                _, parts = prepare_script_v2(adapted.script)
                self.assertIn('cronexp="{{{CRONEXP}}}"', adapted.apply_parts(parts))
                self.assertEqual(adapted.cron_override, '{{{CRONEXP}}}')

    def test_dynamic_cron_rejects_injection_and_invalid_any_choice(self):
        line = 'cron ${CRON} then script("https://example.com/a.js")'
        invalid = ['', '0 8 * *', '0 8 * * * * *', '60 8 * * *', '0 24 * * *', '0 8 0 * *',
                   '0 8 * 13 *', '0 8 * * 8', '*/0 8 * * *', '5-3 8 * * *', '0 8 * * sun',
                   '0 8 * * *\\nInjected', '0 8 * * *\\"', '0 8 * * *\\\\', '${Other}', '0  8 * * *',
                   '٠ 8 * * *', '0 8 * * * #', '0 8 * * *%ARG%']
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(compat.UnverifiedScriptArgument):
                context = self.context([f'CRON=select, "0 8 * * *", "{value}"'], [line])
                compat.adapt_script_v2(parse_script_v2_line(line), context)
        for arguments in [[], ['CRON=switch, true, false'], ['CRON=input, "0 8 * * *", type=number']]:
            with self.subTest(arguments=arguments), self.assertRaises(compat.UnverifiedScriptArgument):
                compat.adapt_script_v2(parse_script_v2_line(line), self.context(arguments, [line]))

    def test_backtick_declaration_defaults_are_rejected_before_cron_rendering(self):
        line = 'cron ${CRON} then script("https://example.com/a.js")'
        for declaration in ['CRON=input, `0 8 * * *`',
                            'CRON=select, `0 8 * * *`, `0 9 * * *`',
                            'CRON=select, "0 8 * * *", `0 9 * * *`']:
            with self.subTest(declaration=declaration), self.assertRaisesRegex(compat.UnverifiedScriptArgument, 'double-quoted'):
                compat.adapt_script_v2(parse_script_v2_line(line), self.context([declaration], [line]))
        adapted = compat.adapt_script_v2(parse_script_v2_line(line), self.context(['CRON=input, "0 8 * * *"'], [line]))
        self.assertEqual(adapted.cron_override, '{{{CRON}}}')

    def test_backtick_finite_selects_are_not_string_declarations(self):
        line = self.line(YOUTUBE, ['captionLang'])
        for declaration in ['captionLang=select, `off`, `zh-Hans`',
                            'captionLang=select, "off", `zh-Hans`']:
            with self.subTest(declaration=declaration), self.assertRaisesRegex(compat.UnverifiedScriptArgument, 'double-quoted'):
                self.adapt_with_probe(line, [declaration])
        adapted = self.adapt_with_probe(line, ['captionLang=select, "off", "zh-Hans"'])
        self.assertEqual(adapted.argument_override, '{"captionLang":"{{{captionLang}}}"}')

    def test_local_object_declarations_are_checked_before_source_fetch(self):
        line = self.line(variables=['tab'])
        for declarations in [[], ['tab=input, "false"'], ['tab=switch, false, true, tag=Tab, bogus']]:
            loader = Mock(side_effect=TimeoutError('offline'))
            with self.subTest(declarations=declarations), self.assertRaises(compat.UnverifiedScriptArgument):
                compat.adapt_script_v2(parse_script_v2_line(line), self.context(declarations), source_loader=loader)
            loader.assert_not_called()

    def test_object_enable_and_cron_declarations_are_checked_without_fetching(self):
        object_line = self.line(variables=['tab'])
        cron_line = object_line.replace('response if ${url} ~= /ads/', 'cron ${Schedule}')
        cases = [(object_line + ' with enable=${Enabled}', ['tab=switch, false, true']),
                 (object_line + ' with enable=${tab}', ['tab=switch, false, true']),
                 (cron_line, ['tab=switch, false, true']),
                 (cron_line, ['tab=switch, false, true', 'Schedule=input, "invalid"'])]
        for line, declarations in cases:
            with self.subTest(line=line, declarations=declarations):
                loader = Mock(side_effect=TimeoutError('offline'))
                with self.assertRaises(compat.UnverifiedScriptArgument):
                    compat.adapt_script_v2(parse_script_v2_line(line), self.context(declarations, [line]), source_loader=loader)
                loader.assert_not_called()

    def test_single_script_api_runs_local_validator_before_verification(self):
        line = self.line(variables=['tab']) + ' with timeout=${Timeout}'
        loader = Mock(side_effect=TimeoutError('offline'))
        with self.assertRaisesRegex(UnverifiedScriptV2, 'Dynamic timeout'):
            compat.adapt_script_v2(parse_script_v2_line(line), self.context(['tab=switch, false, true']),
                                   source_loader=loader, local_validator=prepare_script_v2)
        loader.assert_not_called()

    def test_interpolated_object_script_path_is_rejected_without_fetching(self):
        script = parse_script_v2_line(self.line(variables=['tab']))
        context = self.context(['tab=switch, false, true'])
        for path in [V2Variable('ScriptPath'), V2String(('https://example.com/', V2Variable('File')))]:
            with self.subTest(path=path):
                loader = Mock(side_effect=TimeoutError('offline'))
                with self.assertRaisesRegex(compat.UnverifiedScriptArgument, 'fixed String script path'):
                    compat.adapt_script_v2(replace(script, path=path), context, source_loader=loader,
                                           local_validator=prepare_script_v2)
                loader.assert_not_called()
        loader = Mock(side_effect=TimeoutError('offline'))
        output, report = self.convert_with_loader([self.line(variables=['tab']).replace(SPOTIFY, 'https://example.com/${File}')], loader)
        self.assertIsNone(output)
        self.assertEqual([item['kind'] for item in report], ['unsupported-script'])
        loader.assert_not_called()

    def test_unverified_object_plan_cannot_render(self):
        plan = compat.plan_script_v2(parse_script_v2_line(self.line(variables=['tab'])),
                                    self.context(['tab=switch, false, true']))
        self.assertFalse(plan.source_verified)
        _, parts = prepare_script_v2(plan.script)
        with self.assertRaisesRegex(compat.ScriptSourceVerificationError, 'before rendering'):
            plan.apply_parts(parts)
        with self.assertRaises(compat.ScriptSourceVerificationError):
            compat.verify_script_v2_source(plan)

    def test_unverified_preview_is_read_only_and_matches_verified_render(self):
        script = parse_script_v2_line(self.line(variables=['tab']))
        context = self.context(['tab=switch, false, true'])
        adapters = dict(compat.VERIFIED_OBJECT_ADAPTERS)
        adapters[SPOTIFY] = replace(adapters[SPOTIFY], sha256=hashlib.sha256(PROBE_BYTES).hexdigest())
        with patch.object(compat, 'VERIFIED_OBJECT_ADAPTERS', adapters):
            plan = compat.plan_script_v2(script, context)
            _, parts = prepare_script_v2(plan.script)
            original = list(parts)
            preview = plan.preview_parts(parts)
            self.assertEqual(parts, original)
            self.assertFalse(plan.source_verified)
            self.assertTrue(any(part.startswith('argument=') for part in preview))
            with self.assertRaisesRegex(compat.ScriptSourceVerificationError, 'before rendering'):
                plan.apply_parts(parts)
            verified = compat.verify_script_v2_source(plan, source_loader=lambda _: PROBE_BYTES)
            self.assertTrue(verified.source_verified)
            self.assertFalse(plan.source_verified)
            self.assertEqual(verified.apply_parts(parts), preview)

    def convert_with_loader(self, script_lines, loader, declarations=None):
        declarations = declarations if declarations is not None else ['tab=switch, false, true']
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'Sample.lpx'
            source.write_text('#!name=Sample\n[Argument]\n' + '\n'.join(declarations) +
                              '\n[Script]\n' + '\n'.join(script_lines) + '\n')
            report = []
            result = convert_file(source, root, report, {}, script_source_loader=loader)
            output = (root / result['output']).read_text() if result else None
            return output, report

    def test_converter_excludes_unsupported_object_features_without_fetching(self):
        object_line = self.line(variables=['tab'])
        unsupported = [object_line + ' with timeout=${Timeout}', object_line + ' with debug=${Debug}',
                       object_line + ' with tag="invalid # inline comment"',
                       object_line.replace('/ads/', '/ads/ && ${response.status} == 200'),
                       object_line.replace('response if ${url} ~= /ads/', 'network-changed')]
        for line in unsupported:
            with self.subTest(line=line):
                loader = Mock(side_effect=TimeoutError('offline'))
                output, report = self.convert_with_loader([line], loader)
                self.assertIsNone(output)
                self.assertEqual([item['kind'] for item in report], ['module-excluded'])
                loader.assert_not_called()

    def test_converter_reports_malformed_object_properties_without_fetching(self):
        object_line = self.line(variables=['tab'])
        malformed = ['body_limit=${Limit}', 'body-limit=100', 'requires_body=${Body}',
                     'timeout=0', 'debug="true"', 'tag="A", tag="B"', 'timeout=']
        for properties in malformed:
            with self.subTest(properties=properties):
                loader = Mock(side_effect=TimeoutError('offline'))
                output, report = self.convert_with_loader([object_line + ' with ' + properties], loader)
                self.assertIsNone(output)
                self.assertEqual([item['kind'] for item in report], ['unsupported-script'])
                loader.assert_not_called()

    def test_converter_checks_all_local_lines_before_fetching_any_object(self):
        first = self.line(variables=['tab'])
        cases = [(first + ' with timeout=${Timeout}', 'module-excluded'),
                 (first + ' with body_limit=${Limit}', 'unsupported-script'),
                 (first + ' with timeout=0', 'unsupported-script'),
                 ('generic script-path=https://example.com/not-reviewed.js', 'module-excluded')]
        for second, kind in cases:
            for lines in ([first, second], [second, first]):
                with self.subTest(lines=lines):
                    loader = Mock(side_effect=TimeoutError('offline'))
                    output, report = self.convert_with_loader(lines, loader)
                    self.assertIsNone(output)
                    self.assertEqual([item['kind'] for item in report], [kind])
                    loader.assert_not_called()

    def test_converter_checks_warp_cardinality_before_any_object_fetch(self):
        object_line = self.line(variables=['tab'])
        for warp_lines in [
            [f'generic then script("{WARP_PANEL_SCRIPT_PATH}") with tag="One"',
             f'generic then script("{WARP_PANEL_SCRIPT_PATH}") with tag="Two"'],
            [f'generic script-path={WARP_PANEL_SCRIPT_PATH}, tag=One',
             f'generic then script("{WARP_PANEL_SCRIPT_PATH}") with tag="Two"'],
        ]:
            for lines in itertools.permutations([object_line, *warp_lines]):
                with self.subTest(lines=lines):
                    loader = Mock(side_effect=TimeoutError('offline'))
                    output, report = self.convert_with_loader(lines, loader)
                    self.assertIsNone(output)
                    self.assertEqual([item['kind'] for item in report], ['module-excluded'])
                    self.assertIn('multiple WARP generic entries', report[0]['message'])
                    loader.assert_not_called()

    def test_converter_checks_warp_reference_collisions_before_any_object_fetch(self):
        object_line = self.line(variables=['tab'])
        warp = f'generic then script("{WARP_PANEL_SCRIPT_PATH}") with tag="Same"'
        declarations = ['tab=switch, false, true', 'Enabled=switch, false, true']
        for other in ['cron "0 8 * * *" then script("https://example.com/a.js") with tag="Same"',
                      'cron "0 8 * * *" then script("https://example.com/a.js") with tag="Same", enable=${Enabled}',
                      'cron "0 8 * * *" then script("https://example.com/a.js") with tag="Same", enable=false',
                      'http-response ^https://example.com script-path=https://example.com/a.js, tag=Same, enable={Enabled}']:
            for lines in itertools.permutations([object_line, warp, other]):
                with self.subTest(lines=lines):
                    loader = Mock(side_effect=TimeoutError('offline'))
                    output, report = self.convert_with_loader(lines, loader, declarations)
                    self.assertIsNone(output)
                    self.assertEqual([item['kind'] for item in report], ['module-excluded'])
                    self.assertIn('does not identify exactly one Script', report[0]['message'])
                    loader.assert_not_called()

    def test_converter_checks_warp_fallback_name_collisions_before_object_fetch(self):
        object_line = self.line(variables=['tab'])
        for order in itertools.permutations(['object', 'warp', 'other']):
            cases = [
                {'object': object_line,
                 'warp': f'generic then script("{WARP_PANEL_SCRIPT_PATH}")',
                 'other': 'cron "0 8 * * *" then script("https://example.com/a.js") with tag="generic ' + str(order.index('warp') + 1) + '"'},
                {'object': object_line,
                 'warp': f'generic then script("{WARP_PANEL_SCRIPT_PATH}") with tag="http-response {order.index("other") + 1}"',
                 'other': 'http-response ^https://example.com script-path=https://example.com/a.js'},
            ]
            for case in cases:
                lines = [case[key] for key in order]
                with self.subTest(lines=lines):
                    loader = Mock(side_effect=TimeoutError('offline'))
                    output, report = self.convert_with_loader(lines, loader)
                    self.assertIsNone(output)
                    self.assertEqual([item['kind'] for item in report], ['module-excluded'])
                    self.assertIn('does not identify exactly one Script', report[0]['message'])
                    loader.assert_not_called()

    def test_converter_valid_object_still_fetches_and_fails_closed(self):
        line = self.line(variables=['tab'])
        adapters = dict(compat.VERIFIED_OBJECT_ADAPTERS)
        adapters[SPOTIFY] = replace(adapters[SPOTIFY], sha256=hashlib.sha256(PROBE_BYTES).hexdigest())
        with patch.object(compat, 'VERIFIED_OBJECT_ADAPTERS', adapters):
            loader = Mock(return_value=PROBE_BYTES)
            output, report = self.convert_with_loader([line], loader)
            self.assertIsNotNone(output)
            self.assertIn('script-object-adapted', [item['kind'] for item in report])
            loader.assert_called_once_with(SPOTIFY)
            for bad_loader in [Mock(return_value=b'changed bytes'), Mock(side_effect=TimeoutError('offline'))]:
                with self.subTest(loader=bad_loader):
                    output, report = self.convert_with_loader([line], bad_loader)
                    self.assertIsNone(output)
                    self.assertEqual([item['kind'] for item in report], ['script-verification'])
                    bad_loader.assert_called_once_with(SPOTIFY)

    def test_static_and_generic_scripts_are_unchanged(self):
        for line in ['cron "0 8 * * *" then script("https://example.com/a.js", "x=y") with enable=false',
                     'generic then script("https://example.com/a.js")']:
            script = parse_script_v2_line(line)
            adapted = compat.adapt_script_v2(script, self.context([]))
            self.assertIs(adapted.script, script)
            self.assertIsNone(adapted.enable_prefix)
            self.assertIsNone(adapted.argument_override)
            self.assertIsNone(adapted.cron_override)


if __name__ == '__main__':
    unittest.main()
