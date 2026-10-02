from __future__ import annotations

from dataclasses import replace
import hashlib
import itertools
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import script_v2_compat as compat
from loon_script_v2 import parse_script_v2_line
from convert_kelee_to_surge import prepare_script_v2


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
        for loader in [None, lambda _: b'changed', lambda _: 'not bytes']:
            with self.subTest(loader=loader), self.assertRaises(compat.ScriptSourceVerificationError):
                compat.adapt_script_v2(script, self.context([]), source_loader=loader)
        def unavailable(_):
            raise TimeoutError('offline')
        with self.assertRaisesRegex(compat.ScriptSourceVerificationError, 'TimeoutError'):
            compat.adapt_script_v2(script, self.context([]), source_loader=unavailable)
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
