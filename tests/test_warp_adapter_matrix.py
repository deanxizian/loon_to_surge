"""Offline cross-matrix for the implemented WARP Panel/Script adapter only."""
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
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))

import script_v2_compat as compat
from convert_kelee_to_surge import (
    WARP_PANEL_SCRIPT_PATH, convert_file, convert_kelee_to_surge,
    fatal_report_items, parse_properties, surge_script_reference_name,
)
from validate_surge_modules import validate_surge_modules

SPOTIFY = compat.BASE + 'Spotify/Spotify_remove_ads.js'
PROBE = b'// Offline pinned WARP matrix fixture. Never execute this text.\n'
OBJECT = f'response if ${{url}} ~= /ads/ then script("{SPOTIFY}", {{${{tab}}}}) with tag="Object"'
TRUE_ALIASES = ('true', '1', 'on', 'yes')
FALSE_ALIASES = ('false', '0', 'off', 'no')


@contextlib.contextmanager
def working_directory(path):
    previous = Path.cwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(previous)


class WarpAdapterMatrixTest(unittest.TestCase):
    def setUp(self):
        self.socket_guard = patch('socket.create_connection', side_effect=AssertionError('network forbidden'))
        self.socket_guard.start()
        self.addCleanup(self.socket_guard.stop)
        self.http_guard = patch('urllib.request.urlopen', side_effect=AssertionError('HTTP forbidden'))
        self.http_guard.start()
        self.addCleanup(self.http_guard.stop)
        adapters = dict(compat.VERIFIED_OBJECT_ADAPTERS)
        adapters[SPOTIFY] = replace(adapters[SPOTIFY], sha256=hashlib.sha256(PROBE).hexdigest())
        self.adapter_patch = patch.object(compat, 'VERIFIED_OBJECT_ADAPTERS', adapters)
        self.adapter_patch.start()
        self.addCleanup(self.adapter_patch.stop)

    def warp(self, syntax, enable=None, name='Warp'):
        if syntax == 'legacy':
            return (f'generic script-path={WARP_PANEL_SCRIPT_PATH}, tag={name}, timeout=10' +
                    (f', enable={enable}' if enable is not None else ''))
        encoded_name = json.dumps(name, ensure_ascii=False).replace('${', '\\${')
        return (f'generic then script("{WARP_PANEL_SCRIPT_PATH}") with tag={encoded_name}, timeout=10' +
                (f', enable={enable}' if enable is not None else ''))

    def dynamic(self, syntax):
        return '{Enabled}' if syntax == 'legacy' else '${Enabled}'

    def convert(self, lines, *, default='false', allow_fetch=False):
        loader = Mock(return_value=PROBE) if allow_fetch else Mock(side_effect=AssertionError('must not fetch'))
        opposite = 'false' if default == 'true' else 'true'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'Matrix.lpx'
            source.write_text('#!name=Matrix\n[Argument]\ntab=switch, false, true\n' +
                              f'Enabled=switch, {default}, {opposite}\n[Script]\n' + '\n'.join(lines) + '\n')
            report = []
            result = convert_file(source, root, report, {}, script_source_loader=loader)
            output = (root / result['output']).read_text() if result else None
            return output, report, loader

    def variants(self, aliases):
        return list(dict.fromkeys(value for alias in aliases
                                  for value in (alias, alias.upper(), f'"{alias}"', f"'{alias}'")))

    def orders(self, lines, include_object):
        return itertools.permutations([*lines, OBJECT] if include_object else lines)

    def assert_enabled(self, output, report, loader, include_object, name='Warp'):
        self.assertIsNotNone(output)
        self.assertFalse(fatal_report_items(report), report)
        self.assertNotIn('module-excluded', [item['kind'] for item in report])
        self.assertIn('script-name=' + name, output)
        target = [line for line in output.splitlines() if ' = type=generic' in line]
        self.assertEqual(len(target), 1)
        self.assertTrue(target[0].startswith(name + ' = '), target[0])
        self.assertNotIn('enable=', target[0])
        self.assertEqual(surge_script_reference_name(target[0]), name)
        props = parse_properties(target[0].split(' = ', 1)[1])
        self.assertEqual(props['script-path'], WARP_PANEL_SCRIPT_PATH)
        self.assertEqual(props['timeout'], '10')
        if include_object:
            loader.assert_called_once_with(SPOTIFY)
            self.assertIn('script-object-adapted', [item['kind'] for item in report])
        else:
            loader.assert_not_called()

    def assert_excluded(self, output, report, loader):
        self.assertIsNone(output)
        self.assertEqual([item['kind'] for item in report], ['module-excluded'], report)
        loader.assert_not_called()

    def test_enabled_control_matrix_and_equivalent_legacy_v2_output(self):
        cases = [('legacy', value) for value in [None, *self.variants(TRUE_ALIASES)]]
        cases += [('v2', None), ('v2', 'true')]
        expected_warp_lines = None
        for syntax, value in cases:
            for include_object in (False, True):
                for lines in self.orders([self.warp(syntax, value)], include_object):
                    with self.subTest(syntax=syntax, enable=value, lines=lines):
                        output, report, loader = self.convert(lines, allow_fetch=include_object)
                        self.assert_enabled(output, report, loader, include_object)
                        # Explicit timeout/tag make these equivalent forms comparable;
                        # report wording and unused source arguments are irrelevant.
                        warp_lines = [line for line in output.splitlines()
                                      if line.startswith('Warp = ') or line.startswith('Warp = title=')]
                        if expected_warp_lines is None:
                            expected_warp_lines = warp_lines
                        self.assertEqual(warp_lines, expected_warp_lines)

    def test_disabled_control_matrix_excludes_before_object_verification(self):
        cases = [('legacy', value) for value in self.variants(FALSE_ALIASES)] + [('v2', 'false')]
        for syntax, value in cases:
            for include_object in (False, True):
                for lines in self.orders([self.warp(syntax, value)], include_object):
                    with self.subTest(syntax=syntax, enable=value, lines=lines):
                        self.assert_excluded(*self.convert(lines))

    def test_dynamic_control_matrix_excludes_for_both_defaults_and_orders(self):
        for syntax, default, include_object in itertools.product(('legacy', 'v2'), ('true', 'false'), (False, True)):
            for lines in self.orders([self.warp(syntax, self.dynamic(syntax))], include_object):
                with self.subTest(syntax=syntax, default=default, lines=lines):
                    self.assert_excluded(*self.convert(lines, default=default))

    def test_malformed_enable_controls_are_fatal_without_fetch(self):
        invalid = [('legacy', value) for value in ('bogus', '', '#', '{Missing', 'false, enable=true')]
        invalid += [('v2', value) for value in ('"false"', '1', 'on', '', 'false, enable=true')]
        for syntax, value in invalid:
            for include_object in (False, True):
                for lines in self.orders([self.warp(syntax, value)], include_object):
                    with self.subTest(syntax=syntax, enable=value, lines=lines):
                        output, report, loader = self.convert(lines)
                        self.assertIsNone(output)
                        self.assertTrue(fatal_report_items(report), report)
                        self.assertNotIn('module-excluded', [item['kind'] for item in report])
                        loader.assert_not_called()

    def test_malformed_script_anywhere_precedes_warp_exclusion_and_fetch(self):
        malformed = [
            'http-response ^https://example.com script-path=https://example.com/a.js, requires-body=invalid',
            'generic script-path=https://example.com/a.js, bogus=true',
            'cron "0 8 * * *" then script("https://example.com/a.js") with timeout=0',
            'response if ${url} ~= /invalid/ then script("https://example.com/a.js") with body_limit=1',
        ]
        for syntax, dynamic, include_object, bad in itertools.product(('legacy', 'v2'), (False, True), (False, True), malformed):
            warp = self.warp(syntax, self.dynamic(syntax) if dynamic else 'false')
            for lines in self.orders([warp, bad], include_object):
                with self.subTest(syntax=syntax, dynamic=dynamic, lines=lines):
                    output, report, loader = self.convert(lines)
                    self.assertIsNone(output)
                    self.assertTrue(fatal_report_items(report), report)
                    self.assertNotIn('module-excluded', [item['kind'] for item in report])
                    loader.assert_not_called()

    def test_cardinality_matrix_covers_both_syntaxes_controls_and_orders(self):
        for first_syntax, second_syntax, first_control, second_control, include_object in itertools.product(
                ('legacy', 'v2'), ('legacy', 'v2'), ('absent', 'true', 'false', 'dynamic'),
                ('absent', 'true', 'false', 'dynamic'), (False, True)):
            first_enable = None if first_control == 'absent' else self.dynamic(first_syntax) if first_control == 'dynamic' else first_control
            second_enable = None if second_control == 'absent' else self.dynamic(second_syntax) if second_control == 'dynamic' else second_control
            warps = [self.warp(first_syntax, first_enable, 'One'), self.warp(second_syntax, second_enable, 'Two')]
            for lines in self.orders(warps, include_object):
                with self.subTest(lines=lines):
                    self.assert_excluded(*self.convert(lines))

    def collision_candidate(self, syntax, control, name):
        if syntax == 'legacy':
            return ('http-response ^https://example.com script-path=https://example.com/a.js, tag=' + name +
                    (', enable=' + control if control is not None else ''))
        return ('cron "0 8 * * *" then script("https://example.com/a.js") with tag="' + name + '"' +
                (', enable=' + control if control is not None else ''))

    def test_target_name_matrix_covers_legacy_v2_disabled_dynamic_candidates(self):
        for warp_syntax, other_syntax, control_kind, default, same_name, include_object in itertools.product(
                ('legacy', 'v2'), ('legacy', 'v2'), ('absent', 'true', 'false', 'dynamic'),
                ('true', 'false'), (True, False), (False, True)):
            control = None if control_kind == 'absent' else self.dynamic(other_syntax) if control_kind == 'dynamic' else control_kind
            pair = [self.warp(warp_syntax), self.collision_candidate(other_syntax, control, 'Warp' if same_name else 'Other')]
            for lines in self.orders(pair, include_object):
                with self.subTest(lines=lines, default=default, same_name=same_name):
                    output, report, loader = self.convert(lines, default=default, allow_fetch=include_object and not same_name)
                    if same_name:
                        self.assert_excluded(output, report, loader)
                    else:
                        self.assert_enabled(output, report, loader, include_object)

    def test_plain_tag_name_matrix_preserves_legacy_v2_names(self):
        names = ['Warp', 'WARP INFO', 'WARP · INFO', 'Warp#Info', 'Warp;Info', 'Warp//Info', '网络信息']
        for syntax, name, enable, include_object in itertools.product(('legacy', 'v2'), names, (None, 'true'), (False, True)):
            for lines in self.orders([self.warp(syntax, enable, name)], include_object):
                with self.subTest(syntax=syntax, name=name, lines=lines):
                    self.assert_enabled(*self.convert(lines, allow_fetch=include_object), include_object, name=name)

    def test_unsupported_tag_matrix_excludes_before_object_verification(self):
        common = ['#Warp', ';Warp', '//Warp', '[Warp]', 'Warp=Info',
                  'Warp # comment', 'Warp ; comment', 'Warp // comment', 'Warp\\Info',
                  '{Name}', '${Name}', '%Name%', '{{{Name}}}', 'Warp\tInfo', 'Warp\x7fInfo']
        cases = [('legacy', name) for name in [*common, '"Warp"', "'Warp'", '"Warp,Info"', 'Warp"Info"', "Warp'Info'"]]
        cases += [('v2', name) for name in [*common, 'Warp,Info', 'Warp"Info', "Warp'Info", ' Warp', 'Warp ']]
        for (syntax, name), control, include_object in itertools.product(cases, ('absent', 'true', 'false', 'dynamic'), (False, True)):
            enable = None if control == 'absent' else self.dynamic(syntax) if control == 'dynamic' else control
            for lines in self.orders([self.warp(syntax, enable, name)], include_object):
                with self.subTest(syntax=syntax, name=name, control=control, lines=lines):
                    self.assert_excluded(*self.convert(lines))

    def test_dynamic_v2_tag_remains_fatal_before_enable_exclusion(self):
        for enable, include_object in itertools.product((None, 'true', 'false', '${Enabled}'), (False, True)):
            bad = f'generic then script("{WARP_PANEL_SCRIPT_PATH}") with tag="${{Name}}"'
            if enable is not None:
                bad += ', enable=' + enable
            for lines in self.orders([bad], include_object):
                with self.subTest(enable=enable, lines=lines):
                    output, report, loader = self.convert(lines)
                    self.assertIsNone(output)
                    self.assertEqual([item['kind'] for item in report], ['unsupported-script'])
                    loader.assert_not_called()

    def test_malformed_legacy_tag_quote_matrix_stays_fatal_before_exclusions(self):
        bad_tags = ['"unterminated', "'unterminated", '"Warp" junk', "'Warp' junk",
                    '\"Warp\'', "'Warp\"", 'Warp"', "Warp'"]
        controls = [(None, 'false'), ('true', 'false'), ('false', 'false'), ('{Enabled}', 'false'), ('{Enabled}', 'true')]
        for tag, (enable, default), multiple, object_mode in itertools.product(bad_tags, controls, (False, True), ('none', 'offline', 'good')):
            # Put enable before the malformed tag so an unclosed quote cannot
            # swallow the enable field and accidentally change the test state.
            bad = f'generic script-path={WARP_PANEL_SCRIPT_PATH}, timeout=10'
            if enable is not None:
                bad += ', enable=' + enable
            bad += ', tag=' + tag
            lines = [bad, self.warp('v2', name='Other')] if multiple else [bad]
            for ordered in self.orders(lines, object_mode != 'none'):
                with self.subTest(tag=tag, enable=enable, default=default, multiple=multiple, object_mode=object_mode, lines=ordered):
                    output, report, loader = self.convert(ordered, default=default, allow_fetch=object_mode == 'good')
                    self.assertIsNone(output)
                    self.assertTrue(fatal_report_items(report), report)
                    self.assertIn('unsupported-script', [item['kind'] for item in report])
                    self.assertNotIn('module-excluded', [item['kind'] for item in report])
                    loader.assert_not_called()

    def test_independent_validator_rejects_missing_ambiguous_and_inactive_targets(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(tmp)
            (root / 'Loon').mkdir()
            (root / 'Loon' / 'Warp.lpx').write_text('#!name=Warp\n[Script]\n' + self.warp('v2') + '\n')
            with working_directory(root):
                convert_kelee_to_surge('Loon', 'Surge', 'Surge/convert-report.json')
                output = root / 'Surge' / 'Warp.sgmodule'
                pristine = output.read_text()
                self.assertEqual(validate_surge_modules('Loon', 'Surge', 'Surge/convert-report.json')['modules'], 1)
                mutations = {
                    'missing': pristine.replace('script-name=Warp', 'script-name=Missing'),
                    'ambiguous': pristine + 'Warp = type=cron, cronexp="0 8 * * *", script-path=https://example.com/a.js\n',
                    'static-disabled': pristine.replace('\nWarp = type=generic', '\n#Warp = type=generic'),
                    'dynamic-disabled': '#!requirement=CORE_VERSION>=20\n#!arguments=Enabled:#\n' +
                                        pristine.replace('\nWarp = type=generic', '\n{{{Enabled}}}Warp = type=generic'),
                    'dynamic-enabled': '#!requirement=CORE_VERSION>=20\n#!arguments=Enabled\n' +
                                       pristine.replace('\nWarp = type=generic', '\n{{{Enabled}}}Warp = type=generic'),
                }
                for kind, text in mutations.items():
                    with self.subTest(kind=kind):
                        output.write_text(text)
                        with self.assertRaisesRegex(RuntimeError, 'WARP Script must be unconditionally enabled for Panel linkage'
                                                    if kind in {'static-disabled', 'dynamic-disabled', 'dynamic-enabled'} else 'Panel|panel'):
                            validate_surge_modules('Loon', 'Surge', 'Surge/convert-report.json')
                output.write_text(pristine)


if __name__ == '__main__':
    unittest.main()
