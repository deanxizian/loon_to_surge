"""Documented Loon build 1007/1008 behavior and unavailable-resource publication."""
from __future__ import annotations

import base64
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import convert_kelee_to_surge as converter
from surge_syntax import tokenize_surge_line
from validate_surge_modules import SurgeValidationError, validate_section_line, validate_surge_modules


class OctoberSyntaxTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.input = self.root / "Loon"
        self.output = self.root / "Surge"
        self.input.mkdir()
        self.output.mkdir()
        self.report_path = self.output / "convert-report.json"
        guard = patch("urllib.request.urlopen", side_effect=AssertionError("Unexpected network in offline tests"))
        guard.start()
        self.addCleanup(guard.stop)

    def source(self, text, name="Sample"):
        path = self.input / f"{name}.lpx"
        path.write_text(f"#!name={name}\n" + text, encoding="utf-8")
        return path

    def publish(self):
        with contextlib.chdir(self.root), contextlib.redirect_stdout(io.StringIO()):
            converter.convert_kelee_to_surge(str(self.input), str(self.output), str(self.report_path))
        return json.loads(self.report_path.read_text())

    def validate(self):
        return validate_surge_modules(str(self.input), str(self.output), str(self.report_path))

    def converted(self):
        return (self.output / "Sample.sgmodule").read_text()

    def test_domain_wildcards_preserve_globs_and_scope_rule_flags(self):
        self.source('[Rule]\n'
                    'DOMAIN-WILDCARD,*.example.com,DIRECT\n'
                    'DOMAIN-WILDCARD,api?.example.com,REJECT\n'
                    'OR,((DOMAIN-WILDCARD,node[0-9].example.com),(DOMAIN-WILDCARD,node[!abc].example.com)),REJECT\n'
                    'DOMAIN-WILDCARD,"node[a, b].example.com",DIRECT\n')
        self.publish()
        text = self.converted()
        self.assertIn('DOMAIN-WILDCARD,*.example.com,DIRECT,extended-matching\n', text)
        self.assertIn('DOMAIN-WILDCARD,api?.example.com,REJECT,extended-matching,pre-matching', text)
        self.assertIn('OR,((DOMAIN-WILDCARD,node[0-9].example.com,extended-matching),'
                      '(DOMAIN-WILDCARD,node[!abc].example.com,extended-matching)),REJECT,pre-matching', text)
        self.assertIn('DOMAIN-WILDCARD,"node[a, b].example.com",DIRECT,extended-matching', text)
        self.assertIn('#!requirement=CORE_VERSION>=6010000', text)
        self.validate()

    def test_network_configuration_normalizes_routes_and_keeps_first_ip_action(self):
        self.source('[General]\ninclude-tun = 10.8.0.9/24,10.7.0.1/32,10.8.0.0/24\nipv6-vif = off\n'
                    '[IP Rewrite]\n10.7.0.1 = reflect\n10.7.0.2 = reject\n10.7.0.1 = drop\n10.7.0.3 = drop\n')
        report = self.publish()
        text = self.converted()
        self.assertIn('tun-included-routes = %APPEND% 10.8.0.0/24, 10.7.0.1/32', text)
        self.assertIn('ipv6-vif = disabled', text)
        self.assertIn('[IP Rewrite]\n10.7.0.1 = reflect\n10.7.0.2 = reject\n10.7.0.3 = drop\n', text)
        self.assertNotIn('10.7.0.1 = drop', text)
        self.assertIn('#!requirement=CORE_VERSION>=6010000', text)
        self.assertEqual([x['kind'] for x in report['items']], ['ip-rewrite-duplicate-skipped'])
        self.validate()

    def test_repeated_general_lists_and_aliases_are_merged(self):
        self.source('[General]\n'
                    'real-ip = first.example, shared.example\n'
                    'include-tun = 10.8.0.9/24\n'
                    'ipv6-vif = off\n'
                    'always-real-ip = shared.example, second.example\n'
                    'real-ip = third.example, first.example\n'
                    'include-tun = 10.8.0.0/24, 10.7.0.1/32\n')
        self.publish()
        text = self.converted()
        self.assertIn('[General]\n'
                      'always-real-ip = %APPEND% first.example, shared.example, second.example, third.example\n'
                      'tun-included-routes = %APPEND% 10.8.0.0/24, 10.7.0.1/32\n'
                      'ipv6-vif = disabled\n', text)
        self.assertEqual(text.count('always-real-ip ='), 1)
        self.assertEqual(text.count('tun-included-routes ='), 1)
        self.validate()

    def test_auto_and_always_preserve_main_profile_ipv6_setting(self):
        for value in ('auto', 'always'):
            with self.subTest(value=value):
                self.source(f'[General]\nipv6-vif = {value}\n[Rule]\nDOMAIN,example.com,DIRECT\n')
                self.publish()
                self.assertNotIn('ipv6-vif', self.converted())
                self.assertNotIn('[General]', self.converted())
                self.validate()

    def test_general_only_noop_is_explicitly_excluded(self):
        self.source('[General]\nipv6-vif = auto\n')
        report = self.publish()
        self.assertEqual((report['converted'], report['excluded']), (0, 1))
        self.assertEqual([x['kind'] for x in report['items']], ['general-noop-skipped', 'module-excluded'])

    def test_invalid_network_source_preserves_previous_publication(self):
        cases = [f'[General]\ninclude-tun = {value}\n' for value in (
            '10.7.0.1', '10.7.0.1/33', '::1/128', 'example.com/32', '${route}',
            '10.7.0.1/32,', '', '10.7.0.1/255.255.255.255',
        )]
        cases += [f'[IP Rewrite]\n{value}\n' for value in (
            '10.7.0.1/32 = reflect', '::1 = drop', '${address} = reject',
            '10.7.0.1 = invalid', '10.7.0.1 = reflect\n10.7.0.1 = bad',
            '10.7.0.1 = reflect\n[IP Rewrite]\n10.7.0.2 = drop',
        )]
        cases += ['[General]\nipv6-vif = disabled\n',
                  '[General]\nipv6-vif = off\nipv6-vif = off\n',
                  '[General]\nreal-ip = example.com\nalways-real-ip = example.net,\n',
                  '[General]\ninclude-tun = 10.7.0.1/32\ninclude-tun = ::1/128\n']
        for source in cases:
            with self.subTest(source=source):
                self.source('[Rule]\nDOMAIN,example.com,DIRECT\n')
                self.publish()
                before = {p.name: p.read_bytes() for p in self.output.iterdir()}
                self.source(source)
                with self.assertRaises(RuntimeError):
                    self.publish()
                self.assertEqual(before, {p.name: p.read_bytes() for p in self.output.iterdir()})

    def test_sse_v2_inline_and_remote_mock_keep_content_type(self):
        body = 'event: done\ndata: {"ok":true}\n\n'
        self.source('[Rewrite]\nresponse if ${url} ~= /inline/ then response.body.mock("text/event-stream", '
                    + json.dumps(body) + ', 201)\n'
                    'response if ${url} ~= /remote/ then response.body.mock_file("text/event-stream", "https://example.com/events.txt")\n')
        self.publish()
        text = self.converted()
        self.assertIn('header="Content-Type:text/event-stream"', text)
        inline = next(line for line in text.splitlines() if line.startswith('inline '))
        values = dict(token.split('=', 1) for token in tokenize_surge_line(inline)[1:])
        self.assertEqual(base64.b64decode(values['data']).decode(), body)
        self.assertEqual(values['status-code'], '201')
        self.assertIn('remote data-type=file data="https://example.com/events.txt"', text)
        self.validate()

    def test_sse_legacy_mock_keeps_mime_for_inline_file_and_base64(self):
        for options in ('data="data: hello"', '', 'data-path="https://example.com/events.txt"',
                        'data="ZGF0YTogaGkK" mock-data-is-base64=true'):
            with self.subTest(options=options):
                self.source('[Rewrite]\n^https://example.com/events mock-response-body data-type=text/event-stream ' + options + '\n')
                self.publish()
                self.assertIn('header="Content-Type:text/event-stream"', self.converted())
                self.validate()

    def test_macos_process_paths_preserve_case_spaces_and_quoted_commas(self):
        self.source('#!system=macOS\n[Rule]\n'
                    'PROCESS-NAME,/Applications/Google Chrome.app/,DIRECT\n'
                    'PROCESS-NAME,"/Applications/Test, App.app/Contents/MacOS/*",REJECT\n'
                    'AND,((PROCESS-NAME,/usr/bin/curl),(DOMAIN-WILDCARD,api?.example.com)),DIRECT\n')
        self.publish()
        text = self.converted()
        self.assertIn('PROCESS-NAME,"/Applications/Test, App.app/Contents/MacOS/*",REJECT\n', text)
        self.assertIn('PROCESS-NAME,/Applications/Google Chrome.app/,DIRECT', text)
        self.assertNotIn('pre-matching', text)
        self.assertIn('#!system=mac', text)
        self.validate()

    def test_unverified_process_semantics_are_explicit_exclusions(self):
        cases = [('#!system=macOS\n', 'PROCESS-NAME,curl,DIRECT'),
                 ('#!system=macOS\n', 'PROCESS-NAME,/*/Worker[0-9],DIRECT'),
                 ('', 'PROCESS-NAME,/usr/bin/curl,DIRECT'),
                 ('#!system=macOS\n', 'NOT,((PROCESS-NAME,/usr/bin/curl)),DIRECT'),
                 ('#!system=macOS\n', 'NOT,((AND,((PROCESS-NAME,/usr/bin/curl),(DOMAIN,example.com)))),DIRECT')]
        for metadata, rule in cases:
            with self.subTest(rule=rule, metadata=metadata):
                self.source(metadata + '[Rule]\n' + rule + '\n')
                report = self.publish()
                self.assertEqual((report['converted'], report['excluded']), (0, 1))
                self.assertEqual(report['items'][0]['kind'], 'module-excluded')

    def test_process_exclusion_cannot_hide_malformed_sibling(self):
        self.source('#!system=macOS\n[Rule]\nOR,((PROCESS-NAME,curl),(UNKNOWN,value)),DIRECT\n')
        with self.assertRaisesRegex(RuntimeError, 'Unsupported Loon rule type'):
            self.publish()

    def test_rule_type_names_inside_values_do_not_trigger_feature_guards(self):
        cases = [
            ('URL-REGEX,"^https://example\\.com/\\(PROCESS-NAME,",DIRECT', True),
            ('NOT,((URL-REGEX,"^https://example\\.com/\\(PROCESS-NAME,")),DIRECT', True),
            ('AND,((DOMAIN,example.com),(NOT,((URL-REGEX,"(PROCESS-NAME,|(DOMAIN-WILDCARD,")))),DIRECT', True),
            ('USER-AGENT,"Client (PROCESS-NAME, (DOMAIN-WILDCARD, (URL-REGEX,",DIRECT', False),
            ('NOT,((USER-AGENT,"Client (PROCESS-NAME, (DOMAIN-WILDCARD, (URL-REGEX,")),DIRECT', False),
        ]
        for rule, url_regex in cases:
            with self.subTest(rule=rule):
                self.source('[Rule]\n' + rule + '\n')
                report = self.publish()
                self.assertEqual((report['converted'], report['excluded']), (1, 0))
                text = self.converted()
                self.assertNotIn('#!system=mac', text)
                self.assertNotIn('CORE_VERSION>=6010000', text)
                self.assertEqual('#!requirement=' + converter.SURGE_5_14_FEATURE_REQUIREMENT in text, url_regex)
                self.validate()

    def test_validator_rejects_duplicate_serialized_general_keys(self):
        for source, line in (
            ('real-ip=example.com', 'always-real-ip = %APPEND% example.net'),
            ('include-tun=10.7.0.1/32', 'tun-included-routes = %APPEND% 10.7.0.2/32'),
            ('ipv6-vif=off', 'ipv6-vif = disabled'),
        ):
            with self.subTest(source=source):
                self.source('[General]\n' + source + '\n')
                self.publish()
                path = self.output / 'Sample.sgmodule'
                path.write_text(self.converted().replace('[General]\n', '[General]\n' + line + '\n'))
                with self.assertRaisesRegex(SurgeValidationError, 'duplicate keys'):
                    self.validate()

    def test_unavailable_urls_hide_whole_modules_without_editing_sources(self):
        for url in sorted(converter.UNAVAILABLE_SCRIPT_URLS):
            for legacy in (False, True):
                with self.subTest(url=url, legacy=legacy):
                    script = ('http-request ^https://example.com script-path=' + url if legacy else
                              'request if ${url} ~= /example/ then script("' + url + '") with enable=false')
                    source = self.source('[Rule]\nDOMAIN,keep.example.com,DIRECT\n[Script]\n' + script + '\n')
                    raw = source.read_bytes()
                    report = self.publish()
                    self.assertEqual((report['converted'], report['excluded']), (0, 1))
                    self.assertEqual(report['items'][-1]['reason'], 'unavailable-remote-script')
                    self.assertIn(url, report['items'][-1]['line'])
                    self.assertEqual(source.read_bytes(), raw)
                    self.assertEqual(json.loads((self.output / 'modules.index.json').read_text()), [])
                    self.assertEqual(list(self.output.glob('*.sgmodule')), [])

    def test_unavailable_source_blocks_no_other_urls_and_needs_no_remote_jq(self):
        bad = sorted(converter.UNAVAILABLE_SCRIPT_URLS)[0]
        source = self.source('[Script]\nrequest if ${url} ~= /script/ then script("' + bad + '")\n'
                             '[Rewrite]\nresponse if ${url} ~= /jq/ then response.json.jq_file("https://example.com/program.jq")\n')
        with patch.object(converter, 'fetch_jq_path', side_effect=AssertionError('Must hide before fetching JQ')):
            report = self.publish()
        self.assertEqual(report['excluded'], 1)
        self.source('[Script]\nrequest if ${url} ~= /script/ then script("https://example.com/replacement.js", "' + bad + '")\n')
        self.publish()
        self.assertTrue((self.output / 'Sample.sgmodule').is_file())
        self.validate()

    def test_unavailable_source_does_not_mask_invalid_source(self):
        bad = sorted(converter.UNAVAILABLE_SCRIPT_URLS)[0]
        for malformed in ('[General]\ninclude-tun=10.7.0.1\n', '[IP Rewrite]\n::1=drop\n',
                          '[Rule]\nUNKNOWN,value,DIRECT\n', '[Rewrite]\nresponse if ${url} ~= /x/ then response.json.delete()\n'):
            with self.subTest(malformed=malformed):
                self.source(malformed + '[Script]\nrequest if ${url} ~= /script/ then script("' + bad + '")\n')
                with self.assertRaises(RuntimeError):
                    self.publish()

    def test_validator_rejects_bypassed_guards(self):
        for section, line in (
            ('General', 'tun-included-routes = 10.7.0.1/32'),
            ('General', 'tun-included-routes = %APPEND% ::1/128'),
            ('General', 'tun-included-routes = %APPEND% 10.7.0.9/24'),
            ('General', 'ipv6-vif = always'),
            ('IP Rewrite', '10.7.0.0/24 = reflect'),
            ('IP Rewrite', '10.7.0.1 = route'),
            ('Rule', 'PROCESS-NAME,curl,DIRECT'),
            ('Script', 'bad = type=http-request, pattern=example, script-path=' + sorted(converter.UNAVAILABLE_SCRIPT_URLS)[0]),
        ):
            with self.subTest(section=section, line=line):
                errors = []
                validate_section_line('bad.sgmodule', 1, section, line, errors)
                self.assertTrue(errors)

    def test_validator_checks_new_feature_version_and_platform_gates(self):
        cases = ('[General]\ninclude-tun=10.7.0.1/32\n', '[IP Rewrite]\n10.7.0.1=reflect\n',
                 '[Rule]\nDOMAIN-WILDCARD,*.example.com,DIRECT\n',
                 '[Rule]\nOR,((DOMAIN,example.com),(DOMAIN-WILDCARD,*.example.com)),DIRECT\n',
                 '#!system=macOS\n[Rule]\nPROCESS-NAME,/usr/bin/curl,DIRECT\n',
                 '#!system=macOS\n[Rule]\nAND,((DOMAIN,example.com),(OR,((PROCESS-NAME,/usr/bin/curl)))),DIRECT\n')
        for source in cases:
            with self.subTest(source=source):
                self.source(source)
                self.publish()
                path = self.output / 'Sample.sgmodule'
                path.write_text(self.converted().replace('CORE_VERSION>=6010000', 'CORE_VERSION>=6008000'))
                with self.assertRaisesRegex(SurgeValidationError, '6010000'):
                    self.validate()
        self.publish()
        path.write_text(self.converted().replace('#!system=mac\n', ''))
        with self.assertRaisesRegex(SurgeValidationError, '#!system=mac'):
            self.validate()


if __name__ == '__main__':
    unittest.main()
