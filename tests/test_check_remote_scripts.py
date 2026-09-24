from __future__ import annotations

import hashlib
from http.client import IncompleteRead
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from check_remote_scripts import audit_script, check_remote_scripts, collect_script_urls, inspect_source


class RemoteScriptAuditTest(unittest.TestCase):
    def test_deduplicates_urls_and_keeps_disabled_and_toggle_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'A.sgmodule').write_text('''#!name=A
[Script]
A = type=http-response, pattern=^https://example.com, script-path=https://example.com/a.js
#B = type=cron, cronexp="0 8 * * *", script-path=https://example.com/a.js
{{{Enable}}}C = type=cron, cronexp="0 8 * * *", script-path="https://example.com/b.js?a=1,b=2"
[MITM]
hostname = example.com
''', encoding='utf-8')
            urls = collect_script_urls(root)
            self.assertEqual(len(urls), 2)
            self.assertEqual([item['line'] for item in urls['https://example.com/a.js']], [3, 4])
            self.assertIn('https://example.com/b.js?a=1,b=2', urls)
            with patch('check_remote_scripts.download_script', return_value=(b'$done({});', 'https://example.com/a.js', 'application/javascript')) as download:
                report = check_remote_scripts(root, workers=1)
            self.assertEqual(download.call_count, 2)
            self.assertEqual(report['summary'], {'total': 2, 'ok': 2, 'needs-review': 0, 'download-failed': 0})

    def test_detects_dot_and_bracket_apis_without_claiming_platform_guards(self) -> None:
        source = '''if (typeof $loon !== "undefined") { $utils.gzip(data); }
$crypto["aes"].encrypt(data);
$dns ['query'] ("example.com");
let version = $environment["surge-version"];
'''
        result = inspect_source(source)
        self.assertEqual([hit['api'] for hit in result['api_hits']], ['$utils.gzip', '$crypto.aes', '$dns.query'])
        self.assertEqual([hit['line'] for hit in result['api_hits']], [1, 2, 3])
        self.assertEqual(result['platform_markers'], ['$loon', '$environment.surge-version'])
        with patch('check_remote_scripts.download_script', return_value=(source.encode(), 'https://example.com/a.js', 'text/plain')):
            audit = audit_script('https://example.com/a.js', [], 1, 'test')
        self.assertEqual(audit['status'], 'needs-review')

    def test_hashes_successful_response_and_preserves_references(self) -> None:
        data = b'$done({});'
        refs = [{'module': 'A.sgmodule', 'line': 2}]
        with patch('check_remote_scripts.download_script', return_value=(data, 'https://cdn.example.com/a.js', 'text/plain')):
            result = audit_script('https://example.com/a.js', refs, 1, 'test')
        self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['references'], refs)
        self.assertEqual(result['final_url'], 'https://cdn.example.com/a.js')
        self.assertEqual(result['status'], 'ok')

    def test_download_error_is_a_report_item_and_html_is_not_success(self) -> None:
        with urllib.error.HTTPError('https://example.com/a.js', 404, 'Not found', {}, None) as error, \
                patch('check_remote_scripts.download_script', side_effect=error):
            failed = audit_script('https://example.com/a.js', [], 1, 'test')
        self.assertEqual(failed['status'], 'download-failed')
        self.assertIn('404', failed['error'])
        self.assertNotIn('sha256', failed)
        for body, mime in ((b'', 'text/plain'), (b'<html>blocked</html>', 'text/plain'), (b'Blocked', 'text/html')):
            with self.subTest(body=body), patch('check_remote_scripts.download_script', return_value=(body, 'https://example.com/a.js', mime)):
                result = audit_script('https://example.com/a.js', [], 1, 'test')
                self.assertEqual(result['status'], 'download-failed')

    def test_unexpected_programming_errors_are_not_swallowed(self) -> None:
        with patch('check_remote_scripts.download_script', side_effect=TypeError('bug')), self.assertRaises(TypeError):
            audit_script('https://example.com/a.js', [], 1, 'test')

    def test_interrupted_http_response_is_retried_and_reported(self) -> None:
        with patch('check_remote_scripts.urllib.request.urlopen', side_effect=IncompleteRead(b'partial', 100)) as request, \
                patch('check_remote_scripts.time.sleep') as sleep:
            result = audit_script('https://example.com/a.js', [], 1, 'test')
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(1)
        self.assertEqual(result['status'], 'download-failed')
        self.assertIn('IncompleteRead', result['error'])

    def test_http_404_is_not_retried_but_503_is(self) -> None:
        for code, attempts in ((404, 1), (503, 2)):
            with self.subTest(code=code), \
                    patch('check_remote_scripts.urllib.request.urlopen', side_effect=urllib.error.HTTPError(
                        'https://example.com/a.js', code, 'HTTP failure', {}, None)) as request, \
                    patch('check_remote_scripts.time.sleep'):
                result = audit_script('https://example.com/a.js', [], 1, 'test')
            self.assertEqual(request.call_count, attempts)
            self.assertEqual(result['status'], 'download-failed')


if __name__ == '__main__':
    unittest.main()
