from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from convert_kelee_to_surge import convert_file, convert_kelee_to_surge, normalize_jq_program
from validate_surge_modules import validate_surge_modules, validate_section_line

FIXTURES = Path(__file__).parent / 'fixtures' / 'core-upgrade'


class UpgradeRegressionTest(unittest.TestCase):
    def convert(self, filename):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            report = []
            item = convert_file(FIXTURES / filename, output, report, {})
            return (output / item['output']).read_text() if item else None, report

    def test_actual_kugou_program_gets_legacy_repairs(self):
        output, report = self.convert('KuGou_remove_ads.lpx')
        self.assertIn('jq-expression-corrected', [item['kind'] for item in report])
        self.assertIn(') else . end;removeParentIfNameMatches', output)
        self.assertNotIn(')else .end;removeParentIfNameMatches', output)

    def test_actual_iqiyi_empty_program_is_reported_and_not_emitted(self):
        output, report = self.convert('iQiYi_Video_remove_ads.lpx')
        self.assertEqual([item['kind'] for item in report], ['rewrite-empty-skipped'])
        self.assertNotRegex(output, r"(?m)^http-response-jq .* ''$")
        self.assertIn('http-response-jq', output)

    def test_repairs_do_not_rewrite_jq_literal_or_comments(self):
        for program in ('")else .end;removeParentIfNameMatches"', '# )else .end;removeParentIfNameMatches\n.'):
            report = []
            self.assertEqual(normalize_jq_program(program, report, 'Sample', 'line'), program)
            self.assertEqual(report, [])

    def test_jq_interpolation_literals_are_never_normalized(self):
        program = r'"\(")else .end;removeParentIfNameMatches")"'
        report=[]
        self.assertEqual(normalize_jq_program(program,report,'Sample','line'),program)
        self.assertEqual(report,[])

    def test_verified_generic_v2_adapters_keep_context_and_defaults(self):
        output, report = self.convert('NodeLinkCheck.lpx')
        self.assertIn('type=generic', output)
        self.assertIn('timeout=300', output)
        self.assertIn('policy={{{Policy}}}', output)
        self.assertIn('#!arguments=Policy:PROXY', output)
        self.assertIn('generic-script-adapted', [item['kind'] for item in report])
        output, report = self.convert('WARP_Node_Query.lpx')
        self.assertIn('[Panel]', output)
        self.assertIn('script-name=WARP · INFO', output)
        self.assertIn('WARP · INFO = type=generic', output)
        self.assertIn('timeout=10', output)

    def test_untagged_warp_uses_same_panel_and_script_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            source=root/'WARP.lpx'
            source.write_text('#!name=WARP\n[Script]\ngeneric then script("https://raw.githubusercontent.com/VirgilClyne/Cloudflare/main/js/1.1.1.1.panel.js")\n')
            report=[]
            result=convert_file(source,root,report,{})
            output=(root/result['output']).read_text()
            self.assertIn('script-name=generic 1',output)
            self.assertIn('generic 1 = type=generic',output)

    def test_exact_migrated_driving_school_line_is_repaired_with_provenance(self):
        output, report = self.convert('JiaXiaoDrive_remove_ads.lpx')
        self.assertEqual([item['kind'] for item in report], ['source-repair-applied'])
        self.assertIn('api\\.ksedt\\.com', output)
        self.assertIn('examPageLoadADSwitch', output)
        self.assertNotIn('(?i:http-response)', output)

    @unittest.skipUnless(shutil.which('jq'), 'jq is required for compilation checks')
    def test_real_supported_fixtures_pass_staged_full_validation(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            root=Path(tmp); (root/'Loon').mkdir()
            for name in ('KuGou_remove_ads.lpx','iQiYi_Video_remove_ads.lpx','NodeLinkCheck.lpx','WARP_Node_Query.lpx'):
                shutil.copy(FIXTURES/name, root/'Loon'/name)
            before=Path.cwd()
            try:
                os.chdir(root)
                convert_kelee_to_surge('Loon','Surge','Surge/convert-report.json',require_jq=True)
                result=validate_surge_modules('Loon','Surge','Surge/convert-report.json',require_jq=True)
                self.assertEqual(result['modules'],4)
                self.assertTrue(result['jq_compiled'])
            finally:
                os.chdir(before)

    @unittest.skipUnless(shutil.which('jq'), 'jq is required for compilation checks')
    def test_invalid_candidate_jq_cannot_replace_previous_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'Loon').mkdir(); (root/'Surge').mkdir()
            (root/'Loon'/'invalid.lpx').write_text('#!name=Invalid\n[Rewrite]\nresponse if ${url} ~= /example/ then response.json.jq("this is invalid jq !!!")\n')
            sentinel=root/'Surge'/'previous.sgmodule'; sentinel.write_bytes(b'known-good')
            before=Path.cwd()
            try:
                os.chdir(root)
                with self.assertRaisesRegex(RuntimeError,'jq failed'):
                    convert_kelee_to_surge('Loon','Surge','Surge/convert-report.json',require_jq=True)
                self.assertEqual(list((root/'Surge').iterdir()),[sentinel])
                self.assertEqual(sentinel.read_bytes(),b'known-good')
            finally:
                os.chdir(before)


class OutputJSONQualityTest(unittest.TestCase):
    def test_valid_base64_does_not_hide_invalid_json(self):
        errors=[]
        validate_section_line('Sample',1,'Map Local',
            '^https://example/ data-type=base64 data="ew==" status-code=200 header="Content-Type:application/json"', errors)
        self.assertTrue(any('invalid Map Local JSON payload' in error for error in errors))

    def test_all_supported_header_forms_validate_json_body(self):
        import base64
        headers=['Content-Type:application/json|Cache-Control:no-cache',
                 'Cache-Control:no-cache|Content-Type: application/json; charset=utf-8',
                 'Content-Type : application/json | Cache-Control:no-cache',
                 base64.b64encode(b'Content-Type:application/json\nCache-Control:no-cache').decode(),
                 base64.b64encode(b'Cache-Control:no-cache\r\nContent-Type:application/json').decode()]
        for header in headers:
            with self.subTest(header=header):
                errors=[]
                validate_section_line('Sample',1,'Map Local',
                    f'^https://example/ data-type=base64 data="ew==" status-code=200 header="{header}"',errors)
                self.assertTrue(any('invalid Map Local JSON payload' in error for error in errors))

    def test_legacy_invalid_json_cannot_bypass_staging_with_multiple_headers(self):
        import base64
        for header in ('Content-Type:application/json|Cache-Control:no-cache',
                       base64.b64encode(b'Content-Type:application/json\nCache-Control:no-cache').decode()):
            with self.subTest(header=header), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'Loon').mkdir();(root/'Surge').mkdir()
                (root/'Loon'/'Broken.lpx').write_text('#!name=Broken\n[Rewrite]\n^https://example/ mock-response-body data-type=json data="{" header="'+header+'"\n')
                sentinel=root/'Surge'/'previous.sgmodule';sentinel.write_text('previous')
                before=Path.cwd()
                try:
                    os.chdir(root)
                    with self.assertRaisesRegex(RuntimeError,'invalid Map Local JSON payload'):
                        convert_kelee_to_surge('Loon','Surge','Surge/convert-report.json')
                    self.assertEqual(sentinel.read_text(),'previous')
                finally:os.chdir(before)

    def test_json_header_detection_does_not_misread_unrelated_headers(self):
        for header in ('Content-Type:application/jsonp','X-Note:Content-Type:application/json'):
            errors=[]
            validate_section_line('Sample',1,'Map Local',
                f'^https://example/ data-type=text data="notJSON" status-code=200 header="{header}"', errors)
            self.assertEqual(errors,[])

    def test_json_scalar_types_remain_unchanged(self):
        for text in ('true','false','0','null','[]','{}'):
            errors=[]
            validate_section_line('Sample',1,'Map Local',
                f'^https://example/ data-type=text data="{text}" status-code=200 header="Content-Type:application/json; charset=utf-8"', errors)
            self.assertEqual(errors,[])


class AdapterIntegrationTest(unittest.TestCase):
    def test_object_final_variable_is_declared_and_source_failure_is_fatal(self):
        import hashlib
        from dataclasses import replace
        from unittest.mock import patch
        import script_v2_compat as compat
        import convert_kelee_to_surge as converter
        source='''#!name=Object
[Argument]
tab=switch, false, true
useractivity=switch, true, false
[Script]
response if ${url} ~= /ads/ then script("https://kelee.one/Resource/JavaScript/Spotify/Spotify_remove_ads.js", {${tab}, ${useractivity}})
'''
        url=compat.BASE+'Spotify/Spotify_remove_ads.js'
        probe=b'// Never executed; codec integration fixture'
        adapters=dict(compat.VERIFIED_OBJECT_ADAPTERS)
        adapters[url]=replace(adapters[url],sha256=hashlib.sha256(probe).hexdigest())
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); path=root/'Object.lpx'; path.write_text(source)
            with patch.object(compat,'VERIFIED_OBJECT_ADAPTERS',adapters), patch.object(converter,'fetch_script_source',return_value=probe):
                report=[]; result=converter.convert_file(path,root,report,{})
                output=(root/result['output']).read_text()
                self.assertIn('#!arguments=tab:false,useractivity:true',output)
                self.assertIn('script-object-adapted',[item['kind'] for item in report])
            with patch.object(converter,'fetch_script_source',side_effect=TimeoutError('offline')):
                report=[]; result=converter.convert_file(path,root,report,{})
                self.assertIsNone(result)
                self.assertEqual([item['kind'] for item in report],['script-verification'])

    def test_warp_dynamic_or_disabled_panel_linkage_is_explicitly_excluded(self):
        for enable in ('${Enabled}', 'false'):
            with self.subTest(enable=enable), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);source=root/'Warp.lpx'
                source.write_text('#!name=Warp\n[Argument]\nEnabled=switch,false,true\n[Script]\ngeneric then script("https://raw.githubusercontent.com/VirgilClyne/Cloudflare/main/js/1.1.1.1.panel.js") with enable='+enable+', tag="WARP INFO"\n')
                report=[];result=convert_file(source,root,report,{})
                self.assertIsNone(result)
                self.assertEqual([item['kind'] for item in report],['module-excluded'])
                self.assertIn('Panel/Script linkage',report[0]['message'])

    def test_injected_policy_never_reuses_an_existing_declaration(self):
        for declaration in ('Policy=switch,false,true', 'Policy=input,"PROXY"', 'Policy=select,"A","B"'):
            with self.subTest(declaration=declaration), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);source=root/'Node.lpx'
                source.write_text('#!name=Node\n[Argument]\n'+declaration+'\n[Script]\ngeneric then script("https://kelee.one/Resource/JavaScript/NodeLinkCheck/NodeLinkCheck.js")\n')
                report=[];result=convert_file(source,root,report,{})
                self.assertIsNone(result)
                self.assertEqual([item['kind'] for item in report],['module-excluded'])
                self.assertIn('Policy argument collides',report[0]['message'])

    def test_dynamic_enable_and_cron_keep_declared_defaults(self):
        source='''#!name=Dynamic
[Argument]
Enabled=switch, false, true
Cron=select, "0 8 * * *", "0 9 * * *"
[Script]
cron ${Cron} then script("https://example.com/a.js") with enable=${Enabled}, tag="Daily"
'''
        with tempfile.TemporaryDirectory() as tmp,contextlib.redirect_stdout(io.StringIO()):
            root=Path(tmp);(root/'Loon').mkdir();(root/'Loon'/'Dynamic.lpx').write_text(source)
            before=Path.cwd()
            try:
                os.chdir(root)
                convert_kelee_to_surge('Loon','Surge','Surge/convert-report.json')
                output=(root/'Surge'/'Dynamic.sgmodule').read_text()
                self.assertIn('#!arguments=Enabled:#,Cron:0 8 * * *',output)
                self.assertIn('{{{Enabled}}}Daily = type=cron, cronexp="{{{Cron}}}"',output)
                self.assertEqual(validate_surge_modules('Loon','Surge','Surge/convert-report.json')['modules'],1)
            finally:os.chdir(before)


class SourceRepairIntegrationTest(unittest.TestCase):
    def source(self):
        return (Path(__file__).parent/'fixtures/source-repairs/upstream/BaiduMap_remove_ads.lpx').read_bytes()

    def test_raw_source_is_preserved_and_repair_provenance_cannot_be_forged(self):
        with tempfile.TemporaryDirectory() as tmp,contextlib.redirect_stdout(io.StringIO()):
            root=Path(tmp);(root/'Loon').mkdir();p=root/'Loon'/'BaiduMap_remove_ads.lpx';p.write_bytes(self.source())
            before=Path.cwd()
            try:
                os.chdir(root)
                convert_kelee_to_surge('Loon','Surge','Surge/convert-report.json')
                self.assertEqual(p.read_bytes(),self.source())
                report_path=root/'Surge'/'convert-report.json'
                report=json.loads(report_path.read_text())
                self.assertEqual(report['items'][0]['kind'],'source-repair-applied')
                report['items'][0]['source_sha256']='0'*64
                report_path.write_text(json.dumps(report))
                with self.assertRaisesRegex(RuntimeError,'source repair provenance'):
                    validate_surge_modules('Loon','Surge','Surge/convert-report.json')
            finally:os.chdir(before)

    def test_crlf_or_unknown_source_version_cannot_replace_previous_output(self):
        for changed in (self.source().replace(b'\n',b'\r\n'),self.source()+b'\n# upstream update\n'):
            with self.subTest(size=len(changed)),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'Loon').mkdir();(root/'Surge').mkdir()
                (root/'Loon'/'BaiduMap_remove_ads.lpx').write_bytes(changed)
                for name in ('previous.sgmodule','convert-report.json','modules.index.json'):
                    (root/'Surge'/name).write_bytes(b'previous '+name.encode())
                prior={p.name:p.read_bytes() for p in (root/'Surge').iterdir()}
                before=Path.cwd()
                try:
                    os.chdir(root)
                    with self.assertRaisesRegex(RuntimeError,'source-repair-blocked'):
                        convert_kelee_to_surge('Loon','Surge','Surge/convert-report.json')
                    self.assertEqual(prior,{p.name:p.read_bytes() for p in (root/'Surge').iterdir()})
                finally:os.chdir(before)
