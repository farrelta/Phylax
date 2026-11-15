import html
import io
import json
import re
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from phylax.ai import AIConfig
from phylax.assistant_web import result_content
from phylax.assistant_workflows import complete
from phylax.core import Store
from phylax.jobs import Jobs
from phylax.monitoring import ingest_file, policy_version, reevaluate_events
from scripts.prepare_sensor_demo import prepare, POLICY
import test_review_regressions as http_fixture


LOCAL = AIConfig('http://127.0.0.1:11434/v1', 'local-test', '', 'ollama')
HOSTED = AIConfig('https://provider.example/v1', 'hosted-test', 'private-api-key', 'custom')


class AssistanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name) / 'demo'
        database = prepare(self.directory)
        self.store = Store(database)
        self.addCleanup(self.store.close)
        self.jobs = Jobs(str(database))
        self.addCleanup(self.jobs.close)
        self.http = http_fixture.HTTPAndGuidanceRegressionTests()
        self.http.setUp()
        self.http.store.close()
        self.http.store = self.store
        self.http.server.jobs = self.jobs
        rows = [json.loads(line) for line in (self.directory / 'conn.log').read_text().splitlines()]
        rows.append(rows[2] | {'uid': 'second-observed-connection', 'ts': rows[2]['ts'] + 12})
        path = self.directory / 'extra-conn.log'
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        ingest_file(self.store, path)
        self.alerts = list(self.store.connection.execute("SELECT alert_id,event_ref FROM network_alerts JOIN network_events USING(event_id) WHERE rule_id='zone_policy_violation' ORDER BY event_ref"))
        self.assertEqual(len(self.alerts), 2)
        self.store.import_csv(io.StringIO('asset_id,ip_address,hostname,vendor,product,version,zone,verified,identity_confidence\n'
                                          'example,198.51.100.40,private-host,Example,Tool,1.0,IT,true,high\n'))
        self.store.ingest_normalized([{'cve_id': 'CVE-2024-99999', 'source': 'NVD API 2.0', 'summary': 'Public example',
                                       'affected_products': [{'vendor': 'Example', 'product': 'Tool', 'versions': ['1.0'], 'excluded_versions': ['1.1']}]}], trusted_public=True)
        self.finding = self.store.connection.execute("SELECT finding_id FROM findings WHERE cve_id='CVE-2024-99999'").fetchone()[0]

    def post(self, path='/assist', language='en', **params):
        handler = self.http.handler(path, urlencode({'csrf_token': self.http.Handler.csrf_token, **params}, doseq=True))
        handler.headers['Accept-Language'] = language
        handler.do_POST()
        return handler

    def job(self, handler):
        self.assertEqual(handler.response_status, 303, handler.wfile.getvalue()[:500])
        key = handler.response_headers['Location'].rsplit('/', 1)[-1]
        for _ in range(200):
            job = self.jobs.get(key)
            if job['status'] in {'complete', 'failed'}:
                return job
            time.sleep(.01)
        self.fail('Job did not finish')

    def token(self, response, name='confirm'):
        self.assertEqual(response.response_status, 200)
        return re.search(r'name="' + name + r'" value="([0-9a-f]+)"', response.wfile.getvalue().decode())[1]

    def response(self, config, body, refs, local):
        return {'focus': 'evidence', 'evidence': list(reversed(refs))}, 'actual-model'

    def test_intelligence_and_policy_do_not_offer_ai(self):
        self.store.save_ics_advisories([{'advisory_id': 'demo-ics', 'title': 'Example controller advisory',
                                       'summary': 'This issue could disrupt service.'}])
        with patch('phylax.assistant_web.complete') as model:
            for route in ('/intelligence', '/intelligence/ics', '/assist?task=policy'):
                page = self.http.handler(route)
                page.do_GET()
                self.assertEqual(page.response_status, 200)
                for text in (b'AI summary', b'Summarize advisory', b'Local AI', b'Hosted AI'):
                    self.assertNotIn(text, page.wfile.getvalue())
            for task, key, expected in (('advisory', 'CVE-2024-99999', '/intelligence?q=CVE-2024-99999'),
                                        ('ics-advisory', 'demo-ics', '/intelligence/ics?q=demo-ics')):
                response = self.post(task=task, key=key, mode='hosted')
                self.assertEqual(response.response_status, 303)
                self.assertEqual(response.response_headers['Location'], expected)
                page = self.http.handler(expected)
                page.do_GET()
                self.assertIn(b'Version and source details', page.wfile.getvalue())
            self.assertEqual(self.post(task='policy', mode='hosted').response_status, 200)
            model.assert_not_called()

    def test_report_modes_preview_and_download(self):
        candidate = self.finding
        with patch('phylax.assistant_web.local_config', return_value=LOCAL), patch(
            'phylax.assistant_web.AIConfig.from_env', return_value=HOSTED
        ), patch('phylax.assistant_web.complete', side_effect=self.response) as model:
            built_in = self.job(self.post(task='report', mode='builtin', selected=[candidate]))
            self.assertNotIn('draft', built_in['result'])
            model.assert_not_called()
            local = self.job(self.post(task='report', selected=[candidate]))
            self.assertEqual(local['result']['provider'], 'ollama-local')
            result = self.http.handler('/jobs/' + local['job_id'])
            result.do_GET()
            self.assertIn(b'Download Markdown report', result.wfile.getvalue())

            download = self.http.handler('/reports/draft.md?job=' + local['job_id'])
            download.do_GET()
            self.assertEqual(download.response_status, 200)
            self.assertIn('phylax-investigation.md', download.response_headers['Content-Disposition'])
            for value in (b'AI-organized review', b'CVE-2024-99999', b'Confirmed affected', candidate.encode()):
                self.assertIn(value, download.wfile.getvalue())
            unavailable = self.http.handler('/reports/draft.md?job=unknown')
            unavailable.do_GET()
            self.assertEqual(unavailable.response_status, 404)

            model.reset_mock()
            preview = self.post(task='report', mode='hosted', selected=[candidate], language='id')
            token = self.token(preview)
            payload = html.unescape(re.search(r'<pre[^>]*>(.*?)</pre>', preview.wfile.getvalue().decode(), re.S)[1])
            sent = json.loads(json.loads(payload)['messages'][1]['content'])
            self.assertEqual(sent['language'], 'id')
            self.assertEqual(sent['findings'][0]['applicability'], 'Confirmed affected')
            self.assertEqual(sent['findings'][0]['priority'], self.store.finding(candidate)['priority'])
            for forbidden in ('private-api-key', '198.51.100.40', 'private-host', 'CVE-2024-99999', candidate):
                self.assertNotIn(forbidden, payload)
            model.assert_not_called()
            hosted = self.job(self.post(confirm=token))
            self.assertEqual(hosted['result']['provider'], 'custom-hosted-reviewed')
            translated = self.http.handler('/reports/draft.md?job=' + hosted['job_id'])
            translated.headers['Accept-Language'] = 'id'
            translated.do_GET()
            self.assertIn('Tinjauan yang disusun dengan AI', translated.wfile.getvalue().decode())
            self.assertIn('Terkonfirmasi terdampak', translated.wfile.getvalue().decode())
            self.assertEqual(model.call_args.args[1], payload.encode())
            self.assertEqual(self.post(confirm=token).response_status, 400)

    def test_policy_preview_is_read_only_and_apply_rejects_stale_version(self):
        before = self.store.connection.total_changes
        form = dict(task='policy', policy_preview='yes', version=policy_version(self.store),
                    source='IT', destination='OT', action='remove', IT='198.51.100.0/24', OT='192.0.2.0/24', DMZ='203.0.113.0/24')
        preview = self.post(**form)
        token = self.token(preview, 'preview')
        self.assertIn('Alerts resolved · 2', preview.wfile.getvalue().decode())
        self.assertEqual(self.store.connection.total_changes, before)
        self.assertEqual(self.job(self.post('/policy/apply', preview=token))['status'], 'complete')
        count = self.store.connection.execute("SELECT COUNT(*) FROM network_alert_lifecycle WHERE state='active'").fetchone()[0]
        self.assertEqual(count, 0)
        preview = self.post(**(form | {'version': policy_version(self.store), 'action': 'flag'}))
        stale = self.token(preview, 'preview')
        reevaluate_events(self.store, POLICY | {'denied_zone_pairs': [['OT', 'IT']]})
        job = self.job(self.post('/policy/apply', preview=stale))
        self.assertEqual(job['status'], 'failed')
        self.assertIn('policy changed', job['message'])

    def test_routine_explanations_open_without_a_model(self):
        cases = {'alert': {'key': self.alerts[0]['alert_id']}, 'settings': {},
                 'identity': {'key': 'example', 'identity_type': 'asset'},
                 'remediation': {'key': self.finding}}
        with patch('phylax.assistant_web.complete') as model:
            for task, fields in cases.items():
                with self.subTest(task=task):
                    response = self.post(task=task, mode='hosted', **fields)
                    self.assertEqual(response.response_status, 303)
                    destination = response.response_headers['Location']
                    expected = {'alert': '/triage', 'settings': '/settings', 'identity': '/assets/edit', 'remediation': '/'}
                    self.assertEqual(urlsplit(destination).path, expected[task])
                    legacy = self.http.handler('/assist?' + urlencode({'task': task, **fields}))
                    legacy.do_GET()
                    self.assertEqual(legacy.response_headers['Location'], destination)
            model.assert_not_called()
        response = self.post(task='alert', **cases['alert'])
        page = self.http.handler(response.response_headers['Location'])
        page.do_GET()
        self.assertIn(self.alerts[0]['event_ref'], page.wfile.getvalue().decode())
        finding = self.http.handler('/?' + urlencode({'finding_id': self.finding}))
        finding.do_GET()
        self.assertIn(b'action="/remediation/create"', finding.wfile.getvalue())

    def test_ai_timeout_keeps_selected_report_evidence(self):
        with patch('phylax.assistant_web.local_config', return_value=LOCAL), patch(
            'phylax.assistant_web.complete', side_effect=TimeoutError('Test timeout')
        ):
            failed = self.job(self.post(task='report', mode='local', selected=[self.finding]))
        page = result_content(failed['result'], failed['job_id'])
        self.assertIn('Built-in report', page)
        self.assertIn('CVE-2024-99999', page)
        self.assertIn(self.finding, page)

    def test_transport_rejects_unknown_duplicate_and_missing_evidence(self):
        invalid = (
            ({'focus': 'evidence', 'evidence': ['outside-case', 'E2']}, 'each selected finding'),
            ({'focus': 'evidence', 'evidence': ['E1', 'E1']}, 'each selected finding'),
            ({'focus': 'evidence', 'evidence': ['E2']}, 'each selected finding'),
            ({'focus': 'Every device is safe', 'evidence': ['E1', 'E2']}, 'invalid response'),
        )
        for draft, message in invalid:
            response = {'choices': [{'message': {'content': json.dumps(draft)}}]}
            def opener(request, timeout):
                self.assertNotIn('Authorization', request.headers)
                return io.BytesIO(json.dumps(response).encode())
            with self.assertRaisesRegex(ValueError, message):
                complete(LOCAL, b'{}', {'E1': '/evidence', 'E2': '/evidence'}, True, opener=opener)

    def test_hosted_provider_change_requires_new_preview(self):
        with patch('phylax.assistant_web.AIConfig.from_env', return_value=HOSTED) as config, patch('phylax.assistant_web.complete') as model:
            token = self.token(self.post(task='report', selected=[self.finding], mode='hosted'))
            config.return_value = AIConfig(HOSTED.base_url, 'different-model', HOSTED.api_key, HOSTED.provider)
            job = self.job(self.post(confirm=token))
            self.assertIn('provider changed', job['result']['error'])
            model.assert_not_called()

    def test_transport_rejects_redirects_for_both_modes(self):
        paths = []

        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                paths.append(self.path)
                self.send_response(302)
                self.send_header('Location', '/redirected')
                self.end_headers()

            def do_GET(self):
                paths.append(self.path)
                self.send_response(404)
                self.end_headers()

        with HTTPServer(('127.0.0.1', 0), Redirect) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                for local in (True, False):
                    config = AIConfig(f'http://127.0.0.1:{server.server_port}/v1', 'model', 'dummy')
                    with self.assertRaisesRegex(ValueError, 'HTTP 302'):
                        complete(config, b'{}', {}, local)
            finally:
                server.shutdown()
                thread.join()
        self.assertEqual(paths, ['/v1/chat/completions'] * 2)

    def test_advisory_facts_keep_affected_and_fixed_passages_independent(self):
        from phylax.advisory_views import passages, render_facts
        epics = {'source': 'CISA ICS advisories RSS', 'summary': (
            '<p>Successful exploitation could disrupt service or disclose sensitive information.</p>'
            '<p>EPICS Base release &lt;=7.0.10</p>' + '<p>Detail.</p>' * 1500
            + '<p>Affected users should update to the 7.0.11 release.</p>')}
        html_text = render_facts(passages([epics], ics=True))
        self.assertIn('EPICS Base release &lt;=7.0.10', html_text)
        self.assertIn('7.0.11 release', html_text)

        kev = {'source': 'CISA KEV', 'summary': 'Apple watchOS 10.5 contains an improper authentication vulnerability.'}
        apple = {'source': 'NVD API 2.0', 'summary': (
            'This issue is fixed in watchOS 10.5. The issue may allow bypassing pointer authentication.'),
            'affected_products': [{'vendor': 'Apple', 'product': 'watchOS',
                                   'version_ranges': [{'end_excluding': '10.5'}]}]}
        kev_only = render_facts(passages([kev]))
        self.assertIn('Affected version boundaries need verification', kev_only)
        self.assertNotIn('contains an improper authentication vulnerability', kev_only)
        html_text = render_facts(passages([kev, apple]))
        self.assertIn('watchOS · &lt; 10.5', html_text)
        self.assertIn('fixed in watchOS 10.5', html_text)
        conflicting = apple | {'source': 'Another vendor advisory', 'affected_products': [
            {'vendor': 'Apple', 'product': 'watchOS', 'version_ranges': [{'end_including': '10.5'}]},
        ]}
        self.assertIn('Sources list different affected version statements', render_facts(passages([apple, conflicting])))



if __name__ == '__main__':
    unittest.main()
