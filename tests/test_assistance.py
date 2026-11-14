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
from phylax.assistant_workflows import complete, request_body
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

    def response(self, config, body, task, refs, local):
        data = json.loads(json.loads(body)['messages'][1]['content'])['context']
        draft = {'summary': 'Observed evidence', 'reason': 'Review this case', 'next_step': 'Check the original record',
                 'evidence': list(refs)[:1]}
        if task == 'policy':
            draft.update(data['requested_rule'])
        return draft, 'actual-model'

    def test_ics_summary_uses_the_selected_cached_advisory(self):
        link = 'https://www.cisa.gov/news-events/ics-advisories/example'
        self.store.save_ics_advisories([
            {'advisory_id': 'demo-ics', 'title': 'Example controller advisory', 'link': link,
             'summary': '<p>Source describes product scope.</p><script>ignored-script</script>'},
            {'advisory_id': 'other-ics', 'title': 'Other record', 'summary': 'Unrelated text.'},
        ])
        fields = {'task': 'ics-advisory', 'key': 'demo-ics'}
        with patch('phylax.assistant_web.local_config', return_value=LOCAL), patch(
            'phylax.assistant_web.AIConfig.from_env', return_value=HOSTED
        ), patch('phylax.assistant_web.complete', side_effect=self.response) as model:
            fallback = self.job(self.post(mode='builtin', **fields))['result']
            self.assertIn('Example controller advisory', fallback['context'])
            self.assertNotIn('Source describes product scope.', fallback['context'])
            page = self.http.handler('/assist?' + urlencode(fields))
            page.do_GET()
            self.assertEqual(page.response_status, 200)
            self.assertNotIn(b'Source describes product scope.', page.wfile.getvalue())
            model.assert_not_called()
            self.assertIn('draft', self.job(self.post(mode='local', **fields))['result'])
            model.reset_mock()
            preview = self.post(mode='hosted', **fields)
            token = self.token(preview)
            text = html.unescape(re.search(r'<pre[^>]*>(.*?)</pre>', preview.wfile.getvalue().decode(), re.S)[1])
            self.assertIn('Source describes product scope.', text)
            for excluded in ('ignored-script', 'Unrelated text.', 'private-host', link):
                self.assertNotIn(excluded, text)
            model.assert_not_called()
            self.assertIn('draft', self.job(self.post(confirm=token))['result'])
            self.assertEqual(model.call_args.args[1], text.encode())
            self.assertEqual(self.post(task='ics-advisory', key='other-ics', mode='hosted').response_status, 400)

    def test_all_modes_and_exact_hosted_preview(self):
        cases = {'policy': {'source': 'IT', 'destination': 'OT', 'action': 'flag', 'prompt': 'private-host'},
                 'alert': {'key': self.alerts[0]['alert_id']}, 'settings': {},
                 'identity': {'key': 'example', 'identity_type': 'asset'}, 'advisory': {'key': 'CVE-2024-99999'},
                 'remediation': {'key': self.finding}, 'report': {'selected': [self.finding]}}
        with patch('phylax.assistant_web.local_config', return_value=LOCAL), patch('phylax.assistant_web.AIConfig.from_env', return_value=HOSTED), patch('phylax.assistant_web.complete', side_effect=self.response) as model:
            for task, fields in cases.items():
                with self.subTest(task=task):
                    model.reset_mock()
                    built_in = self.job(self.post(task=task, mode='builtin', **fields))['result']
                    self.assertNotIn('draft', built_in)
                    model.assert_not_called()
                    local = self.job(self.post(task=task, **fields))['result']
                    self.assertEqual(local['provider'], 'ollama-local')
                    model.reset_mock()
                    preview = self.post(task=task, mode='hosted', language='id', **fields)
                    token = self.token(preview)
                    text = html.unescape(re.search(r'<pre[^>]*>(.*?)</pre>', preview.wfile.getvalue().decode(), re.S)[1])
                    for forbidden in ('private-api-key', '198.51.100.40', 'private-host', '192.0.2.10'):
                        self.assertNotIn(forbidden, text)
                    self.assertIn('Bahasa Indonesia', text)
                    model.assert_not_called()
                    hosted = self.job(self.post(confirm=token))['result']
                    self.assertEqual(hosted['provider'], 'custom-hosted-reviewed')
                    self.assertEqual(model.call_args.args[1], text.encode())
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

    def test_ai_failure_retains_plan_and_exact_case_evidence(self):
        with patch('phylax.assistant_web.local_config', return_value=LOCAL), patch('phylax.assistant_web.complete', side_effect=self.response):
            ready = self.job(self.post(task='remediation', mode='local', key=self.finding))
            self.assertIsNone(self.store.get_remediation_plan(self.finding))
            self.assertEqual(self.post(save_remediation=ready['job_id']).response_status, 303)
            saved = self.store.get_remediation_plan(self.finding)
            self.assertEqual(saved['model'], 'actual-model')
            self.assertEqual(saved['plan']['requested_model'], 'local-test')
        with patch('phylax.assistant_web.local_config', return_value=LOCAL), patch('phylax.assistant_web.complete', side_effect=TimeoutError('Test timeout')) as model:
            failed = self.job(self.post(task='remediation', mode='local', key=self.finding))
            self.assertIn('Retry or switch provider', result_content(failed['result'], failed['job_id']))
            self.assertEqual(self.store.get_remediation_plan(self.finding), saved)
            model.assert_called_once()
            for alert in self.alerts:
                job = self.job(self.post(task='alert', key=alert['alert_id'], mode='builtin'))
                query = parse_qs(urlsplit(job['result']['links']['E1']).query)
                self.assertEqual(query['event_ref'], [alert['event_ref']])

    def test_transport_rejects_invented_evidence_and_invalid_payload(self):
        data = {'summary': 'summary', 'reason': 'reason', 'next_step': 'step', 'evidence': ['outside-case']}
        for content, message in ((json.dumps(data), 'outside the selected case'), ('malformed', 'invalid response')):
            response = {'choices': [{'message': {'content': content}}]}
            def opener(request, timeout):
                self.assertNotIn('Authorization', request.headers)
                return io.BytesIO(json.dumps(response).encode())
            with self.assertRaisesRegex(ValueError, message):
                complete(LOCAL, b'{}', 'alert', {'E1': '/evidence'}, True, opener=opener)

    def test_zone_alert_rejects_reversed_direction_and_overstated_claims(self):
        refs = {'E1': '/evidence'}
        body = request_body(LOCAL, 'alert', {'rule': 'zone_policy_violation', 'source_zone': 'IT', 'destination_zone': 'OT'}, refs, 'id', True)
        for summary in ('OT to IT was recorded', 'Koneksi IT ke OT adalah ancaman', 'IT to OT was allowed'):
            draft = {'summary': summary, 'reason': 'Kebijakan zona', 'next_step': 'Buka bukti asli', 'evidence': ['E1']}
            response = {'choices': [{'message': {'content': json.dumps(draft)}}]}
            with self.assertRaisesRegex(ValueError, 'recorded direction or evidence limits'):
                complete(LOCAL, body, 'alert', refs, True, opener=lambda *_a, **_kw: io.BytesIO(json.dumps(response).encode()))

    def test_hosted_provider_change_requires_new_preview(self):
        with patch('phylax.assistant_web.AIConfig.from_env', return_value=HOSTED) as config, patch('phylax.assistant_web.complete') as model:
            token = self.token(self.post(task='alert', key=self.alerts[0]['alert_id'], mode='hosted'))
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
                        complete(config, b'{}', 'alert', {}, local)
            finally:
                server.shutdown()
                thread.join()
        self.assertEqual(paths, ['/v1/chat/completions'] * 2)

    def test_changed_remediation_evidence_requires_new_draft(self):
        with patch('phylax.assistant_web.local_config', return_value=LOCAL), patch('phylax.assistant_web.complete', side_effect=self.response):
            job = self.job(self.post(task='remediation', key=self.finding, mode='local'))
        self.store.connection.execute('UPDATE findings SET missing_evidence=? WHERE finding_id=?', ('["new check"]', self.finding))
        self.store.connection.commit()
        self.assertEqual(self.post(save_remediation=job['job_id']).response_status, 400)
        self.assertIsNone(self.store.get_remediation_plan(self.finding))


if __name__ == '__main__':
    unittest.main()
