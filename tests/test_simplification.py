"""Regression coverage for consolidated navigation, review and feed fetching."""
import io
import json
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request

import test_review_regressions as regressions
from phylax.core import Store
from phylax.feeds import fetch, nvd_pages
from phylax.operator_pages import settings_page
from phylax.remediation import compose_plan
from phylax.theme import NAV, SECONDARY_NAV, layout
from phylax.web import page, remediation_page


class Links(HTMLParser):
    def __init__(self, text):
        super().__init__(); self.links=[]; self.feed(text)
    def handle_starttag(self, tag, attrs):
        if tag=='a': self.links.append(dict(attrs))


class SimplifiedWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.http=regressions.HTTPAndGuidanceRegressionTests(); self.http.setUp()
        self.store=self.http.store; self.fid=self.http.fid
    def tearDown(self): self.http.tearDown()

    def make_plan(self):
        finding=self.store.finding(self.fid)
        for key in ('evidence','missing_evidence'): finding[key]=json.loads(finding[key])
        plan=compose_plan(finding,self.store.public_vulnerability_for_finding(self.fid))
        plan['cisa_required_action']='TEST ONLY: retain source action'
        return self.store.create_remediation_plan(self.fid,'template-fallback','',plan,plan['source_references'])

    def test_seven_primary_destinations_and_contextual_navigation(self):
        self.assertEqual([href for _,items in NAV for href,_ in items],
                         ['/','/assets','/attack-surface','/intelligence','/triage','/reports','/settings'])
        for root,(label,items) in SECONDARY_NAV.items():
            for href,_ in items:
                text=layout('Test view','',href)
                links=Links(text).links
                self.assertEqual(sum(a.get('href')==root and a.get('aria-current')=='page' for a in links),3 if href==root else 2)
                self.assertIn('aria-label="'+label+'"',text)
                self.assertIn('href="'+href+'" aria-current="page"',text)

    def test_overview_summarizes_alerts_and_imports_reassess_automatically(self):
        text=page(self.store)
        self.assertIn('New alerts to review',text)
        self.assertNotIn('>Latest first</a>', text)
        self.assertNotIn('>Add devices</a>', text)
        self.assertIn(str(self.store.dashboard()['unacknowledged_alerts'])+' unacknowledged alerts',text)
        self.assertNotIn('action="/ack"',text)
        self.assertNotIn('action="/correlate"',text)
        settings=settings_page(self.store)
        self.assertIn('Advanced assessment tools',settings)
        self.assertIn('action="/correlate"',settings)

    def test_data_actions_live_on_the_pages_that_own_them(self):
        owners = {'/assets/import': '/assets', '/intelligence/import': '/intelligence',
                  '/network/import': '/network', '/software/wazuh': '/software', '/sync': '/intelligence'}
        for route in ('/', '/assets', '/network', '/intelligence', '/intelligence/ics',
                      '/software', '/reports', '/settings', '/triage'):
            handler = self.http.handler(route)
            handler.do_GET()
            self.assertEqual(handler.response_status, 200, route)
            markup = handler.wfile.getvalue().decode()
            for action, owner in owners.items():
                self.assertEqual(f'action="{action}"' in markup, route == owner, (route, action))
        cases = {
            '/assets/import': ('inventory.csv', b'ip_address\n192.0.2.19\n'),
            '/intelligence/import': ('advisory.json', b'{"vulnerabilities":[]}'),
        }
        for action, (filename, contents) in cases.items():
            boundary = 'testPhylaxBoundary'
            payload = (
                f'--{boundary}\r\nContent-Disposition: form-data; name="csrf_token"\r\n\r\n'
                f'{self.http.Handler.csrf_token}\r\n'
                f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n\r\n'
                + contents.decode() + f'\r\n--{boundary}--\r\n'
            )
            handler = self.http.handler(action, payload)
            handler.headers.replace_header('Content-Type', f'multipart/form-data; boundary={boundary}')
            handler.do_POST()
            self.assertEqual(handler.response_status, 303, action)
            self.assertEqual(urlsplit(handler.response_headers['Location']).path, owners[action])
        for action in cases:
            invalid = self.http.handler(action, urlencode({'csrf_token': self.http.Handler.csrf_token}))
            invalid.do_POST()
            self.assertEqual(invalid.response_status, 400, action)
            self.assertIn(f'action="{action}"'.encode(), invalid.wfile.getvalue())

    def test_one_plan_review_view_preserves_source_action_and_history(self):
        item=self.make_plan()
        self.store.update_remediation_plan(self.fid,'Under Review',change_notes='TEST ONLY review note')
        overview=page(self.store)
        self.assertIn('/?'+urlencode({'finding_id':self.fid}),overview)
        finding=page(self.store,finding_id=self.fid)
        self.assertIn('/remediation?'+urlencode({'finding_id':self.fid}),finding)
        self.assertIn('Plan status: Under Review',finding)
        self.assertNotIn('action="/remediation/update"',overview)
        text=remediation_page(self.store,99,finding_id=self.fid)
        self.assertIn('id="plan-'+self.fid+'"',text)
        self.assertIn('TEST ONLY: retain source action',text)
        self.assertIn('TEST ONLY review note',text)
        self.assertIn('Human approval required:',text)
        self.assertIn('Generate replacement plan',text)
        self.assertIn('clears its review and verification state',text)
        self.assertNotIn('/remediation?page=98',text)
        self.assertEqual(self.store.get_remediation_plan(self.fid)['plan_id'],item['plan_id'])

    def test_focused_plan_get_and_unknown_plan(self):
        self.make_plan()
        h=self.http.handler('/remediation?'+urlencode({'finding_id':self.fid,'page':99})); h.do_GET()
        self.assertEqual(h.response_status,200)
        self.assertIn(('id="plan-'+self.fid+'"').encode(),h.wfile.getvalue())
        h=self.http.handler('/remediation?finding_id=missing'); h.do_GET()
        self.assertEqual(h.response_status,404)

    def test_lifecycle_returns_to_selected_plan_without_changing_finding_or_ack(self):
        self.make_plan(); before=self.store.finding(self.fid)
        ack=tuple(self.store.connection.execute('SELECT alert_id,acknowledged FROM alerts').fetchone())
        h=self.http.handler('/remediation/update',urlencode({'csrf_token':self.http.Handler.csrf_token,'finding_id':self.fid,'status':'Under Review'})); h.do_POST()
        self.assertEqual(h.response_status,303)
        self.assertTrue(h.response_headers['Location'].startswith('/remediation?'+urlencode({'finding_id':self.fid})))
        self.assertEqual(self.store.finding(self.fid),before)
        self.assertEqual(tuple(self.store.connection.execute('SELECT alert_id,acknowledged FROM alerts').fetchone()),ack)

    def test_retired_ack_route_does_not_mutate_alert(self):
        row=self.store.connection.execute('SELECT alert_id,acknowledged FROM alerts').fetchone()
        h=self.http.handler('/ack',urlencode({'csrf_token':self.http.Handler.csrf_token,'alert_id':row['alert_id']})); h.do_POST()
        self.assertEqual(h.response_status,404)
        self.assertEqual(tuple(self.store.connection.execute('SELECT alert_id,acknowledged FROM alerts').fetchone()),tuple(row))
        h=self.http.handler('/triage/ack',urlencode({'csrf_token':self.http.Handler.csrf_token,'category':'exposure','alert_id':row['alert_id']})); h.do_POST()
        self.assertEqual(h.response_status,303)
        self.assertEqual(self.store.connection.execute('SELECT acknowledged FROM alerts').fetchone()[0],1)

    def test_alert_board_opens_exact_exposure_and_returns_to_same_search(self):
        alert_id = self.store.connection.execute('SELECT alert_id FROM alerts').fetchone()[0]
        search = 'CVE-2024-12345'
        board = self.http.handler('/triage?' + urlencode({'q': search}))
        board.do_GET()
        cards = [a for a in Links(board.wfile.getvalue().decode()).links if a.get('class') == 'alert-card']
        self.assertEqual(len(cards), 1)
        url = urlsplit(cards[0]['href'])
        selection = parse_qs(url.query)
        self.assertEqual(selection['alert'], [alert_id])
        self.assertEqual(selection['view'], ['board'])
        case = self.http.handler(cards[0]['href'])
        case.do_GET()
        html = case.wfile.getvalue().decode()
        self.assertIn('id="alert-' + alert_id + '" open', html)
        self.assertIn('Open vulnerability finding', html)
        back = next(a['href'] for a in Links(html).links if a['href'].startswith('/triage?') and 'alert' not in parse_qs(urlsplit(a['href']).query))
        self.assertEqual(parse_qs(urlsplit(back).query), {'q': [search], 'page': ['1'], 'view': ['board']})
        fields = {key: values[0] for key, values in selection.items()}
        fields.update(csrf_token=self.http.Handler.csrf_token, category='exposure', alert_id=alert_id)
        ack = self.http.handler('/triage/ack', urlencode(fields))
        ack.do_POST()
        self.assertEqual(ack.response_status, 303)
        self.assertEqual(parse_qs(urlsplit(ack.response_headers['Location']).query)['alert'], [alert_id])

    def test_settings_error_and_device_edit_stay_with_the_record(self):
        csrf = self.http.Handler.csrf_token
        invalid_url = 'https://example.invalid/advisory.json'
        failed = self.http.handler('/sources/csaf', urlencode({'csrf_token': csrf, 'url': invalid_url, 'enabled': 'false'}))
        failed.do_POST()
        self.assertEqual(failed.response_status, 400)
        self.assertIn(b'id="advisory-sources"', failed.wfile.getvalue())
        self.assertIn(invalid_url.encode(), failed.wfile.getvalue())
        finding = self.store.finding(self.fid)
        fields = {'csrf_token': csrf, 'asset_id': finding['asset_id'], 'ip_address': finding['ip_address']}
        saved = self.http.handler('/assets/save', urlencode(fields))
        saved.do_POST()
        self.assertEqual(saved.response_status, 303)
        destination = urlsplit(saved.response_headers['Location'])
        self.assertEqual(destination.path, '/assets/edit')
        self.assertEqual(parse_qs(destination.query)['asset_id'], [finding['asset_id']])
        editor = self.http.handler(saved.response_headers['Location'])
        editor.do_GET()
        self.assertIn(b'href="/assets">Return to inventory</a>', editor.wfile.getvalue())

    def test_existing_legacy_guidance_table_survives_reopen(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'cache.db'
            with_source=self.store.connection
            destination=Store(path)
            with_source.backup(destination.connection)
            destination.connection.execute('INSERT INTO ai_remediations VALUES (?,?,?,?,?)',
                (self.fid,'legacy-model','{"summary":"retained"}','[]','2026-11-06T00:00:00Z'))
            destination.connection.commit(); destination.close()
            reopened=Store(path)
            try:
                row=dict(reopened.connection.execute('SELECT * FROM ai_remediations').fetchone())
                self.assertEqual(row['guidance_json'],'{"summary":"retained"}')
                self.assertEqual(reopened.connection.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                self.assertIsNotNone(reopened.finding(self.fid))
            finally: reopened.close()


class UnifiedFetchTests(unittest.TestCase):
    def test_keyed_nvd_request_uses_shared_retry_path_and_preserves_headers(self):
        requests=[]
        def opener(request,**kwargs):
            requests.append((request,kwargs))
            if len(requests)==1:
                raise HTTPError(request.full_url,429,'Rate limited',{'Retry-After':'60'},io.BytesIO())
            return io.BytesIO(b'{"vulnerabilities":[],"totalResults":0}')
        with patch('phylax.feeds.urllib.request.urlopen',side_effect=opener), patch('phylax.feeds.time.sleep') as sleep:
            self.assertEqual(list(nvd_pages(api_key='TEST-KEY')),[(1, 0, 0, [])])
        self.assertEqual(len(requests),2)
        self.assertTrue(all(req.get_header('Apikey')=='TEST-KEY' for req,_ in requests))
        self.assertTrue(all(kwargs['timeout']==20 for _,kwargs in requests))
        sleep.assert_called_once_with(30)

    def test_url_and_request_enforce_same_response_limit(self):
        for value in ('https://public.example/feed',Request('https://public.example/feed',headers={'X-Test':'retained'})):
            with patch('phylax.feeds.MAX_RESPONSE_BYTES',3):
                with self.assertRaisesRegex(ValueError,'limit'):
                    fetch(value,opener=lambda *_a,**_kw:io.BytesIO(b'1234'))

    def test_timeout_retries_are_bounded_and_nonretryable_errors_propagate(self):
        with patch('phylax.feeds.time.sleep') as sleep:
            with self.assertRaises(TimeoutError):
                fetch('https://public.example/feed',opener=lambda *_a,**_kw:(_ for _ in ()).throw(TimeoutError()))
            self.assertEqual([c.args[0] for c in sleep.call_args_list],[1,2,4])
            sleep.reset_mock()
            with self.assertRaises(HTTPError) as caught:
                fetch(Request('https://public.example/feed'),opener=lambda *_a,**_kw:(_ for _ in ()).throw(HTTPError('url',403,'denied',{},io.BytesIO())))
            caught.exception.close()
            sleep.assert_not_called()
