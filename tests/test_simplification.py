"""Regression coverage for consolidated navigation, review and feed fetching."""
import io
import json
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlencode
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
                         ['/','/assets','/network','/intelligence','/triage','/reports','/settings'])
        for root,(label,items) in SECONDARY_NAV.items():
            for href,_ in items:
                text=layout('Test view','',href)
                links=Links(text).links
                self.assertEqual(sum(a.get('href')==root and a.get('aria-current')=='page' for a in links),3 if href==root else 2)
                self.assertIn('aria-label="'+label+'"',text)
                self.assertIn('href="'+href+'" aria-current="page"',text)

    def test_overview_summarizes_alerts_and_imports_reassess_automatically(self):
        text=page(self.store)
        self.assertIn('Review new alerts in Triage',text)
        self.assertIn(str(self.store.dashboard()['unacknowledged_alerts'])+' unacknowledged alerts',text)
        self.assertNotIn('action="/ack"',text)
        self.assertNotIn('action="/correlate"',text)
        settings=settings_page(self.store)
        self.assertIn('Advanced assessment tools',settings)
        self.assertIn('action="/correlate"',settings)

    def test_one_plan_review_view_preserves_source_action_and_history(self):
        item=self.make_plan()
        self.store.update_remediation_plan(self.fid,'Under Review',change_notes='TEST ONLY review note')
        overview=page(self.store)
        self.assertIn('/remediation?'+urlencode({'finding_id':self.fid}),overview)
        self.assertIn('Plan status: Under Review',overview)
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
            self.assertEqual(list(nvd_pages(api_key='TEST-KEY')),[])
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
