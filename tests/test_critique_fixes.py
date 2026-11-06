"""Offline regressions for the operator critique refinements."""
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs,urlsplit

import test_review_regressions as regressions
from phylax.web import page,assets_page,remediation_page
from phylax.operator_pages import inventory_form
from phylax.release_web import page as operator_page
from phylax.remediation import compose_plan
from phylax.ui import reference_links,local_return,evidence_url


class CritiqueFixTests(unittest.TestCase):
    def setUp(self):
        self.http=regressions.HTTPAndGuidanceRegressionTests();self.http.setUp()
        self.store=self.http.store;self.fid=self.http.fid

    def tearDown(self):self.http.tearDown()

    def make_plan(self):
        finding=self.store.finding(self.fid)
        for key in ('evidence','missing_evidence'):finding[key]=json.loads(finding[key])
        plan=compose_plan(finding,self.store.public_vulnerability_for_finding(self.fid))
        return self.store.create_remediation_plan(self.fid,'template-fallback','',plan,plan['source_references'])

    def test_triage_is_collapsed_with_stable_case_deep_links(self):
        alert=self.store.connection.execute('SELECT alert_id FROM alerts LIMIT 1').fetchone()[0]
        text=operator_page(self.store,'/triage',{})
        starts=re.findall(r'<details class="triage-case"[^>]*>',text)
        self.assertTrue(starts);self.assertTrue(all(' open' not in tag for tag in starts))
        self.assertIn('Inspect alert',text)
        self.assertIn('Acknowledge this alert',text)
        opened=operator_page(self.store,'/triage',{'case':[alert]})
        self.assertIn('id="alert-'+alert+'" open',opened)

    def test_focused_finding_is_semantic_detail_without_a_wide_table(self):
        self.make_plan()
        text=page(self.store,finding_id=self.fid)
        self.assertIn('class="finding-case"',text)
        self.assertNotIn('<table',text)
        for label in ('Applicability evidence','Missing evidence','Review plan','Why this urgency','Source provenance'):
            self.assertIn(label,text)
        self.assertIn('id="finding-'+self.fid+'"',text)

    def test_identity_review_filter_matches_dashboard_with_search_and_pagination(self):
        self.store.import_csv(io.StringIO('asset_id,ip_address,hostname,vendor,product,identity_confidence,verified\nreview-extra,192.0.2.222,Review Extra,,,low,false\n'))
        rows,total=self.store.search_assets(identity_review=True)
        self.assertEqual(total,self.store.dashboard()['assets_needing_identity_review'])
        selected,count=self.store.search_assets('Review Extra',identity_review=True,limit=1)
        self.assertEqual(count,1);self.assertEqual(selected[0]['asset_id'],'review-extra')
        self.assertEqual(self.store.search_assets('Review Extra',identity_review=True,offset=1)[0],[])
        text=assets_page(self.store,identity_review=True)
        self.assertIn('value="yes" checked',text)
        self.assertIn('identity_review=yes',page(self.store))
        # The review banner is global even beyond its inventory-list offset.
        self.assertIn('identity_review=yes',page(self.store,page_number=2))

    def test_discovery_error_never_rebinds_failed_permission_to_another_asset(self):
        from phylax.release_web import error_page
        self.store.import_csv(io.StringIO('asset_id,ip_address,hostname,asset_type,zone,identity_confidence,verified\nstale-a,192.0.2.220,Old target,PLC,OT,high,true\nsafe-b,192.0.2.221,Other server,server,IT,high,true\n'))
        values={k:[v] for k,v in {'asset_id':'stale-a','ports':'443','permission':'true','target_revision':'0','actor':'fixture','note':'Only old target'}.items()}
        text=error_page(self.store,'/discovery/save',values,'This target is no longer eligible.')
        self.assertNotIn('action="/discovery/save"',text)
        valid=operator_page(self.store,'/discovery',{'asset_id':['safe-b']})
        self.assertIn('action="/discovery/save"',valid)
        self.assertIn('name="asset_id" value="safe-b"',valid)

    def test_inventory_groups_keep_labels_and_record_context(self):
        finding=self.store.finding(self.fid)
        text=inventory_form(self.store,finding['asset_id'])
        self.assertEqual(text.count('<fieldset class="editor">'),4)
        self.assertIn('Verification and source',text)
        self.assertIn('Verification does not approve management',text)
        self.assertIn('asset-verified-help',text)
        self.assertIn('/processes?asset_id=',text)

    def test_reference_and_return_links_reject_external_navigation(self):
        text=reference_links(['https://example.org/advisory?a=1&b=2','javascript:alert(1)','https://example.org/\nattack','https://user:pass@example.org/'])
        self.assertEqual(text.count('<a '),1)
        self.assertIn('a=1&amp;b=2',text)
        for bad in ('https://evil.test/','//evil.test/','/triage\\evil','/settings','/triage\n'):
            self.assertEqual(local_return(bad),'/network')
        back='/triage?category=network&case=abc#alert-abc'
        self.assertEqual(local_return(back),back)
        self.assertEqual(parse_qs(urlsplit(evidence_url('ref',back)).query)['return_to'],[back])

    def test_original_evidence_labels_observation_and_safe_return(self):
        from phylax.asset_intelligence import observe
        observe(self.store,kind='dhcp',ip='192.0.2.33',when='2026-11-06T00:00:00Z',source_file='synthetic.log',event_ref='synthetic-ref',raw={'note':'<script>bad()</script>'})
        text=operator_page(self.store,'/evidence',{'event_ref':['synthetic-ref'],'return_to':['https://evil.test/']})
        self.assertIn('Observed endpoint evidence',text)
        self.assertIn('Endpoint observation · dhcp · 192.0.2.33',text)
        self.assertIn('href="/network"',text)
        self.assertNotIn('href="https://evil.test/',text)
        self.assertIn('&lt;script&gt;',text)
        self.assertIn('aria-label="Monitoring views"',text)

    def test_original_event_distinguishes_superseded_policy_conclusions(self):
        from phylax.monitoring import ingest_file,reevaluate_events
        with tempfile.TemporaryDirectory() as directory:
            log=Path(directory)/'synthetic-modbus.jsonl'
            log.write_text(json.dumps({'ts':'2026-11-06T00:00:00Z','uid':'synthetic-policy','id.orig_h':'192.0.2.30','id.resp_h':'192.0.2.31','id.resp_p':502,'proto':'tcp','function_code':6})+'\n')
            ingest_file(self.store,log,kind='modbus',policy={'authorized_writers':{'192.0.2.31':[]}})
        ref=self.store.connection.execute('SELECT event_ref FROM network_events LIMIT 1').fetchone()[0]
        reevaluate_events(self.store,{})
        text=operator_page(self.store,'/evidence',{'event_ref':[ref]})
        self.assertIn('Historical conclusion',text)
        self.assertNotIn('Active conclusion',text)

    def test_guidance_is_structured_and_rendering_preserves_authoritative_state(self):
        self.make_plan()
        finding=self.store.finding(self.fid)
        before=[tuple(r) for r in self.store.connection.execute('SELECT * FROM alerts')]
        plan_before=self.store.get_remediation_plan(self.fid)
        text=remediation_page(self.store,finding_id=self.fid)
        self.assertIn('class="plan-review"',text)
        self.assertIn('href="#plan-'+self.fid+'-review"',text)
        self.assertLess(text.index('class="plan-review"'),text.index('Prerequisites and approvals'))
        self.assertNotIn("&#x27;identity_confidence&#x27;",text)
        self.assertNotIn('CONFIRMED_MATCH',text)
        self.assertEqual(text.count('action="/remediation/update"'),1)
        self.assertIn('clears its review and verification state',text)
        page(self.store,finding_id=self.fid);operator_page(self.store,'/triage',{})
        self.assertEqual(self.store.finding(self.fid),finding)
        self.assertEqual([tuple(r) for r in self.store.connection.execute('SELECT * FROM alerts')],before)
        self.assertEqual(self.store.get_remediation_plan(self.fid),plan_before)

    def test_old_plan_snapshot_does_not_replace_current_applicability(self):
        self.make_plan()
        self.store.connection.execute("UPDATE findings SET status='NO_MATCH_TO_THIS_ADVISORY',priority='not_applicable' WHERE finding_id=?",(self.fid,))
        self.store.connection.execute("UPDATE remediation_plans SET status='Needs More Evidence' WHERE finding_id=?",(self.fid,))
        self.store.connection.commit()
        text=remediation_page(self.store,finding_id=self.fid)
        summary=text.split('class="plan-review"')[0]
        self.assertIn('Not affected',summary)
        self.assertNotIn('Confirmed affected',summary)
        self.assertIn('generation',text.lower())
        self.assertIn('evidence',summary.lower())
