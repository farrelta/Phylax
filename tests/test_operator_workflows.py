"""Regression checks for the five independently critiqued operator workflows."""
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs,urlparse,urlencode
from html.parser import HTMLParser
from scripts.prepare_release_demo import prepare
from phylax.core import Store
from phylax.asset_intelligence import save_context,context_revision
from phylax.discovery import save_target,enqueue,schedule
from phylax.monitoring import ingest_file
from phylax.release_web import page,post
from phylax.triage import triage,acknowledge
from phylax.web import page as overview,attack_surface_page


class Forms(HTMLParser):
    def __init__(self,text):
        super().__init__();self.forms=[];self.current=None;self.feed(text)
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='form':self.current={'action':attrs.get('action',''),'fields':{}};self.forms.append(self.current)
        if tag=='input' and self.current is not None and attrs.get('name'):
            self.current['fields'][attrs['name']]=attrs.get('value','')
    def handle_endtag(self,tag):
        if tag=='form':self.current=None
    def fields(self,action):return next(f['fields'] for f in self.forms if f['action']==action)


def form_values(values):return {k:[str(v)] for k,v in values.items()}


class OperatorWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.initial=prepare(self.root/'demo');self.store=Store(self.initial['database'])
        self.policy=json.loads((self.root/'demo/policy.json').read_text())

    def tearDown(self):self.store.close();self.temp.cleanup()

    def observe(self):
        path=self.root/'modbus.log'
        path.write_text(json.dumps({'ts':1793944800,'uid':'operator-review','id.orig_h':'172.30.77.99','id.resp_h':'172.30.77.10','id.orig_p':40123,'id.resp_p':502,'func':6,'pdu_type':'REQ'})+'\n')
        ingest_file(self.store,path,kind='modbus',policy=self.policy)

    def test_context_loads_existing_record_and_explicit_selected_asset(self):
        html=page(self.store,'/processes',{'asset_id':['lab-plc']})
        fields=Forms(html).fields('/processes/context')
        self.assertEqual(fields['asset_id'],'lab-plc')
        self.assertEqual(fields['owner'],'Fictional facility maintainer')
        self.assertEqual(fields['location'],'Simulated cooling room')
        self.assertEqual(fields['context_revision'],context_revision(self.store,'lab-plc'))
        self.assertIn('value="commissioned" selected',html)
        other=Forms(page(self.store,'/processes',{'asset_id':['lab-it']})).fields('/processes/context')
        self.assertEqual(other['asset_id'],'lab-it');self.assertEqual(other['owner'],'')

    def test_context_partial_edit_preserves_missing_fields_and_explicit_clear(self):
        before=dict(self.store.connection.execute("SELECT * FROM asset_context WHERE asset_id='lab-plc'").fetchone())
        result=post(self.store,'/processes/context',form_values({'asset_id':'lab-plc','context_revision':context_revision(self.store,'lab-plc'),'owner':'Updated operator'}))
        after=dict(self.store.connection.execute("SELECT * FROM asset_context WHERE asset_id='lab-plc'").fetchone())
        self.assertEqual(after['owner'],'Updated operator')
        for key in ('site','location','lifecycle','tags_json','criticality_rationale'):self.assertEqual(after[key],before[key])
        self.assertIn('notice=',result);self.assertIn('asset_id=lab-plc',result)
        post(self.store,'/processes/context',form_values({'asset_id':'lab-plc','context_revision':context_revision(self.store,'lab-plc'),'location':''}))
        self.assertEqual(self.store.connection.execute("SELECT location FROM asset_context WHERE asset_id='lab-plc'").fetchone()[0],'')

    def test_context_stale_and_missing_revision_cannot_overwrite(self):
        previous=context_revision(self.store,'lab-plc')
        save_context(self.store,'lab-plc',owner='Newer context')
        for revision in (previous,''):
            with self.assertRaises(ValueError):
                post(self.store,'/processes/context',form_values({'asset_id':'lab-plc','context_revision':revision,'owner':'Stale update'}))
        self.assertEqual(self.store.connection.execute("SELECT owner FROM asset_context WHERE asset_id='lab-plc'").fetchone()[0],'Newer context')

    def test_context_post_failure_retains_input_and_security(self):
        from test_review_regressions import HTTPAndGuidanceRegressionTests
        helper=HTTPAndGuidanceRegressionTests();helper.setUp()
        try:
            save_context(helper.store,'a',owner='Saved context')
            helper.store.connection.execute("INSERT OR REPLACE INTO schema_meta VALUES('dataset_label','SYNTHETIC banner regression')")
            helper.store.connection.commit()
            values={'csrf_token':helper.Handler.csrf_token,'asset_id':'a','context_revision':context_revision(helper.store,'a'),'owner':'<script>typed value</script>','lifecycle':'invalid'}
            h=helper.handler('/processes/context',urlencode(values));h.do_POST()
            self.assertEqual(h.response_status,400)
            body=h.wfile.getvalue().decode()
            self.assertIn('role="alert"',body);self.assertIn('&lt;script&gt;typed value&lt;/script&gt;',body)
            self.assertIn('SYNTHETIC banner regression',body)
            self.assertNotIn('<script>typed',body);self.assertIn('name="csrf_token"',body)
            self.assertEqual(helper.store.connection.execute('SELECT owner FROM asset_context').fetchone()[0],'Saved context')
            bad=helper.handler('/processes/context',urlencode({**values,'csrf_token':'bad'}));bad.do_POST()
            self.assertEqual(bad.response_status,403)
        finally:helper.tearDown()

    def test_discovery_only_offers_eligible_assets_and_permitted_execution(self):
        html=page(self.store,'/discovery',{})
        fields=Forms(html).fields('/discovery/save')
        self.assertEqual(fields['asset_id'],'lab-it');self.assertEqual(fields['ports'],'8080')
        self.assertIn('No currently permitted targets',html)
        self.assertNotIn('action="/discovery/run"',html)
        self.assertNotIn('<option value="lab-plc"',html);self.assertNotIn('<option value="lab-reader"',html)
        self.assertIn('value="true" selected>Enabled for selected supported ports',html)
        save_target(self.store,'lab-it',[8080],permission=True,actor='tester',note='Isolated fixture only')
        html=page(self.store,'/discovery',{})
        self.assertIn('action="/discovery/run"',html);self.assertIn('Currently permitted target',html)

    def test_target_revision_stale_save_cannot_regrant_revoked_permission(self):
        current=self.store.connection.execute('SELECT revision FROM scan_targets').fetchone()[0]
        save_target(self.store,'lab-it',[8080],permission=False,actor='tester',note='revoked')
        with self.assertRaises(ValueError):save_target(self.store,'lab-it',[8080],permission=True,actor='tester',note='stale',expected_revision=current)
        self.assertFalse(self.store.connection.execute('SELECT permission FROM scan_targets').fetchone()[0])

    def test_disabled_schedule_can_be_stopped_and_no_regrant_occurs(self):
        tid=save_target(self.store,'lab-it',[8080],permission=True,actor='tester',note='fixture')
        schedule(self.store,tid,15,True)
        rid=enqueue(self.store,tid)
        post(self.store,'/discovery/revoke',form_values({'target_id':tid,'actor':'tester','note':'revoke'}))
        self.assertEqual(self.store.connection.execute('SELECT status FROM scan_runs WHERE run_id=?',(rid,)).fetchone()[0],'cancelled')
        schedule(self.store,tid,15,False)
        self.assertFalse(self.store.connection.execute('SELECT enabled FROM scan_schedules').fetchone()[0])
        save_target(self.store,'lab-it',[8080],permission=True,actor='tester',note='fixture')
        self.store.connection.execute("UPDATE assets SET asset_type='PLC' WHERE asset_id='lab-it'")
        self.store.connection.commit()
        html=page(self.store,'/discovery',{})
        self.assertIn('No eligible supporting IT assets',html)
        self.assertIn('Revoke this permission',html)
        post(self.store,'/discovery/revoke',form_values({'target_id':tid,'actor':'tester','note':'Recategorized control endpoint'}))
        self.assertFalse(self.store.connection.execute('SELECT permission FROM scan_targets').fetchone()[0])

    def test_triage_exposes_context_and_policy_before_raw_record(self):
        self.observe()
        html=page(self.store,'/triage',{'category':['network']})
        visible=html.split('<summary>Raw record</summary>')[0]
        self.assertIn('Fictional facility maintainer',visible);self.assertIn('Simulated facility cooling',visible)
        self.assertIn('Observed evidence',visible);self.assertIn('Configured policy',visible)
        self.assertIn('Not assessed (network / management alert)',visible)
        self.assertIn('Unacknowledged',visible);self.assertNotIn('acknowledged: False',visible)
        self.assertIn('/evidence?',visible);self.assertIn('/policy',visible)
        self.assertIn('No approved maintenance windows',html)

    def test_triage_filters_before_pagination_and_ack_preserves_scope(self):
        self.observe();rows,count=triage(self.store,filters={'category':'network','priority':'critical','acknowledged':'no','q':'LAB-Cooling'})
        self.assertEqual(count,2)
        row=rows[0]
        destination=post(self.store,'/triage/ack',form_values({'category':row['category'],'alert_id':row['alert_id'],'filter_category':'network','priority':'critical','acknowledged':'no','q':'LAB-Cooling','page':1}))
        query=parse_qs(urlparse(destination).query)
        self.assertEqual(query['category'],['network']);self.assertEqual(query['priority'],['critical'])
        self.assertEqual(triage(self.store,filters={'category':'network','priority':'critical','acknowledged':'no'})[1],1)
        self.assertTrue(next(r for r in triage(self.store)[0] if r['alert_id']==row['alert_id'])['acknowledged'])

    def test_overview_count_matches_unacknowledged_triage_including_endpoints(self):
        self.observe()
        self.assertEqual(self.store.dashboard()['unacknowledged_alerts'],sum(not r['acknowledged'] for r in triage(self.store)[0]))

    def test_empty_state_navigation_and_pagination_are_task_led(self):
        s=Store(':memory:')
        try:
            html=overview(s)
            self.assertIn('Add your first asset',html);self.assertNotIn('0/0',html)
            self.assertIn('Skip to main content',html);self.assertIn('mobile-navigation',html)
            self.assertNotIn('<details class="site-navigation mobile-navigation" open',html)
            self.assertIn('aria-label="Workspace"',html);self.assertNotIn('<p class="eyebrow">',html)
            self.assertNotIn('>Next</a>',page(s,'/changes',{}))
        finally:s.close()

    def test_surface_filters_collapsed_and_finding_link_is_addressable(self):
        html=attack_surface_page(self.store)
        self.assertIn('<summary>Filter observed surface',html)
        self.assertNotIn('<details class="workflow" open',html)
        self.assertNotIn('Next assets',html)
        finding=self.store.connection.execute('SELECT finding_id FROM findings LIMIT 1').fetchone()[0]
        self.assertIn('id="finding-'+finding+'"',overview(self.store,finding_id=finding))
        with self.assertRaises(ValueError):overview(self.store,finding_id='absent')


if __name__=='__main__':unittest.main()
