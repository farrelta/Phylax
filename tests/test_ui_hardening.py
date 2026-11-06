"""Offline regressions for the technical UI audit's six findings."""
import json
import unittest
import io
from unittest.mock import patch
from html.parser import HTMLParser
from urllib.parse import urlencode

import test_review_regressions as regression_tests
from phylax.remediation import compose_plan
from phylax.remediation_views import lifecycle_form
from phylax.remediation_lifecycle import TRANSITIONS
from phylax.theme import CSS,term,status_marker
from phylax.web import page,remediation_page,kev_status


class Controls(HTMLParser):
    def __init__(self,text):
        super().__init__();self.controls=[];self.label_depth=0;self.feed(text)
    def handle_starttag(self,tag,attrs):
        if tag=='label':self.label_depth+=1
        if tag in {'input','select','textarea'}:
            data=dict(attrs)
            if data.get('type')!='hidden':self.controls.append((tag,data,self.label_depth>0))
    def handle_endtag(self,tag):
        if tag=='label':self.label_depth-=1


class UIHardeningTests(unittest.TestCase):
    def setUp(self):
        self.http=regression_tests.HTTPAndGuidanceRegressionTests();self.http.setUp()
        self.store=self.http.store;self.fid=self.http.fid
    def tearDown(self):self.http.tearDown()

    def post(self,path,values,**kwargs):
        handler=self.http.handler(path,urlencode({'csrf_token':self.http.Handler.csrf_token,**values}),**kwargs)
        handler.do_POST()
        return handler,handler.wfile.getvalue().decode()

    def make_plan(self):
        f=self.store.finding(self.fid)
        f['evidence']=json.loads(f['evidence']);f['missing_evidence']=json.loads(f['missing_evidence'])
        plan=compose_plan(f,self.store.public_vulnerability_for_finding(self.fid))
        return self.store.create_remediation_plan(self.fid,'template-fallback','',plan,plan['source_references'])

    def test_remediation_forms_share_labels_and_valid_transition_choices(self):
        item=self.make_plan()
        overview=page(self.store)
        self.assertIn('Review plan',overview)
        self.assertIn('Plan status: Recommended',overview)
        self.assertNotIn('action="/remediation/update"',overview)
        html=remediation_page(self.store)
        controls=[r for r in Controls(html).controls if r[1].get('name') in {'status','reviewer','change_notes','verification_evidence'}]
        self.assertEqual(len(controls),4)
        self.assertTrue(all(labelled for tag,attrs,labelled in controls))
        self.assertIn('<legend>Review plan for CVE-2024-12345',html)
        self.assertIn('Required when approving.',html)
        form=lifecycle_form(item)
        for choice in TRANSITIONS['Recommended']:self.assertIn('value="'+choice+'"',form)
        self.assertNotIn('value="Verified"',form);self.assertNotIn('value="Approved"',form)

    def test_invalid_inventory_preserves_escaped_values_and_field_error(self):
        before=dict(self.store.connection.execute("SELECT * FROM assets WHERE asset_id='a'").fetchone())
        h,body=self.post('/assets/save',{'asset_id':'a','ip_address':'bad ip','hostname':'<script>typed العربية</script>','verified':'false'})
        self.assertEqual(h.response_status,400)
        self.assertIn('action="/assets/save"',body);self.assertIn('Edit asset',body)
        self.assertIn('&lt;script&gt;typed العربية&lt;/script&gt;',body);self.assertNotIn('<script>typed',body)
        self.assertIn('id="input-errors" role="alert" tabindex="-1" autofocus',body)
        control=next(attrs for tag,attrs,label in Controls(body).controls if attrs.get('name')=='ip_address')
        self.assertEqual(control['aria-invalid'],'true');self.assertEqual(control['aria-describedby'],'asset-ip_address-error')
        self.assertIn('name="csrf_token"',body)
        self.assertIn('value="false" selected',body)
        self.assertEqual(before,dict(self.store.connection.execute("SELECT * FROM assets WHERE asset_id='a'").fetchone()))

    def test_invalid_policy_preserves_json_and_active_policy(self):
        text='{"protected_assets": ["not-an-ip"], "note": "<script>draft</script>"}'
        h,body=self.post('/policy/apply',{'policy_json':text})
        self.assertEqual(h.response_status,400)
        self.assertIn('action="/policy/apply"',body);self.assertIn('&lt;script&gt;draft&lt;/script&gt;',body)
        self.assertIn('aria-describedby="policy-json-error"',body)
        self.assertEqual(self.store.connection.execute('SELECT COUNT(*) FROM network_policies').fetchone()[0],0)

    def test_invalid_lifecycle_retains_input_and_authoritative_state(self):
        self.make_plan()
        self.store.update_remediation_plan(self.fid,'Under Review')
        before=self.store.get_remediation_plan(self.fid)
        finding_before=self.store.finding(self.fid)
        h,body=self.post('/remediation/update',{'finding_id':self.fid,'status':'Approved','reviewer':'','change_notes':'<script>review draft</script>'})
        self.assertEqual(h.response_status,400)
        self.assertIn('action="/remediation/update"',body)
        self.assertIn('&lt;script&gt;review draft&lt;/script&gt;',body)
        self.assertIn('Reviewer is required for approval',body)
        self.assertEqual(before,self.store.get_remediation_plan(self.fid))
        self.assertEqual(finding_before,self.store.finding(self.fid))
        self.assertFalse(self.store.connection.execute('SELECT acknowledged FROM alerts').fetchone()[0])

    def test_tampered_transition_still_rejected_and_retained(self):
        self.make_plan()
        h,body=self.post('/remediation/update',{'finding_id':self.fid,'status':'Verified','reviewer':'tester','verification_evidence':'draft'})
        self.assertEqual(h.response_status,400)
        self.assertIn('unavailable; choose a valid next status',body)
        self.assertEqual(self.store.get_remediation_plan(self.fid)['status'],'Recommended')

    def test_recovery_does_not_bypass_request_protections(self):
        for kwargs,values in (({'origin':'https://untrusted.example'},{}),({}, {'csrf_token':'bad'})):
            h,body=self.post('/assets/save',values,**kwargs)
            self.assertEqual(h.response_status,403);self.assertNotIn('action="/assets/save"',body)

    def test_glossary_uses_native_in_flow_disclosures_and_markers_are_not_interactive(self):
        text=term('Possibly affected')
        self.assertIn('<details class="term"><summary>Possibly affected</summary>',text)
        self.assertNotIn('data-tip',text);self.assertNotIn('.term:focus::after',CSS)
        self.assertNotIn('<details',status_marker('POTENTIAL_MATCH'))
        self.assertIn('label input,label select{font-size:16px}',CSS)

    def test_kev_wording_distinguishes_unknown_cached_stale_positive_and_synthetic(self):
        f={'kev':False,'synthetic':False}
        self.assertIn('unknown',kev_status(f,[]))
        health={'source':'CISA KEV','last_success_at':'2026-11-06T01:00:00Z','health':'healthy'}
        self.assertIn('Not listed in CISA KEV cached catalog',kev_status(f,[health]))
        self.assertIn('stale cached catalog',kev_status(f,[dict(health,health='stale')]))
        self.assertIn('unavailable',kev_status(f,[dict(health,health='error')]))
        self.assertIn('KEV-associated in stored intelligence',kev_status(dict(f,kev=True),[]))
        self.assertEqual(kev_status(dict(f,synthetic=True),[]),'Synthetic KEV association: no')
        self.assertNotIn('no known exploitation',page(self.store))

    def test_triage_queries_and_evidence_decode_are_bounded_for_a_page(self):
        from phylax.triage import triage
        self.store.connection.execute("UPDATE assets SET criticality='critical'")
        for i in range(500):
            self.store.connection.execute('INSERT INTO network_events(event_id,timestamp,event_ref,source_ip,destination_ip,source_port,destination_port,protocol,operation,event_type,source_file,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                (f'e-{i}','2026-11-06T00:00:00Z',f'ref-{i}','192.0.2.99','192.0.2.1',40123,502,'tcp','6','modbus','SYNTHETIC fixture','{}'))
            self.store.connection.execute('INSERT INTO network_alerts VALUES(?,?,?,?,?,?,?,?,?)',
                (f'a-{i:04}', 'unauthorized_modbus_writer',f'e-{i}','high','SYNTHETIC test write','{"test":"policy"}',int(i%2==0),'2026-11-06T00:00:00Z','2026-11-06T00:00:00Z'))
        self.store.connection.commit()
        statements=[];self.store.connection.set_trace_callback(statements.append)
        try:
            with patch('phylax.triage.json.loads',wraps=json.loads) as loads:
                rows,count=triage(self.store,limit=20)
                self.assertLess(loads.call_count,30)
        finally:self.store.connection.set_trace_callback(None)
        self.assertEqual(count,501);self.assertEqual(len(rows),20)
        self.assertLessEqual(len(statements),12)
        full,_=triage(self.store)
        self.assertEqual(rows,full[:20])
        for filters in ({'category':'network','acknowledged':'yes'},{'category':'exposure'},{'priority':'high','q':'private-inventory'}):
            selected,total=triage(self.store,filters=filters)
            limited,limited_total=triage(self.store,filters=filters,limit=7,offset=4)
            self.assertEqual(total,limited_total);self.assertEqual(limited,selected[4:11])
        self.assertEqual(triage(self.store,limit=0)[0],[])
        with self.assertRaises(ValueError):triage(self.store,filters={'category':'anything'})

    def test_context_precedence_unknown_identity_and_processes_survive_batching(self):
        from phylax.triage import context
        from phylax.asset_intelligence import save_context,save_process
        save_context(self.store,'a',owner='علي – reviewer',criticality_rationale='Reviewed')
        save_process(self.store,'Cooling support','SYNTHETIC process','a','tester','Controlled fixture')
        selected=context(self.store,'192.0.2.1')
        self.assertEqual(selected['asset_id'],'a')
        self.assertEqual(selected['operational_context']['owner'],'علي – reviewer')
        self.assertEqual(selected['processes'][0]['name'],'Cooling support')
        self.store.connection.execute("UPDATE assets SET identification_source='zeek_passive',verified=0")
        self.store.connection.execute("DELETE FROM asset_context");self.store.connection.commit()
        self.assertEqual(context(self.store,'192.0.2.1')['criticality'],'unknown')
        self.assertEqual(context(self.store,'192.0.2.250')['identity_confidence'],'unknown')

    def test_discovery_selector_is_paginated_searchable_and_preserves_target_boundaries(self):
        from phylax.discovery import eligible_inventory,eligible
        from phylax.configuration_pages import discovery_page
        self.store.import_csv(io.StringIO('asset_id,ip_address,hostname,asset_type,zone\n'+''.join(
            f's-{i},10.25.0.{i+1},SYNTHETIC server {i},server,IT\n' for i in range(120))))
        self.store.import_csv(io.StringIO('asset_id,ip_address,hostname,asset_type,zone\nv6,2001:db8::1,IPv6 server,server,IT\not,192.0.2.11,OT server,server,OT\n'))
        rows,total=eligible_inventory(self.store);self.assertEqual(total,120);self.assertEqual(len(rows),50)
        next_rows,_=eligible_inventory(self.store,offset=50);self.assertFalse({r['asset_id'] for r in rows}&{r['asset_id'] for r in next_rows})
        self.assertEqual(eligible_inventory(self.store,'%_')[1],0)
        for aid in ('v6','ot'):
            row=self.store.connection.execute('SELECT ip_address FROM assets WHERE asset_id=?',(aid,)).fetchone()
            with self.assertRaises(ValueError):eligible(self.store,aid,row[0])
        html,_=discovery_page(self.store,{'asset_id':['s-119']},0)
        self.assertIn('value="s-119" selected',html);self.assertIn('Next assets',html)
        self.assertNotIn('<option value="v6"',html);self.assertNotIn('<option value="ot"',html)
        self.assertNotIn('action="/discovery/run"',html)


if __name__=='__main__':unittest.main()
