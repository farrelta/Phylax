"""Offline regressions for the technical UI audit's six findings."""
import json
import unittest
import io
from unittest.mock import patch
from html.parser import HTMLParser
from urllib.parse import urlencode

import test_review_regressions as regression_tests
from phylax.remediation import compose_plan
from phylax.i18n import translate_html
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
        if path == '/remediation/update':
            plan = self.store.get_remediation_plan(values['finding_id'])
            values = {'plan_id': plan['plan_id'], 'plan_version': len(plan['history']), **values}
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
        self.assertIn(f'href="/?finding_id={self.fid}#finding-{self.fid}"',overview)
        self.assertIn('Review finding',overview)
        finding=page(self.store,finding_id=self.fid)
        self.assertIn('Review plan',finding)
        self.assertIn('Plan status: Recommended',finding)
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

    def test_fix_plan_and_finding_show_current_next_step_in_both_languages(self):
        self.make_plan()
        scenarios = [
            ('POTENTIAL_MATCH', 'fixture mitigation', 'Verify device identity and version.', 'Verifikasi identitas dan versi perangkat.'),
            ('POTENTIAL_MATCH', '', 'Verify device identity and version.', 'Verifikasi identitas dan versi perangkat.'),
            ('NEEDS_REVIEW', 'fixture mitigation', 'Resolve missing or conflicting evidence.', 'Periksa bukti yang belum lengkap atau saling bertentangan.'),
            ('NEEDS_REVIEW', '', 'Resolve missing or conflicting evidence.', 'Periksa bukti yang belum lengkap atau saling bertentangan.'),
            ('CONFIRMED_MATCH', 'fixture mitigation', 'Review vendor guidance.', 'Tinjau panduan vendor.'),
            ('CONFIRMED_MATCH', '', 'Consult the advisory or document a mitigation.', 'Baca advisori atau dokumentasikan tindakan mitigasi.'),
            ('NO_MATCH_TO_THIS_ADVISORY', 'fixture mitigation', 'No fix needed for this advisory.', 'Tidak diperlukan perbaikan untuk advisori ini.'),
            ('NO_MATCH_TO_THIS_ADVISORY', '', 'No fix needed for this advisory.', 'Tidak diperlukan perbaikan untuk advisori ini.'),
        ]
        for status, mitigation, english, indonesian in scenarios:
            with self.subTest(status=status, mitigation=mitigation):
                self.store.connection.execute('UPDATE findings SET status=?, missing_evidence=? WHERE finding_id=?',
                                              (status, json.dumps(['Fixture version evidence is incomplete.']), self.fid))
                self.store.connection.execute('UPDATE vulnerabilities SET mitigation=?', (mitigation,))
                if status == 'CONFIRMED_MATCH':
                    self.make_plan()
                plan = remediation_page(self.store, finding_id=self.fid)
                finding = page(self.store, finding_id=self.fid)
                for markup in (plan, finding):
                    self.assertIn(english, markup)
                    self.assertIn(indonesian, translate_html(markup, 'id'))
                self.assertNotIn('fixture mitigation', plan.split('class="plan-review"', 1)[0])
                if status in {'POTENTIAL_MATCH', 'NEEDS_REVIEW'}:
                    self.assertIn('Fixture version evidence is incomplete.', plan)
                    self.assertIn('#case-evidence', plan)
                    self.assertIn('<details><summary>Advisory guidance for reference</summary>', plan)
                if status == 'NO_MATCH_TO_THIS_ADVISORY':
                    self.assertNotIn('Fix plan checklist', plan)
                    self.assertIn('#case-evidence', plan)
                    self.assertNotIn('Generate replacement plan</button>', plan)
                    before = self.store.get_remediation_plan(self.fid)
                    handler, _ = self.post('/remediation/create', {'finding_id': self.fid,
                                           'replace_plan_id': before['plan_id'], 'replace_plan_version': len(before['history'])})
                    self.assertEqual(handler.response_status, 400)
                    self.assertEqual(before, self.store.get_remediation_plan(self.fid))
        self.store.connection.execute('DELETE FROM remediation_plans WHERE finding_id=?', (self.fid,))
        self.assertNotIn('action="/remediation/create"', page(self.store, finding_id=self.fid))
        handler, _ = self.post('/remediation/create', {'finding_id': self.fid})
        self.assertEqual(handler.response_status, 400)
        self.assertIsNone(self.store.get_remediation_plan(self.fid))

    def test_paused_or_outdated_plan_does_not_claim_active_checklist_progress(self):
        for status, label in (('Deferred', 'Plan deferred.'), ('Rejected', 'Plan rejected.')):
            with self.subTest(status=status):
                self.make_plan()
                self.store.update_remediation_plan(self.fid, status)
                markup = remediation_page(self.store, finding_id=self.fid)
                checklist = markup.split('class="plan-checklist"', 1)[1].split('</section>', 1)[0]
                self.assertIn(label, checklist)
                self.assertIn(f'href="#plan-{self.fid}-status"', checklist)
                self.assertNotIn('aria-current="step"', checklist)
        plan = self.make_plan()['plan']
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                outdated = {key: value for key, value in plan.items() if key != 'finding_revision'}
                if not legacy:
                    outdated['finding_revision'] = 'stale'
                self.store.connection.execute("UPDATE remediation_plans SET status='Verified', verification_evidence='Previous review', plan_json=? WHERE finding_id=?",
                                              (json.dumps(outdated), self.fid))
                markup = remediation_page(self.store, finding_id=self.fid)
                checklist = markup.split('class="plan-checklist"', 1)[1].split('</section>', 1)[0]
                self.assertIn('Generate replacement plan', checklist)
                self.assertNotIn('Implementation recorded.', checklist)
                self.assertNotIn('Verification evidence recorded.', checklist)
                self.assertEqual(checklist.count('aria-current="step"'), 1)
                self.assertIn('Previous review', markup)

    def test_updated_advisory_action_reopens_plan_even_when_still_confirmed(self):
        finding = self.store.finding(self.fid)
        advisory = {'cve_id': finding['cve_id'], 'source': 'CISA KEV', 'summary': 'Test advisory',
                    'kev': True, 'synthetic': False, 'affected_products': [], 'mitigation': 'First recorded action'}
        self.store.ingest_normalized([advisory], trusted_public=True)
        plan = self.make_plan()
        self.assertEqual(plan['plan']['cisa_required_action'], 'First recorded action')
        self.store.update_remediation_plan(self.fid, 'Under Review')
        self.store.ingest_normalized([advisory | {'mitigation': 'Revised recorded action'}], trusted_public=True)
        current = self.store.get_remediation_plan(self.fid)
        self.assertEqual(self.store.finding(self.fid)['status'], 'CONFIRMED_MATCH')
        self.assertEqual(current['status'], 'Needs More Evidence')
        self.assertEqual(current['history'][-1]['notes'], 'Supporting finding evidence changed; review required')
        self.assertIn('Generate a replacement plan using the current finding evidence', remediation_page(self.store, finding_id=self.fid))

    def test_lifecycle_rejects_unconfirmed_stale_and_legacy_plan_advancement(self):
        original = self.make_plan()
        evidence = self.store.finding(self.fid)['evidence']
        legacy = dict(original['plan'])
        del legacy['finding_revision']
        transitions = [('Under Review', 'Approved'), ('Approved', 'Implemented'), ('Implemented', 'Verified')]
        for reason, finding_status, finding_evidence, snapshot in (
            ('potential', 'POTENTIAL_MATCH', evidence, original['plan']),
            ('needs evidence', 'NEEDS_REVIEW', evidence, original['plan']),
            ('excluded', 'NO_MATCH_TO_THIS_ADVISORY', evidence, original['plan']),
            ('changed evidence', 'CONFIRMED_MATCH', '["Different evidence"]', original['plan']),
            ('legacy', 'CONFIRMED_MATCH', evidence, legacy),
        ):
            for from_status, to_status in transitions:
                with self.subTest(reason=reason, transition=to_status):
                    self.store.connection.execute('UPDATE findings SET status=?, evidence=? WHERE finding_id=?',
                                                  (finding_status, finding_evidence, self.fid))
                    self.store.connection.execute('UPDATE remediation_plans SET status=?, plan_json=? WHERE finding_id=?',
                                                  (from_status, json.dumps(snapshot), self.fid))
                    before = self.store.get_remediation_plan(self.fid)
                    handler, text = self.post('/remediation/update', {'finding_id': self.fid, 'status': to_status,
                                              'reviewer': 'Operator', 'change_notes': 'Simulated change',
                                              'verification_evidence': 'Recorded outcome'})
                    self.assertEqual(handler.response_status, 400)
                    self.assertEqual(before, self.store.get_remediation_plan(self.fid))
                    self.assertNotIn(f'<option value="{to_status}">', text)

    def test_approval_without_stored_mitigation_requires_action_and_current_form(self):
        self.store.connection.execute("UPDATE vulnerabilities SET mitigation=''")
        self.make_plan()
        self.store.update_remediation_plan(self.fid, 'Under Review', change_notes='Initial review')
        before = self.store.get_remediation_plan(self.fid)
        fields = {'finding_id': self.fid, 'status': 'Approved', 'reviewer': 'Operator',
                  'plan_id': before['plan_id'], 'plan_version': len(before['history'])}
        handler, text = self.post('/remediation/update', fields)
        self.assertEqual(handler.response_status, 400)
        self.assertIn('Enter the specific mitigation or compensating control', text)
        self.assertEqual(before, self.store.get_remediation_plan(self.fid))
        self.make_plan()
        current = self.store.update_remediation_plan(self.fid, 'Under Review')
        fields['change_notes'] = 'Use the approved isolation procedure for the simulated device.'
        handler, text = self.post('/remediation/update', fields)
        self.assertEqual(handler.response_status, 400)
        self.assertIn('The fix plan changed while this form was open.', text)
        self.assertEqual(current, self.store.get_remediation_plan(self.fid))
        fields['plan_version'] = len(current['history'])
        handler, _ = self.post('/remediation/update', fields)
        self.assertEqual(handler.response_status, 303)
        saved = self.store.get_remediation_plan(self.fid)
        self.assertEqual((saved['status'], saved['change_notes']), ('Approved', fields['change_notes']))

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

if __name__=='__main__':unittest.main()
