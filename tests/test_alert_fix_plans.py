import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import urlencode

from phylax.alert_fix_plans import alert_record, plan_url, read_plan
from phylax.asset_intelligence import add_subnet, endpoint_decision, observe
from phylax.core import Store
from phylax.monitoring import ingest_file, reevaluate_events
from phylax.remediation import compose_plan
from phylax.triage import alert_url, triage, zone_alert
from phylax.ui import evidence_url
import test_review_regressions as http_regressions


class AlertFixPlansTests(unittest.TestCase):
    source, controller = '198.51.100.10', '192.0.2.10'
    policy = {'zone_subnets': {'IT': ['198.51.100.0/24'], 'OT': ['192.0.2.0/24']},
              'denied_zone_pairs': [['IT', 'OT']]}

    def setUp(self):
        self.http = http_regressions.HTTPAndGuidanceRegressionTests()
        self.http.setUp()
        self.addCleanup(self.http.tearDown)
        self.store = self.http.store
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.log = Path(directory.name) / 'conn.log'
        reevaluate_events(self.store, self.policy)

    def get(self, path, language='en'):
        handler = self.http.handler(path)
        handler.headers['Accept-Language'] = language
        handler.do_GET()
        self.assertEqual(handler.response_status, 200, path)
        return handler.wfile.getvalue().decode()

    def submit(self, action, fields, expected=303):
        handler = self.http.handler('/remediation/' + action, urlencode({
            'csrf_token': self.http.Handler.csrf_token, **fields,
        }))
        handler.do_POST()
        body = handler.wfile.getvalue().decode()
        self.assertEqual(handler.response_status, expected, body.split('<main',1)[-1][:300])
        return body

    def connection(self, uid, ts=1794474000):
        self.log.write_text(json.dumps({'uid': uid, 'ts': ts, 'id.orig_h': self.source, 'id.orig_p': 40100,
                                       'id.resp_h': self.controller, 'id.resp_p': 502, 'proto': 'tcp',
                                       'conn_state': 'SF'}) + '\n', encoding='utf-8')
        return ingest_file(self.store, self.log, kind='conn')

    def device_observation(self, when, ref, mac=''):
        observe(self.store, kind='connection', ip=self.controller, when=when,
                source_file='test.log', event_ref=ref, raw={}, mac=mac)
        self.store.connection.commit()

    def fields(self, category, alert_id, existing=True):
        alert = alert_record(self.store, category, alert_id)
        fields = {'category': category, 'alert_id': alert_id, 'alert_revision': alert['revision']}
        if existing:
            plan = read_plan(self.store, category, alert_id)
            fields.update(plan_id=plan['plan_id'], plan_version=plan['version'])
        return fields

    def create(self, category, alert_id):
        fields = self.fields(category, alert_id, existing=False)
        case = self.get(alert_url(alert_id))
        self.assertIn('Create fix plan', case)
        self.assertIn(fields['alert_revision'], case)
        self.submit('create', fields)

    def verify(self, category, alert_id):
        for status, extra in (
            ('Under Review', {'change_notes': 'Reviewed recorded alert evidence'}),
            ('Approved', {'reviewer': 'Test owner', 'change_notes': 'Documented simulated corrective action'}),
            ('Implemented', {}),
            ('Verified', {'verification_evidence': 'Simulated outcome checked'}),
        ):
            self.submit('update', self.fields(category, alert_id) | {'status': status, **extra})

    def test_close_verified_network_alert_preserves_event_and_distinct_alerts(self):
        self.assertEqual(self.connection('original')['alerts_created'], 1)
        alert = zone_alert(self.store)
        alert_id = alert['alert_id']
        handler = self.http.handler('/triage/ack', urlencode({'csrf_token': self.http.Handler.csrf_token,
                                                            'category': 'network', 'alert_id': alert_id}))
        handler.do_POST()
        self.assertEqual(handler.response_status, 303)
        self.create('network', alert_id)
        fields = self.fields('network', alert_id)
        self.submit('close', fields | {'actor': 'Operator', 'note': 'Too early'}, expected=400)
        self.submit('create', self.fields('network', alert_id, existing=False), expected=400)
        self.submit('update', fields | {'category': 'endpoint', 'status': 'Under Review'}, expected=400)
        cross_action = self.http.handler('/remediation/close', urlencode(fields | {'actor': 'Operator', 'note': 'No form token'}))
        cross_action.do_POST()
        self.assertEqual(cross_action.response_status, 403)
        self.verify('network', alert_id)
        url = plan_url('network', alert_id)
        self.assertIn('Close with verified evidence', self.get(url))
        self.assertIn('Tutup dengan bukti terverifikasi', self.get(url, 'id'))
        self.submit('close', self.fields('network', alert_id) | {'actor': '', 'note': 'Missing operator'}, expected=400)
        closure = self.fields('network', alert_id) | {'actor': 'Test operator', 'note': 'Verified corrective action'}
        self.submit('close', closure)
        saved = read_plan(self.store, 'network', alert_id)
        self.assertEqual(saved['history'][1]['snapshot']['change_notes'], 'Reviewed recorded alert evidence')
        self.submit('close', closure, expected=400)
        self.assertEqual(read_plan(self.store, 'network', alert_id), saved)
        case = self.get(alert_url(alert_id))
        self.assertIn('Closed by operator', case)
        self.assertIn('Verified corrective action', case)
        self.assertIn('Original event', case)
        board = self.get('/triage')
        self.assertRegex(board, f'data-alert="{alert_id}" data-kind="network" data-from="2"')
        self.assertIn('original', self.get(evidence_url(saved['alert']['event_ref'])))
        self.assertIsNone(zone_alert(self.store))
        self.assertEqual(self.store.dashboard()['network_alerts_count'], 0)
        self.assertEqual(self.connection('original')['duplicates_skipped'], 1)
        reevaluate_events(self.store, self.policy)
        self.assertEqual(zone_alert(self.store, alert_id)['state'], 'resolved')
        self.connection('second', 1794474001)
        self.assertNotEqual(zone_alert(self.store)['alert_id'], alert_id)
        payload = json.loads(self.store.report('json'))
        self.assertEqual(payload['alert_fix_plans'][0]['closed_by'], 'Test operator')
        original = next(row for row in payload['network_alerts'] if row['alert_id'] == alert_id)
        self.assertEqual((original['lifecycle_state'], original['condition_state']), ('resolved', 'active'))
        self.assertIn('alert_fix_plan', self.store.report('csv'))
        self.assertIn('Verified corrective action', self.store.report('markdown'))

    def test_device_approval_resolves_alert_and_existing_plan_can_finish(self):
        subnet = add_subnet(self.store, 'Simulated subnet', '192.0.2.0/24')
        self.device_observation('2026-11-12T09:00:00Z', 'first-device')
        rows, _ = triage(self.store, filters={'category': 'endpoint'})
        alert_id = rows[0]['alert_id']
        self.create('endpoint', alert_id)
        opened = self.fields('endpoint', alert_id)
        self.device_observation('2026-11-12T09:00:01Z', 'routine-next-observation')
        self.assertEqual(self.fields('endpoint', alert_id), opened)
        endpoint_decision(self.store, subnet, ip=self.controller, actor='Test owner', note='Approved lab device')
        self.assertEqual(alert_record(self.store, 'endpoint', alert_id)['state'], 'resolved')
        self.verify('endpoint', alert_id)
        plan = self.get(plan_url('endpoint', alert_id))
        self.assertIn('Verification evidence recorded.', plan)
        self.assertNotIn('Close with verified evidence</button>', plan)
        self.assertIn('This device management alert was resolved.', self.get(alert_url(alert_id)))

    def test_new_device_observation_reopens_manual_closure_and_retains_history(self):
        add_subnet(self.store, 'Simulated subnet', '192.0.2.0/24')
        when = '2026-11-12T09:00:01Z'
        self.device_observation(when, 'first-device')
        rows, _ = triage(self.store, filters={'category': 'endpoint'})
        alert_id = rows[0]['alert_id']
        self.create('endpoint', alert_id)
        self.verify('endpoint', alert_id)
        stale_closure = self.fields('endpoint', alert_id) | {'actor': 'Operator', 'note': 'Previously checked'}
        self.device_observation('2026-11-12T09:00:01.500000Z', 'reappeared-before-close')
        rejected = self.submit('close', stale_closure, expected=400)
        self.assertIn('The device was observed again after verification.', rejected)
        self.verify('endpoint', alert_id)
        fields = self.fields('endpoint', alert_id)
        self.submit('close', fields | {'actor': 'Operator', 'note': 'Simulated device removed'})
        closed = self.get(alert_url(alert_id))
        self.assertIn('Recorded device evidence', closed)
        self.assertIn('event_ref=reappeared-before-close', closed)
        self.device_observation(when, 'first-device')
        self.device_observation('2026-11-12T09:00:00Z', 'older-device-observation')
        self.assertEqual(alert_record(self.store, 'endpoint', alert_id)['state'], 'resolved')
        self.device_observation('2026-11-12T09:00:02Z', 'device-seen-again')
        reopened = read_plan(self.store, 'endpoint', alert_id)
        self.assertEqual((reopened['alert']['state'], reopened['status']), ('active', 'Needs More Evidence'))
        self.assertEqual(reopened['verification_evidence'], '')
        self.assertEqual(reopened['history'][-2]['snapshot']['closure_reason'], 'Simulated device removed')
        self.assertEqual(reopened['history'][-2]['snapshot']['verification_evidence'], 'Simulated outcome checked')
        self.assertIn('Simulated device removed', self.store.report('markdown'))
        self.assertRegex(self.get('/triage'), f'data-alert="{alert_id}" data-kind="endpoint" data-from="0"')
        self.submit('update', fields | {'status': 'Under Review'}, expected=400)
        self.submit('create', self.fields('endpoint', alert_id))
        self.assertEqual(read_plan(self.store, 'endpoint', alert_id)['status'], 'Recommended')

    def test_material_policy_change_requires_replacement_and_mixed_list_keeps_vulnerability_plan(self):
        self.connection('different-rule-context')
        alert_id = zone_alert(self.store)['alert_id']
        self.create('network', alert_id)
        fields = self.fields('network', alert_id)
        new_policy = {'zone_subnets': {'DMZ': ['198.51.100.0/24'], 'OT': ['192.0.2.0/24']},
                      'denied_zone_pairs': [['DMZ', 'OT']]}
        reevaluate_events(self.store, new_policy)
        self.submit('update', fields | {'status': 'Under Review'}, expected=400)
        self.assertIn('Generate replacement plan', self.get(plan_url('network', alert_id)))
        self.submit('create', self.fields('network', alert_id))
        finding = self.store.finding(self.http.fid)
        plan = compose_plan(finding, {})
        self.store.create_remediation_plan(self.http.fid, 'template-fallback', '', plan, plan['source_references'])
        listing = self.get('/remediation')
        self.assertIn(alert_id, listing)
        self.assertIn(self.http.fid, listing)

    def test_additive_migration_preserves_previous_database_records(self):
        db_path = self.log.with_name('existing.db')
        store = Store(db_path)
        store.connection.execute("INSERT INTO schema_meta VALUES('dataset_label','Previous demo')")
        for name in ('network_case_states', 'endpoint_case_states'):
            store.connection.execute(f'DROP VIEW {name}')
        for name in ('alert_fix_plan_events', 'alert_fix_plans'):
            store.connection.execute(f'DROP TABLE {name}')
        store.connection.execute("DELETE FROM schema_meta WHERE key='alert_fix_plans_v1'")
        store.connection.commit()
        store.close()
        backup = db_path.with_name(db_path.name + '.pre-alert-fix-plans.sqlite')
        backup.unlink()
        upgraded = Store(db_path)
        try:
            self.assertTrue(backup.exists())
            self.assertEqual(upgraded.connection.execute("SELECT value FROM schema_meta WHERE key='dataset_label'").fetchone()[0],
                             'Previous demo')
            self.assertEqual(upgraded.connection.execute('SELECT count(*) FROM alert_fix_plans').fetchone()[0], 0)
        finally:
            upgraded.close()
