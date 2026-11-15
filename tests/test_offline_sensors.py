from html import unescape
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

from phylax.core import Store
from phylax.fingerprints import latest_fingerprint, save_mapping
from phylax.monitoring import ingest_file, reevaluate_events, validate_policy
from phylax.observations import review_component
from phylax.pcap import analyze_pcap
from phylax.release_web import page as operator_page, post
from phylax.sensor_imports import import_wazuh
from phylax.triage import alert_url, zone_alert
from phylax.watcher import LogWatcher
from phylax.web import attack_surface_page, page
from scripts.prepare_sensor_demo import PLC, IT, DMZ, UNKNOWN, POLICY, EPOCH, identity_rows, prepare, rehearse, stage_presentation, write_jsonl
import test_review_regressions as http_regressions


class OfflineSensorTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name) / 'demo'
        self.database = prepare(self.directory)
        self.store = Store(self.database)
        self.addCleanup(self.store.close)

    def test_rehearsal_from_empty_inventory(self):
        result = rehearse(self.directory, self.database)
        self.assertEqual(result['before_review'][PLC], 'POTENTIAL_MATCH')
        self.assertEqual(result['after_review'][PLC], 'CONFIRMED_MATCH')
        self.assertEqual(result['zone_alerts'], 1)
        self.assertEqual(result['sources'], ['modbus-identity', 'wazuh_inventory'])
        self.assertFalse((self.directory/'eve.json').exists())

    def test_presentation_populates_navigation_and_retains_live_review(self):
        self.assertFalse(self.store.assets())
        self.assertEqual(stage_presentation(self.directory, self.database)[PLC], 'POTENTIAL_MATCH')
        assets = {asset['ip_address']: asset for asset in self.store.assets()}
        self.assertEqual(len(assets), 5)
        self.assertEqual(assets[UNKNOWN]['product'], '')

        http = http_regressions.HTTPAndGuidanceRegressionTests()
        http.setUp()
        http.store.close()
        http.store = self.store

        def get(path):
            handler = http.handler(path)
            handler.do_GET()
            self.assertEqual(handler.response_status, 200, path)
            return handler.wfile.getvalue().decode()

        for route, expected in {
            '/': 'Possibly affected',
            '/assets': 'Simulated DMZ Host',
            '/approvals': 'Simulated industrial network',
            '/software': 'Simulated Workstation Linux',
            '/changes': PLC,
            '/processes': 'Simulated facility cooling',
            '/network': 'lab-flow-2',
            '/attack-surface': PLC,
            '/intelligence': 'CVE-2021-22800',
            '/intelligence/ics': 'Rockwell Automation FactoryTalk Activation',
            '/triage': 'Zone Policy Violation',
            '/remediation': 'Draft for the simulated support-site investigation',
            '/reports': 'Markdown report',
            '/settings': '2 finalized Zeek logs imported',
            '/policy': '198.51.100.0/24',
            '/glossary': 'Glossary',
        }.items():
            with self.subTest(route=route):
                self.assertIn(expected, get(route))
        self.assertIn('Loaded saved Schneider Electric and CISA advisories offline.', get('/settings'))
        board = get('/triage')
        self.assertIn('Fix plan recorded', board)
        self.assertIn('data-kind="exposure" data-from="3"', board)
        self.assertIn('>Plan drafted</span>', board)
        self.assertNotIn('Plan in progress', board)
        alert = zone_alert(self.store)
        self.assertEqual((alert['source_ip'], alert['destination_ip']), (IT, PLC))
        self.assertEqual(len(self.store.dashboard()['network_alerts']), 1)
        self.assertIn(DMZ, get('/network'))
        case = get('/triage?' + urlencode({'alert': alert['alert_id']}))
        evidence_link = unescape(case.split('href="/evidence?', 1)[1].split('"', 1)[0])
        self.assertIn('lab-flow-2', get('/evidence?' + evidence_link))

        report = json.loads(get('/report.json'))
        software = report['asset_intelligence']['software_components']
        self.assertEqual({row['raw_name'] for row in software if row['asset_id'] == assets[IT]['asset_id']},
                         {'Wazuh OS: Simulated Workstation Linux', 'Wazuh package: Example Lab Package'})
        self.assertIn('CVE-2021-22800', get('/report.csv'))
        self.assertIn('CVE-2021-22800', get('/report.md'))

        finding_id = next(row['finding_id'] for row in report['findings'] if row['ip_address'] == PLC)
        finding_path = '/?' + urlencode({'finding_id': finding_id})
        self.assertIn('Possibly affected', get(finding_path))
        component_id = self.store.connection.execute(
            'SELECT component_id FROM modbus_identity_components WHERE asset_id=?',
            (assets[PLC]['asset_id'],),
        ).fetchone()[0]
        review = http.handler('/software/review', urlencode({
            'csrf_token': http.Handler.csrf_token, 'component_id': component_id,
            'verified': 'true', 'active': 'true', 'actor': 'Demo operator',
            'note': 'Verified against the simulated controller identity',
        }))
        review.do_POST()
        self.assertEqual(review.response_status, 303, review.wfile.getvalue().decode())
        self.assertIn('Confirmed affected', get(finding_path))

        fresh_directory = self.directory.parent / 'new-presentation'
        fresh_database = prepare(fresh_directory)
        self.assertEqual(stage_presentation(fresh_directory, fresh_database)[PLC], 'POTENTIAL_MATCH')

    def test_fingerprint_dedup_change_conflict_and_separate_transactions(self):
        log = self.directory/'modbus_read_device_identification.log'
        first = identity_rows(PLC, '5.1.0.6')
        write_jsonl(log, first)
        self.assertEqual(ingest_file(self.store, log)['events_inserted'], 1)
        self.assertEqual(ingest_file(self.store, log)['duplicates_skipped'], 1)
        db = self.store.connection
        component = db.execute('SELECT component_id FROM modbus_identity_components').fetchone()[0]
        review_component(self.store, component, verified=True, actor='Operator', note='Checked lab identity')
        self.assertEqual(db.execute('SELECT status FROM findings').fetchone()[0], 'CONFIRMED_MATCH')

        write_jsonl(log, identity_rows(PLC, '5.1.0.5', uid='new', observed=EPOCH+1))
        ingest_file(self.store, log)
        self.assertEqual(db.execute('SELECT status FROM findings').fetchone()[0], 'POTENTIAL_MATCH')
        with self.assertRaisesRegex(ValueError, 'no longer current'):
            review_component(self.store, component, verified=True, actor='Operator', note='Old review')

        partial = identity_rows(PLC, '5.1.0.4', uid='partial', observed=EPOCH+2)
        write_jsonl(log, [*partial[:2], partial[2] | {'tid': 2}])
        ingest_file(self.store, log)
        self.assertFalse(latest_fingerprint(self.store, PLC)['revision'])
        self.assertIsNone(db.execute('SELECT status FROM findings').fetchone())
        write_jsonl(log, identity_rows(PLC, '5.1.0.6', uid='another-unit', unit=2, observed=EPOCH+3))
        ingest_file(self.store, log)
        self.assertTrue(latest_fingerprint(self.store, PLC)['conflict'])
        self.assertIsNone(db.execute('SELECT status FROM findings').fetchone())

    def test_mapping_requires_explicit_revision_meaning(self):
        log = self.directory/'modbus_read_device_identification.log'
        save_mapping(self.store, 'Schneider Electric', 'Modicon M218', 'schneider electric',
                     'modicon m218', 'PLC', False, 'Operator', 'Role mapping only')
        ingest_file(self.store, log)
        fingerprint = latest_fingerprint(self.store, PLC)
        self.assertEqual(fingerprint['revision'], '5.1.0.6')
        self.assertEqual(fingerprint['mapping']['role'], 'PLC')
        self.assertFalse(fingerprint['mapping']['firmware'])
        self.assertEqual(self.store.connection.execute('SELECT COUNT(*) FROM findings').fetchone()[0], 0)

    def test_zone_rule_is_directional_and_reevaluates(self):
        log = self.directory/'conn.log'
        result = ingest_file(self.store, log)
        self.assertEqual(result['alerts_created'], 1)
        self.assertIn('zone_policy: TCP establishment is not recorded', result['diagnostics'])
        alert = self.store.dashboard()['network_alerts'][0]
        policy = json.loads(alert['policy_evidence'])
        self.assertEqual((policy['source_zone'], policy['destination_zone']), ('IT', 'OT'))
        self.assertTrue(policy['policy_id'])
        self.assertEqual(reevaluate_events(self.store, POLICY)['alerts_created'], 0)
        reevaluate_events(self.store, POLICY | {'denied_zone_pairs': [['OT', 'IT']]})
        self.assertEqual(self.store.connection.execute('SELECT state FROM network_alert_lifecycle').fetchone()[0],
                         'resolved')
        with self.assertRaisesRegex(ValueError, 'must not overlap'):
            validate_policy(POLICY | {'zone_subnets': {'IT': ['192.0.2.0/24'], 'OT': ['192.0.2.10/32']}})

    def test_alert_board_tracks_review_and_resolution(self):
        ingest_file(self.store, self.directory/'conn.log')
        alert_id = zone_alert(self.store)['alert_id']

        default_board = operator_page(self.store, '/triage', {})
        self.assertIn('class="alert-board"', default_board)
        self.assertIn('name="q"', default_board)
        self.assertIn('class="board-ack"><form method="post" action="/triage/ack"', default_board)
        filtered_list = {'category': ['endpoint'], 'priority': ['critical'], 'acknowledged': ['yes']}
        explicit_board = operator_page(self.store, '/triage', {**filtered_list, 'view': ['board']})
        card = f'/triage?alert={alert_id}&amp;view=board&amp;page=1#alert-{alert_id}'
        self.assertIn(card, explicit_board)
        self.assertNotIn(f'data-alert="{alert_id}"', operator_page(self.store, '/triage', {'q': ['does not match']}))
        list_page = operator_page(self.store, '/triage', {'view': ['list']})
        for key in filtered_list:
            self.assertNotIn(f'<select name="{key}"', default_board)
            self.assertNotIn(f'<select name="{key}"', explicit_board)
            self.assertIn(f'name="{key}"', list_page)
        self.assertNotIn('class="alert-board"', operator_page(self.store, '/triage', filtered_list))

        def board_column(column):
            board = operator_page(self.store, '/triage', {})
            return board.split(f'id="alert-column-{column}"', 1)[1].split('</section>', 1)[0]

        self.assertIn(card, board_column(0))
        post(self.store, '/triage/ack', {'category': ['network'], 'alert_id': [alert_id]})
        self.assertIn(card, board_column(1))
        reevaluate_events(self.store, POLICY | {'denied_zone_pairs': []})
        self.assertIn(card, board_column(2))
        self.assertIn('resolved after reevaluation',
                      operator_page(self.store, '/triage', {'alert': [alert_id]}))

    def test_zone_alert_links_to_exact_topology_case_and_original_event(self):
        log = self.directory/'conn.log'
        ingest_file(self.store, log)
        first = zone_alert(self.store)
        first_id = first['alert_id']
        row = json.loads(log.read_text().splitlines()[2])
        write_jsonl(log, [row | {'ts': EPOCH+10, 'uid': 'same-pair-later'}])
        ingest_file(self.store, log)
        current = zone_alert(self.store)
        alert_id = current['alert_id']
        self.assertNotEqual(alert_id, first_id)
        path = f'/attack-surface?alert={alert_id}#topology'
        self.assertIn(f'href="{path}">Show on topology', page(self.store))

        topology = attack_surface_page(self.store, parse_qs(urlsplit(path).query))
        self.assertIn(f'class="alert-topology-edge" href="{alert_url(alert_id)}"', topology)
        self.assertLess(topology.index(IT), topology.index(PLC))
        self.assertIn('IT zone', topology)
        self.assertIn('OT zone', topology)

        case = operator_page(self.store, '/triage', {'alert': [alert_id], 'page': ['12']})
        self.assertIn(f'id="alert-{alert_id}" open', case)
        self.assertNotIn(f'id="alert-{first_id}"', case)
        self.assertLess(case.index('>Original event</a>'), case.index('Operational context</h3>'))
        link = unescape(case.split('href="/evidence?', 1)[1].split('"', 1)[0])
        evidence_query = parse_qs(link)
        self.assertTrue(evidence_query['event_ref'][0].startswith('same-pair-later:'))
        self.assertEqual(evidence_query['return_to'], [alert_url(alert_id)])
        self.assertIn('same-pair-later', operator_page(self.store, '/evidence', evidence_query))

        redirect = post(self.store, '/triage/ack', {'category': ['network'], 'alert_id': [alert_id], 'alert': [alert_id]})
        self.assertEqual(parse_qs(urlsplit(redirect).query)['alert'], [alert_id])
        self.assertEqual(zone_alert(self.store)['alert_id'], first_id)
        reevaluate_events(self.store, POLICY | {'denied_zone_pairs': []})
        self.assertNotIn('Show on topology', page(self.store))
        self.assertIn('resolved after reevaluation', operator_page(self.store, '/triage', {'alert': [alert_id]}))

    def test_historical_suricata_evidence_remains_available(self):
        source = 'Suricata EVE: archived.json'
        event_ref = 'historical-flow'
        timestamp = '2026-11-12T09:00:00.000000Z'
        self.store.connection.execute(
            'INSERT INTO network_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
            (event_ref, event_ref, timestamp, IT, 40002, PLC, 502, 'tcp', '',
             'suricata_flow', source, '{"event_type":"flow"}'),
        )
        self.store.observe_ip(IT, timestamp, source='suricata_passive')
        self.store.connection.commit()
        reopened = Store(self.database)
        try:
            report = json.loads(reopened.report('json'))
            self.assertIn({
                'kind': 'suricata_flow', 'ip': IT, 'observed_at': timestamp,
                'source_file': source, 'event_ref': event_ref,
            }, report['asset_intelligence']['sensor_evidence'])
            self.assertEqual(reopened.assets()[0]['identification_source'], 'suricata_passive')
            self.assertIn(source, operator_page(reopened, '/evidence', {'event_ref': [event_ref]}))
        finally:
            reopened.close()

    def test_wazuh_inventory_deduplication_and_binding(self):
        self.store.import_csv(io.StringIO(f'ip_address,asset_id,zone\n{IT},it,IT\n{DMZ},other,IT\n'))
        wazuh = self.directory/'wazuh-packages.json'
        args = {'manager': 'lab', 'agent_id': '001', 'asset_id': 'it', 'kind': 'packages'}
        self.assertEqual(import_wazuh(self.store, wazuh, **args)['events_inserted'], 1)
        self.assertEqual(import_wazuh(self.store, wazuh, **args)['duplicates_skipped'], 1)
        with self.assertRaisesRegex(ValueError, 'different asset'):
            import_wazuh(self.store, wazuh, **(args | {'asset_id': 'other'}))
        with self.assertRaisesRegex(ValueError, 'agent ID does not match'):
            import_wazuh(self.store, wazuh, **(args | {'agent_id': '002'}))
        os_export = json.loads(wazuh.read_text())
        os_export['data']['affected_items'][0]['os'] = {'name': 'Example Linux', 'version': '1'}
        wazuh.write_text(json.dumps(os_export))
        self.assertEqual(import_wazuh(self.store, wazuh, **(args | {'kind': 'os'}))['events_inserted'], 1)
        self.assertEqual(self.store.connection.execute('SELECT COUNT(*) FROM software_components').fetchone()[0], 2)
        self.assertEqual(self.store.connection.execute('SELECT COUNT(*) FROM wazuh_bindings').fetchone()[0], 1)

    def test_watcher_and_pcap_dispatch_identity_log(self):
        exported = self.directory/'modbus_read_device_identification.log'
        watch_directory = self.directory/'watch'
        watch_directory.mkdir()
        (watch_directory/exported.name).write_bytes(exported.read_bytes())
        watcher = LogWatcher(self.store, watch_directory)
        watcher.poll()
        watcher.poll()
        self.assertEqual(latest_fingerprint(self.store, PLC)['revision'], '5.1.0.6')

        def analyze(command, *, cwd, **kwargs):
            self.assertIn('packages/icsnpp-modbus', command)
            rows = identity_rows(PLC, '5.1.0.5', observed=EPOCH+3)
            write_jsonl(Path(cwd)/exported.name, rows)
            return SimpleNamespace(returncode=0)

        with patch('phylax.pcap.shutil.which', return_value='/usr/bin/zeek'):
            result = analyze_pcap(self.store, self.directory/'simulated-identification.pcap', icsnpp=True, runner=analyze)
        self.assertTrue(result['modbus_identity'])
        self.assertEqual(latest_fingerprint(self.store, PLC)['revision'], '5.1.0.5')

    def test_dashboard_multipart_recognizes_identity_filename_and_sensor_uploads(self):
        http = http_regressions.HTTPAndGuidanceRegressionTests()
        http.setUp()
        http.store.close()
        http.store = self.store

        def upload(route, path, *, status=303, **fields):
            boundary = 'PhylaxDemoBoundary'
            parts = []
            for key, value in (fields | {'csrf_token': http.Handler.csrf_token}).items():
                parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n')
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
                         f'Content-Type: application/octet-stream\r\n\r\n{path.read_text()}\r\n--{boundary}--\r\n')
            handler = http.handler(route, ''.join(parts))
            handler.headers.replace_header('Content-Type', f'multipart/form-data; boundary="{boundary}"')
            handler.do_POST()
            self.assertEqual(handler.response_status, status, handler.wfile.getvalue().decode())

        upload('/network/import', self.directory/'modbus_read_device_identification.log')
        upload('/network/suricata', self.directory/'conn.log', status=404)
        for language in ('en', 'id'):
            handler = http.handler('/network')
            handler.headers['Accept-Language'] = language
            handler.do_GET()
            monitoring = handler.wfile.getvalue().decode()
            self.assertIn('action="/network/import"', monitoring)
            self.assertNotIn('action="/network/suricata"', monitoring)
        self.store.import_csv(io.StringIO(f'ip_address,asset_id,zone\n{IT},it,IT\n'))
        upload('/software/wazuh', self.directory/'wazuh-packages.json', manager='lab', agent_id='001',
               asset_id='it', kind='packages')
        handler = http.handler('/assets')
        handler.headers['Accept-Language'] = 'id'
        handler.do_GET()
        self.assertIn('Modicon M218', handler.wfile.getvalue().decode())
        self.assertIn('Dugaan PLC', handler.wfile.getvalue().decode())
