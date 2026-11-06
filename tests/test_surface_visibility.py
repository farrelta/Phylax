"""Observation existence and filtered relationship bounds use stored evidence."""
import io
import ipaddress
import unittest
from unittest.mock import patch

from phylax.core import Store


class SurfaceVisibilityTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.store.import_csv(io.StringIO(
            'asset_id,ip_address,hostname,asset_type,zone,criticality,identity_confidence,verified\n'
            'old,192.0.2.11,Old controller,PLC,OT,high,high,true\n'
            'target,192.0.2.10,Target controller,PLC,OT,high,high,true\n'
            'recent,192.0.2.20,Recent server,server,IT,medium,high,true\n'
            'silent,192.0.2.12,Silent inventory,PLC,OT,high,high,true\n'))
        self.add_event('old', '192.0.2.11', '192.0.2.10', '2026-10-01T00:00:00Z', source_port=12345)
        self.add_event('old-peer', '203.0.113.99', '192.0.2.10', '2026-10-01T00:00:00Z')
        for index in range(1001):
            peer = str(ipaddress.IPv4Address('10.30.0.1') + index)
            self.add_event('recent-' + str(index), peer, '192.0.2.20', '2026-11-06T06:00:00Z')
        self.store.connection.commit()

    def tearDown(self):
        self.store.close()

    def add_event(self, uid, source, destination, timestamp, source_port=None):
        self.store.connection.execute('INSERT INTO network_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', (
            uid, 'ref-' + uid, timestamp, source, source_port, destination, 502,
            'tcp', '3', 'modbus', 'synthetic-visibility.jsonl', '{}'))

    def test_display_cap_does_not_change_endpoint_existence(self):
        view = self.store.attack_surface()
        nodes = {node['ip_address']: node for node in view['nodes']}
        self.assertEqual(len(view['edges']), 1000)
        self.assertEqual(view['relationship_count'], 1003)
        self.assertTrue(view['relationships_truncated'])
        self.assertEqual(view['event_count'], 1003)
        self.assertNotIn('ref-old', {edge['sample_event_ref'] for edge in view['edges']})
        self.assertTrue(nodes['192.0.2.11']['observed'])
        self.assertTrue(nodes['192.0.2.11']['ever_observed'])
        self.assertEqual(nodes['192.0.2.11']['visibility'], 'Observed in imported logs')
        self.assertEqual(nodes['192.0.2.11']['first_observed'], '2026-10-01T00:00:00Z')
        self.assertEqual(nodes['192.0.2.11']['last_observed'], '2026-10-01T00:00:00Z')
        # All known peers remain available to the caller's endpoint search.
        self.assertTrue(nodes['203.0.113.99']['observed'])
        self.assertEqual(nodes['203.0.113.99']['identity'], 'Unknown peer')
        self.assertEqual(nodes['203.0.113.99']['asset_id'], '')
        self.assertEqual(nodes['203.0.113.99']['version'], 'unknown')
        self.assertFalse(nodes['203.0.113.99']['verified'])

    def test_asset_and_focus_filters_precede_relationship_cap(self):
        for filters in ({'zone': 'OT'}, {'criticality': 'high'},
                        {'subnet': '192.0.2.0/28'}, {'node': '192.0.2.11'}):
            with self.subTest(filters=filters):
                view = self.store.attack_surface(filters)
                self.assertEqual(view['relationship_count'], 1)
                self.assertFalse(view['relationships_truncated'])
                self.assertEqual(view['edges'][0]['sample_event_ref'], 'ref-old')
                self.assertEqual(view['edges'][0]['source_port'], 12345)
                self.assertEqual(view['edges'][0]['source_file'], 'synthetic-visibility.jsonl')
                # Event count intentionally describes the time scope, not asset filters.
                self.assertEqual(view['event_count'], 1003)

    def test_management_filter_precedes_relationship_cap(self):
        def status(_store, ip):
            return {'status': 'approved' if ip in ('192.0.2.10', '192.0.2.11') else 'unmonitored'}
        with patch('phylax.surface.management_status', side_effect=status):
            view = self.store.attack_surface({'management_status': 'approved'})
        self.assertEqual(view['relationship_count'], 1)
        self.assertEqual(view['edges'][0]['sample_event_ref'], 'ref-old')

    def test_time_window_distinguishes_previous_observations_from_never_observed(self):
        view = self.store.attack_surface({'since': '2026-11-01T00:00:00Z'})
        nodes = {node['ip_address']: node for node in view['nodes']}
        old = nodes['192.0.2.11']
        self.assertFalse(old['observed'])
        self.assertTrue(old['ever_observed'])
        self.assertEqual(old['first_observed'], '')
        self.assertEqual(old['last_observed'], '')
        self.assertEqual(old['visibility'], 'Previously observed; no imported traffic in the selected period')
        self.assertFalse(nodes['192.0.2.12']['observed'])
        self.assertFalse(nodes['192.0.2.12']['ever_observed'])
        self.assertEqual(nodes['192.0.2.12']['visibility'], 'Inventory only; no imported traffic observed')
        self.assertFalse(nodes['203.0.113.99']['observed'])
        self.assertTrue(nodes['203.0.113.99']['ever_observed'])
        self.assertTrue(nodes['192.0.2.20']['observed'])
        self.assertEqual(view['event_count'], 1001)
        self.assertEqual(view['relationship_count'], 1001)
        self.assertTrue(view['relationships_truncated'])

    def test_empty_time_window_retains_known_peers_without_inventing_inventory(self):
        view = self.store.attack_surface({'since': '2027-01-01T00:00:00Z'})
        nodes = {node['ip_address']: node for node in view['nodes']}
        self.assertIn('203.0.113.99', nodes)
        self.assertFalse(nodes['203.0.113.99']['observed'])
        self.assertEqual(nodes['203.0.113.99']['asset_id'], '')
        self.assertEqual(view['event_count'], 0)
        self.assertEqual(view['relationship_count'], 0)
        self.assertEqual(view['edges'], [])
        self.assertFalse(view['relationships_truncated'])

    def test_reads_preserve_database_and_source_port_aggregation(self):
        self.add_event('old-again', '192.0.2.11', '192.0.2.10', '2026-10-02T00:00:00Z', source_port=12346)
        self.store.connection.commit()
        before = self.store.connection.total_changes
        view = self.store.attack_surface({'node': '192.0.2.11'})
        edge = view['edges'][0]
        self.assertEqual(edge['event_count'], 2)
        self.assertEqual(edge['source_port_count'], 2)
        self.assertEqual(edge['source_port'], 'multiple')
        self.assertEqual(edge['protocol'], 'tcp')
        self.assertEqual(edge['operation'], '3')
        self.assertEqual(edge['first_seen'], '2026-10-01T00:00:00Z')
        self.assertEqual(edge['last_seen'], '2026-10-02T00:00:00Z')
        self.assertEqual(edge['sample_event_ref'], 'ref-old')
        self.assertEqual(self.store.connection.total_changes, before)


if __name__ == '__main__':
    unittest.main()
