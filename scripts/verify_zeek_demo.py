"""Rehearse offline Zeek capture analysis in a new, isolated directory."""
from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phylax.core import Store, utc_now
from phylax.pcap import analyze_pcap
from scripts.generate_passive_demo import generate


def verify(directory: Path, image: str) -> dict:
    directory.mkdir(parents=True, exist_ok=False)
    captures = directory / 'captures'
    generate(captures)
    policy = json.loads((captures / 'policy.json').read_text())
    checks = []
    expected_rules = {'unexpected_communication', 'unauthorized_modbus_writer',
                      'write_outside_maintenance_window'}
    store = Store(directory / 'verification.db')
    try:
        for capture, expected_count in (('benign-read', 0), ('unauthorized-write', 3)):
            started = time.perf_counter()
            result = analyze_pcap(store, captures / f'synthetic-{capture}.pcap',
                                  policy=policy, docker_image=image)
            elapsed = time.perf_counter() - started
            alerts = store.dashboard()['network_alerts']
            if len(alerts) != expected_count:
                raise RuntimeError(f'{capture}: expected {expected_count} alerts, got {len(alerts)}')
            checks.append({'capture': capture, 'elapsed_seconds': round(elapsed, 6),
                           'active_alerts_after_import': len(alerts), 'result': result})
        alerts = store.dashboard()['network_alerts']
        if {a['rule_id'] for a in alerts} != expected_rules:
            raise RuntimeError('Unexpected detection rule coverage')
        for alert in alerts:
            event = store.connection.execute(
                'SELECT raw_json,source_file FROM network_events WHERE event_id=?',
                (alert['event_id'],)).fetchone()
            if 'pcap-sha256:' not in event['source_file']:
                raise RuntimeError('Alert is missing capture evidence')
            if json.loads(event['raw_json']).get('pdu_type') == 'RESP':
                raise RuntimeError('Response PDU created a duplicate request alert')
        event_count = store.connection.execute('SELECT COUNT(*) FROM network_events').fetchone()[0]
        replay = analyze_pcap(store, captures / 'synthetic-unauthorized-write.pcap',
                              policy=policy, docker_image=image)
        if not replay.get('already_analyzed'):
            raise RuntimeError('Repeated capture did not use the stored result')
        if store.connection.execute('SELECT COUNT(*) FROM network_events').fetchone()[0] != event_count:
            raise RuntimeError('Repeated capture duplicated events')
        if len(store.dashboard()['network_alerts']) != 3:
            raise RuntimeError('Repeated capture changed the expected alert count')
        for format, suffix in (('json', 'json'), ('csv', 'csv'), ('markdown', 'md')):
            report = store.report(format)
            (directory / f'report.{suffix}').write_text(report, encoding='utf-8')
        summary = {'generated_at': utc_now(), 'synthetic': True,
                   'scope': 'Two generated offline captures; no real OT devices or incidents.',
                   'docker_image': image, 'python': platform.python_version(),
                   'platform': platform.platform(), 'events_stored': event_count,
                   'active_alerts': 3, 'rules': sorted(expected_rules),
                   'duplicate_capture_deduplicated': True, 'captures': checks,
                   'coverage': 'Installed Zeek connection/Modbus analyzer only; ICSNPP is not certified.'}
        (directory / 'verification.json').write_text(json.dumps(summary, indent=2)+'\n', encoding='utf-8')
        return summary
    finally:
        store.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--docker-image', required=True, help='Already installed Zeek image; prefer its digest')
    parser.add_argument('--output-dir', required=True, type=Path, help='New directory; existing directories are refused')
    args = parser.parse_args()
    print(json.dumps(verify(args.output_dir, args.docker_image), indent=2))
