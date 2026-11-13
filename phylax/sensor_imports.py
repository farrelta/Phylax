"""Offline Suricata flow and Wazuh Syscollector imports."""
from dataclasses import replace
from pathlib import Path
import json
import re

from .asset_intelligence import identifier, text
from .core import read_json_limited, utc_now
from .monitoring import normalize_row
from .observations import SoftwareObservation, observe_connection, scalar, software_component, timestamp


def import_suricata(store, path, *, source_file=None):
    path = Path(path)
    if path.stat().st_size > 500_000_000:
        raise ValueError('Suricata log exceeds 500 MB limit')
    source = 'Suricata EVE: ' + (source_file or path.name)
    inserted = duplicates = skipped = 0
    with store.atomic('suricata_import'), path.open(encoding='utf-8') as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                if len(line) > 1_000_000:
                    raise ValueError('Record exceeds 1 MB')
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError('Expected an EVE object')
                if not scalar(row, 'event_type'):
                    raise ValueError('EVE record requires event_type')
                if row['event_type'] != 'flow':
                    skipped += 1
                    continue
                if not all(scalar(row, field) for field in ('src_ip', 'dest_ip', 'proto', 'flow_id')):
                    raise ValueError('EVE flow requires endpoint addresses, protocol and flow ID')
                flow = row.get('flow')
                if not isinstance(flow, dict):
                    raise ValueError('EVE flow record requires a flow object')
                ref = identifier('suricata_flow', json.dumps(row, sort_keys=True))
                event = normalize_row({
                    'timestamp': timestamp(scalar(flow, 'start') or scalar(row, 'timestamp')),
                    'source_ip': row['src_ip'], 'destination_ip': row['dest_ip'],
                    'source_port': row.get('src_port'), 'destination_port': row.get('dest_port'),
                    'proto': row['proto']
                }, kind='conn', source_file=source)
                event = replace(event, event_type='suricata_flow', event_ref=ref, raw=row)
            except (TypeError, ValueError) as exc:
                raise ValueError(f'Malformed Suricata row {number}: {exc}') from exc
            result = store.connection.execute('INSERT OR IGNORE INTO network_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                (ref, ref, event.timestamp, event.source_ip, event.source_port, event.destination_ip,
                 event.destination_port, event.protocol, '', event.event_type, source, json.dumps(row, sort_keys=True)))
            if result.rowcount:
                observe_connection(store, event)
                inserted += 1
            else:
                duplicates += 1
        store.audit('suricata_import', source, {'observations': inserted, 'duplicates': duplicates, 'skipped': skipped})
    store.connection.commit()
    return {'events_inserted': inserted, 'duplicates_skipped': duplicates, 'records_skipped': skipped,
            'alerts_created': 0, 'diagnostics': [], 'diagnostic_count': 0}


def import_wazuh(store, path, *, manager, agent_id, asset_id, kind, source_file=None):
    path = Path(path)
    with path.open('rb') as stream:
        payload = read_json_limited(stream.read(5_000_001), max_bytes=5_000_000)
    manager = text(manager, 120)
    if not manager or not re.fullmatch(r'[0-9]{3,16}', agent_id) or kind not in {'os', 'packages'}:
        raise ValueError('Wazuh import requires a named manager, numeric agent ID and OS or packages export')
    data = payload.get('data')
    if payload.get('error') != 0 or not isinstance(data, dict) or data.get('total_failed_items', 0):
        raise ValueError('Wazuh export must contain a successful Syscollector response')
    records = data.get('affected_items')
    if not isinstance(records, list):
        raise ValueError('Wazuh export requires data.affected_items')
    source = f'Wazuh {manager}/{agent_id}: {source_file or path.name}'
    inserted = duplicates = skipped = 0
    with store.atomic('wazuh_import'):
        db = store.connection
        asset = db.execute("SELECT * FROM assets WHERE asset_id=? AND zone='IT'", (asset_id,)).fetchone()
        if not asset:
            raise ValueError('Wazuh agent must be bound to an existing IT asset')
        binding = db.execute('SELECT asset_id FROM wazuh_bindings WHERE manager=? AND agent_id=?',
                             (manager, agent_id)).fetchone()
        if binding and binding['asset_id'] != asset_id:
            raise ValueError('This Wazuh manager and agent are already bound to a different asset')
        db.execute('INSERT OR IGNORE INTO wazuh_bindings VALUES(?,?,?)', (manager, agent_id, asset_id))
        for index, row in enumerate(records, 1):
            try:
                if not isinstance(row, dict) or scalar(row, 'agent_id') != agent_id:
                    raise ValueError('Inventory record agent ID does not match the binding')
                item = row.get('os') if kind == 'os' else row
                scan = row.get('scan')
                if not isinstance(item, dict) or not isinstance(scan, dict):
                    raise ValueError('Inventory record lacks OS/package or scan data')
                name, version = scalar(item, 'name'), scalar(item, 'version')
                when = timestamp(scalar(scan, 'time'))
            except ValueError as exc:
                raise ValueError(f'Malformed Wazuh record {index}: {exc}') from exc
            if not name:
                skipped += 1
                continue
            raw_name = ('Wazuh OS: ' if kind == 'os' else 'Wazuh package: ') + name
            ref = identifier('wazuh_inventory', manager, agent_id, kind, json.dumps(row, sort_keys=True))
            evidence = db.execute('''INSERT OR IGNORE INTO observations
                VALUES(?,?,?,?,?,?,?,?,?)''',
                (ref, 'wazuh_inventory', asset['ip_address'], '', when, utc_now(), source, ref,
                 json.dumps(row, sort_keys=True)))
            if evidence.rowcount:
                software_component(store, SoftwareObservation(asset['ip_address'], raw_name, version, when),
                                   source, ref, row, asset_id=asset_id)
                inserted += 1
            else:
                duplicates += 1
        if inserted:
            store.correlate(asset_ids=[asset_id], commit=False)
        store.audit('wazuh_inventory_import', asset_id, {'manager': manager, 'agent_id': agent_id, 'kind': kind,
                    'observations': inserted, 'duplicates': duplicates, 'skipped': skipped})
    store.connection.commit()
    return {'events_inserted': inserted, 'duplicates_skipped': duplicates, 'records_skipped': skipped,
            'alerts_created': 0, 'diagnostics': [], 'diagnostic_count': 0}
