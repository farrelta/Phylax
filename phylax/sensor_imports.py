"""Offline Wazuh Syscollector imports."""
from pathlib import Path
import json
import re

from .asset_intelligence import identifier, text
from .core import read_json_limited, utc_now
from .observations import SoftwareObservation, scalar, software_component, timestamp


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
