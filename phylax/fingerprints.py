"""Passive Modbus identification evidence and its reviewed firmware projection."""
from itertools import groupby, islice
import json
from pathlib import Path

from .asset_intelligence import actor_note, address, identifier, observe, text
from .monitoring import zeek_rows
from .observations import asset_for_ip, scalar, timestamp

KIND = 'modbus-identity'
LOG_NAME = 'modbus_read_device_identification'
COMPONENT_PREFIX = 'Modbus identification firmware: '
OBJECTS = {'0x00': 'vendor', '0x01': 'product_code', '0x02': 'revision'}


def _response(row):
    direction = scalar(row, 'request_response').upper()
    if direction == 'REQUEST':
        return None
    if direction != 'RESPONSE' or scalar(row, 'mei_type') != 'READ-DEVICE-IDENTIFICATION':
        raise ValueError('Expected a Modbus device identification response')
    ip = address(scalar(row, 'source_h') or scalar(row, 'id.resp_h'))
    responder = scalar(row, 'id.resp_h')
    if responder and ip != address(responder):
        raise ValueError('Modbus response source disagrees with the Zeek responder')
    unit = scalar(row, 'unit') or scalar(row, 'uint')
    tid = scalar(row, 'tid')
    uid = scalar(row, 'uid')
    if not uid or not unit.isdecimal() or int(unit) > 255 or not tid.isdecimal() or int(tid) > 65535:
        raise ValueError('Modbus response requires a connection, transaction and unit')
    return (ip, int(unit), uid, int(tid), timestamp(scalar(row, 'ts')),
            scalar(row, 'modbus_detailed_link_id'), scalar(row, 'source_p'),
            scalar(row, 'destination_h'), scalar(row, 'destination_p'))


def latest_fingerprint(store, ip):
    records = store.connection.execute(
        '''SELECT * FROM observations WHERE kind=? AND ip=? AND observed_at=(
           SELECT MAX(observed_at) FROM observations WHERE kind=? AND ip=?)
           ORDER BY event_ref''', (KIND, ip, KIND, ip)).fetchall()
    if not records:
        return None
    fingerprints = [json.loads(row['raw_json']) for row in records]
    best = max(range(len(records)), key=lambda i: sum(bool(fingerprints[i][field]) for field in OBJECTS.values()))
    fingerprint = fingerprints[best]
    row = records[best]
    units = store.connection.execute(
        "SELECT COUNT(DISTINCT json_extract(raw_json,'$.unit')) FROM observations WHERE kind=? AND ip=?",
        (KIND, ip)).fetchone()[0]
    conflict = units > 1 or any(
        item['conflict'] or any(item[field] and fingerprint[field] and item[field] != fingerprint[field]
                                for field in OBJECTS.values())
        for item in fingerprints)
    mapping = store.connection.execute(
        'SELECT * FROM modbus_identity_mappings WHERE observed_vendor=? AND product_code=?',
        (fingerprint['vendor'], fingerprint['product_code'])).fetchone()
    return fingerprint | {'conflict': conflict, 'event_ref': row['event_ref'], 'observed_at': row['observed_at'],
                          'source_file': row['source_file'], 'mapping': dict(mapping) if mapping else None}


def project(store, ip):
    fingerprint = latest_fingerprint(store, ip)
    if fingerprint is None:
        return
    asset = asset_for_ip(store, ip)
    if asset is None:
        candidates = store.connection.execute('SELECT asset_id FROM assets WHERE ip_address=?', (ip,))
        for (asset_id,) in candidates:
            retire(store, asset_id)
            store.correlate(asset_ids=[asset_id], commit=False)
        return
    asset_id = asset['asset_id']
    mapping = fingerprint['mapping']
    if fingerprint['conflict'] or not mapping or not mapping['firmware'] or not fingerprint['revision']:
        retire(store, asset_id)
    else:
        identity = {field: fingerprint[field] for field in ('vendor', 'product_code', 'revision', 'unit')}
        name = COMPONENT_PREFIX + json.dumps([fingerprint['vendor'], fingerprint['product_code'],
                                              fingerprint['unit'], mapping['vendor'], mapping['product']], ensure_ascii=False)
        existing = store.connection.execute(
            'SELECT component_id FROM software_components WHERE asset_id=? AND raw_name=? AND version=?',
            (asset_id, name, fingerprint['revision'])).fetchone()
        component_id = existing['component_id'] if existing else identifier(KIND, asset_id, identity, mapping['vendor'], mapping['product'])
        prior = store.connection.execute(
            'SELECT component_id FROM modbus_identity_components WHERE asset_id=?', (asset_id,)).fetchone()
        if not prior or prior['component_id'] != component_id:
            retire(store, asset_id)
        observed = fingerprint['observed_at']
        store.connection.execute('''INSERT INTO software_components VALUES(?,?,?,?,?,?,0,1,?,?,?,?,?,'')
            ON CONFLICT(component_id) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen)''',
            (component_id, asset_id, name, fingerprint['revision'], mapping['vendor'], mapping['product'],
             observed, observed, fingerprint['source_file'], fingerprint['event_ref'], json.dumps(identity)))
        if not prior or prior['component_id'] != component_id:
            store.connection.execute(
                "UPDATE software_components SET active=1,verified=0,reviewer='',source_file=?,event_ref=? WHERE component_id=?",
                (fingerprint['source_file'], fingerprint['event_ref'], component_id))
            store.connection.execute('INSERT INTO modbus_identity_components VALUES(?,?)', (asset_id, component_id))
    store.correlate(asset_ids=[asset_id], commit=False)


def retire(store, asset_id):
    store.connection.execute('''UPDATE software_components SET verified=0,active=0,reviewer=''
        WHERE component_id=(SELECT component_id FROM modbus_identity_components WHERE asset_id=?)''', (asset_id,))
    store.connection.execute('DELETE FROM modbus_identity_components WHERE asset_id=?', (asset_id,))


def save_mapping(store, observed_vendor, product_code, vendor, product, role, firmware, actor, note):
    actor, note = actor_note(actor, note)
    fields = [text(value, 250) for value in (observed_vendor, product_code, vendor, product)]
    if not all(fields) or role not in {'unknown', 'PLC'}:
        raise ValueError('An exact vendor and product mapping is required')
    with store.atomic('modbus_identity_mapping'):
        store.connection.execute('''INSERT INTO modbus_identity_mappings VALUES(?,?,?,?,?,?)
            ON CONFLICT(observed_vendor,product_code) DO UPDATE SET vendor=excluded.vendor,
            product=excluded.product,role=excluded.role,firmware=excluded.firmware''', (*fields, role, int(firmware)))
        store.audit('modbus_identity_mapping', identifier(*fields[:2]), {'actor': actor, 'note': note})
        endpoints = store.connection.execute('''SELECT DISTINCT ip FROM observations WHERE kind=?
            AND json_extract(raw_json,'$.vendor')=? AND json_extract(raw_json,'$.product_code')=?''',
            (KIND, *fields[:2])).fetchall()
        for (ip,) in endpoints:
            project(store, ip)
    store.connection.commit()


def ingest(store, path, *, source_file=None, commit=True):
    path = Path(path)
    if path.stat().st_size > 500_000_000:
        raise ValueError('Zeek log exceeds 500 MB limit')
    inserted = duplicates = skipped = 0
    endpoints = set()
    source = source_file or path.name
    with store.atomic('modbus_identity_import'), path.open(encoding='utf-8') as stream:
        # ICSNPP writes the objects of each response consecutively.
        rows = (row for _, row in zeek_rows(stream, max_line_length=1_000_000))
        for response, records in groupby(rows, key=_response):
            if response is None:
                skipped += sum(1 for _ in records)
                continue
            raw = list(islice(records, 257))
            if len(raw) > 256:
                raise ValueError('Too many objects in one Modbus identification response')
            values = {field: set() for field in OBJECTS.values()}
            for row in raw:
                field = OBJECTS.get(scalar(row, 'object_id_code').lower())
                value = scalar(row, 'object_value')
                if field and value:
                    values[field].add(value)
            fingerprint = {field: next(iter(items)) if len(items) == 1 else '' for field, items in values.items()}
            ip, unit, uid, tid, when, *_ = response
            fingerprint.update(unit=unit, uid=uid, tid=tid, conflict=any(len(items) > 1 for items in values.values()),
                               records=raw)
            ref = identifier(KIND, response, sorted({json.dumps(r, sort_keys=True) for r in raw}))
            new = observe(store, kind=KIND, ip=ip, when=when, source_file=source, event_ref=ref, raw=fingerprint)
            inserted += int(new)
            duplicates += int(not new)
            if new:
                endpoints.add(ip)
        for ip in sorted(endpoints):
            project(store, ip)
        store.audit('modbus_identity_import', source, {'observations': inserted, 'duplicates': duplicates, 'skipped': skipped})
    if commit:
        store.connection.commit()
    return {'events_inserted': inserted, 'duplicates_skipped': duplicates, 'records_skipped': skipped,
            'alerts_created': 0, 'diagnostics': [], 'diagnostic_count': 0}
