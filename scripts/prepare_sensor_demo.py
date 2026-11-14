"""Prepare the isolated passive identity demo and optionally rehearse saved exports."""
import argparse
import io
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phylax.asset_intelligence import add_subnet, endpoint_decision, heartbeat, save_context, save_process
from phylax.core import Store
from phylax.csaf import normalize as normalize_csaf
from phylax.fingerprints import save_mapping
from phylax.monitoring import reevaluate_events
from phylax.observations import review_component
from phylax.remediation import compose_plan
from phylax.sensor_imports import import_wazuh
from phylax.watcher import LogWatcher
from scripts.generate_passive_demo import frame

PLC = '192.0.2.10'
FIXED = '192.0.2.11'
IT = '198.51.100.40'
DMZ = '203.0.113.30'
UNKNOWN = '192.0.2.99'
ADVISORY = ('https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2021-285-04'
            '&p_File_Name=SEVD-2021-285-04_M218_Security_Notification.pdf&p_enDocType=Security+and+Safety+Notice')
CISA_FIXTURE = Path(__file__).resolve().parents[1] / 'tests/fixtures/public_cisa_icsa_24_004_01.json'
CISA_URL = 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2024/icsa-24-004-01.json'
CISA_RETRIEVED_AT = '2026-11-04T05:12:00Z'
POLICY = {'zone_subnets': {'IT': ['198.51.100.0/24'], 'DMZ': ['203.0.113.0/24'], 'OT': ['192.0.2.0/24']},
          'denied_zone_pairs': [['IT', 'OT']]}
WHEN = '2026-11-12T09:00:00Z'
EPOCH = 1794474000
DEMO_LABEL = 'SIMULATED fictional TNI AD support-site traffic and assets. Advisory SEVD-2021-285-04 is public and real.'


def identity_rows(ip, revision, *, unit=1, uid='lab-identification', observed=EPOCH):
    base = {'ts': observed, 'uid': uid, 'source_h': ip, 'source_p': 502, 'destination_h': DMZ,
            'destination_p': 40000, 'unit': unit, 'tid': 1, 'request_response': 'RESPONSE',
            'mei_type': 'READ-DEVICE-IDENTIFICATION'}
    return [base | {'object_id_code': f'0x{index:02x}', 'object_value': value}
            for index, value in enumerate(('Schneider Electric', 'Modicon M218', revision))]


def write_jsonl(path, records):
    path.write_text(''.join(json.dumps(row) + '\n' for row in records), encoding='utf-8')


def identity_capture(conversations):
    """Encode benign identification exchanges as a file, with no network I/O."""
    output = bytearray(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for index, (client, controller, revision) in enumerate(conversations):
        port = 40000 + index
        request_data = bytes((1, 43, 14, 1, 0))
        request = struct.pack('!HHH', 1, 0, len(request_data)) + request_data
        objects = bytearray()
        identity = ('Schneider Electric', 'Modicon M218', revision) if revision else ('Schneider Electric',)
        for number, value in enumerate(identity):
            encoded = value.encode('ascii')
            objects.extend(bytes((number, len(encoded))) + encoded)
        response_data = bytes((1, 43, 14, 1, 1, 0, 0, len(identity))) + objects
        response = struct.pack('!HHH', 1, 0, len(response_data)) + response_data
        next_client = 101 + len(request)
        next_server = 201 + len(response)
        packets = (
            frame(client, controller, port, 502, 100, 0, 2),
            frame(controller, client, 502, port, 200, 101, 18),
            frame(client, controller, port, 502, 101, 201, 16),
            frame(client, controller, port, 502, 101, 201, 24, request),
            frame(controller, client, 502, port, 201, next_client, 24, response),
            frame(client, controller, port, 502, next_client, next_server, 17),
            frame(controller, client, 502, port, next_server, next_client+1, 17),
            frame(client, controller, port, 502, next_client+1, next_server+1, 16),
        )
        for offset, packet in enumerate(packets):
            output.extend(struct.pack('<IIII', EPOCH+index, offset*1000, len(packet), len(packet)))
            output.extend(packet)
    return bytes(output)


def prepare(directory):
    directory.mkdir(parents=True, exist_ok=False)
    fixture = {'synthetic': False, 'vulnerabilities': [
        {'cve_id': 'CVE-2021-22800', 'source': 'Schneider Electric SEVD-2021-285-04',
         'summary': 'Schneider Electric advisory for Modicon M218 firmware through 5.1.0.6.',
         'severity': 'high', 'published': '2021-10-12', 'references': [ADVISORY],
         'affected_products': [{'vendor': 'schneider electric', 'product': 'modicon m218',
                                'version_ranges': [{'end_including': '5.1.0.6'}]}],
         'mitigation': 'Schneider Electric identifies firmware 5.1.0.8 as containing the fix.'}]}
    (directory/'advisory.json').write_text(json.dumps(fixture, indent=2), encoding='utf-8')
    (directory/'policy.json').write_text(json.dumps(POLICY, indent=2), encoding='utf-8')
    (directory/'simulated-identification.pcap').write_bytes(identity_capture(
        [(DMZ, PLC, '5.1.0.6'), (DMZ, FIXED, '5.1.0.8'), (DMZ, UNKNOWN, None)]))
    (directory/'simulated-denied-connection.pcap').write_bytes(identity_capture([(IT, PLC, '5.1.0.6')]))
    write_jsonl(directory/'modbus_read_device_identification.log',
                identity_rows(PLC, '5.1.0.6')+identity_rows(FIXED, '5.1.0.8', uid='lab-fixed', observed=EPOCH+1)+
                identity_rows(UNKNOWN, '', uid='lab-unknown', observed=EPOCH+2)[:1])
    conns = []
    for index, (client, server, state) in enumerate([(DMZ, PLC, 'SF'), (DMZ, FIXED, 'SF'),
                                                     (IT, PLC, 'SF'), (IT, UNKNOWN, 'S0')]):
        conns.append({'ts': EPOCH+index, 'uid': f'lab-flow-{index}', 'id.orig_h': client, 'id.orig_p': 40000+index,
                      'id.resp_h': server, 'id.resp_p': 502, 'proto': 'tcp', 'service': 'modbus', 'conn_state': state})
    write_jsonl(directory/'conn.log', conns)
    wazuh = {'error': 0, 'data': {'total_failed_items': 0, 'affected_items': [
        {'agent_id': '001', 'scan': {'time': WHEN}, 'name': 'Example Lab Package', 'version': '1.2.3'}]}}
    (directory/'wazuh-packages.json').write_text(json.dumps(wazuh, indent=2), encoding='utf-8')
    wazuh['data']['affected_items'] = [
        {'agent_id': '001', 'scan': {'time': WHEN},
         'os': {'name': 'Simulated Workstation Linux', 'version': '12.0'}}]
    (directory/'wazuh-os.json').write_text(json.dumps(wazuh, indent=2), encoding='utf-8')
    (directory/'README.txt').write_text(DEMO_LABEL+' All packets are generated in files only.\n', encoding='utf-8')
    database = directory/'phylax-demo.db'
    store = Store(database)
    try:
        store.connection.execute("INSERT INTO schema_meta VALUES('dataset_label',?)", (DEMO_LABEL,))
        store.ingest_fixture(fixture)
        reevaluate_events(store, POLICY)
        save_mapping(store, 'Schneider Electric', 'Modicon M218', 'schneider electric', 'modicon m218',
                     'PLC', True, 'Lab operator', 'Simulated model and firmware mapping for this exercise')
    finally:
        store.close()
    return database


def stage_presentation(directory, database):
    """Load saved observations while leaving identity review for the presenter."""
    store = Store(database)
    try:
        if store.assets():
            raise RuntimeError('Presentation setup requires the fresh empty demo inventory')
        watcher = LogWatcher(store, directory)
        watcher.poll()
        imports = watcher.poll()
        heartbeat(store, watcher.key, 'watcher', 'stopped',
                  f"Offline demo preparation: {imports['imported']} finalized Zeek logs imported.")
        if imports['failed'] or imports['imported'] != 2:
            raise RuntimeError(f'Expected both saved Zeek logs to import: {imports}')

        assets = {asset['ip_address']: asset for asset in store.assets()}
        inventory = (
            'asset_id,ip_address,hostname,zone,criticality,identification_source\n'
            f"{assets[PLC]['asset_id']},{PLC},Simulated Cooling Controller,OT,critical,zeek_passive\n"
            f"{assets[FIXED]['asset_id']},{FIXED},Simulated Backup Controller,OT,medium,zeek_passive\n"
            f"{assets[IT]['asset_id']},{IT},Simulated IT Workstation,IT,medium,zeek_passive\n"
            f"{assets[DMZ]['asset_id']},{DMZ},Simulated DMZ Host,DMZ,medium,zeek_passive\n"
        )
        result = store.import_csv(io.StringIO(inventory))
        if result['errors']:
            raise RuntimeError(result['errors'])

        actor = 'Demo operator'
        subnet_id = add_subnet(store, 'Simulated industrial network', POLICY['zone_subnets']['OT'][0])
        endpoint_decision(store, subnet_id, ip=PLC, actor=actor,
                          note='Management approval for the simulated controller.')
        controller_id = assets[PLC]['asset_id']
        save_context(store, controller_id, owner='Simulated facilities team', site='Fictional support site',
                     location='Simulated cooling room', lifecycle='commissioned',
                     criticality_rationale='Supports the simulated facility cooling process.')
        save_process(store, 'Simulated facility cooling', 'Cooling for the fictional support site.',
                     controller_id, actor, 'Recorded for the simulated investigation.')

        for kind in ('os', 'packages'):
            import_wazuh(store, directory/f'wazuh-{kind}.json', manager='simulated-manager',
                         agent_id='001', asset_id=assets[IT]['asset_id'], kind=kind)

        document = json.loads(CISA_FIXTURE.read_text(encoding='utf-8'))
        _, advisories = normalize_csaf(document, CISA_URL, CISA_RETRIEVED_AT)
        store.save_ics_advisories(advisories)
        store.set_source_health('Demo advisory cache', 'cached', records=1 + len(advisories),
                                message='Loaded saved Schneider Electric and CISA advisories offline.')

        before = _statuses(store)
        if before.get(PLC) != 'POTENTIAL_MATCH':
            raise RuntimeError('The simulated controller must begin as a potential match')
        finding = next(row for row in store.dashboard()['findings'] if row['asset_id'] == controller_id)
        for field in ('evidence', 'missing_evidence'):
            finding[field] = json.loads(finding[field])
        finding['references'] = json.loads(finding['references_json'])
        finding_id = finding['finding_id']
        plan = compose_plan(finding, store.public_vulnerability_for_finding(finding_id))
        plan['provider_note'] += ' Draft for the simulated support-site investigation.'
        store.create_remediation_plan(finding_id, 'template-fallback', '', plan, plan['source_references'])

        alert = store.connection.execute("SELECT alert_id FROM network_alerts WHERE rule_id='zone_policy_violation'").fetchall()
        if len(alert) != 1:
            raise RuntimeError('Expected exactly one IT to OT policy alert')
        return before
    finally:
        store.close()


def rehearse(directory, database):
    before = stage_presentation(directory, database)
    store = Store(database)
    try:
        for (component,) in store.connection.execute('SELECT component_id FROM modbus_identity_components').fetchall():
            review_component(store, component, verified=True, actor='Lab operator',
                             note='Verified against the simulated lab identity')
        after = _statuses(store)
        if after != {PLC: 'CONFIRMED_MATCH', FIXED: 'NO_MATCH_TO_THIS_ADVISORY'}:
            raise RuntimeError(f'Unexpected advisory statuses: {after}')
        report = json.loads(store.report('json'))
        violations = [row for row in report['network_alerts'] if row['rule_id'] == 'zone_policy_violation']
        if len(violations) != 1 or violations[0]['source_ip'] != IT:
            raise RuntimeError('Expected exactly one IT to OT policy alert')
        evidence = {row['kind'] for row in report['asset_intelligence']['sensor_evidence']}
        if evidence != {'modbus-identity', 'wazuh_inventory'}:
            raise RuntimeError('Expected Zeek identity and Wazuh software evidence in the report')
        (directory/'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        return {'before_review': before, 'after_review': after, 'zone_alerts': len(violations),
                'sources': sorted(evidence), 'report': str(directory/'report.json')}
    finally:
        store.close()


def _statuses(store):
    return dict(store.connection.execute('SELECT a.ip_address,f.status FROM findings f JOIN assets a USING(asset_id)'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--rehearse', action='store_true')
    modes.add_argument('--presentation', action='store_true', help='Load demo evidence and leave the identity review to the presenter')
    args = parser.parse_args()
    database = prepare(args.output_dir)
    result = {'database': str(database)}
    if args.rehearse:
        result = rehearse(args.output_dir, database)
    elif args.presentation:
        result['findings_before_review'] = stage_presentation(args.output_dir, database)
    print(json.dumps(result, indent=2))
