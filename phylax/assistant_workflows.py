"""Small, evidence-bound inputs for operator-requested AI assistance."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import urlencode

from .advisory_views import passages
from .ai import _endpoint, _opener
from .asset_intelligence import collectors
from .monitoring import active_policy, validate_policy
from .triage import alert_url, triage
from .ui import evidence_url

ZONES = ('IT', 'DMZ', 'OT')
OPERATIONS = ('flag', 'remove')
ADVISORY_TASKS = {'advisory', 'ics-advisory'}
BUILTIN_TASKS = {'alert', 'settings', 'identity', 'remediation'} | ADVISORY_TASKS
TITLES = {'policy': 'Edit zone rules', 'report': 'Create investigation report',
          **dict.fromkeys(BUILTIN_TASKS, 'Built-in explanation')}
REPORT_FOCUSES = {
    'applicability': 'Review applicability',
    'evidence': 'Verify supporting evidence',
    'priority': 'Review findings by urgency',
}


def choice(value, allowed):
    return value if value in allowed else 'unknown'


def merge_zone_policy(base, ranges, rule):
    policy = dict(base or {})
    zones = {zone: values.split() for zone, values in ranges.items() if values.strip()}
    pairs = [list(pair) for pair in policy.get('denied_zone_pairs', [])]
    if rule:
        source, destination, action = (rule[key] for key in ('source', 'destination', 'action'))
        if source not in ZONES or destination not in ZONES or source == destination or action not in OPERATIONS:
            raise ValueError('Choose two different zones and a rule action.')
        pair = [source, destination]
        if action == 'flag' and pair not in pairs:
            pairs.append(pair)
        elif action == 'remove':
            pairs = [item for item in pairs if item != pair]
    return validate_policy(policy | {'zone_subnets': zones, 'denied_zone_pairs': pairs})


def _finding_link(key):
    return '/?' + urlencode({'finding_id': key})


def _one(store, sql, key):
    row = store.connection.execute(sql, (key,)).fetchone()
    if row is None:
        raise ValueError('The selected record was not found.')
    return dict(row)


APPLICABILITY = {
    'CONFIRMED_MATCH': 'Confirmed affected',
    'POTENTIAL_MATCH': 'Possibly affected',
    'NEEDS_REVIEW': 'Needs review',
    'NO_MATCH_TO_THIS_ADVISORY': 'Not affected by this advisory',
}


def _finding_summary(row):
    return {'advisory': row['cve_id'], 'applicability': APPLICABILITY.get(row['status'], 'Needs review'),
            'missing_evidence_count': len(json.loads(row['missing_evidence']))}


def _alert(store, key):
    rows, _ = triage(store, alert_id=key, history=True)
    if rows:
        row = rows[0]
        obs = row['observed']
        policy = row['evidence']['policy']
        data = {'category': 'network policy', 'source': 'Device A', 'destination': 'Device B', 'rule': row['rule_id'],
                'state': row['state'], 'source_zone': choice(policy.get('source_zone'), ZONES),
                'destination_zone': choice(policy.get('destination_zone'), ZONES),
                'protocol': choice(obs.get('protocol'), ('tcp', 'udp', 'modbus'))}
        local = data | {'source_address': obs['source_ip'], 'destination_address': obs['destination_ip']}
        fallback = row['explanation']
        if row['rule_id'] == 'zone_policy_violation':
            data['recorded_connection'] = 'established'
            local = data
            fallback = (f"The sensor recorded a connection from the {data['source_zone']} network to the {data['destination_zone']} network. "
                        'The policy in effect for this alert disallowed that direction. Compromise is unconfirmed.')
        return local, fallback, evidence_url(row['evidence']['event_ref'], alert_url(key)), alert_url(key)
    exposure = store.connection.execute('SELECT finding_id FROM alerts WHERE alert_id=?', (key,)).fetchone()
    if exposure:
        finding = store.finding(exposure[0])
        data = _finding_summary(finding) | {'category': 'vulnerability exposure'}
        link = _finding_link(exposure[0])
        return data, 'Check the finding and the evidence needed to verify applicability.', link, link
    row = _one(store, 'SELECT state,status FROM endpoint_alerts WHERE alert_id=?', key)
    data = {'device': 'Device A', 'category': 'device management', 'state': choice(row['state'], ('active', 'resolved')),
            'management_status': choice(row['status'], ('approved', 'unmanaged', 'unauthorized', 'needs_identity_review'))}
    return data, 'Review the recorded device management evidence.', '/approvals', '/triage'


def _settings(store):
    feeds, inventory = store.source_health()[:12], collectors(store)[:12]
    sources = [{'source': choice(row['source'], ('NVD API 2.0', 'CISA KEV', 'CISA ICS advisories RSS', 'CISA CSAF', 'Demo advisory cache')),
                'health': choice(row['health'], ('healthy', 'stale', 'unavailable', 'cached')),
                'received_data': bool(row['last_success_at']) or row['health'] == 'cached'} for row in feeds]
    sensors = [{'type': choice(row['kind'], ('watcher', 'worker')), 'last_success_recorded': bool(row['last_success']),
                'status': choice(row['status'], ('running', 'stopped', 'degraded', 'stale'))} for row in inventory]
    for item, row in zip(sources, feeds):
        item['last_success'] = row['last_success_at']
    for item, row in zip(sensors, inventory):
        item['last_success'] = row['last_success']
    failed = store.connection.execute("SELECT COUNT(*) FROM ingestion_files WHERE status='failed'").fetchone()[0]
    return {'feeds': sources, 'collectors': sensors, 'failed_imports': failed}


def context(store, task, key, fields):
    """Return stored evidence, an explanation, a return path, and links."""
    links = {}
    if task == 'policy':
        current = active_policy(store) or {}
        data = {'configured_zones': [zone for zone in ZONES if current.get('zone_subnets', {}).get(zone)],
                'current_rules': current.get('denied_zone_pairs', []), 'requested_rule': fields['rule']}
        return data, 'Review network ranges and choose a rule direction before previewing.', '/policy', links
    if task == 'alert':
        local, fallback, link, back = _alert(store, key)
        return local, fallback, back, {'E1': link}
    if task == 'settings':
        return _settings(store), 'Check the last successful update and collector status in Settings.', '/settings', {'E1': '/settings'}
    if task == 'identity':
        if fields.get('identity_type') == 'asset':
            row = _one(store, 'SELECT ip_address,verified FROM assets WHERE asset_id=?', key)
            from .fingerprints import latest_fingerprint
            observed = latest_fingerprint(store, row['ip_address'])
            data = {'device': 'Device A', 'verified': bool(row['verified']), 'identity_observed': bool(observed),
                    'conflicting_observations': bool(observed and observed['conflict']),
                    'mapping_present': bool(observed and observed['mapping']), 'revision_present': bool(observed and observed['revision'])}
            if observed:
                links['E1'] = evidence_url(observed['event_ref'], '/assets')
            back = '/assets'
        else:
            row = _one(store, 'SELECT * FROM software_components WHERE component_id=?', key)
            competing = store.connection.execute('SELECT COUNT(DISTINCT version) FROM software_components WHERE asset_id=? AND raw_name=? AND active=1',
                                                 (row['asset_id'], row['raw_name'])).fetchone()[0]
            data = {'device': 'Device A', 'verified': bool(row['verified']), 'active': bool(row['active']),
                    'mapping_present': bool(row['vendor'] and row['product']), 'version_present': bool(row['version']),
                    'active_version_count': competing}
            data['reported_version'] = row['version'][:200]
            back = '/software?' + urlencode({'component_id': key}) + '#review-component'
            links['E1'] = back
        data['review_status'] = 'verified' if data['verified'] else 'unverified'
        return data, 'Check the original observation and resolve conflicting identity before verifying it.', back, links
    if task == 'ics-advisory':
        row = _one(store, 'SELECT * FROM ics_advisories WHERE advisory_id=?', key)
        back = '/intelligence/ics?' + urlencode({'q': row['advisory_id'][:100]})
        records = [row | {'source_url': row['link']}]
        data = {'title': row['title'][:300], 'passages': passages(records, ics=True)}
        return data, 'Use the original advisory to confirm scope and recommended actions.', back, {
            ref: '#advisory-' + ref for ref in data['passages']}
    if task == 'advisory':
        row = _one(store, 'SELECT * FROM vulnerabilities WHERE cve_id=?', key)
        records = [item['record'] for item in store.vulnerability_provenance(key)
                   if item['public_trusted'] and not item['record'].get('synthetic')]
        if not records:
            records = [row | {'affected_products': json.loads(row['affected_products']),
                              'references': json.loads(row['references_json'])}]
        data = {'title': key, 'passages': passages(records)}
        back = '/intelligence?' + urlencode({'q': key})
        return data, 'Check the advisory exclusions and unresolved conditions before deciding what applies.', back, {
            ref: '#advisory-' + ref for ref in data['passages']}
    if task == 'remediation':
        row = store.finding(key)
        if row is None:
            raise ValueError('The selected record was not found.')
        record = store.public_vulnerability_for_finding(key)
        back = _finding_link(key)
        data = {'public_advisory': record, 'applicability': _finding_summary(row)}
        return data, 'Check the advisory exclusions and unresolved conditions before deciding what applies.', back, {'E1': back}
    if task == 'report':
        selected = fields.get('selected', [])
        data = []
        for index, finding_id in enumerate(selected, 1):
            row = store.finding(finding_id)
            if row is None:
                raise ValueError('A selected finding is unavailable. Select findings again.')
            ref = f'E{index}'
            links[ref] = _finding_link(finding_id)
            data.append(_finding_summary(row) | {'evidence': ref,
                                                 'name': row['hostname'] or row['ip_address'],
                                                 'priority': choice(row['priority'], ('critical', 'high', 'medium', 'low', 'not_applicable')),
                                                 'synthetic': bool(row['synthetic']),
                                                 'recorded_evidence': json.loads(row['evidence']),
                                                 'references': list(dict.fromkeys(filter(None, [row['source_url'], *json.loads(row['references_json'])]))),
                                                 'missing_evidence': json.loads(row['missing_evidence'])})
        return {'findings': data, 'finding_count': len(data)}, 'Review the selected findings and download the report.', '/reports', links
    raise ValueError('Unknown assistance workflow.')


def request_body(config, data, refs, language, local):
    # Send review metadata only. Asset names, addresses, IDs and source text stay local.
    findings = [{key: row[key] for key in ('evidence', 'applicability', 'priority', 'missing_evidence_count')}
                for row in data['findings']]
    schema = {
        'type': 'object', 'additionalProperties': False, 'required': ['focus', 'evidence'],
        'properties': {
            'focus': {'type': 'string', 'enum': list(REPORT_FOCUSES)},
            'evidence': {'type': 'array', 'minItems': len(refs), 'maxItems': len(refs),
                         'uniqueItems': True, 'items': {'type': 'string', 'enum': list(refs)}},
        },
    }
    request = {'model': config.model, 'messages': [
        {'role': 'system', 'content': 'Organize an investigation report. Choose one review focus and order all supplied evidence IDs. '
         'Prioritize urgent findings and evidence gaps. Preserve all IDs exactly once. '
         'Return only JSON matching this schema: ' + json.dumps(schema)},
        {'role': 'user', 'content': json.dumps({'language': language, 'findings': findings})},
    ], 'max_tokens': 320}
    if config.provider in {'gemini', 'google'} and not local:
        request['extra_body'] = {'google': {'thinking_config': {'thinking_level': 'low'}}}
    if local:
        request['temperature'] = 0
        request['response_format'] = {'type': 'json_schema', 'json_schema': {'name': 'report', 'schema': schema}}
    return json.dumps(request, indent=2).encode()


def complete(config, body, refs, local, *, opener=None):
    headers = {'Content-Type': 'application/json'}
    if not local:
        headers['Authorization'] = f'Bearer {config.api_key}'
    request = urllib.request.Request(_endpoint(config.base_url), data=body, headers=headers, method='POST')
    try:
        with (opener or _opener(local))(request, timeout=config.timeout_seconds) as response:
            raw = response.read(128_001)
    except urllib.error.HTTPError as exc:
        exc.close()
        raise ValueError(f'AI provider returned HTTP {exc.code}.') from None
    except OSError:
        raise ValueError('AI provider is unavailable or timed out.') from None
    if len(raw) > 128_000:
        raise ValueError('AI response is too large.')
    try:
        envelope = json.loads(raw)
        text = envelope['choices'][0]['message']['content'].strip()
        if text.startswith('```json') and text.endswith('```'):
            text = text[7:-3].strip()
        result = json.loads(text)
        model = envelope.get('model') or config.model
    except (ValueError, KeyError, TypeError, IndexError, AttributeError, RecursionError):
        raise ValueError('AI provider returned an invalid response.') from None
    if (not isinstance(result, dict) or set(result) != {'focus', 'evidence'}
            or not isinstance(result['focus'], str) or result['focus'] not in REPORT_FOCUSES
            or not isinstance(model, str) or not 0 < len(model) <= 200):
        raise ValueError('AI provider returned an invalid response.')
    evidence = result['evidence']
    if (not isinstance(evidence, list) or len(evidence) != len(refs)
            or any(not isinstance(ref, str) for ref in evidence) or set(evidence) != set(refs)):
        raise ValueError('AI must include each selected finding exactly once.')
    return result, model
