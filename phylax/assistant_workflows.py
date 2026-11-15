"""Small, evidence-bound inputs for operator-requested AI assistance."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from urllib.parse import urlencode

from .ai import _endpoint, _opener
from .monitoring import validate_policy

ZONES = ('IT', 'DMZ', 'OT')
OPERATIONS = ('flag', 'remove')
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


APPLICABILITY = {
    'CONFIRMED_MATCH': 'Confirmed affected',
    'POTENTIAL_MATCH': 'Possibly affected',
    'NEEDS_REVIEW': 'Needs review',
    'NO_MATCH_TO_THIS_ADVISORY': 'Not affected by this advisory',
}


def report_context(store, selected):
    links = {}
    data = []
    for index, finding_id in enumerate(selected, 1):
        row = store.finding(finding_id)
        if row is None:
            raise ValueError('A selected finding is unavailable. Select findings again.')
        ref = f'E{index}'
        links[ref] = _finding_link(finding_id)
        missing = json.loads(row['missing_evidence'])
        data.append({'advisory': row['cve_id'], 'applicability': APPLICABILITY.get(row['status'], 'Needs review'),
                     'missing_evidence_count': len(missing), 'evidence': ref,
                     'name': row['hostname'] or row['ip_address'],
                     'priority': choice(row['priority'], ('critical', 'high', 'medium', 'low', 'not_applicable')),
                     'synthetic': bool(row['synthetic']),
                     'recorded_evidence': json.loads(row['evidence']),
                     'references': list(dict.fromkeys(filter(None, [row['source_url'], *json.loads(row['references_json'])]))),
                     'missing_evidence': missing})
    return {'findings': data}, links


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
