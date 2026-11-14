"""Server-rendered review and consent for local and hosted drafts."""
from __future__ import annotations

import json
from urllib.parse import urlencode

from .ai import AIConfig, _endpoint, local_config
from .assistant_workflows import (OPERATIONS, TITLES, ZONES, complete, context,
                                  merge_zone_policy, request_body)
from .monitoring import active_policy, policy_version, preview_policy, reevaluate_events, validate_policy
from .remediation_service import generate_plan, remediation_version
from .theme import PLAIN_STATUS, layout
from .ui import e, evidence_url, hidden, select

POLICY_ERRORS = ('Network ranges overlap.', 'A network range is invalid.', 'A rule refers to an unconfigured zone.',
                 'The rule or network ranges failed validation.')


def _provider(mode):
    if mode == 'local':
        return local_config()
    if mode == 'hosted':
        return AIConfig.from_env()
    return None


def _get(values, key, default=''):
    return values.get(key, [default])[0]


def _fields(values):
    task = _get(values, 'task')
    if task not in TITLES:
        raise ValueError('Unknown assistance workflow.')
    selected = list(dict.fromkeys(value[:256] for value in values.get('selected', [])))
    if len(selected) > 12:
        raise ValueError('Select up to 12 findings.')
    return {'task': task, 'key': _get(values, 'key')[:2048 if task == 'ics-advisory' else 256], 'identity_type': _get(values, 'identity_type')[:10],
            'mode': _get(values, 'mode', 'local' if local_config() else 'builtin'),
            'selected': selected,
            'prompt': _get(values, 'prompt')[:1200], 'rule': {key: _get(values, key)[:12] for key in ('source', 'destination', 'action')},
            'ranges': {zone: _get(values, zone)[:6000] for zone in ZONES},
            'policy_error': _get(values, 'policy_error') if _get(values, 'policy_error') in POLICY_ERRORS else ''}


def _controls(fields, *, base=True):
    markup = hidden('task', fields['task']) + hidden('key', fields['key']) + hidden('identity_type', fields['identity_type'])
    if base:
        options = [('local', 'Local AI'), ('hosted', 'Hosted AI'), ('builtin', 'Built-in workflow')]
        markup += select('mode', 'Assistance provider', options, fields['mode'])
    return markup


def _form(fields, *, policy=False, ranges=None):
    markup = _controls(fields, base=not policy)
    if fields['task'] == 'policy':
        rule = fields['rule']
        markup += '<fieldset><legend>Network rule</legend>'
        if not policy:
            markup += hidden('policy_error', fields['policy_error'])
            for zone, value in fields['ranges'].items():
                markup += hidden(zone, value)
            markup += ('<label>Describe the rule for Local AI<textarea name="prompt" maxlength="1200">'
                       + e(fields['prompt']) + '</textarea></label><p>Hosted AI uses the zone choices below.</p>')
        markup += select('source', 'From zone', [('', 'Choose zone'), *((z, z) for z in ZONES)], rule['source'])
        markup += select('destination', 'To zone', [('', 'Choose zone'), *((z, z) for z in ZONES)], rule['destination'])
        markup += select('action', 'Rule action', [('', 'Choose action'), ('flag', 'Flag this direction'), ('remove', 'Remove this directional rule')], rule['action'])
        if policy:
            markup += '<p>Enter one network range per line in CIDR format.</p>'
            for zone in ZONES:
                markup += '<label>' + e(zone + ' network ranges') + '<textarea name="' + zone + '" maxlength="6000">' + e(ranges[zone]) + '</textarea></label>'
        markup += '</fieldset>'
    if fields['task'] == 'report' and not policy:
        for key in fields['selected']:
            markup += hidden('selected', key)
    return markup


def _links(links):
    return ''.join('<p><a href="' + e(url) + '">Open supporting evidence · ' + e(ref) + '</a></p>' for ref, url in links.items())


def _source_info(task, data):
    if task == 'settings':
        markup = '<ul>'
        for source in data['feeds']:
            markup += '<li>' + e(source['source']) + ' · ' + e(source['health']) + ' · ' + e(source.get('last_success') or 'No data received yet') + '</li>'
        for sensor in data['collectors']:
            markup += '<li>' + e(sensor['type']) + ' · ' + e(sensor['status']) + ' · ' + e(sensor.get('last_success') or 'No data received yet') + '</li>'
        return markup + '</ul><p>Failed imports · ' + str(data['failed_imports']) + '</p>'
    if task == 'report':
        return '<ul>' + ''.join('<li>' + e(row['advisory']) + ' · ' + e(PLAIN_STATUS.get(row['applicability'], row['applicability'])) + '</li>' for row in data['findings']) + '</ul>'
    if task == 'identity':
        states = ('Identity checked' if data['verified'] else 'Identity needs review',
                  'Product mapping recorded' if data['mapping_present'] else 'No product mapping recorded')
        if data.get('conflicting_observations') or data.get('active_version_count', 0) > 1:
            states += ('Conflicting identity evidence',)
        return '<ul>' + ''.join('<li>' + e(state) + '</li>' for state in states) + '</ul>'
    if task == 'ics-advisory':
        record = data['public_advisory']
        return '<h2 translate="no">' + e(record['title']) + '</h2>'
    if task in {'advisory', 'remediation'}:
        record = data['public_advisory']
        markup = '<p translate="no">' + e(record.get('summary', '')) + '</p>' if record.get('summary') else ''
        for product in record.get('affected_products', []):
            markup += '<p translate="no"><strong>' + e(' '.join((product.get('vendor', ''), product.get('product', '')))) + '</strong></p>'
            if product['versions']:
                markup += '<p>Affected versions · ' + e(', '.join(product['versions'])) + '</p>'
            if product['excluded_versions']:
                markup += '<p>Excluded versions · ' + e(', '.join(product['excluded_versions'])) + '</p>'
            if product['conditions_unresolved'] or product['version_semantics_unknown']:
                markup += '<p>Applicability conditions require review.</p>'
        return markup
    return ''


def assistance_page(store, values, *, error=''):
    fields = _fields(values)
    task = fields['task']
    data, fallback, back, links = context(store, task, fields['key'], fields, False)
    markup = ('<p class="notice error" role="alert">' + e(error) + '</p>') if error else ''
    markup += '<p>' + e(fallback) + '</p>' + _links(links) + _source_info(task, data)
    form = _form(fields)
    if task == 'report':
        form = _controls(fields) + '<fieldset><legend>Select up to 12 findings</legend>'
        rows = store.connection.execute('''SELECT f.finding_id,f.cve_id,f.status,a.ip_address FROM findings f
            JOIN assets a USING(asset_id) ORDER BY f.updated_at DESC,f.finding_id LIMIT 30''')
        for row in rows:
            checked = ' checked' if row['finding_id'] in fields['selected'] else ''
            form += '<label class="inline-check"><input type="checkbox" name="selected" value="' + e(row['finding_id']) + '"' + checked + '>' + e(row['cve_id'] + ' · ' + row['ip_address'] + ' · ' + PLAIN_STATUS.get(row['status'], row['status'])) + '</label>'
        form += '</fieldset>'
    markup += '<form method="post" action="/assist">' + form + '<button>Continue</button></form>'
    return layout(TITLES[task], markup + '<p><a href="' + e(back) + '">Return to source</a></p>')


def error_page(store, values, error):
    try:
        return assistance_page(store, values, error=error)
    except ValueError:
        return layout('Assistance unavailable', '<p class="notice error" role="alert">' + e(error)
                      + '</p><p><a href="/">Return to overview</a></p>')


def _prepare(store, fields, language):
    task, mode = fields['task'], fields['mode']
    key = fields['key']
    if mode not in {'local', 'hosted', 'builtin'}:
        raise ValueError('Choose an assistance provider.')
    if task == 'report' and not fields['selected']:
        raise ValueError('Select at least one finding.')
    if task == 'policy' and mode == 'hosted':
        rule = fields['rule']
        if rule['source'] not in ZONES or rule['destination'] not in ZONES or rule['source'] == rule['destination'] or rule['action'] not in OPERATIONS:
            raise ValueError('Choose two different zones and a rule action for Hosted AI.')
        fields = fields | {'prompt': ''}
    config = _provider(mode)
    with store.atomic('assistance_snapshot'):
        data, fallback, back, links = context(store, task, key, fields, mode == 'hosted' and config is not None)
        display = context(store, task, key, fields, False)[0] if task in {'settings', 'advisory', 'remediation'} and mode == 'hosted' else data
        policy = active_policy(store) if task == 'policy' else None
        version = policy_version(store) if task == 'policy' else remediation_version(store, key) if task == 'remediation' else None
    result = {'fields': fields, 'message': fallback, 'back': back, 'links': links,
              'version': version, 'policy': policy, 'context': _source_info(task, display)}
    body = request_body(config, task, data, links, language, mode == 'local') if config else None
    return result, config, body


def _queue(jobs, fields, language, prepared):
    result, config, body = prepared
    task, mode = fields['task'], fields['mode']

    def work(store, update):
        if config is None:
            return result if mode == 'builtin' else result | {'error': 'The selected AI provider is not configured.'}
        try:
            current, active_config, active_body = _prepare(store, fields, language)
            if active_config != config or active_body != body or current['version'] != result['version'] or current['links'] != result['links']:
                raise ValueError('The source or provider changed. Review a new request.')
            draft, model = complete(config, body, task, result['links'], mode == 'local')
            if task == 'policy' and mode == 'hosted' and any(draft[k] != fields['rule'][k] for k in fields['rule']):
                raise ValueError('AI returned a rule different from the reviewed direction.')
            return result | {'draft': draft, 'model': model, 'requested_model': config.model,
                             'mode': mode, 'provider': 'ollama-local' if mode == 'local' else config.provider + '-hosted-reviewed'}
        except (ValueError, RuntimeError, OSError) as exc:
            return result | {'error': str(exc)}

    return '/jobs/' + jobs.submit(TITLES[task], work, deduplicate=False)


def submit_assistance(store, jobs, values, language):
    if _get(values, 'confirm'):
        kind, fields, language, prepared = jobs.consume(_get(values, 'confirm'))
        if kind != 'hosted' or fields['mode'] != 'hosted':
            raise ValueError('This preview cannot authorize a hosted request.')
        return _queue(jobs, fields, language, prepared), None
    if _get(values, 'save_remediation'):
        job_id = _get(values, 'save_remediation')
        result = (jobs.get(job_id) or {}).get('result', {})
        if result.get('fields', {}).get('task') != 'remediation' or not result.get('draft'):
            raise ValueError('This remediation draft has expired. Generate a new draft.')
        key = result['fields']['key']
        generate_plan(store, key, expected_version=result['version'], result=result)
        return '/remediation?' + urlencode({'finding_id': key}), None
    fields = _fields(values)
    if _get(values, 'policy_preview'):
        if fields['task'] != 'policy':
            raise ValueError('This is not a policy draft.')
        version = _get(values, 'version')
        if policy_version(store) != version:
            raise ValueError('The saved policy changed. Start a new preview.')
        rule = fields['rule'] if any(fields['rule'].values()) else None
        try:
            policy = merge_zone_policy(active_policy(store), fields['ranges'], rule)
            changes = preview_policy(store, policy, version)
        except ValueError as exc:
            message = str(exc)
            category = next((index for index, term in enumerate(('overlap', 'network', 'configured zone')) if term in message), 3)
            fields['policy_error'] = POLICY_ERRORS[category]
            result = {'fields': fields, 'message': 'Correct the network ranges or rule and preview again.', 'back': '/policy',
                      'links': {}, 'context': '', 'policy': active_policy(store), 'version': version}
            return None, layout('Review network policy', '<p class="notice error" role="alert">' + e(exc) + '</p>'
                                + result_content(result, '', ranges=fields['ranges']))
        token = jobs.prepare(('policy', policy, version))
        body = '<p>This preview evaluates saved traffic. Saving changes how Phylax flags observations.</p>'
        body += '<ul>' + ''.join('<li>' + e(label) + ' · ' + str(changes[key]) + '</li>' for key, label in
                                 (('events', 'Events checked'), ('added', 'Alerts added'), ('retained', 'Alerts retained'), ('resolved', 'Alerts resolved'))) + '</ul>'
        for status, rows in changes['examples'].items():
            for rule_id, ref in rows:
                body += '<p>' + e(status) + ' · <a href="' + e(evidence_url(ref, '/policy')) + '">' + e(rule_id.replace('_', ' ')) + '</a></p>'
        body += '<details><summary>Proposed policy JSON</summary><pre>' + e(json.dumps(policy, indent=2)) + '</pre></details>'
        body += '<form method="post" action="/policy/apply">' + hidden('preview', token) + '<button>Save reviewed policy</button></form>'
        body += ('<details><summary>Edit this draft</summary><form method="post" action="/assist">'
                 + hidden('policy_preview', 'yes') + hidden('version', version) + _form(fields, policy=True, ranges=fields['ranges'])
                 + '<button>Preview on saved traffic</button></form></details>')
        return None, layout('Preview network policy', body + '<p><a href="/assist?task=policy">Start a new draft</a></p>')
    prepared = _prepare(store, fields, language)
    result, config, body = prepared
    if fields['mode'] == 'hosted' and config is not None:
        token = jobs.prepare(('hosted', result['fields'], language, prepared))
        preview = '<p>Review the request before sending it to the hosted provider.</p><p>' + e(config.provider) + ' · ' + e(_endpoint(config.base_url)) + '</p>'
        preview += '<pre class="assistance-request" translate="no">' + e(body.decode()) + '</pre>'
        preview += '<form method="post" action="/assist">' + hidden('confirm', token) + '<button>Confirm and send to Hosted AI</button></form>'
        return None, layout('Review hosted request', preview + '<p><a href="' + e(result['back']) + '">Return to source</a></p>')
    return _queue(jobs, fields, language, prepared), None


def apply_preview(jobs, token):
    kind, *data = jobs.consume(token)
    if kind != 'policy':
        raise ValueError('This preview cannot authorize a policy change.')
    policy, version = data
    return jobs.submit('Reevaluate passive network policy', lambda store, update: str(reevaluate_events(store, policy, expected_version=version)), deduplicate=False)


def result_content(result, job_id, *, ranges=None):
    fields, draft = result['fields'], result.get('draft')
    task = fields['task']
    body = '<p>' + e(result['message']) + '</p>' + result['context']
    if result.get('error'):
        body += '<p class="notice error" role="status">' + e(result['error']) + '</p>'
    if draft:
        body += '<h2>AI draft for review</h2><p>' + e(result['provider']) + ' · ' + e(result['model']) + '</p>'
        for key, label in (('summary', 'Summary'), ('reason', 'Why it matters'), ('next_step', 'Next check')):
            body += '<h3>' + label + '</h3><p translate="no">' + e(draft[key]) + '</p>'
    references = result['links']
    if draft and draft['evidence']:
        references = {ref: references[ref] for ref in dict.fromkeys(draft['evidence'])}
    body += _links(references)
    if task == 'policy':
        if ranges is None:
            ranges = fields['ranges'] if fields['policy_error'] else {zone: '\n'.join((result['policy'] or {}).get('zone_subnets', {}).get(zone, [])) for zone in ZONES}
        if draft:
            fields = fields | {'rule': {key: draft[key] for key in fields['rule']}}
        body += ('<form method="post" action="/assist">' + hidden('policy_preview', 'yes') + hidden('version', result['version'])
                 + _form(fields, policy=True, ranges=ranges) + '<button>Preview on saved traffic</button></form>')
    if task == 'remediation':
        action = '/assist' if draft else '/remediation/create'
        confirm = hidden('save_remediation', job_id) if draft else hidden('finding_id', fields['key'])
        body += '<form method="post" action="' + action + '">' + confirm + '<button>' + ('Save reviewed draft' if draft else 'Save built-in plan') + '</button></form>'
    body += '<details><summary>Retry or switch provider</summary><form method="post" action="/assist">' + _form(fields) + '<button>Continue</button></form></details>'
    return body + '<p><a href="' + e(result['back']) + '">Return to source</a></p>'
