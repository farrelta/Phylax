"""Server-rendered review and consent for local and hosted drafts."""
from __future__ import annotations

import json
from urllib.parse import urlencode

from .advisory_views import render_facts
from .ai import AIConfig, _endpoint, local_config
from .assistant_workflows import (ADVISORY_TASKS, BUILTIN_TASKS, REPORT_FOCUSES, TITLES, ZONES, complete, context,
                                  merge_zone_policy, request_body)
from .monitoring import active_policy, policy_version, preview_policy, reevaluate_events
from .reports import selected_report_markdown
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
    if task == 'policy' or task in BUILTIN_TASKS:
        values = values | {'mode': ['builtin']}
    if task not in TITLES:
        raise ValueError('Unknown assistance workflow.')
    selected = list(dict.fromkeys(value[:256] for value in values.get('selected', [])))
    if len(selected) > 12:
        raise ValueError('Select up to 12 findings.')
    return {'task': task, 'key': _get(values, 'key')[:2048 if task == 'ics-advisory' else 256], 'identity_type': _get(values, 'identity_type')[:10],
            'mode': _get(values, 'mode', 'local' if local_config() else 'builtin'),
            'selected': selected,
            'rule': {key: _get(values, key)[:12] for key in ('source', 'destination', 'action')},
            'ranges': {zone: _get(values, zone)[:6000] for zone in ZONES},
            'policy_error': _get(values, 'policy_error') if _get(values, 'policy_error') in POLICY_ERRORS else ''}


def _controls(fields, *, base=True):
    markup = hidden('task', fields['task']) + hidden('key', fields['key']) + hidden('identity_type', fields['identity_type'])
    if base:
        options = [('builtin', 'Built-in report')]
        if local_config():
            options.append(('local', 'Local AI'))
        if AIConfig.from_env():
            options.append(('hosted', 'Hosted AI'))
        if len(options) > 1:
            markup += select('mode', 'Report method', options, fields['mode'])
        else:
            markup += hidden('mode', 'builtin')
    return markup


def _form(fields, *, policy=False, ranges=None):
    markup = _controls(fields, base=not policy)
    if fields['task'] == 'policy':
        rule = fields['rule']
        markup += '<fieldset><legend>Network rule</legend>'
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
            status = 'Cached advisory data' if source['health'] == 'cached' else source['health']
            markup += '<li>' + e(source['source']) + ' · ' + e(status)
            if source['health'] != 'cached':
                markup += ' · ' + e(source.get('last_success') or 'No synchronization recorded')
            markup += '</li>'
        for sensor in data['collectors']:
            markup += '<li>' + e(sensor['type']) + ' · ' + e(sensor['status']) + ' · ' + e(sensor.get('last_success') or 'No data received yet') + '</li>'
        return markup + '</ul><p>Failed imports · ' + str(data['failed_imports']) + '</p>'
    if task == 'alert':
        if data.get('category') == 'vulnerability exposure':
            return '<p>' + e(data['advisory']) + ' · ' + e(data['applicability']) + '</p>'
        if data.get('category') == 'device management':
            label = {'unmanaged': 'Unmanaged endpoint', 'approved': 'Approved endpoint',
                     'unauthorized': 'Explicitly blocked in device management',
                     'needs_identity_review': 'Identity needs review'}.get(data['management_status'], 'Unknown')
            return '<p>' + e(label) + '</p>'
    if task == 'report':
        return '<ol>' + ''.join(
            '<li>' + e(row['device']) + ' · ' + e(row['advisory']) + ' · ' + e(row['applicability']) + ' · ' + e(row['evidence']) + '</li>'
            for row in data['findings']
        ) + '</ol>'
    if task == 'identity':
        states = ('Identity checked' if data['verified'] else 'Identity needs review',
                  'Product mapping recorded' if data['mapping_present'] else 'No product mapping recorded')
        if data.get('conflicting_observations') or data.get('active_version_count', 0) > 1:
            states += ('Conflicting identity evidence',)
        markup = '<ul>' + ''.join('<li>' + e(state) + '</li>' for state in states)
        if data.get('reported_version'):
            markup += '<li>Reported version · <span translate="no">' + e(data['reported_version']) + '</span></li>'
        return markup + '</ul>'
    if task in ADVISORY_TASKS:
        return '<h2 translate="no">' + e(data['title']) + '</h2>' + render_facts(data['passages'])
    if task == 'remediation':
        record = data['public_advisory']
        markup = '<p translate="no">' + e(record.get('summary', '')) + '</p>' if record.get('summary') else ''
        markup = '<p>Recorded applicability · ' + e(data['applicability']['applicability']) + '</p>' + markup
        for product in (record.get('affected_products') or [])[:4]:
            markup += '<p translate="no"><strong>' + e(' '.join((product.get('vendor', ''), product.get('product', '')))) + '</strong></p>'
            if (product.get('versions') or []):
                markup += '<p>Affected versions · ' + e(', '.join((product.get('versions') or []))) + '</p>'
            if (product.get('excluded_versions') or []):
                markup += '<p>Excluded versions · ' + e(', '.join((product.get('excluded_versions') or []))) + '</p>'
            if product.get('conditions_unresolved') or product.get('version_semantics_unknown'):
                markup += '<p>Applicability conditions require review.</p>'
        return markup
    return ''


def assistance_page(store, values, *, error=''):
    fields = _fields(values)
    task = fields['task']
    data, fallback, back, links = context(store, task, fields['key'], fields)
    markup = ('<p class="notice error" role="alert">' + e(error) + '</p>') if error else ''
    if task == 'policy':
        policy = active_policy(store) or {}
        result = {'fields': fields, 'message': fallback, 'back': '/policy', 'links': {},
                  'version': policy_version(store), 'policy': policy, 'context': ''}
        return layout(TITLES[task], markup + result_content(result, ''))
    markup += '<p>' + e(fallback) + '</p>' + _links(links) + _source_info(task, data)
    if task in BUILTIN_TASKS:
        title = 'Review steps' if task == 'remediation' else 'Built-in explanation'
        if task == 'remediation':
            action = '<form method="post" action="/remediation/create">'
            markup += action + hidden('finding_id', fields['key']) + '<button>Save built-in plan</button></form>'
        return layout(title, markup + '<p><a href="' + e(back) + '">Return to source</a></p>')
    form = _form(fields)
    if task == 'report':
        form = _controls(fields) + '<fieldset><legend>Select up to 12 findings</legend>'
        selected = fields['selected']
        placeholders = ','.join('?' for _ in selected) or 'NULL'
        rows = list(store.connection.execute(f'''SELECT f.finding_id,f.cve_id,f.status,a.ip_address,a.hostname FROM findings f
            JOIN assets a USING(asset_id) ORDER BY f.finding_id IN ({placeholders}) DESC,
            f.updated_at DESC,f.finding_id LIMIT 30''', selected))
        if not rows:
            return layout(TITLES[task], markup + '<p>No findings are available for this report.</p><p><a href="/reports">Return to reports</a></p>', '/reports')
        for row in rows:
            checked = ' checked' if row['finding_id'] in fields['selected'] else ''
            form += '<label class="inline-check"><input type="checkbox" name="selected" value="' + e(row['finding_id']) + '"' + checked + '>' + e(row['cve_id'] + ' · ' + (row['hostname'] or row['ip_address']) + ' · ' + PLAIN_STATUS.get(row['status'], row['status'])) + '</label>'
        form += '</fieldset>'
    label = 'Create report'
    markup += '<form method="post" action="/assist">' + form + '<button>' + label + '</button></form>'
    return layout(TITLES[task], markup + '<p><a href="' + e(back) + '">Return to reports</a></p>', '/reports')


def error_page(store, values, error):
    if _get(values, 'confirm'):
        values = {'task': ['report']}
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
    config = _provider(mode)
    with store.atomic('assistance_snapshot'):
        data, fallback, back, links = context(store, task, key, fields)
        label = store.connection.execute("SELECT value FROM schema_meta WHERE key='dataset_label'").fetchone()
    result = {'fields': fields, 'message': fallback, 'back': back, 'links': links,
              'findings': data['findings'], 'language': language, 'dataset_label': label[0] if label else ''}
    body = request_body(config, data, links, language, mode == 'local') if config else None
    return result, config, body


def _queue(jobs, fields, language, prepared):
    result, config, body = prepared
    task, mode = fields['task'], fields['mode']

    def work(store, update):
        if config is None:
            return result if mode == 'builtin' else result | {'error': 'The selected AI provider is not configured. The built-in report is ready.'}
        try:
            current, active_config, active_body = _prepare(store, fields, language)
            if active_config != config or active_body != body or current != result:
                raise ValueError('The source or provider changed. Review a new request.')
            draft, model = complete(config, body, result['links'], mode == 'local')
            return result | {'draft': draft, 'model': model, 'requested_model': config.model,
                             'mode': mode, 'provider': 'ollama-local' if mode == 'local' else config.provider + '-hosted-reviewed'}
        except (ValueError, RuntimeError, OSError) as exc:
            return result | {'error': str(exc)}

    return '/jobs/' + jobs.submit(TITLES[task], work, deduplicate=False)


def submit_assistance(store, jobs, values, language):
    if _get(values, 'confirm'):
        kind, fields, language, prepared = jobs.consume(_get(values, 'confirm'))
        if kind != 'hosted' or fields['mode'] != 'hosted' or fields['task'] != 'report':
            raise ValueError('This preview cannot authorize a hosted request.')
        return _queue(jobs, fields, language, prepared), None
    fields = _fields(values)
    if fields['task'] in BUILTIN_TASKS:
        return None, assistance_page(store, values)
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
    if fields['task'] == 'policy':
        return None, assistance_page(store, values)
    prepared = _prepare(store, fields, language)
    result, config, body = prepared
    if fields['mode'] == 'hosted' and config is not None:
        try:
            endpoint = _endpoint(config.base_url)
        except ValueError:
            return _queue(jobs, fields, language, (result, None, None)), None
        token = jobs.prepare(('hosted', result['fields'], language, prepared))
        preview = '<p>Review the request before sending it to the hosted provider.</p><p>' + e(config.provider) + ' · ' + e(endpoint) + '</p>'
        preview += '<p>This request includes finding statuses, priorities, evidence-gap counts and anonymous evidence IDs.</p>'
        preview += '<details open><summary>View exact outgoing request</summary>'
        preview += '<pre class="assistance-request" translate="no">' + e(body.decode()) + '</pre></details>'
        preview += '<form method="post" action="/assist">' + hidden('confirm', token) + '<button>Confirm and send to Hosted AI</button></form>'
        back = '/assist?' + urlencode({'task': fields['task'], 'key': fields['key'],
                                      'mode': fields['mode'], 'selected': fields['selected']}, doseq=True)
        return None, layout('Review hosted request', preview + '<p><a href="' + e(back) + '">Return to report selection</a></p>')
    return _queue(jobs, fields, language, prepared), None


def apply_preview(jobs, token):
    kind, *data = jobs.consume(token)
    if kind != 'policy':
        raise ValueError('This preview cannot authorize a policy change.')
    policy, version = data
    return jobs.submit('Reevaluate passive network policy', lambda store, update: str(reevaluate_events(store, policy, expected_version=version)), deduplicate=False)


def result_content(result, job_id, *, ranges=None):
    fields = result['fields']
    if fields['task'] == 'policy':
        if ranges is None:
            ranges = {zone: '\n'.join(result['policy'].get('zone_subnets', {}).get(zone, [])) for zone in ZONES}
        return ('<p>' + e(result['message']) + '</p><form method="post" action="/assist">'
                + hidden('policy_preview', 'yes') + hidden('version', result['version'])
                + _form(fields, policy=True, ranges=ranges)
                + '<button>Preview on saved traffic</button></form><p><a href="/policy">Return to network policy</a></p>')
    rows, focus = report_sections(result)
    draft = result.get('draft')
    body = '<p>' + e(result['message']) + '</p>'
    if result.get('error'):
        body += '<p class="notice error" role="status">' + e(result['error']) + '</p>'
    body += '<h2>' + ('AI-organized report' if draft else 'Built-in report') + '</h2>'
    if draft:
        body += '<p>' + e(result['model']) + '</p><p>' + e(focus) + '</p>'
    body += '<p><a class="btn primary" href="/reports/draft.md?' + e(urlencode({'job': job_id}))
    body += '">Download Markdown report</a></p><ol>'
    for row in rows:
        link = result['links'][row['evidence']]
        body += ('<li><a href="' + e(link) + '">' + e(row['advisory']) + ' · ' + e(row['name'])
                 + '</a><br>' + e(row['applicability']) + ' · ' + e(row['priority']))
        if row['missing_evidence']:
            body += '<ul>' + ''.join('<li>' + e(item) + '</li>' for item in row['missing_evidence']) + '</ul>'
        body += '</li>'
    body += '</ol>'
    selection = urlencode({'task': 'report', 'mode': fields['mode'], 'selected': fields['selected']}, doseq=True)
    return body + '<p><a href="/assist?' + e(selection) + '">Edit selection</a> · <a href="/reports">Return to reports</a></p>'


def report_sections(result):
    draft = result.get('draft')
    rows = result['findings']
    if draft:
        by_ref = {row['evidence']: row for row in rows}
        return [by_ref[ref] for ref in draft['evidence']], REPORT_FOCUSES[draft['focus']]
    return rows, ''


def report_download(jobs, job_id, origin):
    job = jobs.get(job_id) or {}
    result = job.get('result', {})
    if result.get('fields', {}).get('task') != 'report':
        raise ValueError('This report is unavailable. Create a new report.')
    rows, focus = report_sections(result)
    links = {ref: origin + link for ref, link in result['links'].items()}
    return selected_report_markdown(rows, focus, links, result['language'], result['dataset_label'])
