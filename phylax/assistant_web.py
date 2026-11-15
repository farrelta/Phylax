"""Server-rendered review and consent for local and hosted drafts."""
from __future__ import annotations

import json
from urllib.parse import quote, urlencode

from .ai import AIConfig, _endpoint, local_config
from .assistant_workflows import (REPORT_FOCUSES, ZONES, complete, merge_zone_policy,
                                  report_context, request_body)
from .monitoring import active_policy, policy_version, preview_policy, reevaluate_events
from .reports import selected_report_markdown
from .theme import PLAIN_STATUS, layout
from .ui import e, evidence_url, hidden, select

def _provider(mode):
    if mode == 'local':
        return local_config()
    if mode == 'hosted':
        return AIConfig.from_env()
    return None


def _get(values, key, default=''):
    return values.get(key, [default])[0]


def legacy_destination(store, values):
    task, key = _get(values, 'task'), _get(values, 'key')[:2048]
    if task == 'alert':
        return '/triage?' + urlencode({'alert': key}) + '#alert-' + quote(key, safe='')
    if task == 'settings':
        return '/settings#data-sources'
    if task == 'identity':
        if _get(values, 'identity_type') == 'asset':
            return '/assets/edit?' + urlencode({'asset_id': key})
        return '/software?' + urlencode({'component_id': key}) + '#review-component'
    if task in {'advisory', 'ics-advisory'}:
        path = '/intelligence/ics' if task == 'ics-advisory' else '/intelligence'
        return path + '?' + urlencode({'q': key[:100]})
    if task == 'remediation':
        if store.get_remediation_plan(key):
            return '/remediation?' + urlencode({'finding_id': key}) + '#replace-plan-' + quote(key, safe='')
        return '/?' + urlencode({'finding_id': key}) + '#case-fix'
    return None


def _report_fields(values):
    selected = list(dict.fromkeys(values.get('selected', [])))
    if len(selected) > 12 or any(len(key) > 256 for key in selected):
        raise ValueError('Select up to 12 findings.')
    return {'mode': _get(values, 'mode', 'local' if local_config() else 'builtin'), 'selected': selected}


def _policy_fields(values):
    return {'rule': {key: _get(values, key)[:12] for key in ('source', 'destination', 'action')},
            'ranges': {zone: _get(values, zone)[:6000] for zone in ZONES}}


def _policy_form(rule, ranges, version):
    zones = [('', 'Choose zone'), *((zone, zone) for zone in ZONES)]
    markup = hidden('task', 'policy') + hidden('policy_preview', 'yes') + hidden('version', version)
    markup += '<fieldset><legend>Network rule</legend>'
    markup += select('source', 'From zone', zones, rule['source'])
    markup += select('destination', 'To zone', zones, rule['destination'])
    markup += select('action', 'Rule action', [('', 'Choose action'), ('flag', 'Flag this direction'),
                                               ('remove', 'Remove this directional rule')], rule['action'])
    markup += '<p>Enter one network range per line in CIDR format.</p>'
    for zone in ZONES:
        markup += '<label>' + e(zone + ' network ranges') + '<textarea name="' + zone + '" maxlength="6000">' + e(ranges[zone]) + '</textarea></label>'
    return '<form method="post" action="/assist">' + markup + '</fieldset><button>Preview on saved traffic</button></form>'


def _policy_page(fields, version, error=''):
    markup = '<p class="notice error" role="alert">' + e(error) + '</p>' if error else ''
    markup += '<p>Review network ranges and choose a rule direction before previewing.</p>'
    markup += _policy_form(fields['rule'], fields['ranges'], version)
    return layout('Edit zone rules', markup + '<p><a href="/policy">Return to network policy</a></p>', '/policy')


def assistance_page(store, values, *, error=''):
    task = _get(values, 'task')
    if task == 'policy':
        fields = _policy_fields(values)
        if not _get(values, 'policy_preview'):
            saved = (active_policy(store) or {}).get('zone_subnets', {})
            fields['ranges'] = {zone: '\n'.join(saved.get(zone, [])) for zone in ZONES}
        return _policy_page(fields, policy_version(store), error)
    if task != 'report':
        raise ValueError('Unknown assistance workflow.')

    fields = _report_fields(values)
    selected = fields['selected']
    placeholders = ','.join('?' for _ in selected) or 'NULL'
    rows = list(store.connection.execute(f"""SELECT f.finding_id,f.cve_id,f.status,a.ip_address,a.hostname FROM findings f
        JOIN assets a USING(asset_id) ORDER BY f.finding_id IN ({placeholders}) DESC,
        f.updated_at DESC,f.finding_id LIMIT 30""", selected))
    markup = '<p class="notice error" role="alert">' + e(error) + '</p>' if error else ''
    if rows:
        options = [('builtin', 'Built-in report')]
        if local_config():
            options.append(('local', 'Local AI'))
        if AIConfig.from_env():
            options.append(('hosted', 'Hosted AI'))
        form = hidden('task', 'report')
        form += select('mode', 'Report method', options, fields['mode']) if len(options) > 1 else hidden('mode', 'builtin')
        form += '<fieldset><legend>Select up to 12 findings</legend>'
        for row in rows:
            checked = ' checked' if row['finding_id'] in selected else ''
            label = row['cve_id'] + ' · ' + (row['hostname'] or row['ip_address']) + ' · ' + PLAIN_STATUS.get(row['status'], row['status'])
            form += '<label class="inline-check"><input type="checkbox" name="selected" value="' + e(row['finding_id']) + '"' + checked + '>' + e(label) + '</label>'
        markup += '<form method="post" action="/assist">' + form + '</fieldset><button>Create report</button></form>'
    else:
        markup += '<p>No findings are available for this report.</p>'
    return layout('Create investigation report', markup + '<p><a href="/reports">Return to reports</a></p>', '/reports')


def error_page(store, values, error):
    if _get(values, 'confirm'):
        values = {'task': ['report']}
    try:
        return assistance_page(store, values, error=error)
    except ValueError:
        return layout('Assistance unavailable', '<p class="notice error" role="alert">' + e(error)
                      + '</p><p><a href="/">Return to overview</a></p>')


def _prepare(store, fields, language):
    mode = fields['mode']
    if mode not in {'local', 'hosted', 'builtin'}:
        raise ValueError('Choose an assistance provider.')
    if not fields['selected']:
        raise ValueError('Select at least one finding.')
    config = _provider(mode)
    with store.atomic('assistance_snapshot'):
        data, links = report_context(store, fields['selected'])
        label = store.connection.execute("SELECT value FROM schema_meta WHERE key='dataset_label'").fetchone()
    result = {'fields': fields, 'message': 'Review the selected findings and download the report.', 'links': links,
              'findings': data['findings'], 'language': language, 'dataset_label': label[0] if label else ''}
    body = request_body(config, data, links, language, mode == 'local') if config else None
    return result, config, body


def _queue(jobs, fields, language, prepared):
    result, config, body = prepared
    mode = fields['mode']

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

    return '/jobs/' + jobs.submit('Create investigation report', work, deduplicate=False)


def submit_assistance(store, jobs, values, language):
    if _get(values, 'confirm'):
        kind, fields, language, prepared = jobs.consume(_get(values, 'confirm'))
        if kind != 'hosted':
            raise ValueError('This preview cannot authorize a hosted request.')
        return _queue(jobs, fields, language, prepared), None
    destination = legacy_destination(store, values)
    if destination:
        return destination, None
    task = _get(values, 'task')
    if task == 'policy':
        if not _get(values, 'policy_preview'):
            return None, assistance_page(store, values)
        fields = _policy_fields(values)
        version = _get(values, 'version')
        if policy_version(store) != version:
            raise ValueError('The saved policy changed. Start a new preview.')
        rule = fields['rule'] if any(fields['rule'].values()) else None
        try:
            policy = merge_zone_policy(active_policy(store), fields['ranges'], rule)
            changes = preview_policy(store, policy, version)
        except ValueError as exc:
            return None, _policy_page(fields, version, str(exc))
        token = jobs.prepare(('policy', policy, version))
        body = '<p>This preview evaluates saved traffic. Saving changes how Phylax flags observations.</p>'
        body += '<ul>' + ''.join('<li>' + e(label) + ' · ' + str(changes[key]) + '</li>' for key, label in
                                 (('events', 'Events checked'), ('added', 'Alerts added'), ('retained', 'Alerts retained'), ('resolved', 'Alerts resolved'))) + '</ul>'
        for status, rows in changes['examples'].items():
            for rule_id, ref in rows:
                body += '<p>' + e(status) + ' · <a href="' + e(evidence_url(ref, '/policy')) + '">' + e(rule_id.replace('_', ' ')) + '</a></p>'
        body += '<details><summary>Proposed policy JSON</summary><pre>' + e(json.dumps(policy, indent=2)) + '</pre></details>'
        body += '<form method="post" action="/policy/apply">' + hidden('preview', token) + '<button>Save reviewed policy</button></form>'
        body += '<details><summary>Edit this draft</summary>' + _policy_form(fields['rule'], fields['ranges'], version) + '</details>'
        return None, layout('Preview network policy', body + '<p><a href="/policy">Return to network policy</a></p>', '/policy')
    if task != 'report':
        raise ValueError('Unknown assistance workflow.')
    fields = _report_fields(values)
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
        back = '/assist?' + urlencode({'task': 'report',
                                      'mode': fields['mode'], 'selected': fields['selected']}, doseq=True)
        return None, layout('Review hosted request', preview + '<p><a href="' + e(back) + '">Return to report selection</a></p>')
    return _queue(jobs, fields, language, prepared), None


def apply_preview(jobs, token):
    kind, *data = jobs.consume(token)
    if kind != 'policy':
        raise ValueError('This preview cannot authorize a policy change.')
    policy, version = data
    return jobs.submit('Reevaluate passive network policy', lambda store, update: str(reevaluate_events(store, policy, expected_version=version)), deduplicate=False)


def result_content(result, job_id):
    fields = result['fields']
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
    if 'findings' not in result:
        raise ValueError('This report is unavailable. Create a new report.')
    rows, focus = report_sections(result)
    links = {ref: origin + link for ref, link in result['links'].items()}
    return selected_report_markdown(rows, focus, links, result['language'], result['dataset_label'])
