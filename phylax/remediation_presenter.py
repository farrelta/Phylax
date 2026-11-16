"""Readable remediation guidance without changing review or execution semantics."""

from __future__ import annotations

import ast
import json
import re
from urllib.parse import urlencode

from .remediation_views import alert_plan_fields, lifecycle_form
from .alert_fix_plans import closure_error
from .remediation import CONFIRMED, EXCLUDED, next_step
from .remediation_lifecycle import plan_review_block
from .theme import PLAIN_STATUS
from .triage import alert_url
from .ui import e, evidence_url, field, reference_links, verbatim, form, hidden


def _text(value) -> str:
    if value is None:
        return "Not recorded"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    text = str(value)
    for code, label in PLAIN_STATUS.items():
        text = text.replace(code, label)
    return text


def _items(value) -> list:
    if value is None or value == "":
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _content(value, *, source=False) -> str:
    """Keep stored structured values readable and escaped, including legacy data."""
    if source:
        return verbatim(value if isinstance(value,str) else json.dumps(value,ensure_ascii=False))
    if isinstance(value, dict):
        return '<dl class="facts">' + "".join(
            '<div><dt>' + e(str(key).replace('_', ' ').capitalize())
            + '</dt><dd>' + _content(item) + '</dd></div>'
            for key, item in value.items()
        ) + '</dl>'
    if isinstance(value, (list, tuple)):
        return _list(value)
    return e(_text(value))


def _list(values, empty="None recorded.", *, ordered=False, source=False) -> str:
    values = _items(values)
    if not values:
        return '<p class="muted">' + e(empty) + '</p>'
    tag = 'ol' if ordered else 'ul'
    return '<' + tag + '>' + ''.join('<li>' + _content(v,source=source) + '</li>' for v in values) + '</' + tag + '>'


def _paragraph(label, value, *, source=False) -> str:
    return '<p><b>' + e(label) + ':</b> ' + _content(value if value not in (None, '') else 'Not recorded',source=source and value not in (None,'')) + '</p>'


def _section(label, body, *, opened=False, css='', section_id='') -> str:
    return '<details' + (' id="' + e(section_id) + '"' if section_id else '') + (' class="' + e(css) + '"' if css else '') + (' open' if opened else '') + '><summary>' + e(label) + '</summary><div class="plan-section-body">' + body + '</div></details>'


def _references(values) -> str:
    rendered = reference_links(_items(values))
    return '<p class="plan-references">' + rendered + '</p>' if rendered else '<p class="muted">No source references are stored.</p>'


def _confidence(value) -> tuple[dict, str]:
    if isinstance(value, dict):
        return value, ''
    if isinstance(value, str):
        # Older stored plans can contain either JSON or a Python literal string.
        # literal_eval reads data only; it does not execute names or expressions.
        for decoder in (json.loads, ast.literal_eval):
            try:
                parsed = decoder(value)
            except (ValueError, SyntaxError, TypeError, RecursionError):
                continue
            if isinstance(parsed, dict):
                return parsed, ''
            if isinstance(parsed, (list, tuple)):
                return {'unresolved': list(parsed)}, ''
        return {}, value
    return {}, ''


def _score(plan) -> str:
    factors = _items(plan.get('priority_factors'))
    explanation = plan.get('priority_explanation') or 'No priority explanation is stored.'
    # The local template stores the same inputs twice. Preserve its narrative
    # and every factor once, rather than showing a second semicolon paragraph.
    suffix = 'Plan generation does not recalculate or change it.'
    if (factors and isinstance(explanation, str)
            and explanation.startswith('Existing deterministic Phylax priority: ')
            and ' Inputs: ' in explanation and explanation.endswith(suffix)):
        explanation = explanation.split(' Inputs: ', 1)[0] + ' ' + suffix
    rows, notes = [], []
    for factor in factors:
        if isinstance(factor, dict) and 'input' in factor:
            label, value, points = factor['input'], factor.get('value', 'Unknown'), factor.get('points')
        elif isinstance(factor, str):
            match = re.fullmatch(r'(.+?): (.+) \(\+(-?\d+(?:\.\d+)?)\)', factor)
            if not match:
                notes.append(factor)
                continue
            label, value, points = match.groups()
            if value in ('True', 'False'):
                value = value == 'True'
        else:
            notes.append(factor)
            continue
        rows.append('<div><dt>' + e(label) + '</dt><dd>' + _content(value)
                    + (' · ' + e(points) + ' points' if points is not None else '') + '</dd></div>')
    generated_priority = plan.get('recommended_priority')
    return (_paragraph('Priority at generation', _text(generated_priority).replace('_', ' ').capitalize())
            + '<p>' + _content(explanation) + '</p>'
            + ('<dl class="plan-score-factors">' + ''.join(rows) + '</dl>' if rows else '')
            + (_list(notes) if notes else ''))


def _history(items) -> str:
    rows = []
    for item in items or []:
        rows.append('<li><b>' + e(item.get('old_status', 'Not recorded')) + ' → '
                    + e(item.get('new_status', 'Not recorded')) + '</b> · '
                    + (verbatim(item['actor']) if item.get('actor') else e('system')) + ' · '
                    + e(item.get('created_at', 'Not recorded'))
                    + ('<p>' + (e(item['notes']) if item.get('actor')=='system' else verbatim(item['notes'])) + '</p>' if item.get('notes') else '') + '</li>')
    return '<ol>' + ''.join(rows) + '</ol>' if rows else '<p>No lifecycle changes recorded.</p>'


def _checklist_row(title, state, content=''):
    current = ' aria-current="step"' if state == 'Next step' else ''
    return ('<li' + current + '><div class="plan-checkline"><strong>' + e(title) + '</strong>'
            + '<span>' + e(state) + '</span></div>' + content + '</li>')


def closure_summary(item):
    body = '<div class="notice"><p><b>Closed by operator</b></p>'
    body += _paragraph('Operator name', item['closed_by'], source=True)
    body += _paragraph('Closure reason', item['closure_reason'], source=True)
    return body + _paragraph('Closed UTC', item['closed_at']) + '</div>'


def alert_plan_card(item, submitted=None, error=''):
    alert = item['alert']
    plan_status = item['status']
    prefix = 'plan-' + item['alert_id']
    stale = item['evidence_revision'] != alert['revision'] or plan_status == 'Needs More Evidence'
    closed = bool(item['closed_at'])
    approved = (closed or not stale) and plan_status in {'Approved', 'Implemented', 'Verified'}
    implemented = approved and plan_status in {'Implemented', 'Verified'}
    verified = implemented and plan_status == 'Verified' and bool(item['verification_evidence'].strip())
    review = '<a href="#' + e(prefix) + '-status">Open plan review</a>'
    case_url = alert_url(item['alert_id'])
    links = '<a href="' + e(case_url) + '">Open alert</a>'
    evidence = item['history'][-1]['snapshot']['alert'] if closed else alert
    if evidence['event_ref']:
        label = 'Original event' if item['category'] == 'network' else 'Recorded device evidence'
        links += ' · <a href="' + e(evidence_url(evidence['event_ref'], case_url)) + '">' + e(label) + '</a>'
    if item['category'] == 'network':
        category = 'Network policy'
        title = alert['source_ip'] + ' → ' + alert['destination_ip']
        evidence_step = 'Review the recorded connection and rule with the network owner.'
    else:
        category = 'Device management'
        title = alert['ip']
        evidence_step = 'Confirm the device identity, ownership and authorization on this subnet.'
        links += ' · <a href="/approvals?' + e(urlencode({'ip': alert['ip']})) + '">Review management approval</a>'
    body = '<article class="panel plan" id="' + e(prefix) + '"><header class="plan-header"><h2>' + verbatim(title) + '</h2>'
    shown_status = 'Needs More Evidence' if stale and not closed else plan_status
    body += '<p>' + e(category) + '</p></header>' + _paragraph('Plan status', shown_status)
    body += '<div class="record-actions">' + links + '</div>'
    if closed:
        body += closure_summary(item)
        body += _paragraph('Recorded verification evidence', item['verification_evidence'], source=True)
    elif alert['state'] == 'resolved':
        reason = ('This policy alert was resolved after reevaluation.' if item['category'] == 'network'
                  else 'This device management alert was resolved.')
        body += '<p class="notice">' + e(reason) + '</p>'
    review_error = error if submitted and 'status' in submitted and not stale and not closed else ''
    if error and not review_error:
        body += '<p class="notice error" role="alert">' + e(error) + '</p>'
    if stale and not closed:
        replacement = form('/remediation/create', alert_plan_fields(item), 'Generate replacement plan')
        body += ('<section class="plan-checklist"><h3>Fix plan checklist</h3><ol>'
                 + _checklist_row('Review alert evidence', 'Next step', '<p>' + e(evidence_step) + '</p>' + replacement)
                 + '</ol></section>')
    else:
        paused = plan_status in {'Deferred', 'Rejected'}
        in_review = plan_status == 'Under Review' or approved
        prep_state = 'Recorded' if in_review else 'Pending' if paused else 'Next step'
        prep_content = '<p>' + e(evidence_step) + (' ' + review if not in_review and not paused else '') + '</p>'
        approval_content = '<p>Document the corrective action and check operational impact before recording approval. ' + review + '</p>' if plan_status == 'Under Review' else ''
        outcome = ''
        if implemented:
            outcome += '<p>Implementation recorded.</p>'
        if verified:
            outcome += '<p>Verification evidence recorded.</p>'
        elif approved:
            outcome += '<p>' + e('Record verification evidence.' if implemented else 'Record implementation.') + ' ' + review + '</p>'
        body += ('<section class="plan-checklist"><h3>Fix plan checklist</h3><ol>'
                 + _checklist_row('Review alert evidence', prep_state, prep_content)
                 + _checklist_row('Record approval', 'Recorded' if approved else 'Next step' if plan_status == 'Under Review' else 'Pending', approval_content)
                 + _checklist_row('Record implementation and verify the outcome', 'Recorded' if verified else 'Next step' if approved else 'Pending', outcome)
                 + '</ol></section>')
        if not closed:
            body += _section('Review plan', lifecycle_form(item, submitted, review_error),
                             opened=bool(review_error), css='plan-review')
        if verified and alert['state'] == 'active':
            values = submitted or {}
            if reason := closure_error(item, alert, item['history'][-1]['snapshot']['alert']):
                body += '<p class="notice">' + e(reason) + ' ' + review + '</p>'
            else:
                inputs = alert_plan_fields(item)
                inputs += field('actor', 'Operator name', values.get('actor', ''), maxlength=120, required=True)
                inputs += field('note', 'Closure reason', values.get('note', ''), maxlength=4000, required=True)
                body += form('/remediation/close', inputs, 'Close with verified evidence')
    history = []
    for event in item['history']:
        snapshot = event['snapshot']
        details = ''.join(_paragraph(label, snapshot[key], source=True) for key, label in
                          (('reviewer','Recorded reviewer'), ('change_notes','Recorded change notes'),
                           ('verification_evidence','Recorded verification evidence'),
                           ('closed_by','Operator name'), ('closure_reason','Closure reason')) if snapshot.get(key))
        history.append('<li><b>' + e(event['action']) + '</b> · ' + e(event['recorded_at']) + details + '</li>')
    body += _section('Lifecycle history', '<ol>' + ''.join(history) + '</ol>')
    return body + '</article>'


def _fix_checklist(item, blocked):
    applicability = item.get('finding_status') or 'NEEDS_REVIEW'
    finding_id = item['finding_id']
    evidence_url = '/?' + urlencode({'finding_id': finding_id}) + '#case-evidence'
    evidence = '<a href="' + e(evidence_url) + '">Review current finding</a>'
    if applicability == EXCLUDED:
        return '<p>' + e(next_step(applicability, '')) + ' ' + evidence + '</p>'

    status = item['status']
    paused = status in {'Deferred', 'Rejected'}
    current = not blocked
    approved = current and status in {'Approved', 'Implemented', 'Verified'}
    implemented = approved and status in {'Implemented', 'Verified'}
    verified = implemented and status == 'Verified' and bool((item.get('verification_evidence') or '').strip())
    review = '<a href="' + e('#plan-' + finding_id + '-status') + '">Open plan review</a>'
    heading = '<section class="plan-checklist"><h3>Fix plan checklist</h3>'
    if paused:
        decision = 'Plan deferred.' if status == 'Deferred' else 'Plan rejected.'
        heading += '<p>' + e(decision) + ' ' + review + '</p>'

    if applicability == CONFIRMED:
        confirm = _checklist_row('Confirm device identity and applicability', 'Recorded')
    else:
        details = '<p>' + e(next_step(applicability, '')) + ' ' + evidence + '</p>'
        if missing := item.get('current_missing_evidence'):
            details += _list(missing)
        confirm = _checklist_row('Confirm device identity and applicability',
                                 'Pending' if paused else 'Next step', details)

    preparation = 'Pending'
    preparation_details = ''
    if applicability == CONFIRMED and not paused:
        if blocked:
            preparation = 'Next step'
            replacement = '<a href="' + e('#replace-plan-' + finding_id) + '">Generate replacement plan</a>'
            preparation_details = '<p>' + e(blocked) + ' ' + replacement + '</p>'
        elif status in {'Under Review', 'Approved', 'Implemented', 'Verified'}:
            preparation = 'Recorded'
        else:
            preparation = 'Next step'
            preparation_details = '<p>' + e(next_step(applicability, item.get('current_mitigation'))) + ' ' + review + '</p>'

    approval = 'Recorded' if approved else 'Pending'
    approval_details = ''
    if current and status == 'Under Review':
        approval = 'Next step'
        approval_details = ('<p>Check the maintenance window and rollback plan before recording approval. '
                            + review + '</p>')

    outcome = 'Recorded' if verified else 'Pending'
    outcome_details = '<p>Implementation recorded.</p>' if implemented else ''
    if verified:
        outcome_details += '<p>Verification evidence recorded.</p>'
    elif approved:
        outcome = 'Next step'
        action = 'Record verification evidence.' if implemented else 'Record implementation.'
        if status == 'Verified':
            action = 'Reopen plan review to record verification evidence.'
        outcome_details += '<p>' + e(action) + ' ' + review + '</p>'

    return (heading + '<ol>' + confirm
            + _checklist_row('Prepare the current plan for review', preparation, preparation_details)
            + _checklist_row('Record approval', approval, approval_details)
            + _checklist_row('Record implementation and verify the outcome', outcome, outcome_details)
            + '</ol></section>')


def plan_card(item, submitted=None, error='') -> str:
    """Render one stored plan with exactly one existing lifecycle form."""
    plan = item['plan']
    prefix = 'plan-' + str(item['finding_id'])
    asset = item.get('hostname') or item.get('ip_address') or 'Unknown asset'
    confidence, legacy_confidence = _confidence(plan.get('confidence_and_questions'))
    stored_applicability = confidence.get('applicability')
    applicability = item.get('finding_status') or 'NEEDS_REVIEW'
    questions = confidence.get('unresolved', [])
    priority = item.get('priority') or 'unknown'
    facts = [('Current priority', _text(priority).replace('_', ' ').capitalize()),
             ('Current identity confidence', item.get('current_identity_confidence') or 'Unknown'),
             ('Human approval required:', plan.get('human_approval_required', True))]
    body = '<article class="panel plan" id="' + e(prefix) + '"><header class="plan-header"><h2>' + verbatim(asset) + '</h2>'
    body += '<p class="mono">' + e(item.get('cve_id', 'Finding')) + '</p></header><div class="plan-summary">'
    body += _paragraph('Plan status', item.get('status', 'Unknown'))
    current_mitigation = item.get('current_mitigation', '')
    revision = plan.get('finding_revision')
    evidence_changed = (revision != item.get('current_finding_revision') if revision
                        else bool(stored_applicability and stored_applicability != applicability))
    blocked = plan_review_block(item)
    body += _fix_checklist(item, blocked)
    if evidence_changed:
        body += '<div class="notice"><p><b>Evidence review required.</b></p>'
        body += '<p>Supporting finding evidence has changed since this plan was generated.</p>'
        body += '</div>'
    body += _paragraph('Current applicability', _text(applicability))
    history = item.get('history', [])
    if (not history or history[-1].get('actor') == 'system') and not any(item.get(key) for key in ('reviewer', 'change_notes', 'verification_evidence')):
        body += '<p class="muted">No review recorded yet.</p>'
    body += '</div>'

    matching = submitted and submitted.get('finding_id') == item['finding_id']
    review = (_paragraph('Recorded reviewer', item.get('reviewer') or 'Not recorded',source=bool(item.get('reviewer')))
              + _paragraph('Recorded change notes', item.get('change_notes') or 'None',source=bool(item.get('change_notes')))
              + _paragraph('Recorded verification evidence', item.get('verification_evidence') or 'Not recorded',source=bool(item.get('verification_evidence')))
              + lifecycle_form(item, submitted if matching else None, error if matching else ''))
    body += _section('Review plan', review,
                     opened=bool(matching and error), css='plan-review', section_id=prefix+'-review')
    current_details = '<dl class="facts">' + ''.join(
        '<div><dt>' + e(label) + '</dt><dd>' + _content(value) + '</dd></div>'
        for label, value in facts) + '</dl>' + _paragraph('Operational impact', plan.get('operational_impact'))
    current_details += '<h3>Current missing evidence</h3>' + _list(item.get('current_missing_evidence'), 'No missing evidence is recorded for the current finding.')
    body += _section('Current finding details', current_details)

    guidance = _paragraph('Vendor guidance status', plan.get('vendor_guidance_status'))
    if current_mitigation:
        guidance += _paragraph('Stored advisory mitigation', current_mitigation, source=True)
    if plan.get('preferred_remediation') and plan['preferred_remediation'] != current_mitigation:
        guidance += _paragraph('Guidance at plan generation', plan['preferred_remediation'], source=str(plan.get('vendor_guidance_status','')).startswith('source-provided'))
    guidance += '<h3>Alternative controls</h3>' + _list(plan.get('alternative_controls'))
    if plan.get('cisa_required_action'):
        guidance += _paragraph('CISA required action', plan['cisa_required_action'],source=True)
    if plan.get('ai_summary'):
        guidance += '<section class="notice plan-ai"><h3>AI-generated, unverified supplement</h3>'
        guidance += _paragraph('Model', plan.get('returned_model') or item.get('model') or 'Not recorded',source=True)
        guidance += _paragraph('Plan created UTC', item.get('created_at', 'Not recorded'))
        guidance += '<p>' + _content(plan['ai_summary'],source=True) + '</p>' + _list(plan.get('ai_steps'), ordered=True,source=True)
        guidance += _paragraph('Suggested validation', plan.get('ai_validation'),source=True)
        guidance += '<h4>Validated source references</h4>' + _references(plan.get('ai_source_references'))
        guidance += '<p>Only eligible public advisory data was sent to the hosted model. Local asset identities, inventory, network events, policies and operational context were not sent. This supplement does not change applicability, priority, approvals or recorded outcomes.</p></section>'
    label = 'Advisory guidance for reference' if blocked else 'Guidance and alternative controls'
    if plan.get('ai_summary'):
        label += ' · includes unverified AI supplement'
    body += '<div class="plan-sections">'
    body += _section('Prerequisites and approvals', _list(plan.get('preconditions'), ordered=True))
    body += _section(label, guidance, opened=not blocked)
    body += _section('Validation and outcome verification', '<h3>Before an approved change</h3>' + _list(plan.get('validation_steps'), ordered=True)
                     + '<h3>After remediation</h3>' + _list(plan.get('post_remediation_verification'), ordered=True))
    body += _section('Rollback and recovery', _list(plan.get('rollback_considerations')))
    evidence = '<p class="muted">This is the stored assessment snapshot from plan generation. Current applicability and priority are shown above; this snapshot does not update when finding evidence changes.</p>'
    evidence += _paragraph('Applicability at generation', stored_applicability)
    evidence += _paragraph('Identity confidence at generation', confidence.get('identity_confidence') or 'Not recorded')
    evidence += '<h3>Unresolved evidence and questions at generation</h3>' + _list(questions, 'No unresolved evidence was recorded at generation. This does not establish safety.')
    if legacy_confidence:
        evidence += _paragraph('Stored confidence notes at generation', legacy_confidence)
    extra_confidence = {k: v for k, v in confidence.items() if k not in ('applicability', 'identity_confidence', 'unresolved')}
    if extra_confidence:
        evidence += '<h3>Other confidence details at generation</h3>' + _content(extra_confidence)
    summary=plan.get('finding_summary')
    prefix, separator, source_summary=str(summary or '').partition(': ')
    if separator and any(code in prefix for code in PLAIN_STATUS):
        evidence += '<p><b>Finding summary at generation:</b> '+e(_text(prefix))+': '+verbatim(source_summary)+'</p>'
    else:
        evidence += _paragraph('Finding summary at generation', summary,source=True)
    if plan.get('evidence'):
        evidence += '<h3>Supporting evidence at generation</h3>' + _list(plan['evidence'])
    evidence += '<h3>Priority factors at generation</h3>' + _score(plan)
    body += _section('Assessment snapshot and priority factors at generation', evidence)

    source = _paragraph('Plan source', plan.get('provider_note') or item.get('provider') or 'Not recorded')
    source += _paragraph('Provider identifier', item.get('provider', 'Not recorded'),source=True)
    source += _paragraph('Created UTC', item.get('created_at', 'Not recorded'))
    for key, label in (('model', 'Recorded model'), ('requested_model', 'Requested model'), ('returned_model', 'Returned model')):
        value = item.get(key) if key == 'model' else plan.get(key)
        if value:
            source += _paragraph(label, value,source=True)
    source += '<h3>Source references</h3>' + _references(plan.get('source_references'))
    body += _section('Provenance and source references', source)
    body += _section('Lifecycle history', _history(item.get('history')))
    if applicability != EXCLUDED:
        replacement = '<p>Generating a replacement archives this plan and clears its review and verification state.</p>'
        replacement += form('/remediation/create', hidden('finding_id', item['finding_id'])
                            + hidden('replace_plan_id', item['plan_id']) + hidden('replace_plan_version', len(item['history'])),
                            'Generate replacement plan')
        body += _section('Replace plan', replacement, opened=applicability == CONFIRMED and bool(blocked),
                         section_id='replace-plan-'+item['finding_id'])
    return body + '</div></article>'
