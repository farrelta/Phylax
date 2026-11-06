"""Readable remediation guidance without changing review or execution semantics."""

from __future__ import annotations

import ast
import json
import re
from urllib.parse import urlencode

from .remediation_views import lifecycle_form
from .theme import PLAIN_STATUS
from .ui import e, hidden, reference_links


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


def _content(value) -> str:
    """Keep stored structured values readable and escaped, including legacy data."""
    if isinstance(value, dict):
        return '<dl class="facts">' + "".join(
            '<div><dt>' + e(str(key).replace('_', ' ').capitalize())
            + '</dt><dd>' + _content(item) + '</dd></div>'
            for key, item in value.items()
        ) + '</dl>'
    if isinstance(value, (list, tuple)):
        return _list(value)
    return e(_text(value))


def _list(values, empty="None recorded.", *, ordered=False) -> str:
    values = _items(values)
    if not values:
        return '<p class="muted">' + e(empty) + '</p>'
    tag = 'ol' if ordered else 'ul'
    return '<' + tag + '>' + ''.join('<li>' + _content(v) + '</li>' for v in values) + '</' + tag + '>'


def _paragraph(label, value) -> str:
    return '<p><b>' + e(label) + ':</b> ' + _content(value if value not in (None, '') else 'Not recorded') + '</p>'


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
                    + e(item.get('actor') or 'system') + ' · '
                    + e(item.get('created_at', 'Not recorded'))
                    + ('<p>' + e(item['notes']) + '</p>' if item.get('notes') else '') + '</li>')
    return '<ol>' + ''.join(rows) + '</ol>' if rows else '<p>No lifecycle changes recorded.</p>'


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
    facts = [('Plan status', item.get('status', 'Unknown')),
             ('Current applicability', _text(applicability)),
             ('Current priority', _text(priority).replace('_', ' ').capitalize()),
             ('Current identity confidence', item.get('current_identity_confidence') or 'Unknown'),
             ('Human approval required:', plan.get('human_approval_required', True))]
    body = '<article class="panel plan" id="' + e(prefix) + '"><header class="plan-header"><h2>' + e(item.get('cve_id', 'Finding')) + ' · ' + e(asset) + '</h2><p><a class="btn" href="#' + e(prefix) + '-review">Review plan</a></p></header>'
    body += '<div class="plan-summary"><dl class="facts">' + ''.join(
        '<div><dt>' + e(label) + '</dt><dd>' + _content(value) + '</dd></div>'
        for label, value in facts) + '</dl>'
    evidence_changed = stored_applicability is not None and stored_applicability != applicability
    if evidence_changed or item.get('status') == 'Needs More Evidence':
        warning = ('Supporting finding evidence has changed since this plan was generated.'
                   if evidence_changed else 'This plan needs more evidence.')
        finding_url = '/?' + urlencode({'finding_id': item['finding_id']}) + '#finding-' + str(item['finding_id'])
        body += '<div class="notice"><p><b>Evidence review required.</b> ' + e(warning)
        body += ' The guidance and assessment snapshot below describe the plan at generation; they may be outdated.</p><p><a href="' + e(finding_url) + '">Review current finding</a></p></div>'
    body += _paragraph('Recommended action', plan.get('preferred_remediation'))
    body += _paragraph('Operational impact', plan.get('operational_impact'))
    body += '<h3>Current missing evidence</h3>' + _list(item.get('current_missing_evidence'), 'No missing evidence is recorded for the current finding.')
    body += '</div>'

    matching = submitted and submitted.get('finding_id') == item['finding_id']
    review = (_paragraph('Recorded reviewer', item.get('reviewer') or 'Not recorded')
              + _paragraph('Recorded change notes', item.get('change_notes') or 'None')
              + _paragraph('Recorded verification evidence', item.get('verification_evidence') or 'Not recorded')
              + lifecycle_form(item, submitted if matching else None, error if matching else ''))
    body += _section('Review plan · ' + str(item.get('status', 'Unknown')), review,
                     opened=bool(matching and error), css='plan-review', section_id=prefix+'-review')

    guidance = _paragraph('Vendor guidance status', plan.get('vendor_guidance_status'))
    guidance += '<h3>Alternative controls</h3>' + _list(plan.get('alternative_controls'))
    if plan.get('cisa_required_action'):
        guidance += _paragraph('CISA required action', plan['cisa_required_action'])
    if plan.get('ai_summary'):
        guidance += '<section class="notice plan-ai"><h3>AI-generated, unverified supplement</h3>'
        guidance += _paragraph('Model', plan.get('returned_model') or item.get('model') or 'Not recorded')
        guidance += _paragraph('Plan created UTC', item.get('created_at', 'Not recorded'))
        guidance += '<p>' + _content(plan['ai_summary']) + '</p>' + _list(plan.get('ai_steps'), ordered=True)
        guidance += _paragraph('Suggested validation', plan.get('ai_validation'))
        guidance += '<h4>Validated source references</h4>' + _references(plan.get('ai_source_references'))
        guidance += '<p>Only eligible public advisory data was sent to the hosted model. Local asset identities, inventory, network events, policies and operational context were not sent. This supplement does not change applicability, priority, approvals or recorded outcomes.</p></section>'
    label = 'Guidance and alternative controls' + (' · includes unverified AI supplement' if plan.get('ai_summary') else '')
    body += '<div class="plan-sections">'
    body += _section('Prerequisites and approvals', _list(plan.get('preconditions'), ordered=True))
    body += _section(label, guidance, opened=True)
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
    evidence += _paragraph('Finding summary at generation', plan.get('finding_summary'))
    if plan.get('evidence'):
        evidence += '<h3>Supporting evidence at generation</h3>' + _list(plan['evidence'])
    evidence += '<h3>Priority factors at generation</h3>' + _score(plan)
    body += _section('Assessment snapshot and priority factors at generation', evidence)

    source = _paragraph('Plan source', plan.get('provider_note') or item.get('provider') or 'Not recorded')
    source += _paragraph('Provider identifier', item.get('provider', 'Not recorded'))
    source += _paragraph('Created UTC', item.get('created_at', 'Not recorded'))
    for key, label in (('model', 'Recorded model'), ('requested_model', 'Requested model'), ('returned_model', 'Returned model')):
        value = item.get(key) if key == 'model' else plan.get(key)
        if value:
            source += _paragraph(label, value)
    source += '<h3>Source references</h3>' + _references(plan.get('source_references'))
    body += _section('Provenance and source references', source)
    body += _section('Lifecycle history', _history(item.get('history')))
    replacement = '<p>Generating a replacement archives this plan and clears its review and verification state. A failed hosted request keeps the prior hosted plan.</p>'
    replacement += '<form method="post" action="/remediation/create">' + hidden('finding_id', item['finding_id']) + '<button>Generate replacement plan</button></form>'
    body += _section('Regenerate plan', replacement)
    return body + '</div></article>'
