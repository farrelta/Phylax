"""Operator corrective-action records for an exact network or device alert."""

import hashlib
import json
import uuid
from urllib.parse import urlencode

from .asset_intelligence import actor_note, text
from .core import utc_now
from .remediation_lifecycle import TRANSITIONS

def plan_url(category, alert_id, **query):
    return '/remediation?' + urlencode({'category': category, 'alert_id': alert_id, **query})


def alert_revision(category, evidence):
    if category == 'network':
        policy = {key: value for key, value in evidence['policy'].items() if key != 'policy_id'}
        content = [evidence['event_ref'], evidence['rule_id'], policy]
    else:
        content = [evidence.get(key, '') for key in ('subnet_id', 'ip', 'mac')]
        content.append(evidence['status'] == 'needs_identity_review')
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()


def alert_record(store, category, alert_id):
    if category == 'network':
        row = store.connection.execute('''SELECT a.alert_id,a.rule_id,a.policy_evidence,a.explanation,
            e.event_ref,e.source_ip,e.destination_ip,e.source_file,e.timestamp,
            s.state,s.condition_state,s.policy_id FROM network_alerts a JOIN network_events e USING(event_id)
            JOIN network_case_states s USING(alert_id) WHERE a.alert_id=?''', (alert_id,)).fetchone()
        if row:
            record = dict(row)
            record['policy'] = json.loads(record.pop('policy_evidence'))
    elif category == 'endpoint':
        row = store.connection.execute('''SELECT a.alert_id,a.ip,a.subnet_id,a.status,a.evidence_json,a.last_seen,
            s.state,s.condition_state FROM endpoint_alerts a JOIN endpoint_case_states s USING(alert_id)
            WHERE a.alert_id=?''', (alert_id,)).fetchone()
        if row:
            record = dict(row)
            device = json.loads(record.pop('evidence_json'))
            record['mac'] = device.get('mac', '')
            record['subnet'] = device.get('subnet', '')
            record['event_ref'] = next((item['event_ref'] for item in device.get('evidence', [])
                                        if item.get('event_ref')), '')
            if not record['event_ref']:
                observation = store.connection.execute('''SELECT event_ref FROM observations
                    WHERE ip=? AND kind!='wazuh_inventory' ORDER BY observed_at DESC,observation_id LIMIT 1''',
                    (record['ip'],)).fetchone()
                record['event_ref'] = observation['event_ref'] if observation else ''
    else:
        raise ValueError('Unsupported alert category.')
    if not row:
        raise ValueError('Alert not found.')
    return record | {'category': category, 'revision': alert_revision(category, record)}


def draft_revision(row):
    evidence = dict(row['evidence'])
    if row['category'] == 'network':
        evidence['rule_id'] = row['rule_id']
    else:
        evidence.update(ip=row['ip'], subnet_id=row['subnet_id'], status=row['management_status'])
    return alert_revision(row['category'], evidence)


def _plan(store, category, alert_id):
    row = store.connection.execute('SELECT * FROM alert_fix_plans WHERE category=? AND alert_id=?',
                                   (category, alert_id)).fetchone()
    return dict(row) if row else None


def read_plan(store, category, alert_id):
    with store.atomic('read_alert_fix_plan'):
        plan = _plan(store, category, alert_id)
        if not plan:
            raise ValueError('Alert fix plan not found.')
        plan['alert'] = alert_record(store, category, alert_id)
        plan['history'] = [{'action': row['action'], 'snapshot': json.loads(row['snapshot_json']), 'recorded_at': row['recorded_at']}
                           for row in store.connection.execute('''SELECT action,snapshot_json,recorded_at
                               FROM alert_fix_plan_events WHERE plan_id=? ORDER BY version''', (plan['plan_id'],))]
    return plan


def _record(store, plan, action, alert):
    snapshot = {key: plan[key] for key in ('status', 'reviewer', 'change_notes', 'verification_evidence',
                                         'closed_by', 'closure_reason', 'closed_at')}
    snapshot['alert'] = alert
    store.connection.execute('INSERT INTO alert_fix_plan_events VALUES (?,?,?,?,?)',
                             (plan['plan_id'], plan['version'], action, json.dumps(snapshot), utc_now()))


def _update(store, plan, alert, action, **fields):
    fields.update(version=plan['version'] + 1, updated_at=utc_now())
    assignments = ','.join(f'{name}=?' for name in fields)
    store.connection.execute(f'UPDATE alert_fix_plans SET {assignments} WHERE plan_id=?',
                             (*fields.values(), plan['plan_id']))
    _record(store, plan | fields, action, alert)


def _check_form(plan, alert, fields):
    if (fields.get('plan_id', ''), fields.get('plan_version', '')) != (plan['plan_id'], str(plan['version'])):
        raise ValueError('The fix plan changed while this form was open. Review the current plan before saving.')
    if fields.get('alert_revision') != alert['revision']:
        raise ValueError('Alert evidence changed. Reload the alert fix plan.')


def closure_error(plan, alert, verification_snapshot):
    if alert['state'] != 'active' or plan['status'] != 'Verified' or not plan['verification_evidence'].strip():
        return 'Closing requires an active alert and a verified fix plan.'
    if plan['category'] == 'endpoint' and verification_snapshot.get('last_seen') != alert['last_seen']:
        return 'The device was observed again after verification. Reopen plan review and verify the outcome again.'
    return ''


def save_plan(store, action, fields):
    category, alert_id = fields.get('category', ''), fields.get('alert_id', '')
    if fields.get('finding_id'):
        raise ValueError('Choose a single subject for the fix plan.')
    with store.atomic('alert_fix_plan'):
        # Serialize the evidence check and the write with collectors and policy replay.
        store.connection.execute('UPDATE alert_fix_plans SET version=version WHERE category=? AND alert_id=?',
                                 (category, alert_id))
        alert = alert_record(store, category, alert_id)
        plan = _plan(store, category, alert_id)
        if action == 'create' and not plan:
            if alert['state'] != 'active':
                raise ValueError('Only active alerts can get a new fix plan.')
            if fields.get('plan_id') or fields.get('alert_revision') != alert['revision']:
                raise ValueError('Alert evidence changed. Reload the alert fix plan.')
            store.connection.execute('''INSERT INTO alert_fix_plans
                (plan_id,category,alert_id,evidence_revision,status,updated_at) VALUES (?,?,?,?,?,?)''',
                (str(uuid.uuid4()), category, alert_id, alert['revision'], 'Recommended', utc_now()))
            _record(store, _plan(store, category, alert_id), 'Plan drafted', alert)
            return
        if not plan:
            raise ValueError('Alert fix plan not found.')
        _check_form(plan, alert, fields)
        if plan['closed_at']:
            raise ValueError('This alert was already closed by an operator.')
        current = plan['evidence_revision'] == alert['revision'] and plan['status'] != 'Needs More Evidence'
        if action == 'create':
            if current:
                raise ValueError('A current fix plan already exists for this alert.')
            _update(store, plan, alert, 'Plan replaced', evidence_revision=alert['revision'],
                    status='Recommended', reviewer='', change_notes='', verification_evidence='')
            return
        if not current:
            raise ValueError('Generate a replacement plan using the current alert evidence before advancing.')
        if action == 'close':
            event = store.connection.execute('SELECT snapshot_json FROM alert_fix_plan_events WHERE plan_id=? AND version=?',
                                             (plan['plan_id'], plan['version'])).fetchone()
            verification = json.loads(event['snapshot_json'])['alert'] if event else {}
            if reason := closure_error(plan, alert, verification):
                raise ValueError(reason)
            actor, note = actor_note(fields.get('actor', ''), fields.get('note', ''))
            _update(store, plan, alert, 'Closed by operator', closed_by=actor, closure_reason=note,
                    closed_at=utc_now(), closed_last_seen=alert.get('last_seen', ''))
            return
        status = fields.get('status', '')
        if status not in TRANSITIONS.get(plan['status'], ()):
            raise ValueError(f"Invalid remediation transition: {plan['status']} → {status}")
        reviewer = text(fields.get('reviewer', ''), 120)
        note = text(fields.get('change_notes', ''), 2000)
        verification = text(fields.get('verification_evidence', ''))
        if status == 'Approved' and not reviewer:
            raise ValueError('Reviewer is required for approval')
        if status == 'Approved' and not note:
            raise ValueError('Enter the specific mitigation or compensating control in the approval notes.')
        if status == 'Verified' and not verification:
            raise ValueError('Verification evidence is required before marking a plan verified')
        changes = {'status': status}
        if reviewer:
            changes['reviewer'] = reviewer
        if note:
            changes['change_notes'] = note
        if status == 'Verified':
            changes['verification_evidence'] = verification
        elif status == 'Under Review':
            changes['verification_evidence'] = ''
        _update(store, plan, alert, status, **changes)


def reopen_endpoint(store, alert_id, last_seen):
    row = store.connection.execute('''SELECT * FROM alert_fix_plans
        WHERE category='endpoint' AND alert_id=? AND closed_at!='' AND closed_last_seen<?''',
        (alert_id, last_seen)).fetchone()
    if row:
        alert = alert_record(store, 'endpoint', alert_id)
        _update(store, dict(row), alert | {'state': 'active'}, 'New device activity reopened the alert',
                status='Needs More Evidence', reviewer='', change_notes='', verification_evidence='',
                closed_by='', closure_reason='', closed_at='', closed_last_seen='')
        store.connection.execute('UPDATE endpoint_alerts SET acknowledged=0 WHERE alert_id=?', (alert_id,))
