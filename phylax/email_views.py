"""Local email preview and delivery status."""

from . import email_alerts
from .theme import layout
from .triage import alert_url
from .ui import e, form, hidden, table, verbatim


LABELS = {
    'preview': 'Preview only', 'queued': 'Queued', 'sending': 'Sending',
    'sent': 'Sent', 'failed': 'Failed', 'unknown': 'Delivery unknown',
}


def delivery_summary(store, *, public=False):
    settings = email_alerts.config(store, public=public)
    if settings.mode == 'public':
        return 'Email alerts are disabled on public hosting.'
    row = store.connection.execute('SELECT status FROM alert_email_outbox ORDER BY updated_at DESC, alert_id LIMIT 1').fetchone()
    if row:
        return LABELS[row['status']]
    return {
        'preview': 'Preview only', 'off': 'Email alerts are off.',
        'smtp': 'No email alerts recorded.',
        'invalid': 'Email settings are invalid or incomplete. Check the server environment.',
    }[settings.mode]


def preview_link(store, alert_id, *, public=False):
    if email_alerts.public_disabled(public=public):
        return ''
    if not store.connection.execute('SELECT 1 FROM alert_email_outbox WHERE alert_id=?', (alert_id,)).fetchone():
        return ''
    return '<a href="' + e(email_alerts.preview_url(alert_id)) + '">Preview email</a>'


def preview_page(store, alert_id, language):
    row = store.connection.execute('SELECT * FROM alert_email_outbox WHERE alert_id=?', (alert_id,)).fetchone()
    if row is None:
        return None
    subject, body = email_alerts.render_message(row, language=language if row['status'] == 'preview' else None)
    content = ('<section class="cardx"><h2>Subject</h2><p>' + verbatim(subject) + '</p>'
               '<h2>Message</h2><pre translate="no">' + e(body) + '</pre>'
               '<p><a href="' + e(alert_url(alert_id)) + '">Open the alert in Phylax</a></p></section>')
    return layout('Email preview', content, '/triage', lead='Opening this preview does not send email.')


def settings_section(store, *, public=False):
    settings = email_alerts.config(store, public=public)
    description = {
        'public': 'Email alerts are disabled on public hosting.',
        'off': 'Email alerts are off.',
        'invalid': 'Email settings are invalid or incomplete. Check the server environment.',
        'preview': 'Email alerts are saved as local previews.',
        'smtp': 'SMTP delivery is configured for new IT → OT policy alerts.',
    }[settings.mode]
    body = '<h2 id="email-alerts">Email alerts</h2><p>' + e(description) + '</p>'
    if settings.mode == 'public':
        return body
    rows = []
    for row in store.connection.execute('SELECT * FROM alert_email_outbox ORDER BY updated_at DESC,alert_id LIMIT 50'):
        current_envelope = (row['sender'], row['recipient'], row['base_url'])
        can_send = settings.mode == 'smtp' and settings.envelope == current_envelope
        actions = '<a href="' + e(email_alerts.preview_url(row['alert_id'])) + '">Preview email</a>'
        if row['status'] == 'failed' and can_send:
            actions += form('/email-alerts/retry', hidden('alert', row['alert_id']), 'Retry email')
        detail = row['detail']
        if row['status'] == 'queued' and not can_send:
            detail = 'Waiting for the original SMTP delivery settings.'
        rows.append({'observed_at': row['observed_at'], 'status': LABELS[row['status']],
                     'message': detail, 'actions': actions})
    return body + table(rows, [('observed_at', 'Observed UTC'), ('status', 'Status'), ('message', 'Details')],
                        actions=lambda row: row['actions'], empty='No email alerts recorded.')
