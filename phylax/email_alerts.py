"""Local outbox for observed IT-to-OT policy violations."""

from contextlib import suppress
from dataclasses import dataclass, field
from email.headerregistry import Address
from email.message import EmailMessage
from email.errors import HeaderParseError
import os
import smtplib
import sqlite3
import ssl
from threading import Event, Thread
from urllib.parse import urlencode, urlsplit

from .core import Store, utc_now
from .triage import alert_url


@dataclass(frozen=True)
class EmailConfig:
    mode: str = 'off'
    language: str = 'en'
    host: str = ''
    port: int = 587
    sender: str = ''
    recipient: str = ''
    base_url: str = ''
    username: str = ''
    password: str = field(default='', repr=False)

    @property
    def envelope(self):
        return self.sender, self.recipient, self.base_url


def public_disabled(*, public=False):
    return public or os.environ.get('PHYLAX_PUBLIC') == '1'


def _mailbox(value):
    if not value.isascii() or any(ord(char) < 33 for char in value):
        raise ValueError('Expected a single ASCII mailbox')
    address = Address(addr_spec=value)
    if not address.username or not address.domain or address.addr_spec != value:
        raise ValueError('Expected a single ASCII mailbox')
    return address.addr_spec


def _base_url(value):
    if any(char.isspace() or ord(char) < 32 for char in value) or '\\' in value:
        raise ValueError('Expected a dashboard origin')
    url = urlsplit(value)
    port = url.port
    if not url.hostname or url.username is not None or url.path not in ('', '/') or '?' in value or '#' in value or port == 0:
        raise ValueError('Expected a dashboard origin')
    if url.scheme != 'https' and not (url.scheme == 'http' and url.hostname in ('127.0.0.1', 'localhost', '::1')):
        raise ValueError('Expected HTTPS or loopback HTTP')
    return value.rstrip('/')


def config(store, *, public=False):
    if public_disabled(public=public):
        return EmailConfig(mode='public')
    env = os.environ
    language = 'id' if env.get('PHYLAX_EMAIL_LANGUAGE') == 'id' else 'en'
    if store.connection.execute("SELECT 1 FROM schema_meta WHERE key='dataset_label'").fetchone():
        return EmailConfig(mode='preview', language=language)
    mode = env.get('PHYLAX_EMAIL_MODE', 'off')
    if mode in ('off', 'preview'):
        return EmailConfig(mode=mode, language=language)
    if mode != 'smtp' or store.path == ':memory:':
        return EmailConfig(mode='invalid')
    try:
        host = env['PHYLAX_SMTP_HOST']
        port = int(env.get('PHYLAX_SMTP_PORT', '587'))
        username = env.get('PHYLAX_SMTP_USERNAME', '')
        password = env.get('PHYLAX_SMTP_PASSWORD', '')
        if not host or any(char.isspace() or ord(char) < 32 or char in '/\\' for char in host):
            raise ValueError('Expected an SMTP host')
        if not 1 <= port <= 65535 or bool(username) != bool(password):
            raise ValueError('Invalid SMTP port or credentials')
        return EmailConfig(mode='smtp', language=language, host=host, port=port,
                           sender=_mailbox(env['PHYLAX_EMAIL_FROM']), recipient=_mailbox(env['PHYLAX_EMAIL_TO']),
                           base_url=_base_url(env['PHYLAX_EMAIL_BASE_URL']), username=username, password=password)
    except (KeyError, ValueError, HeaderParseError):
        return EmailConfig(mode='invalid')


def enqueue(store, settings, alert_id, observed_at):
    if settings.mode not in ('preview', 'smtp') or public_disabled():
        return
    status = 'preview' if settings.mode == 'preview' else 'queued'
    store.connection.execute('''INSERT OR IGNORE INTO alert_email_outbox
        (alert_id, observed_at, language, sender, recipient, base_url, status, updated_at)
        VALUES (?,?,?,?,?,?,?,?)''',
        (alert_id, observed_at, settings.language, *settings.envelope, status, utc_now()))


def preview_url(alert_id):
    return '/email-alerts/preview?' + urlencode({'alert': alert_id})


def render_message(row, *, language=None):
    link = row['base_url'] + alert_url(row['alert_id'])
    if (language or row['language']) == 'id':
        subject = 'Phylax | Pelanggaran kebijakan IT → OT'
        body = ('Sebuah koneksi dari jaringan IT ke jaringan industri melanggar aturan zona yang dikonfigurasi.\n'
                f'Waktu pengamatan (UTC): {row["observed_at"]}\n\nBuka peringatan di Phylax: {link}\n')
    else:
        subject = 'Phylax | IT → OT policy violation'
        body = ('A connection from the IT network to the industrial network violated the configured zone policy.\n'
                f'Observed at (UTC): {row["observed_at"]}\n\nOpen the alert in Phylax: {link}\n')
    return subject, body


def _deliver(settings, row):
    subject, body = render_message(row)
    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = row['sender']
    message['To'] = row['recipient']
    message['Message-ID'] = f'<{row["alert_id"]}@phylax.local>'
    message.set_content(body)
    server = None
    try:
        try:
            server = smtplib.SMTP(settings.host, settings.port, timeout=5)
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            if settings.username:
                server.login(settings.username, settings.password)
        except smtplib.SMTPAuthenticationError:
            return 'failed', 'SMTP sign-in was rejected. Check the relay username and app password or SMTP key.'
        except ssl.SSLCertVerificationError:
            return 'failed', 'The SMTP relay certificate could not be verified.'
        except smtplib.SMTPNotSupportedError:
            return 'failed', 'The relay does not support the configured SMTP security or sign-in method.'
        except (OSError, smtplib.SMTPException, UnicodeError):
            return 'failed', 'Could not establish a secure SMTP session.'
        try:
            server.send_message(message)
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPDataError):
            return 'failed', 'SMTP relay rejected the message.'
        except (OSError, smtplib.SMTPException):
            return 'unknown', 'SMTP relay acceptance could not be confirmed.'
        return 'sent', ''
    finally:
        if server is not None:
            with suppress(OSError, smtplib.SMTPException):
                server.close()


def recover_interrupted(store):
    store.connection.execute('''UPDATE alert_email_outbox SET status='unknown', updated_at=?,
        detail='Sending was interrupted before the outcome was recorded.'
        WHERE status='sending' AND datetime(updated_at) <= datetime('now','-5 minutes')''', (utc_now(),))
    store.connection.commit()


def dispatch_one(store, settings, *, public=False):
    if settings.mode != 'smtp' or config(store, public=public) != settings:
        return False
    candidate = store.connection.execute('''SELECT alert_id FROM alert_email_outbox WHERE status='queued'
        AND sender=? AND recipient=? AND base_url=? ORDER BY updated_at, alert_id LIMIT 1''', settings.envelope).fetchone()
    if candidate is None:
        return False
    row = store.connection.execute('''UPDATE alert_email_outbox SET status='sending', updated_at=?
        WHERE alert_id=? AND status='queued' RETURNING *''', (utc_now(), candidate['alert_id'])).fetchone()
    store.connection.commit()
    if row is None:
        return False
    status, detail = _deliver(settings, row)
    store.connection.execute('''UPDATE alert_email_outbox SET status=?, detail=?, updated_at=?
        WHERE alert_id=? AND status='sending' ''', (status, detail, utc_now(), row['alert_id']))
    store.connection.commit()
    return True


def retry(store, alert_id, *, public=False):
    settings = config(store, public=public)
    if settings.mode != 'smtp':
        raise ValueError('Configure private SMTP delivery before retrying.')
    result = store.connection.execute('''UPDATE alert_email_outbox SET status='queued', detail='', updated_at=?
        WHERE alert_id=? AND status='failed' AND sender=? AND recipient=? AND base_url=?''',
        (utc_now(), alert_id, *settings.envelope))
    store.connection.commit()
    if not result.rowcount:
        raise ValueError('This email cannot be retried with the current settings.')


class EmailWorker:
    def __init__(self, database, settings):
        self.stop = Event()
        self.thread = None
        if settings.mode == 'smtp':
            self.thread = Thread(target=self._run, args=(database, settings), name='phylax-email', daemon=True)
            self.thread.start()

    def _run(self, database, settings):
        store = Store(database)
        try:
            while not self.stop.is_set():
                try:
                    recover_interrupted(store)
                    while not self.stop.is_set() and dispatch_one(store, settings):
                        pass
                except sqlite3.OperationalError:
                    store.connection.rollback()
                self.stop.wait(5)
        finally:
            store.close()

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=1)
