from concurrent.futures import ThreadPoolExecutor
from html import escape
import os
from pathlib import Path
import smtplib
import ssl
from tempfile import TemporaryDirectory
from threading import Event
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from phylax import email_alerts
from phylax.core import Store
from phylax.i18n import COOKIE_NAME
from phylax.monitoring import ingest_file, policy_version, preview_policy, reevaluate_events
from phylax.pcap import analyze_pcap
from phylax.triage import alert_url, zone_alert
from scripts.prepare_sensor_demo import DMZ, IT, PLC, POLICY, prepare, stage_presentation
import test_review_regressions as http_regressions


SMTP_ENV = {
    'PHYLAX_EMAIL_MODE': 'smtp', 'PHYLAX_SMTP_HOST': 'relay.example',
    'PHYLAX_EMAIL_FROM': 'alerts@example.org', 'PHYLAX_EMAIL_TO': 'operator@example.org',
    'PHYLAX_EMAIL_BASE_URL': 'https://dashboard.example.org', 'PHYLAX_EMAIL_LANGUAGE': 'id',
}


class EmailAlertTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name) / 'demo'
        self.database = prepare(self.directory)
        self.store = Store(self.database)
        self.addCleanup(self.store.close)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def rows(self):
        return self.store.connection.execute('SELECT * FROM alert_email_outbox ORDER BY alert_id').fetchall()

    def use_private_database(self):
        self.store.connection.execute("DELETE FROM schema_meta WHERE key='dataset_label'")
        self.store.connection.commit()

    def queue_smtp(self):
        self.use_private_database()
        os.environ.update(SMTP_ENV)
        ingest_file(self.store, self.directory / 'conn.log')
        self.assertEqual([row['status'] for row in self.rows()], ['queued'])
        return email_alerts.config(self.store)

    def test_demo_has_one_offline_preview_and_exact_bilingual_links(self):
        self.store.close()
        with patch.dict(os.environ, SMTP_ENV), patch('smtplib.SMTP') as smtp:
            stage_presentation(self.directory, self.database)
            self.store = Store(self.database)
            self.addCleanup(self.store.close)
            ingest_file(self.store, self.directory / 'conn.log')
            self.assertEqual([row['status'] for row in self.rows()], ['preview'])
            smtp.assert_not_called()

        row, = self.rows()
        alert = zone_alert(self.store)
        self.assertEqual(row['alert_id'], alert['alert_id'])
        self.assertEqual((alert['source_ip'], alert['destination_ip']), (IT, PLC))
        harness = http_regressions.HTTPAndGuidanceRegressionTests()
        harness.setUp()
        harness.store.close()
        harness.store = self.store
        target = alert_url(row['alert_id'])
        preview = email_alerts.preview_url(row['alert_id'])
        case = harness.handler(target.split('#')[0])
        case.do_GET()
        self.assertIn(escape(preview), case.wfile.getvalue().decode())
        for language, expected in [('en', 'Observed at (UTC)'), ('id', 'Waktu pengamatan (UTC)')]:
            handler = harness.handler(preview)
            handler.headers['Cookie'] = COOKIE_NAME + '=' + language
            handler.do_GET()
            self.assertEqual(handler.response_status, 200)
            html = handler.wfile.getvalue().decode()
            self.assertIn(expected, html)
            self.assertIn('href="' + escape(target) + '"', html)
            self.assertIn(row['observed_at'], html)
            for private in (IT, PLC, DMZ, 'conn.log', 'Simulated Cooling Controller'):
                self.assertNotIn(private, html)

        public = harness.handler(preview)
        public.public = True
        public.do_GET()
        self.assertEqual(public.response_status, 404)

    def test_off_public_policy_replay_and_rollback_do_not_queue(self):
        self.use_private_database()
        self.assertEqual(email_alerts.config(self.store).mode, 'off')
        os.environ['PHYLAX_EMAIL_MODE'] = 'preview'
        conn = self.directory / 'conn.log'
        malformed = self.directory / 'malformed.log'
        malformed.write_bytes(conn.read_bytes() + b'{bad json}\n')
        with self.assertRaises(ValueError):
            ingest_file(self.store, malformed)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.store.connection.execute('SELECT COUNT(*) FROM network_alerts').fetchone()[0], 0)

        permit = POLICY | {'denied_zone_pairs': []}
        with patch.dict(os.environ, {'PHYLAX_PUBLIC': '1'}):
            result = ingest_file(self.store, conn)
            self.assertEqual(result['alerts_created'], 1)
            self.assertEqual(self.rows(), [])
        reevaluate_events(self.store, permit)
        preview_policy(self.store, POLICY, policy_version(self.store))
        self.assertEqual(self.rows(), [])
        reevaluate_events(self.store, POLICY)
        ingest_file(self.store, conn)
        self.assertEqual(self.rows(), [])

    def test_only_first_import_can_queue_alert_even_when_policy_later_denies(self):
        self.use_private_database()
        os.environ['PHYLAX_EMAIL_MODE'] = 'preview'
        conn = self.directory / 'conn.log'
        ingest_file(self.store, conn, policy=POLICY | {'denied_zone_pairs': []})
        self.assertEqual(self.rows(), [])
        self.assertEqual(ingest_file(self.store, conn, policy=POLICY)['alerts_created'], 1)
        self.assertEqual(self.rows(), [])

    def test_pcap_ingestion_queues_once(self):
        def analyze(_command, *, cwd, **_kwargs):
            (Path(cwd) / 'conn.log').write_bytes((self.directory / 'conn.log').read_bytes())
            return SimpleNamespace(returncode=0)

        path = self.directory / 'simulated-denied-connection.pcap'
        with patch('phylax.pcap.shutil.which', return_value='/usr/bin/zeek'):
            analyze_pcap(self.store, path, runner=analyze)
            self.assertTrue(analyze_pcap(self.store, path, runner=analyze)['already_analyzed'])
        self.assertEqual([row['status'] for row in self.rows()], ['preview'])

    def test_background_worker_sends_from_a_separate_connection(self):
        settings = self.queue_smtp()
        delivered = Event()
        with patch('smtplib.SMTP') as relay:
            relay.return_value.send_message.side_effect = lambda _message: delivered.set()
            worker = email_alerts.EmailWorker(self.database, settings)
            try:
                self.assertTrue(delivered.wait(timeout=5))
            finally:
                worker.close()
        self.assertEqual(self.rows()[0]['status'], 'sent')

    def test_smtp_uses_verified_starttls_and_claims_once_across_workers(self):
        settings = self.queue_smtp()

        def dispatch(_):
            store = Store(self.database)
            try:
                return email_alerts.dispatch_one(store, settings)
            finally:
                store.close()

        with patch('smtplib.SMTP') as relay, ThreadPoolExecutor(2) as pool:
            self.assertEqual(sorted(pool.map(dispatch, range(2))), [False, True])
            smtp = relay.return_value
            smtp.send_message.assert_called_once()
            context = smtp.starttls.call_args.kwargs['context']
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            msg = smtp.send_message.call_args.args[0]
            self.assertEqual(str(msg['To']), SMTP_ENV['PHYLAX_EMAIL_TO'])
            self.assertIn('Pelanggaran kebijakan', str(msg['Subject']))
            self.assertIn(SMTP_ENV['PHYLAX_EMAIL_BASE_URL'] + alert_url(self.rows()[0]['alert_id']), msg.get_content())
        self.assertEqual(self.rows()[0]['status'], 'sent')

    def test_rejection_is_retryable_but_timeout_during_send_is_not(self):
        settings = self.queue_smtp()
        alert_id = self.rows()[0]['alert_id']
        with patch('smtplib.SMTP') as relay:
            relay.return_value.send_message.side_effect = smtplib.SMTPDataError(550, b'private relay message')
            self.assertTrue(email_alerts.dispatch_one(self.store, settings))
            self.assertEqual(self.rows()[0]['status'], 'failed')
            self.assertNotIn('private relay message', self.rows()[0]['detail'])
            harness = http_regressions.HTTPAndGuidanceRegressionTests()
            harness.setUp()
            harness.store.close()
            harness.store = self.store
            page = harness.handler('/settings')
            page.do_GET()
            html = page.wfile.getvalue().decode()
            self.assertIn('<dt>Email delivery</dt><dd>Failed</dd>', html)
            self.assertIn('Retry email</button>', html)
            retry = harness.handler('/email-alerts/retry', urlencode({'alert': alert_id,
                                                                     'csrf_token': harness.Handler.csrf_token}))
            retry.do_POST()
            self.assertEqual(retry.response_status, 303)
            self.assertEqual(self.rows()[0]['status'], 'queued')
            relay.return_value.send_message.side_effect = TimeoutError()
            self.assertTrue(email_alerts.dispatch_one(self.store, settings))
            self.assertEqual(self.rows()[0]['status'], 'unknown')
            self.assertFalse(email_alerts.dispatch_one(self.store, settings))
            with self.assertRaises(ValueError):
                email_alerts.retry(self.store, alert_id)
            self.assertEqual(relay.return_value.send_message.call_count, 2)

    def test_authentication_failure_reports_a_safe_diagnostic(self):
        os.environ.update(PHYLAX_SMTP_USERNAME='operator', PHYLAX_SMTP_PASSWORD='test-password')
        settings = self.queue_smtp()
        with patch('smtplib.SMTP') as relay:
            relay.return_value.login.side_effect = smtplib.SMTPAuthenticationError(535, b'private relay response')
            self.assertTrue(email_alerts.dispatch_one(self.store, settings))
            relay.return_value.send_message.assert_not_called()
        row = self.rows()[0]
        self.assertEqual(row['status'], 'failed')
        self.assertIn('SMTP sign-in was rejected', row['detail'])
        self.assertNotIn('private relay response', row['detail'])

    def test_restart_recovers_interrupted_claim_without_resending(self):
        settings = self.queue_smtp()
        self.store.connection.execute("UPDATE alert_email_outbox SET status='sending', updated_at='2000-01-01T00:00:00Z'")
        self.store.connection.commit()
        reopened = Store(self.database)
        self.addCleanup(reopened.close)
        with patch('smtplib.SMTP') as relay:
            email_alerts.recover_interrupted(reopened)
            self.assertFalse(email_alerts.dispatch_one(reopened, settings))
            relay.assert_not_called()
        self.assertEqual(self.rows()[0]['status'], 'unknown')

    def test_public_or_changed_destination_cannot_deliver_an_existing_queue(self):
        settings = self.queue_smtp()
        with patch('smtplib.SMTP') as relay, patch.dict(os.environ, {'PHYLAX_PUBLIC': '1'}):
            self.assertFalse(email_alerts.dispatch_one(self.store, settings))
            relay.assert_not_called()
        with patch('smtplib.SMTP') as relay, patch.dict(os.environ, {'PHYLAX_EMAIL_TO': 'other@example.org'}):
            self.assertFalse(email_alerts.dispatch_one(self.store, email_alerts.config(self.store)))
            relay.assert_not_called()
        self.assertEqual(self.rows()[0]['status'], 'queued')
