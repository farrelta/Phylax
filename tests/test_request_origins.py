"""Origin canonicalization without loosening local dashboard request boundaries."""
import unittest
from unittest.mock import patch
from phylax.web_security import valid_host,valid_origin
import test_review_regressions as regressions


class RequestOriginTests(unittest.TestCase):
    def test_response_preserves_local_form_origin_and_withholds_external_referrers(self):
        http=regressions.HTTPAndGuidanceRegressionTests();http.setUp()
        try:
            handler=http.handler('/intelligence');handler.do_GET()
            self.assertEqual(handler.response_headers['Referrer-Policy'],'same-origin')
            self.assertIn(b'name="csrf_token"',handler.wfile.getvalue())
        finally:http.tearDown()

    def test_equivalent_origins_compare_canonical_host_and_port(self):
        for origin,host,port in (
            ('http://localhost:8765','LOCALHOST:8765',8765),
            ('http://LOCALHOST:8765','localhost:8765',8765),
            ('http://localhost','localhost:80',80),
            ('http://127.0.0.1:80','127.0.0.1',80),
            ('http://[::1]:8765','[::1]:8765',8765),
        ):
            with self.subTest(origin=origin,host=host):self.assertTrue(valid_origin(origin,host,port))

    def test_different_and_opaque_origins_and_malformed_hosts_stay_rejected(self):
        for origin in ('null','https://127.0.0.1:8765','http://localhost:8765',
                       'http://127.0.0.1:8766','http://evil.example:8765',
                       'http://127.0.0.1:8765/other','http://127.0.0.1:8765?x=1',
                       'http://:password@127.0.0.1:8765','http://127.0.0.1:8765\n'):
            with self.subTest(origin=origin):self.assertFalse(valid_origin(origin,'127.0.0.1:8765',8765))
        for host in ('localhost:0','localhost:8765/path',':password@localhost:8765','localhost:8765\n','evil.example:8765'):
            with self.subTest(host=host):self.assertFalse(valid_host(host,8765))

    def test_sync_accepts_same_origin_with_valid_token_without_calling_real_feeds(self):
        http=regressions.HTTPAndGuidanceRegressionTests();http.setUp()
        try:
            with patch('phylax.web.sync_store',return_value={'mocked-source':{'ok':True}}) as sync:
                handler=http.handler('/sync','csrf_token='+http.Handler.csrf_token,origin='http://localhost:8765',host='LOCALHOST:8765')
                handler.do_POST()
                self.assertEqual(handler.response_status,303)
                self.assertEqual(handler.response_headers['Location'],'/jobs/testjob')
                sync.assert_called_once()
        finally:http.tearDown()

    def test_sync_rejects_foreign_opaque_and_expired_forms_before_feed_work(self):
        http=regressions.HTTPAndGuidanceRegressionTests();http.setUp()
        try:
            with patch('phylax.web.sync_store') as sync:
                for origin in ('null','http://localhost:8765','https://evil.example'):
                    handler=http.handler('/sync','csrf_token='+http.Handler.csrf_token,origin=origin)
                    handler.do_POST()
                    self.assertEqual(handler.response_status,403)
                    self.assertIn(b'Open http://127.0.0.1:8765/',handler.wfile.getvalue())
                handler=http.handler('/sync','csrf_token=expired');handler.do_POST()
                self.assertEqual(handler.response_status,403)
                sync.assert_not_called()
        finally:http.tearDown()
