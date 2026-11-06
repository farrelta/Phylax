"""Separate CVE and ICS advisory routes, search and pagination."""
import unittest
import test_review_regressions as regressions
from phylax.web import intelligence_page,ics_advisories_page


class IntelligencePageTests(unittest.TestCase):
    def setUp(self):
        self.http=regressions.HTTPAndGuidanceRegressionTests();self.http.setUp();self.store=self.http.store
        self.store.save_ics_advisories([{'advisory_id':'ics-example','title':'Example ICS advisory','summary':'ADVISORY_ONLY_TEXT','link':'https://example.org/ics-example'}])

    def tearDown(self):self.http.tearDown()

    def test_separate_collections_have_contextual_navigation(self):
        cves=intelligence_page(self.store);ics=ics_advisories_page(self.store)
        self.assertIn('CVE-2024-12345',cves);self.assertNotIn('ADVISORY_ONLY_TEXT',cves)
        self.assertIn('ADVISORY_ONLY_TEXT',ics);self.assertNotIn('CVE-2024-12345',ics)
        self.assertIn('href="/intelligence/ics"',cves)
        self.assertIn('href="/intelligence/ics" aria-current="page"',ics)
        self.assertIn('aria-label="Intelligence views"',ics)

    def test_advisory_search_count_and_pagination_are_independent(self):
        self.store.save_ics_advisories([{'advisory_id':f'item-{n:03}','title':'Pagination advisory '+str(n),'summary':'Test source summary.'} for n in range(55)])
        first,total=self.store.search_ics_advisories('Pagination',limit=50)
        second,total_again=self.store.search_ics_advisories('Pagination',limit=50,offset=50)
        self.assertEqual((len(first),len(second),total,total_again),(50,5,55,55))
        self.assertFalse({r['advisory_id'] for r in first}&{r['advisory_id'] for r in second})
        self.assertIn('/intelligence/ics?q=Pagination&page=2',ics_advisories_page(self.store,'Pagination'))
        self.assertEqual(self.store.search_ics_advisories('%_')[1],0)
        self.assertIn('No advisories match',ics_advisories_page(self.store,'missing-product'))

    def test_http_routes_render_correct_collection_and_protected_sync_forms(self):
        for path,expected,absent in [('/intelligence',b'CVE-2024-12345',b'ADVISORY_ONLY_TEXT'),('/intelligence/ics',b'ADVISORY_ONLY_TEXT',b'CVE-2024-12345')]:
            with self.subTest(path=path):
                handler=self.http.handler(path);handler.do_GET()
                self.assertEqual(handler.response_status,200)
                self.assertIn(expected,handler.wfile.getvalue());self.assertNotIn(absent,handler.wfile.getvalue())
                self.assertIn(b'name="csrf_token"',handler.wfile.getvalue())
