"""Cached advisory excerpts remain bounded, readable and inert."""
import unittest
from html import unescape
from phylax.advisory_views import advisory_summary,advisory_text
from phylax.core import Store
from phylax.web import ics_advisories_page


class AdvisoryViewTests(unittest.TestCase):
    def test_summary_section_preferred_over_csaf_link_and_technical_details(self):
        value='<p><a href="https://example.org/csaf">View CSAF</a></p><h2>Summary</h2><p>Exploitation could cause denial of service.</p><h2>Affected versions</h2><p>Version &lt;= 2.0.</p>'
        text=advisory_summary(value)
        preview=text.split('</p>',1)[0]
        self.assertIn('Exploitation could cause denial of service.',preview)
        self.assertNotIn('View CSAF',preview)
        self.assertIn('Read full advisory text',text)
        self.assertIn('Version &lt;= 2.0.',text)
        self.assertNotIn('<details class="advisory-content" open',text)

    def test_long_preview_is_bounded_with_full_text_retained(self):
        value='Long advisory evidence. '*1000
        text=advisory_summary(value)
        preview=unescape(text.split('class="advisory-preview">',1)[1].split('</p>',1)[0])
        self.assertLessEqual(len(preview),321)
        self.assertTrue(preview.endswith('…'))
        self.assertIn(value.strip(),text)

    def test_markup_and_active_content_are_not_rendered(self):
        value='<style>hidden-style</style><script>alert("unsafe")</script><p>Source says &lt;img src=x onerror=evil()&gt; &amp; version &lt; 3.</p>'
        text=advisory_summary(value)
        self.assertNotIn('<script',text);self.assertNotIn('<img',text)
        self.assertNotIn('hidden-style',text);self.assertNotIn('alert(',text)
        self.assertIn('&lt;img',text)
        self.assertEqual(advisory_text('<p>A <strong>safe</strong> description.</p>'),'A safe description.')

    def test_short_empty_plain_and_malformed_text(self):
        self.assertEqual(advisory_text(None),'')
        self.assertIn('No advisory summary supplied',advisory_summary(''))
        self.assertNotIn('<details',advisory_summary('Short source summary.'))
        self.assertIn('Unclosed paragraph',advisory_summary('<p>Unclosed paragraph'))

    def test_rendering_old_cached_html_does_not_change_stored_advisory(self):
        store=Store(':memory:')
        try:
            value='<h2>Executive Summary</h2><p>Short source statement.</p><p>'+('Detail. '*500)+'</p>'
            store.save_ics_advisories([{'advisory_id':'test','title':'Example advisory','summary':value,'link':'https://example.org/advisory'}])
            before=dict(store.connection.execute('SELECT * FROM ics_advisories').fetchone())
            text=ics_advisories_page(store)
            self.assertIn('Short source statement.',text)
            self.assertIn('Read full advisory text',text)
            self.assertNotIn('&lt;h2&gt;Executive Summary',text)
            self.assertEqual(dict(store.connection.execute('SELECT * FROM ics_advisories').fetchone()),before)
        finally:store.close()
