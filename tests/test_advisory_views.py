"""Cached advisory excerpts remain bounded, readable and inert."""
import unittest
from html import unescape
from phylax.advisory_views import advisory_summary,advisory_text
from phylax.core import Store
from phylax.web import ics_advisories_page


class AdvisoryViewTests(unittest.TestCase):
    def test_first_substantive_paragraph_is_visible_with_full_text_collapsed(self):
        first = 'Exploitation could cause denial of service.'
        value = ('<p><a href="https://example.org/csaf">View CSAF</a></p><h2>Summary</h2>'
                 f'<p>{first}</p><h2>Affected versions</h2><p>Version &lt;= 2.0.</p>')
        text = advisory_summary(value)
        full, preview = text.split('</details>', 1)
        self.assertIn('<details class="advisory-content"><summary>', full)
        self.assertIn('Show first substantive paragraph', full)
        self.assertIn('Version &lt;= 2.0.', full)
        self.assertEqual(preview, f'<p translate="no" class="advisory-preview">{first}</p>')

    def test_first_paragraph_is_not_truncated(self):
        first = 'Long advisory evidence. ' * 50
        text = advisory_summary(f'<p>{first}</p><p>More detail.</p>')
        preview = unescape(text.split('class="advisory-preview">', 1)[1].split('</p>', 1)[0])
        self.assertEqual(preview, first.strip())

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
            self.assertIn('Show full cached text',text)
            self.assertIn('/assist?task=ics-advisory&amp;key=test',text)
            self.assertIn('AI summary',text)
            self.assertNotIn('>Clear search</a>', text)
            self.assertNotIn('&lt;h2&gt;Executive Summary',text)
            self.assertEqual(dict(store.connection.execute('SELECT * FROM ics_advisories').fetchone()),before)
        finally:store.close()
