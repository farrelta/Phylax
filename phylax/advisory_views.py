"""Compact, inert presentation of cached advisory text; never a new assessment."""
import re
from html.parser import HTMLParser
from .ui import e, reference_links


class _AdvisoryText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts=[]
        self.hidden=0

    def handle_starttag(self,tag,attrs):
        if tag in {'script','style','template'}:self.hidden+=1
        if not self.hidden and tag in {'p','div','li','br','hr','tr','td','th','h1','h2','h3','h4','h5','h6'}:self.parts.append('\n')

    def handle_endtag(self,tag):
        if tag in {'script','style','template'}:
            self.hidden=max(0,self.hidden-1)
        if not self.hidden and tag in {'p','div','li','tr','td','th','h1','h2','h3','h4','h5','h6'}:self.parts.append('\n')

    def handle_data(self,data):
        if not self.hidden:self.parts.append(data)


def advisory_text(value):
    parser=_AdvisoryText()
    parser.feed(str(value or ''));parser.close()
    return '\n\n'.join(' '.join(line.split()) for line in ''.join(parser.parts).splitlines() if line.strip())


def advisory_summary(value):
    """Show the first substantive paragraph with the full cached description on demand."""
    full = advisory_text(value)
    if not full:
        return '<p class="muted">No advisory summary supplied.</p>'
    paragraphs = full.split('\n\n')
    summary_heading = r'(?:\d+[.\s]*)?(?:executive\s+)?summary'
    substantive = [
        line for line in paragraphs
        if line.casefold() not in {'view csaf', 'view advisory'}
        and not re.fullmatch(summary_heading, line, re.I)
    ]
    first = substantive[0] if substantive else paragraphs[0]
    full_markup = '<div class="advisory-text" translate="no">' + e(full) + '</div>'
    if full == first:
        return full_markup
    return (
        '<details class="advisory-content"><summary>'
        '<span class="advisory-collapse">Show first substantive paragraph</span>'
        '<span class="advisory-expand">Show full cached text</span>'
        '</summary>' + full_markup + '</details>'
        '<p translate="no" class="advisory-preview">' + e(first) + '</p>'
    )



def passages(records, *, ics=False):
    """Present explicit cached version boundaries and source recommendations."""
    facts = {}
    scopes = {}
    for record in records:
        source = record.get('source') or 'Unknown source'
        url = record.get('source_url')
        paragraphs = advisory_text(record.get('summary')).split('\n\n')
        sentences = [sentence for paragraph in paragraphs
                     for sentence in re.split(r'(?<=[.!?])\s+', paragraph)]
        affected = []
        for product in record.get('affected_products') or []:
            if product.get('conditions_unresolved') or product.get('version_semantics_unknown'):
                continue
            name = product.get('product') or product.get('vendor') or ''
            versions = list(product.get('versions') or [])
            for bounds in product.get('version_ranges') or []:
                limits = [symbol + ' ' + bounds[key] for key, symbol in
                          (('start_including', '>='), ('start_excluding', '>'),
                           ('end_including', '<='), ('end_excluding', '<')) if bounds.get(key)]
                if limits:
                    versions.append(' and '.join(limits))
            if versions:
                scope = ', '.join(versions)
                if product.get('excluded_versions'):
                    scope += ' (excluding ' + ', '.join(product['excluded_versions']) + ')'
                affected.append(name + ' · ' + scope)
                scopes.setdefault((product.get('vendor', ''), name), {}).setdefault(source, set()).add(scope)
        if ics:
            affected.extend(sentence for sentence in sentences
                            if re.search(r'(?:<=|>=|≤|≥)\s*\d|\b\d+(?:\.\d+)+\s+and (?:earlier|prior)\b', sentence, re.I))
        actions = [sentence for sentence in sentences if re.search(
            r'\b(?:fixed in|addressed in|update to|upgrade to)\b', sentence, re.I)]
        if record.get('mitigation'):
            actions.insert(0, advisory_text(record['mitigation']))
        for label, entries in (('Affected versions', affected), ('Fixed versions or recommended action', actions)):
            for entry in dict.fromkeys(entries):
                facts[f'E{len(facts)+1}'] = (label, entry, source, url)
    if not any(fact[0] == 'Affected versions' for fact in facts.values()):
        facts[f'E{len(facts)+1}'] = ('Affected version boundaries need verification', '', '', '')
    if any(len({frozenset(entries) for entries in by_source.values()}) > 1 for by_source in scopes.values()):
        facts[f'E{len(facts)+1}'] = ('Sources list different affected version statements', '', '', '')
    return facts


def render_facts(facts):
    return ''.join(
        '<section><h3>' + e(label) + '</h3>'
        + ('<p translate="no">' + e(value) + '</p>' if value else '')
        + ('<p>' + e(source) + (' · ' + reference_links([url]) if url else '') + '</p>' if source else '')
        + '</section>' for label, value, source, url in facts.values())
