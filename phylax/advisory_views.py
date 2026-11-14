"""Compact, inert presentation of cached advisory text; never a new assessment."""
import re
from html.parser import HTMLParser
from .ui import e


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
