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


def advisory_summary(value,limit=320):
    """Preview source text, with all readable source content available on demand."""
    full=advisory_text(value)
    if not full:return '<p class="muted">No advisory summary supplied.</p>'
    paragraphs=full.split('\n\n')
    selected=next((i+1 for i,line in enumerate(paragraphs[:-1]) if re.fullmatch(r'(?:\d+[.\s]*)?(?:executive\s+)?summary',line,re.I)),None)
    preview=paragraphs[selected] if selected is not None else next((line for line in paragraphs if line.casefold() not in {'view csaf','view advisory'}),paragraphs[0])
    if len(preview)>limit:
        cut=preview[:limit].rsplit(' ',1)[0]
        preview=(cut or preview[:limit]).rstrip()+'…'
    body='<p class="advisory-preview">'+e(preview)+'</p>'
    if full!=preview:
        body+='<details class="advisory-content"><summary>Read full advisory text</summary><div class="advisory-text" tabindex="0" role="region" aria-label="Full advisory text">'+e(full)+'</div></details>'
    return body
