"""Offline presentation translations; persisted records and wire values stay canonical.

HTML is translated only at the HTTP presentation boundary. Attribute values used
by forms, links, CSS, SVG geometry, JSON, CSV and raw evidence are never changed.
Catalog templates describe application messages, including interpolated counts
and validation errors. External/source content can opt out with translate="no".
"""
from __future__ import annotations

import html
import json
import re
from functools import lru_cache
from html.parser import HTMLParser
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit

LANGUAGES = {'en': 'English', 'id': 'Bahasa Indonesia'}
COOKIE_NAME = 'phylax_language'
PLACEHOLDER = re.compile(r'\{(\d+)\}')


@lru_cache(maxsize=1)
def catalog() -> dict[str, str]:
    return json.loads(Path(__file__).with_name('locales').joinpath('id.json').read_text(encoding='utf-8'))


def request_language(headers) -> str:
    cookies = SimpleCookie()
    try:
        cookies.load(headers.get('Cookie', ''))
        selected = cookies.get(COOKIE_NAME)
        if selected and selected.value in LANGUAGES:
            return selected.value
    except CookieError:
        pass
    candidates = []
    for index, item in enumerate(headers.get('Accept-Language', '').split(',')):
        name, *parameters = item.strip().lower().split(';')
        try:
            quality = next((float(p.strip()[2:]) for p in parameters if p.strip().startswith('q=')), 1.0)
        except ValueError:
            continue
        language = name.split('-')[0]
        if language in LANGUAGES and 0 < quality <= 1:
            candidates.append((quality, -index, language))
    return max(candidates)[2] if candidates else 'en'


def local_destination(value: str) -> str:
    if not isinstance(value, str) or len(value) > 4096 or not value.startswith('/') or value.startswith('//'):
        return '/'
    if '\\' in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return '/'
    try:
        parts = urlsplit(value)
    except ValueError:
        return '/'
    if parts.scheme or parts.netloc or parts.path == '/language':
        return '/'
    return value


@lru_cache(maxsize=1)
def _templates():
    result = []
    for source, target in catalog().items():
        fields = list(PLACEHOLDER.finditer(source))
        if not fields:
            continue
        static = PLACEHOLDER.sub('', source)
        if len(re.sub(r'[^A-Za-z]', '', static)) < 5:
            continue
        chunks = PLACEHOLDER.split(source)
        pattern = ''.join(re.escape(chunk) if i % 2 == 0 else '(.*?)' for i, chunk in enumerate(chunks))
        result.append((len(static), re.compile(pattern, re.DOTALL), [m[1] for m in fields], target))
    return sorted(result, key=lambda row: -row[0])


@lru_cache(maxsize=4096)
def _translate(value: str, depth: int = 0) -> str:
    normalized = ' '.join(value.split())
    if not normalized or depth > 4 or len(value) > 20000:
        return value
    translated = catalog().get(normalized)
    if translated is not None and not PLACEHOLDER.search(normalized):
        return value[:len(value)-len(value.lstrip())] + translated + value[len(value.rstrip()):]
    if not re.search(r'\s', normalized) and ':' in normalized:
        return value
    # Structured source conditions also occur inline in older stored plans.
    # Translate their explanatory prefix while preserving the JSON payload.
    for marker in re.finditer(r'[\[{]', value):
        try:
            payload, end = json.JSONDecoder().raw_decode(value[marker.start():])
        except ValueError:
            continue
        if isinstance(payload, (dict, list)):
            start = marker.start(); end += start
            return _translate(value[:start], depth+1)+value[start:end]+_translate(value[end:], depth+1)
    for _, pattern, names, target in _templates():
        match = pattern.fullmatch(normalized)
        if match:
            replacements = {name: _translate(captured, depth+1) for name, captured in zip(names, match.groups())}
            translated = PLACEHOLDER.sub(lambda m: replacements[m[1]], target)
            return value[:len(value)-len(value.lstrip())] + translated + value[len(value.rstrip()):]
    # Captions and notices concatenate complete messages at runtime. Translate
    # each sentence or separated fact using the same catalog templates.
    for separator in (r'(?<=[.!?]) (?!$)', r' · '):
        parts = re.split('('+separator+')', value)
        if len(parts) > 1:
            return ''.join(part if index % 2 else _translate(part, depth+1) for index, part in enumerate(parts))
    if normalized.endswith(('.', ':')):
        stem = value.rstrip()[:-1]
        result = _translate(stem, depth+1)
        if result != stem:
            return result + normalized[-1] + value[len(value.rstrip()):]
    # Concatenated labels and application fragments retain punctuation and values.
    # Match whole phrases, never substrings in IDs, URLs or technical identifiers.
    translated = _fragments().sub(lambda match: catalog()[match[0]], normalized)
    return value[:len(value)-len(value.lstrip())] + translated + value[len(value.rstrip()):] if translated != normalized else value


@lru_cache(maxsize=1)
def _fragments():
    phrases = sorted((s for s in catalog() if not PLACEHOLDER.search(s) and re.search('[A-Za-z]', s)), key=len, reverse=True)
    return re.compile(r'(?<![\w/.@-])(?:'+'|'.join(re.escape(s) for s in phrases)+r')(?![\w/@-]|\.[A-Za-z0-9_])')


def translate_text(value: str, language: str = 'en') -> str:
    return _translate(str(value)) if language == 'id' else str(value)


class _TranslatedHTML(HTMLParser):
    """Keep original markup verbatim, changing only visible text and accessible labels."""
    protected_tags = {'style', 'script', 'pre', 'code', 'textarea'}

    def __init__(self, language: str):
        super().__init__(convert_charrefs=True)
        self.language = language
        self.output = []
        self.stack = []

    @property
    def protected(self):
        return any(skip for _, skip in self.stack)

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        skip = (tag in self.protected_tags or data.get('translate') == 'no'
                or 'advisory-text' in data.get('class', '').split())
        original = self.get_starttag_text()
        if tag == 'html':
            original = re.sub(r'\blang=([\"\']).*?\1', 'lang="'+self.language+'"', original, count=1)
        if not self.protected and data.get('translate') != 'no':
            def label(match):
                translated = translate_text(html.unescape(match[3]), self.language)
                return match[1] + match[2] + html.escape(translated, quote=True) + match[2]
            original = re.sub(r'(?<![\w:-])((?:aria-label|placeholder|title|alt)\s*=\s*)([\"\'])(.*?)\2', label, original, flags=re.DOTALL)
        self.output.append(original)
        if tag not in {'area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'}:
            self.stack.append((tag, skip))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_endtag(self, tag):
        self.output.append('</'+tag+'>')
        for index in range(len(self.stack)-1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, value):
        if self.stack and self.stack[-1][0] in {'style', 'script'}:
            self.output.append(value)
        else:
            self.output.append(html.escape(value if self.protected else translate_text(value, self.language), quote=False))

    def handle_entityref(self, name):
        self.output.append('&'+name+';')

    def handle_charref(self, name):
        self.output.append('&#'+name+';')

    def handle_decl(self, decl):
        self.output.append('<!'+decl+'>')

    def handle_comment(self, value):
        self.output.append('<!--'+value+'-->')


def translate_html(markup: str, language: str) -> str:
    if language != 'id':
        return markup
    parser = _TranslatedHTML(language)
    parser.feed(markup)
    parser.close()
    return ''.join(parser.output)


def language_control(destination: str, language: str) -> str:
    destination = local_destination(destination)
    path = urlsplit(destination).path
    # Validation responses are served from POST actions. Switching language
    # returns to their GET editor rather than navigating to an action as GET.
    action_views = {'/assets/save':'/assets/edit', '/policy/apply':'/policy',
                    '/remediation/update':'/remediation'}
    if path in action_views:
        destination = action_views[path]
    elif path.count('/') > 1 and path.split('/')[1] in {'processes','approvals','software','triage','sources'}:
        destination = '/settings' if path.startswith('/sources/') else '/'+path.split('/')[1]
    options = ''.join('<option value="'+code+'"'+(' selected' if code == language else '')+'>'+label+'</option>'
                      for code, label in LANGUAGES.items())
    return ('<form class="language-control" method="post" action="/language">'
            '<input type="hidden" name="next" value="'+html.escape(destination, quote=True)+'">'
            '<label for="interface-language">'+translate_text('Language', language)+'</label>'
            '<select id="interface-language" name="language" translate="no">'+options+'</select>'
            '<button>'+translate_text('Apply language', language)+'</button></form>')
