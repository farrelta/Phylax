"""Local browser request checks and CSRF form protection."""
from __future__ import annotations
import hmac
import re
from urllib.parse import urlsplit, parse_qs

CSP = "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"


def valid_host(host: str, port: int) -> bool:
    try:
        parsed=urlsplit('//'+host)
        return parsed.hostname in {'127.0.0.1','localhost','::1'} and (parsed.port or 80)==port and not parsed.username and not parsed.path and not parsed.query and not parsed.fragment
    except ValueError:return False


def valid_origin(origin: str, host: str, port: int) -> bool:
    try:
        parsed=urlsplit(origin)
        return parsed.scheme=='http' and valid_host(parsed.netloc,port) and parsed.netloc==host and parsed.path in {'','/'} and not parsed.query and not parsed.fragment
    except ValueError:return False


def protect_forms(body: str, token: str) -> str:
    # Renderer-owned form tags; untrusted text is escaped before reaching here.
    return re.sub(r'(<form\b[^>]*\bmethod=["\']post["\'][^>]*>)',lambda m:m[0]+f'<input type="hidden" name="csrf_token" value="{token}">',body,flags=re.I)


def form_token(raw: bytes, content_type: str) -> str:
    if content_type.startswith('multipart/form-data'):
        match=re.search(br'name="csrf_token"\r\n\r\n([A-Za-z0-9_-]{20,100})\r\n',raw)
        return match[1].decode() if match else ''
    return parse_qs(raw.decode('utf-8','replace')).get('csrf_token',[''])[0]


def valid_token(actual: str, expected: str) -> bool:
    return bool(expected) and hmac.compare_digest(actual.encode(),expected.encode())
