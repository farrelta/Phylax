"""Local browser request checks and CSRF form protection."""
from __future__ import annotations
import hmac
import re
from urllib.parse import urlsplit, parse_qs

CSP = "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"


def _local_authority(host: str, port: int) -> tuple[str, int] | None:
    """Canonical loopback authority, without accepting aliases as the same origin."""
    try:
        if not host or any(c.isspace() or ord(c)<32 for c in host):return None
        parsed=urlsplit('//'+host)
        actual_port=parsed.port if parsed.port is not None else 80
        if (parsed.hostname not in {'127.0.0.1','localhost','::1'} or actual_port!=port
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment):return None
        return parsed.hostname,actual_port
    except ValueError:return None


def valid_host(host: str, port: int) -> bool:
    return _local_authority(host,port) is not None


def valid_origin(origin: str, host: str, port: int) -> bool:
    try:
        parsed=urlsplit(origin)
        expected=_local_authority(host,port)
        return bool(expected and parsed.scheme=='http'
                    and not any(c.isspace() or ord(c)<32 for c in origin)
                    and _local_authority(parsed.netloc,port)==expected
                    and parsed.path in {'','/'} and not parsed.query and not parsed.fragment)
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
