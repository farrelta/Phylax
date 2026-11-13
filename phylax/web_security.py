"""Local browser request checks and CSRF form protection."""
from __future__ import annotations
import hmac
import re
from email.message import Message
from email.parser import BytesParser
from email.policy import HTTP
from urllib.parse import urlsplit

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


def multipart_fields(raw: bytes, content_type: str) -> dict[str, Message]:
    if '\r' in content_type or '\n' in content_type:
        return {}
    headers = f'Content-Type: {content_type}\r\n\r\n'.encode('latin-1')
    message = BytesParser(policy=HTTP).parsebytes(headers + raw)
    if message.get_content_type() != 'multipart/form-data' or message.defects or not message.is_multipart():
        return {}
    fields = {}
    for part in message.iter_parts():
        if part.get_content_disposition() == 'form-data' and not part.is_multipart():
            name = part.get_param('name', header='Content-Disposition')
            if name:
                fields.setdefault(name, part)
    return fields


def valid_token(actual: str, expected: str) -> bool:
    return bool(expected) and hmac.compare_digest(actual.encode(),expected.encode())
