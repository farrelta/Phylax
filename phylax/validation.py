"""Shared validation for public intelligence and inventory import boundaries."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit
from .identifiers import cpe_parts

RANGE_KEYS = ('start_including', 'start_excluding', 'end_including', 'end_excluding')


def utc_timestamp(value: str) -> str:
    if not value:
        return ''
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError('timezone is required')
        return dt.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')
    except (ValueError, TypeError) as exc:
        raise ValueError('timestamp must be ISO 8601 with a timezone') from exc


def strings(value: Any, label: str, *, limit: int = 1000, length: int = 4096) -> list[str]:
    if not isinstance(value, list) or len(value) > limit or any(not isinstance(v, str) or len(v) > length for v in value):
        raise ValueError(f'{label} must be an array of at most {limit} bounded strings')
    return list(value)


def products(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 10000:
        raise ValueError('affected_products must be an array of at most 10000 products')
    result = []
    for p in value:
        if not isinstance(p, dict) or any(not isinstance(p.get(k), str) or not p[k].strip() or len(p[k]) > 500 for k in ('vendor', 'product')):
            raise ValueError('Each affected product needs bounded vendor and product strings')
        item = {'vendor': p['vendor'].strip(), 'product': p['product'].strip(), 'versions': strings(p.get('versions', []), 'versions', length=200)}
        ranges = p.get('version_ranges', [])
        if not isinstance(ranges, list) or len(ranges) > 1000:
            raise ValueError('version_ranges must be an array')
        item['version_ranges'] = []
        for r in ranges:
            if not isinstance(r, dict) or any(k not in RANGE_KEYS for k in r):
                raise ValueError('Unsupported version-range fields; supply explicit inclusive/exclusive bounds')
            if any(not isinstance(v, str) or len(v) > 200 for v in r.values()) or not any(r.values()):
                raise ValueError('Version range needs at least one bounded string boundary')
            item['version_ranges'].append({k: r.get(k, '') for k in RANGE_KEYS})
        for key in ('conditions_unresolved', 'version_semantics_unknown'):
            flag = p.get(key, False)
            if not isinstance(flag, bool):
                raise ValueError(f'{key} must be boolean')
            item[key] = flag
        item['cpe_names'] = strings(p.get('cpe_names', []), 'cpe_names')
        item['unsupported_constraints'] = strings(p.get('unsupported_constraints', []), 'unsupported_constraints')
        for name in item['cpe_names']:
            parts = cpe_parts(name)
            if not parts:
                raise ValueError('Invalid CPE 2.3 name')
            item['unsupported_constraints'].extend(f'{key}={value}' for key,value in zip(('update','edition','language','sw_edition','target_sw','target_hw','other'),parts[6:]) if value != '*')
        item['unsupported_constraints'] = sorted(set(item['unsupported_constraints']))
        if item['unsupported_constraints']:
            item['conditions_unresolved'] = True
        if any(not v or any(ch in v for ch in ('*','?')) for v in item['versions']):
            item['version_semantics_unknown'] = True
            item['versions'] = [v for v in item['versions'] if v and not any(ch in v for ch in ('*','?'))]
        result.append(item)
    combined: dict[tuple[str,str],dict[str,Any]] = {}
    for item in result:
        identity=tuple(re.sub(r'[^a-z0-9]+',' ',item[k].casefold()).strip() for k in ('vendor','product'))
        if identity not in combined:combined[identity]=item;continue
        prior=combined[identity]
        for key in ('versions','version_ranges','cpe_names','unsupported_constraints'):
            prior[key].extend(value for value in item[key] if value not in prior[key])
        for key in ('conditions_unresolved','version_semantics_unknown'):prior[key] |= item[key]
    return list(combined.values())


def vulnerability(record: Any, *, synthetic_default: bool = False) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError('Each vulnerability must be an object')
    r = dict(record)
    cve = r.get('cve_id', '')
    if not isinstance(cve, str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve.upper()):
        raise ValueError(f'Invalid CVE identifier: {str(cve)[:80]!r}')
    r['cve_id'] = cve.upper()
    for key in ('summary', 'source', 'source_url', 'mitigation', 'exploitation_metadata', 'severity', 'published', 'modified', 'retrieved_at'):
        if key in r and (not isinstance(r[key], str) or len(r[key]) > 100000):
            raise ValueError(f'{key} must be a bounded string')
    if not r.get('summary', '').strip():
        raise ValueError(f'Missing summary for {cve}')
    score = r.get('cvss')
    if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10):
        raise ValueError('CVSS must be a number between 0 and 10 or null')
    for key in ('kev', 'synthetic'):
        if key in r and not isinstance(r[key], bool):
            raise ValueError(f'{key} must be boolean')
    r['synthetic'] = r.get('synthetic', synthetic_default)
    r['affected_products'] = products(r.get('affected_products', []))
    r['references'] = strings(r.get('references', [r['source_url']] if r.get('source_url') else []), 'references', length=2048)
    for url in r['references'] + ([r['source_url']] if r.get('source_url') else []):
        p = urlsplit(url)
        if p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password:
            raise ValueError('Source references must be public HTTP(S) URLs without credentials')
    return r


def csv_value(value: Any) -> Any:
    """Prevent spreadsheet formulas when untrusted strings are opened as CSV."""
    if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')):
        return "'" + value
    return value
