"""Small extension contract for structured intelligence feeds.

NVD retains its specialized resumable page workflow in feeds.py. All adapters
emit the same validated vulnerability records consumed by Store, so adding a
feed never changes correlation code.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


@dataclass
class IntelligenceBatch:
    vulnerabilities: list[dict[str,Any]] = field(default_factory=list)
    advisories: list[dict[str,str]] = field(default_factory=list)


class IntelligenceAdapter(Protocol):
    name: str
    trusted_public: bool

    def collect(self, fetcher: Callable[[str],bytes], retrieved_at: str) -> IntelligenceBatch: ...


class KEVAdapter:
    name='CISA KEV'
    trusted_public=True

    def collect(self, fetcher, retrieved_at):
        import json
        from .feeds import KEV_URL,normalize_kev
        records=normalize_kev(json.loads(fetcher(KEV_URL)))
        for record in records:record['retrieved_at']=retrieved_at
        return IntelligenceBatch(vulnerabilities=records)


class ICSAdapter:
    name='CISA ICS advisories RSS'
    trusted_public=True

    def collect(self, fetcher, retrieved_at):
        from .feeds import ICS_RSS_URL,normalize_ics_rss
        return IntelligenceBatch(advisories=normalize_ics_rss(fetcher(ICS_RSS_URL),retrieved_at))
