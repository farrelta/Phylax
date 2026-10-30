"""Documented, read-only public vulnerability source adapters."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from .adapters import IntelligenceAdapter, KEVAdapter, ICSAdapter
from .identifiers import cpe_parts as _cpe_parts, cpe_components as _cpe_components


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ICS_RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
MAX_RESPONSE_BYTES = 20_000_000


def fetch(url: str, *, timeout: float = 20, opener: Callable[..., Any] = urllib.request.urlopen) -> bytes:
    """Fetch a fixed adapter URL with bounded body, timeout, and transient retries."""
    headers = {"User-Agent": "Phylax/0.1 (local vulnerability intelligence client)", "Accept": "application/json, application/rss+xml, application/xml"}
    for attempt in range(4):
        request = urllib.request.Request(url, headers=headers)
        try:
            with opener(request, timeout=timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("Source response exceeds 20 MB limit")
                return body
        except urllib.error.HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 3:
                raise
            delay = exc.headers.get("Retry-After", "")
            try:
                wait = min(30, max(0, float(delay)))
            except ValueError:
                wait = 2 ** attempt
            time.sleep(wait)
        except (urllib.error.URLError, TimeoutError):
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("unreachable")


def _first_description(descriptions: list[dict[str, Any]]) -> str:
    return next((str(item.get("value", "")) for item in descriptions if item.get("lang") == "en"), "")


def _cvss(cve: dict[str, Any]) -> tuple[str, float | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key, [])
        if rows:
            data = rows[0].get("cvssData", {})
            return str(data.get("baseSeverity") or rows[0].get("baseSeverity") or ""), data.get("baseScore")
    return "", None




def normalize_nvd(vulnerability: dict[str, Any], retrieved_at: str) -> dict[str, Any]:
    cve = vulnerability.get("cve", vulnerability)
    severity, cvss = _cvss(cve)
    products: dict[tuple[str, str], dict[str, Any]] = {}
    unresolved_conditions = False

    def visit(node: dict[str, Any]) -> None:
        nonlocal unresolved_conditions
        if str(node.get("operator", "")).upper() == "AND" or node.get("negate") is True:
            unresolved_conditions = True
        for match in node.get("cpeMatch", []):
            if match.get("vulnerable") is not True:
                unresolved_conditions = True
                continue
            criteria = str(match.get("criteria", ""))
            parts = _cpe_parts(criteria)
            vendor, product, version = _cpe_components(criteria)
            if not vendor or not product or vendor in {"*", "-"} or product in {"*", "-"}:
                continue
            key = (vendor, product)
            entry = products.setdefault(key, {"versions": set(), "version_ranges": [], "version_semantics_unknown": False, "cpe_names": [], "unsupported_constraints": []})
            entry["cpe_names"].append(criteria)
            for name, value in zip(("update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other"), parts[6:]):
                if value != "*":
                    entry["unsupported_constraints"].append(f"{name}={value}")
            if any(ch in version for ch in ("*", "?")) and version != "*":
                entry["version_semantics_unknown"] = True
            version_range = {
                "start_including": str(match.get("versionStartIncluding") or ""),
                "start_excluding": str(match.get("versionStartExcluding") or ""),
                "end_including": str(match.get("versionEndIncluding") or ""),
                "end_excluding": str(match.get("versionEndExcluding") or ""),
            }
            has_bounds = any(version_range.values())
            if has_bounds:
                entry["version_ranges"].append(version_range)
            elif version in {"*", "-"}:
                entry["version_semantics_unknown"] = True
            else:
                entry["versions"].add(version)
        for child in node.get("nodes", []):
            visit(child)

    for config in cve.get("configurations", []):
        visit(config)
    affected = [{"vendor": vendor, "product": product, "versions": sorted(entry["versions"]), "version_ranges": entry["version_ranges"], "version_semantics_unknown": entry["version_semantics_unknown"], "conditions_unresolved": unresolved_conditions or bool(entry["unsupported_constraints"]), "cpe_names": list(dict.fromkeys(entry["cpe_names"])), "unsupported_constraints": sorted(set(entry["unsupported_constraints"]))} for (vendor, product), entry in products.items()]
    references = [item.get("url", "") for item in cve.get("references", []) if item.get("url")]
    return {
        "cve_id": cve.get("id", ""), "summary": _first_description(cve.get("descriptions", [])),
        "published": cve.get("published", ""), "modified": cve.get("lastModified", ""),
        "severity": severity, "cvss": cvss, "source": "NVD API 2.0", "source_url": references[0] if references else "", "references": references,
        "kev": False, "exploitation_metadata": "", "mitigation": "", "affected_products": affected,
        "retrieved_at": retrieved_at, "synthetic": False,
    }


def normalize_kev(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    if not isinstance(catalog, dict) or not isinstance(catalog.get("vulnerabilities"), list):
        raise ValueError("KEV response must contain a vulnerabilities array")
    for item in catalog["vulnerabilities"]:
        if not isinstance(item, dict):
            raise ValueError("KEV catalog entries must be objects")
        cve = str(item.get("cveID", "")).upper()
        if not cve:
            continue
        product = str(item.get("product", ""))
        vendor = str(item.get("vendorProject", ""))
        result.append({
            "cve_id": cve,
            "summary": str(item.get("shortDescription") or item.get("vulnerabilityName") or "CISA KEV catalog entry; see source references."),
            "published": str(item.get("dateAdded", "")), "modified": str(item.get("dateAdded", "")),
            "severity": "", "cvss": None, "source": "CISA KEV", "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "kev": True,
            "exploitation_metadata": json.dumps({"date_added": item.get("dateAdded"), "due_date": item.get("dueDate"), "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"), "notes": item.get("notes")}),
            "mitigation": str(item.get("requiredAction", "")),
            # KEV names vendor/product but does not supply affected versions; never infer one.
            "affected_products": [{"vendor": vendor, "product": product, "versions": []}] if vendor and product else [],
            "retrieved_at": "", "synthetic": False,
        })
    return result


def normalize_ics_rss(xml_body: bytes, retrieved_at: str) -> list[dict[str, str]]:
    """Preserve structured feed entries, without inventing affected version data."""
    root = ET.fromstring(xml_body)
    if root.tag not in {"rss", "RDF", "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}RDF"}:
        raise ValueError("Expected an ICS RSS feed")
    records = []
    for item in root.findall(".//item"):
        get = lambda tag: (item.findtext(tag) or "").strip()
        records.append({"advisory_id": get("guid") or get("link"), "title": get("title"), "link": get("link"), "published": get("pubDate"), "summary": get("description"), "retrieved_at": retrieved_at, "source": "CISA ICS advisories RSS"})
    return records


def nvd_pages(*, since: datetime | None = None, until: datetime | None = None, page_size: int = 2000, start_index: int = 0, api_key: str | None = None, fetcher: Callable[[str], bytes] = fetch, now: datetime | None = None, on_page: Callable[[int, int, int], None] | None = None, on_batch: Callable[[int, int, int, list[dict[str, Any]]], None] | None = None):
    """Yield normalized CVEs; callbacks expose page batches for durable resumable ingestion."""
    now = now or datetime.now(timezone.utc)
    end = (until or now).astimezone(timezone.utc)
    start = since.astimezone(timezone.utc) if since else end - timedelta(days=30)
    if (end - start).days > 120:
        raise ValueError("NVD last-modified window cannot exceed 120 days")
    if start_index < 0 or page_size < 1:
        raise ValueError("NVD page offset and page size must be positive")
    start_index = int(start_index)
    retrieved_at = end.isoformat().replace("+00:00", "Z")
    while True:
        params = {"lastModStartDate": start.isoformat(timespec="milliseconds").replace("+00:00", "Z"), "lastModEndDate": end.isoformat(timespec="milliseconds").replace("+00:00", "Z"), "resultsPerPage": str(min(2000, max(1, page_size))), "startIndex": str(start_index)}
        url = NVD_URL + "?" + urllib.parse.urlencode(params)
        # The default fetcher accepts a Request; callers can inject deterministic byte fixtures.
        if fetcher is fetch and api_key:
            request = urllib.request.Request(url, headers={"apiKey": api_key, "User-Agent": "Phylax/0.1"})
            body = fetch_request(request)
        else:
            body = fetcher(url)
        payload = json.loads(body)
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list) or "totalResults" not in payload:
            raise ValueError("NVD response is missing vulnerabilities/totalResults")
        rows = payload["vulnerabilities"]
        total = int(payload["totalResults"])
        if total < 0:raise ValueError("NVD totalResults must not be negative")
        page_number = start_index // min(2000, max(1, page_size)) + 1
        records = [normalize_nvd(row, retrieved_at) for row in rows]
        if on_batch:
            on_batch(page_number, total, start_index + len(rows), records)
        if on_page:
            on_page(page_number, total, len(rows))
        yield from records
        if not rows and start_index < total:
            raise RuntimeError(f"NVD returned an empty page at offset {start_index} of {total}; keeping the sync checkpoint")
        start_index += len(rows)
        if not rows or start_index >= total:
            break


def fetch_request(request: urllib.request.Request) -> bytes:
    """Same bounds and retry behavior as fetch(), with an NVD API-key header."""
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("Source response exceeds 20 MB limit")
                return body
        except urllib.error.HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 3:
                raise
            try:
                wait = min(30, max(0, float(exc.headers.get("Retry-After", ""))))
            except (TypeError, ValueError):
                wait = 2 ** attempt
            time.sleep(wait)
        except (urllib.error.URLError, TimeoutError):
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("unreachable")


def collect_live(fetcher: Callable[[str], bytes] = fetch, *, nvd_since: datetime | None = None, api_key: str | None = None) -> dict[str, Any]:
    """Collect all three official feeds into normalized records; caller persists atomically."""
    now = datetime.now(timezone.utc)
    timestamp = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    nvd = list(nvd_pages(since=nvd_since, api_key=api_key, fetcher=fetcher))
    kev_data = json.loads(fetcher(KEV_URL))
    kev = normalize_kev(kev_data)
    rss = normalize_ics_rss(fetcher(ICS_RSS_URL), timestamp)
    return {"retrieved_at": timestamp, "nvd": nvd, "kev": kev, "ics_advisories": rss}


def sync_store(store: Any, *, fetcher: Callable[[str], bytes] = fetch, api_key: str | None = None, progress: Callable[[str, str, str], None] | None = None, backfill_days: int | None = None, nvd_page_size: int = 2000, additional_adapters: tuple[IntelligenceAdapter, ...] = ()) -> dict[str, Any]:
    """Synchronize each source independently and preserve source health on failure."""
    def log(source: str, stage: str, message: str) -> None:
        if progress:
            progress(source, stage, message)

    now = datetime.now(timezone.utc)
    results: dict[str, Any] = {}
    checkpoint = store.sync_checkpoint("NVD API 2.0")
    row = store.connection.execute("SELECT last_success_at FROM intelligence_sources WHERE source='NVD API 2.0'").fetchone()
    if checkpoint:
        since = datetime.fromisoformat(checkpoint["window_start"].replace("Z", "+00:00"))
        until = datetime.fromisoformat(checkpoint["window_end"].replace("Z", "+00:00"))
        next_index = int(checkpoint["next_start_index"])
        page_size = int(checkpoint["page_size"])
        resume_message = f"Resuming saved NVD window from page {next_index // page_size + 1} (offset {next_index})."
    else:
        if backfill_days is not None:
            if not 1 <= backfill_days <= 120:
                raise ValueError("NVD backfill days must be between 1 and 120")
            since = now - timedelta(days=backfill_days)
        elif row and row["last_success_at"]:
            try:
                since = datetime.fromisoformat(row["last_success_at"].replace("Z", "+00:00")) - timedelta(days=1)
            except ValueError:
                since = now - timedelta(days=1)
        else:
            since = now - timedelta(days=1)
        since = max(since, now - timedelta(days=120))
        until = now
        next_index = 0
        page_size = min(2000, max(1, nvd_page_size))
        resume_message = f"Fetching CVEs modified since {since.date()} (incremental window)."
    try:
        log("NVD API 2.0", "start", resume_message)
        saved = 0
        def persist_batch(page: int, total: int, next_offset: int, records: list[dict[str, Any]]) -> None:
            nonlocal saved
            saved += store.ingest_normalized(records, trusted_public=True)
            store.save_sync_checkpoint("NVD API 2.0", since.isoformat().replace("+00:00", "Z"), until.isoformat().replace("+00:00", "Z"), next_offset, page_size, total)
            log("NVD API 2.0", "progress", f"Saved page {page}; {len(records)} records on this page, {next_offset}/{total} fetched in this window.")
        for _record in nvd_pages(since=since, until=until, page_size=page_size, start_index=next_index, api_key=api_key or os.environ.get("NVD_API_KEY"), fetcher=fetcher, on_batch=persist_batch):
            pass
        store.set_source_health("NVD API 2.0", "healthy", records=saved, message=f"Retrieved {saved} CVE records since {since.date()}.", attempted_at=until.isoformat().replace("+00:00", "Z"))
        store.clear_sync_checkpoint("NVD API 2.0")
        results["NVD API 2.0"] = {"ok": True, "records": saved}
        log("NVD API 2.0", "done", f"Stored {saved} CVE records for the {since.date()} to {until.date()} window.")
    except Exception as exc:
        store.set_source_health("NVD API 2.0", "unavailable", message=f"{type(exc).__name__}: {exc}")
        results["NVD API 2.0"] = {"ok": False, "error": str(exc)}
        log("NVD API 2.0", "error", f"Failed: {type(exc).__name__}: {exc}")
    for adapter in (KEVAdapter(),ICSAdapter(),*additional_adapters):
        try:
            log(adapter.name,'start','Retrieving structured public intelligence.')
            timestamp=datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
            batch=adapter.collect(fetcher,timestamp)
            saved=store.ingest_normalized(batch.vulnerabilities,trusted_public=adapter.trusted_public) if batch.vulnerabilities else 0
            if batch.advisories:saved+=store.save_ics_advisories(batch.advisories)
            message=f'Retrieved {saved} records. Advisory-only entries do not imply version applicability.'
            store.set_source_health(adapter.name,'healthy',records=saved,message=message)
            results[adapter.name]={'ok':True,'records':saved}
            log(adapter.name,'done',message)
        except Exception as exc:
            store.set_source_health(adapter.name,'unavailable',message=f'{type(exc).__name__}: {exc}')
            results[adapter.name]={'ok':False,'error':str(exc)}
            log(adapter.name,'error',f'Failed: {type(exc).__name__}: {exc}')
    return results


def refresh_cve(store: Any, cve_id: str, *, fetcher: Callable[[str],bytes] = fetch) -> int:
    """Refresh one public record without uploading any asset or local context."""
    import re
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve_id.upper()):raise ValueError('Invalid CVE identifier')
    url=NVD_URL+'?'+urllib.parse.urlencode({'cveId':cve_id.upper()})
    if fetcher is fetch and os.environ.get('NVD_API_KEY'):
        body=fetch_request(urllib.request.Request(url,headers={'apiKey':os.environ['NVD_API_KEY'],'User-Agent':'Phylax/0.1'}))
    else:body=fetcher(url)
    payload=json.loads(body)
    if not isinstance(payload,dict) or not isinstance(payload.get('vulnerabilities'),list) or len(payload['vulnerabilities'])!=1:
        raise ValueError('NVD did not return exactly one public CVE record')
    timestamp=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    record=normalize_nvd(payload['vulnerabilities'][0],timestamp)
    if record['cve_id']!=cve_id.upper():raise ValueError('NVD returned a different CVE identifier')
    return store.ingest_normalized([record],trusted_public=True)
