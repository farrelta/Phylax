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


def _cpe_components(criteria: str) -> tuple[str, str, str]:
    """Decode only the vendor, product and version slots of a CPE 2.3 name."""
    parts: list[str] = []
    current = ""
    escaped = False
    for character in criteria:
        if escaped:
            current += character
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            parts.append(current)
            current = ""
        else:
            current += character
    parts.append(current)
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return "", "", ""
    return parts[3], parts[4], parts[5]


def normalize_nvd(vulnerability: dict[str, Any], retrieved_at: str) -> dict[str, Any]:
    cve = vulnerability.get("cve", vulnerability)
    severity, cvss = _cvss(cve)
    products: dict[tuple[str, str], set[str]] = {}
    has_range: set[tuple[str, str]] = set()
    unresolved_conditions = False

    def visit(node: dict[str, Any]) -> None:
        nonlocal unresolved_conditions
        if str(node.get("operator", "")).upper() == "AND" or node.get("negate") is True:
            unresolved_conditions = True
        for match in node.get("cpeMatch", []):
            if match.get("vulnerable") is not True:
                unresolved_conditions = True
                continue
            vendor, product, version = _cpe_components(str(match.get("criteria", "")))
            if not vendor or not product or vendor in {"*", "-"} or product in {"*", "-"}:
                continue
            key = (vendor, product)
            ranged = any(match.get(field) for field in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"))
            if version in {"*", "-"} or ranged:
                has_range.add(key)
            else:
                products.setdefault(key, set()).add(version)
        for child in node.get("nodes", []):
            visit(child)

    for config in cve.get("configurations", []):
        visit(config)
    affected = [{"vendor": vendor, "product": product, "versions": sorted(versions) if (vendor, product) not in has_range else [], "conditions_unresolved": unresolved_conditions} for (vendor, product), versions in products.items()]
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
    for item in catalog.get("vulnerabilities", []):
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
    records = []
    for item in root.findall(".//item"):
        get = lambda tag: (item.findtext(tag) or "").strip()
        records.append({"advisory_id": get("guid") or get("link"), "title": get("title"), "link": get("link"), "published": get("pubDate"), "summary": get("description"), "retrieved_at": retrieved_at, "source": "CISA ICS advisories RSS"})
    return records


def nvd_pages(*, since: datetime | None = None, page_size: int = 2000, api_key: str | None = None, fetcher: Callable[[str], bytes] = fetch, now: datetime | None = None, on_page: Callable[[int, int, int], None] | None = None):
    """Yield normalized CVEs, paging the official API and respecting its 120-day window."""
    now = now or datetime.now(timezone.utc)
    end = now.astimezone(timezone.utc)
    start = since.astimezone(timezone.utc) if since else end - timedelta(days=30)
    if (end - start).days > 120:
        raise ValueError("NVD last-modified window cannot exceed 120 days")
    start_index = 0
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
        rows = payload.get("vulnerabilities", [])
        total = int(payload.get("totalResults", len(rows)))
        if on_page:
            on_page(start_index // min(2000, max(1, page_size)) + 1, total, len(rows))
        for row in rows:
            yield normalize_nvd(row, retrieved_at)
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


def sync_store(store: Any, *, fetcher: Callable[[str], bytes] = fetch, api_key: str | None = None, progress: Callable[[str, str, str], None] | None = None) -> dict[str, Any]:
    """Synchronize each source independently and preserve source health on failure."""
    def log(source: str, stage: str, message: str) -> None:
        if progress:
            progress(source, stage, message)

    now = datetime.now(timezone.utc)
    results: dict[str, Any] = {}
    row = store.connection.execute("SELECT last_success_at FROM intelligence_sources WHERE source='NVD API 2.0'").fetchone()
    if row and row["last_success_at"]:
        try:
            since = datetime.fromisoformat(row["last_success_at"].replace("Z", "+00:00")) - timedelta(days=1)
            since = max(since, now - timedelta(days=120))
        except ValueError:
            since = now - timedelta(days=30)
    else:
        since = now - timedelta(days=30)
    try:
        log("NVD API 2.0", "start", f"Fetching CVEs modified since {since.date()} (incremental window).")
        def nvd_progress(page: int, total: int, count: int) -> None:
            log("NVD API 2.0", "progress", f"Fetched page {page}; {count} records on this page, {total} total in the query window.")
        nvd_records = list(nvd_pages(since=since, api_key=api_key or os.environ.get("NVD_API_KEY"), fetcher=fetcher, on_page=nvd_progress))
        saved = store.ingest_normalized(nvd_records)
        store.set_source_health("NVD API 2.0", "healthy", records=saved, message=f"Retrieved {len(nvd_records)} CVE records since {since.date()}.")
        results["NVD API 2.0"] = {"ok": True, "records": saved}
        log("NVD API 2.0", "done", f"Stored {saved} records ({len(nvd_records)} returned).")
    except Exception as exc:
        store.set_source_health("NVD API 2.0", "unavailable", message=f"{type(exc).__name__}: {exc}")
        results["NVD API 2.0"] = {"ok": False, "error": str(exc)}
        log("NVD API 2.0", "error", f"Failed: {type(exc).__name__}: {exc}")
    try:
        log("CISA KEV", "start", "Downloading and parsing the Known Exploited Vulnerabilities catalog.")
        kev_data = json.loads(fetcher(KEV_URL))
        kev_records = normalize_kev(kev_data)
        retrieved = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        for record in kev_records:
            record["retrieved_at"] = retrieved
        saved = store.ingest_normalized(kev_records)
        store.set_source_health("CISA KEV", "healthy", records=saved, message=f"Retrieved {len(kev_records)} catalog records.")
        results["CISA KEV"] = {"ok": True, "records": saved}
        log("CISA KEV", "done", f"Stored/updated {saved} catalog records ({len(kev_records)} returned).")
    except Exception as exc:
        store.set_source_health("CISA KEV", "unavailable", message=f"{type(exc).__name__}: {exc}")
        results["CISA KEV"] = {"ok": False, "error": str(exc)}
        log("CISA KEV", "error", f"Failed: {type(exc).__name__}: {exc}")
    try:
        log("CISA ICS advisories RSS", "start", "Downloading and parsing the CISA ICS advisory feed.")
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        advisories = normalize_ics_rss(fetcher(ICS_RSS_URL), timestamp)
        saved = store.save_ics_advisories(advisories)
        store.set_source_health("CISA ICS advisories RSS", "healthy", records=saved, message=f"Retrieved {len(advisories)} advisory entries. Product/version applicability is not inferred from RSS text.")
        results["CISA ICS advisories RSS"] = {"ok": True, "records": saved}
        log("CISA ICS advisories RSS", "done", f"Stored/updated {saved} advisory entries; RSS does not provide evaluated product/version ranges.")
    except Exception as exc:
        store.set_source_health("CISA ICS advisories RSS", "unavailable", message=f"{type(exc).__name__}: {exc}")
        results["CISA ICS advisories RSS"] = {"ok": False, "error": str(exc)}
        log("CISA ICS advisories RSS", "error", f"Failed: {type(exc).__name__}: {exc}")
    return results
