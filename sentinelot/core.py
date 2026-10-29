"""Persistence and the first, deliberately conservative Phylax workflow."""

from __future__ import annotations

import csv
import ipaddress
import json
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ASSET_FIELDS = (
    "asset_id", "ip_address", "mac_address", "hostname", "asset_type", "vendor",
    "product", "version", "operating_system", "zone", "criticality",
    "identification_source", "identity_confidence", "last_seen", "notes", "verified",
)
ASSET_TYPES = {"PLC", "RTU", "HMI", "engineering workstation", "server", "network device", "gateway", "unknown"}
ZONES = {"IT", "OT", "DMZ", "unknown"}
CRITICALITIES = {"low", "medium", "high", "critical"}
CONFIDENCES = {"low", "medium", "high"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _normalized(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").casefold()).strip()


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY, ip_address TEXT NOT NULL, mac_address TEXT DEFAULT '',
                hostname TEXT DEFAULT '', asset_type TEXT NOT NULL DEFAULT 'unknown', vendor TEXT DEFAULT '',
                product TEXT DEFAULT '', version TEXT DEFAULT '', operating_system TEXT DEFAULT '',
                zone TEXT NOT NULL DEFAULT 'unknown', criticality TEXT NOT NULL DEFAULT 'medium',
                identification_source TEXT NOT NULL DEFAULT 'manual', identity_confidence TEXT NOT NULL DEFAULT 'low',
                last_seen TEXT DEFAULT '', notes TEXT DEFAULT '', verified INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY, summary TEXT NOT NULL, published TEXT DEFAULT '', modified TEXT DEFAULT '',
                severity TEXT DEFAULT '', cvss REAL, source TEXT NOT NULL, source_url TEXT DEFAULT '',
                kev INTEGER NOT NULL DEFAULT 0, exploitation_metadata TEXT DEFAULT '', mitigation TEXT DEFAULT '',
                affected_products TEXT NOT NULL, retrieved_at TEXT NOT NULL, synthetic INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
                cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
                status TEXT NOT NULL, evidence TEXT NOT NULL, missing_evidence TEXT NOT NULL,
                priority TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(asset_id, cve_id)
            );
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY, finding_id TEXT NOT NULL UNIQUE REFERENCES findings(finding_id) ON DELETE CASCADE,
                severity TEXT NOT NULL, explanation TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
        """)
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def assets(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute("SELECT * FROM assets ORDER BY ip_address, asset_id")]

    def import_csv(self, source: str | Path | Any) -> dict[str, Any]:
        """Import rows, retaining valid rows and reporting each malformed row."""
        close = False
        if isinstance(source, (str, Path)):
            source = open(source, newline="", encoding="utf-8-sig")
            close = True
        errors: list[dict[str, Any]] = []
        imported = 0
        try:
            reader = csv.DictReader(source)
            missing = {"ip_address"} - set(reader.fieldnames or [])
            if missing:
                return {"imported": 0, "errors": [{"row": 1, "error": "Missing required header: ip_address"}]}
            for line, raw in enumerate(reader, start=2):
                row = {k: (v or "").strip() for k, v in raw.items() if k is not None}
                ip = row.get("ip_address", "")
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    errors.append({"row": line, "error": "ip_address must be a valid IPv4 or IPv6 address"})
                    continue
                asset_type = row.get("asset_type", "unknown") or "unknown"
                zone = row.get("zone", "unknown") or "unknown"
                criticality = row.get("criticality", "medium") or "medium"
                confidence = row.get("identity_confidence", "low") or "low"
                if asset_type.casefold() not in {v.casefold() for v in ASSET_TYPES}:
                    errors.append({"row": line, "error": f"Unsupported asset_type: {asset_type}"})
                    continue
                if zone.upper() not in {v.upper() for v in ZONES}:
                    errors.append({"row": line, "error": f"Unsupported zone: {zone}"})
                    continue
                if criticality.casefold() not in CRITICALITIES:
                    errors.append({"row": line, "error": f"Unsupported criticality: {criticality}"})
                    continue
                if confidence.casefold() not in CONFIDENCES:
                    errors.append({"row": line, "error": f"Unsupported identity_confidence: {confidence}"})
                    continue
                asset_id = row.get("asset_id") or str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentinelot:{ip}:{row.get('mac_address', '')}"))
                values = {
                    "asset_id": asset_id, "ip_address": ip, "mac_address": row.get("mac_address", ""),
                    "hostname": row.get("hostname", ""), "asset_type": asset_type,
                    "vendor": row.get("vendor", ""), "product": row.get("product", ""),
                    "version": row.get("version", ""), "operating_system": row.get("operating_system", ""),
                    "zone": zone.upper(), "criticality": criticality.casefold(),
                    "identification_source": row.get("identification_source", "manual") or "manual",
                    "identity_confidence": confidence.casefold(), "last_seen": row.get("last_seen", ""),
                    "notes": row.get("notes", ""), "verified": int(row.get("verified", "").casefold() in {"1", "true", "yes"}),
                    "updated_at": utc_now(),
                }
                try:
                    self.connection.execute(f"INSERT INTO assets ({','.join(values)}) VALUES ({','.join('?' for _ in values)}) ON CONFLICT(asset_id) DO UPDATE SET " + ",".join(f"{key}=excluded.{key}" for key in values if key != "asset_id"), tuple(values.values()))
                    imported += 1
                except sqlite3.IntegrityError as exc:
                    errors.append({"row": line, "error": str(exc)})
        finally:
            if close:
                source.close()
        self.connection.commit()
        return {"imported": imported, "errors": errors}

    def export_assets_csv(self, target: str | Path | Any) -> None:
        rows = self.assets()
        writer = csv.DictWriter(target, fieldnames=ASSET_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    def ingest_fixture(self, source: str | Path | dict[str, Any]) -> dict[str, Any]:
        if isinstance(source, (str, Path)):
            data = json.loads(Path(source).read_text(encoding="utf-8"))
        else:
            data = source
        records = data.get("vulnerabilities")
        if not isinstance(records, list):
            raise ValueError("Fixture must contain a vulnerabilities array")
        ingested = []
        for record in records:
            cve = str(record.get("cve_id", "")).upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
                raise ValueError(f"Invalid CVE identifier: {cve!r}")
            if not str(record.get("summary", "")).strip():
                raise ValueError(f"Missing summary for {cve}")
            products = record.get("affected_products", [])
            if not isinstance(products, list):
                raise ValueError(f"affected_products must be an array for {cve}")
            normalized = []
            for p in products:
                if not isinstance(p, dict) or not p.get("vendor") or not p.get("product"):
                    raise ValueError(f"Each affected product for {cve} needs vendor and product")
                # This MVP only evaluates exact versions from a source that explicitly supplies them.
                normalized.append({"vendor": str(p["vendor"]), "product": str(p["product"]), "versions": [str(x) for x in p.get("versions", [])]})
            values = (cve, record["summary"], record.get("published", ""), record.get("modified", ""), record.get("severity", ""), record.get("cvss"), record.get("source", "offline-fixture"), record.get("source_url", ""), int(bool(record.get("kev", False))), str(record.get("exploitation_metadata", "")), str(record.get("mitigation", "")), json.dumps(normalized), utc_now(), int(bool(record.get("synthetic", data.get("synthetic", True)))))
            self.connection.execute("""INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET summary=excluded.summary,published=excluded.published,modified=excluded.modified,severity=excluded.severity,cvss=excluded.cvss,source=excluded.source,source_url=excluded.source_url,kev=excluded.kev,exploitation_metadata=excluded.exploitation_metadata,mitigation=excluded.mitigation,affected_products=excluded.affected_products,retrieved_at=excluded.retrieved_at,synthetic=excluded.synthetic""", values)
            ingested.append(cve)
        self.connection.commit()
        return {"ingested": ingested, "retrieved_at": utc_now()}

    def correlate(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        assets = self.assets()
        vulns = [dict(r) for r in self.connection.execute("SELECT * FROM vulnerabilities")]
        for asset in assets:
            for vuln in vulns:
                affected = json.loads(vuln["affected_products"])
                product_match = next((p for p in affected if _normalized(p["vendor"]) == _normalized(asset["vendor"]) and _normalized(p["product"]) == _normalized(asset["product"])), None)
                if not asset["vendor"] or not asset["product"]:
                    status, evidence, missing = "NEEDS_REVIEW", ["Asset product identity is incomplete"], ["vendor", "product"]
                elif product_match is None:
                    # Do not create unrelated manufacturer-wide findings.
                    continue
                elif not asset["version"]:
                    status, evidence, missing = "POTENTIAL_MATCH", [f"Exact vendor/product identity matches source: {product_match['vendor']} {product_match['product']}"], ["asset version; source version applicability cannot be evaluated"]
                elif not product_match.get("versions"):
                    status, evidence, missing = "NEEDS_REVIEW", [f"Exact vendor/product identity matches source: {product_match['vendor']} {product_match['product']}"], ["source does not define affected version semantics"]
                elif asset["version"] in product_match["versions"]:
                    status, evidence, missing = "CONFIRMED_MATCH", [f"Exact vendor/product match: {product_match['vendor']} {product_match['product']}", f"Asset version {asset['version']} is explicitly listed by source"], []
                else:
                    status, evidence, missing = "NO_MATCH_TO_THIS_ADVISORY", [f"Exact vendor/product match, but asset version {asset['version']} is not among source-listed versions"], []
                priority = self._priority(asset, vuln, status)
                current = self.connection.execute("SELECT finding_id FROM findings WHERE asset_id=? AND cve_id=?", (asset["asset_id"], vuln["cve_id"])).fetchone()
                finding_id = current["finding_id"] if current else str(uuid.uuid5(uuid.NAMESPACE_URL, f"{asset['asset_id']}:{vuln['cve_id']}"))
                self.connection.execute("""INSERT INTO findings VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(asset_id,cve_id) DO UPDATE SET status=excluded.status,evidence=excluded.evidence,missing_evidence=excluded.missing_evidence,priority=excluded.priority,updated_at=excluded.updated_at""", (finding_id, asset["asset_id"], vuln["cve_id"], status, json.dumps(evidence), json.dumps(missing), priority, utc_now()))
                counts[status] = counts.get(status, 0) + 1
                if status in {"CONFIRMED_MATCH", "POTENTIAL_MATCH"}:
                    severity = vuln["severity"] or "Unknown"
                    explanation = f"{status}: {vuln['cve_id']} {severity}; {evidence[0]}. KEV membership: {'yes' if vuln['kev'] else 'no'} (catalog status does not indicate this asset is under attack)."
                    self.connection.execute("""INSERT INTO alerts VALUES (?,?,?,?,0,?,?) ON CONFLICT(finding_id) DO UPDATE SET severity=excluded.severity,explanation=excluded.explanation,updated_at=excluded.updated_at""", (str(uuid.uuid5(uuid.NAMESPACE_URL, finding_id)), finding_id, severity, explanation, utc_now(), utc_now()))
                else:
                    self.connection.execute("DELETE FROM alerts WHERE finding_id=?", (finding_id,))
        self.connection.commit()
        return counts

    @staticmethod
    def _priority(asset: dict[str, Any], vuln: dict[str, Any], status: str) -> str:
        if status not in {"CONFIRMED_MATCH", "POTENTIAL_MATCH"}:
            return "not_applicable"
        score = int(bool(vuln["kev"])) * 3 + {"critical": 3, "high": 2, "medium": 1}.get((vuln["severity"] or "").casefold(), 0) + {"critical": 3, "high": 2, "medium": 1}.get(asset["criticality"], 0) + (2 if status == "CONFIRMED_MATCH" else 0)
        return "critical" if score >= 8 else "high" if score >= 6 else "medium" if score >= 3 else "low"

    def dashboard(self) -> dict[str, Any]:
        return {
            "assets": self.connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0],
            "confirmed_assets": self.connection.execute("SELECT COUNT(DISTINCT asset_id) FROM findings WHERE status='CONFIRMED_MATCH'").fetchone()[0],
            "potential_assets": self.connection.execute("SELECT COUNT(DISTINCT asset_id) FROM findings WHERE status='POTENTIAL_MATCH'").fetchone()[0],
            "kev_findings": self.connection.execute("SELECT COUNT(*) FROM findings f JOIN vulnerabilities v USING(cve_id) WHERE v.kev=1 AND f.status IN ('CONFIRMED_MATCH','POTENTIAL_MATCH')").fetchone()[0],
            "unacknowledged_alerts": self.connection.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0],
            "findings": [dict(r) for r in self.connection.execute("""SELECT f.*,a.ip_address,a.hostname,a.vendor,a.product,a.version,v.summary,v.severity,v.kev,v.source,v.source_url,v.published,v.modified,v.mitigation,v.synthetic FROM findings f JOIN assets a USING(asset_id) JOIN vulnerabilities v USING(cve_id) ORDER BY CASE f.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, f.updated_at DESC""")],
            "alerts": [dict(r) for r in self.connection.execute("SELECT * FROM alerts ORDER BY created_at DESC")],
        }

    def acknowledge(self, alert_id: str) -> bool:
        cur = self.connection.execute("UPDATE alerts SET acknowledged=1,updated_at=? WHERE alert_id=?", (utc_now(), alert_id))
        self.connection.commit()
        return cur.rowcount == 1

    def report(self, format: str = "json") -> str:
        data = self.dashboard()
        payload = {"generated_at": utc_now(), "scope": "local inventory and locally stored intelligence", "known_limitations": ["No active scanning or device control is performed.", "Version matching currently uses only exact version strings explicitly supplied by the source.", "A missing match does not establish that an asset is safe.", "A vulnerability finding does not establish compromise."], "findings": data["findings"]}
        if format == "json":
            return json.dumps(payload, indent=2)
        if format == "csv":
            from io import StringIO
            out = StringIO()
            rows = payload["findings"]
            columns = ["asset_id", "ip_address", "hostname", "vendor", "product", "version", "cve_id", "status", "priority", "severity", "kev", "summary", "evidence", "missing_evidence", "source_url", "mitigation"]
            writer = csv.DictWriter(out, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({**row, "evidence": "; ".join(json.loads(row["evidence"])), "missing_evidence": "; ".join(json.loads(row["missing_evidence"]))})
            return out.getvalue()
        raise ValueError("format must be json or csv")


def read_json_limited(raw: bytes, max_bytes: int = 5_000_000) -> dict[str, Any]:
    if len(raw) > max_bytes:
        raise ValueError(f"Input exceeds {max_bytes} byte limit")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("JSON input must be an object")
    return parsed
