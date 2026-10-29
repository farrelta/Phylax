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
from typing import Any


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


def _numeric_version(value: str) -> tuple[int, ...] | None:
    """Return a comparable tuple only for plain numeric dotted versions."""
    value = value.strip()
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        return None
    parts = [int(part) for part in value.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _version_applicability(asset_version: str, product: dict[str, Any]) -> bool | None:
    """Compare exact versions and documented NVD numeric bounds; None means uncertain."""
    if asset_version in product.get("versions", []):
        return True

    ranges = product.get("version_ranges", [])
    unresolved = bool(product.get("version_semantics_unknown"))
    version = _numeric_version(asset_version)
    for item in ranges:
        keys = ("start_including", "start_excluding", "end_including", "end_excluding")
        bounds = {key: _numeric_version(str(item.get(key, ""))) if item.get(key) else None for key in keys}
        if version is None or any(item.get(key) and bounds[key] is None for key in keys):
            unresolved = True
            continue
        start_including = bounds["start_including"]
        start_excluding = bounds["start_excluding"]
        end_including = bounds["end_including"]
        end_excluding = bounds["end_excluding"]
        above_start = (start_including is None or version >= start_including) and (start_excluding is None or version > start_excluding)
        below_end = (end_including is None or version <= end_including) and (end_excluding is None or version < end_excluding)
        if above_start and below_end:
            return True
    if unresolved:
        return None
    if ranges or product.get("versions"):
        return False
    return None


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
                affected_products TEXT NOT NULL, retrieved_at TEXT NOT NULL, synthetic INTEGER NOT NULL DEFAULT 0,
                references_json TEXT NOT NULL DEFAULT '[]'
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
            CREATE TABLE IF NOT EXISTS intelligence_sources (
                source TEXT PRIMARY KEY, health TEXT NOT NULL DEFAULT 'unknown',
                last_attempt_at TEXT DEFAULT '', last_success_at TEXT DEFAULT '',
                record_count INTEGER NOT NULL DEFAULT 0, message TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS sync_checkpoints (
                source TEXT PRIMARY KEY, window_start TEXT NOT NULL, window_end TEXT NOT NULL,
                next_start_index INTEGER NOT NULL, page_size INTEGER NOT NULL,
                total_results INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS intelligence_changes (
                change_id TEXT PRIMARY KEY, cve_id TEXT NOT NULL, source TEXT NOT NULL,
                change_type TEXT NOT NULL, changed_at TEXT NOT NULL, summary TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ics_advisories (
                advisory_id TEXT PRIMARY KEY, title TEXT NOT NULL, link TEXT DEFAULT '',
                published TEXT DEFAULT '', summary TEXT DEFAULT '', source TEXT NOT NULL,
                retrieved_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS network_events (
                event_id TEXT PRIMARY KEY, event_ref TEXT NOT NULL UNIQUE, timestamp TEXT NOT NULL,
                source_ip TEXT DEFAULT '', source_port INTEGER, destination_ip TEXT DEFAULT '',
                destination_port INTEGER, protocol TEXT DEFAULT '', operation TEXT DEFAULT '',
                event_type TEXT NOT NULL, source_file TEXT DEFAULT '', raw_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS network_alerts (
                alert_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, event_id TEXT NOT NULL REFERENCES network_events(event_id) ON DELETE CASCADE,
                severity TEXT NOT NULL, explanation TEXT NOT NULL, policy_evidence TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                UNIQUE(rule_id,event_id)
            );
            CREATE TABLE IF NOT EXISTS ai_remediations (
                finding_id TEXT PRIMARY KEY REFERENCES findings(finding_id) ON DELETE CASCADE,
                model TEXT NOT NULL, guidance_json TEXT NOT NULL, source_urls_json TEXT NOT NULL,
                generated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS remediation_plans (
                plan_id TEXT PRIMARY KEY, finding_id TEXT NOT NULL UNIQUE REFERENCES findings(finding_id) ON DELETE CASCADE,
                provider TEXT NOT NULL, model TEXT DEFAULT '', plan_json TEXT NOT NULL, source_urls_json TEXT NOT NULL,
                status TEXT NOT NULL, reviewer TEXT DEFAULT '', change_notes TEXT DEFAULT '', verification_evidence TEXT DEFAULT '',
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS remediation_plan_events (
                event_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES remediation_plans(plan_id) ON DELETE CASCADE,
                old_status TEXT NOT NULL, new_status TEXT NOT NULL, actor TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT NOT NULL
            );
        """)
        columns = {row["name"] for row in self.connection.execute("PRAGMA table_info(vulnerabilities)")}
        if "references_json" not in columns:
            self.connection.execute("ALTER TABLE vulnerabilities ADD COLUMN references_json TEXT NOT NULL DEFAULT '[]'")
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def assets(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute("SELECT * FROM assets ORDER BY ip_address, asset_id")]

    def search_assets(self, search: str = "", *, limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        search = search.strip()[:100]
        where = ""
        params: list[Any] = []
        if search:
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where = "WHERE ip_address LIKE ? ESCAPE '\\' OR hostname LIKE ? ESCAPE '\\' OR vendor LIKE ? ESCAPE '\\' OR product LIKE ? ESCAPE '\\'"
            params = [f"%{escaped}%"] * 4
        count = self.connection.execute(f"SELECT COUNT(*) FROM assets {where}", params).fetchone()[0]
        rows = [dict(row) for row in self.connection.execute(f"SELECT * FROM assets {where} ORDER BY ip_address,asset_id LIMIT ? OFFSET ?", [*params, min(max(1, limit), 100), max(0, offset)])]
        return rows, count

    def search_intelligence(self, search: str = "", *, limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        search = search.strip()[:100]
        where = ""
        params: list[Any] = []
        if search:
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where = "WHERE cve_id LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\' OR source LIKE ? ESCAPE '\\'"
            params = [f"%{escaped}%"] * 3
        count = self.connection.execute(f"SELECT COUNT(*) FROM vulnerabilities {where}", params).fetchone()[0]
        rows = [dict(row) for row in self.connection.execute(f"SELECT * FROM vulnerabilities {where} ORDER BY modified DESC,published DESC,cve_id LIMIT ? OFFSET ?", [*params, min(max(1, limit), 100), max(0, offset)])]
        advisories = [dict(row) for row in self.connection.execute("SELECT * FROM ics_advisories ORDER BY published DESC LIMIT 20")]
        return rows, count, advisories

    def recent_network_events(self, *, limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        count = self.connection.execute("SELECT COUNT(*) FROM network_events").fetchone()[0]
        rows = [dict(row) for row in self.connection.execute("""SELECT e.*,GROUP_CONCAT(a.rule_id) AS rule_ids,GROUP_CONCAT(a.alert_id) AS alert_ids FROM network_events e LEFT JOIN network_alerts a USING(event_id) GROUP BY e.event_id ORDER BY e.timestamp DESC LIMIT ? OFFSET ?""", (min(max(1, limit), 100), max(0, offset)))]
        return rows, count

    def attack_surface(self) -> dict[str, Any]:
        """Inventory nodes and bounded communication edges from stored observations only."""
        rows = [dict(row) for row in self.connection.execute("""SELECT source_ip,source_port,destination_ip,destination_port,protocol,operation,event_type,source_file,
            MIN(timestamp) AS first_seen,MAX(timestamp) AS last_seen,MIN(event_ref) AS sample_event_ref,COUNT(*) AS event_count
            FROM network_events GROUP BY source_ip,source_port,destination_ip,destination_port,protocol,operation,event_type,source_file
            ORDER BY last_seen DESC LIMIT 1000""")]
        by_ip: dict[str, dict[str, Any]] = {}
        for asset in self.assets():
            candidate = by_ip.get(asset["ip_address"])
            if not candidate or (asset["verified"], asset["identity_confidence"] == "high") > (candidate["verified"], candidate["identity_confidence"] == "high"):
                by_ip[asset["ip_address"]] = asset
        observed_ips = {ip for row in rows for ip in (row["source_ip"], row["destination_ip"]) if ip}
        nodes = []
        for ip in sorted(set(by_ip) | observed_ips):
            asset = by_ip.get(ip)
            nodes.append({
                "ip_address": ip, "asset_id": asset["asset_id"] if asset else "",
                "identity": (asset["hostname"] or (asset["vendor"] + " " + asset["product"]).strip() or ("Unknown / low-confidence observed endpoint" if asset["identification_source"] == "zeek_passive" else "Unknown")) if asset else "Unknown peer",
                "asset_type": asset["asset_type"] if asset else "unknown",
                "zone": asset["zone"] if asset else "unknown", "criticality": asset["criticality"] if asset else "unknown",
                "vendor": asset["vendor"] if asset else "", "product": asset["product"] if asset else "",
                "version": asset["version"] if asset else "", "identity_confidence": asset["identity_confidence"] if asset else "unknown",
                "verified": bool(asset["verified"]) if asset else False,
                "last_seen": asset["last_seen"] if asset else "", "observed": ip in observed_ips,
                "visibility": "Observed in imported logs" if ip in observed_ips else "Inventory only; no imported traffic observed",
            })
        edges = []
        for row in rows:
            source = by_ip.get(row["source_ip"])
            destination = by_ip.get(row["destination_ip"])
            row.update({"source_identity": (source["hostname"] or (source["vendor"] + " " + source["product"]).strip() or ("Unknown / low-confidence observed endpoint" if source["identification_source"] == "zeek_passive" else source["asset_id"])) if source else "Unknown peer", "destination_identity": (destination["hostname"] or (destination["vendor"] + " " + destination["product"]).strip() or ("Unknown / low-confidence observed endpoint" if destination["identification_source"] == "zeek_passive" else destination["asset_id"])) if destination else "Unknown peer"})
            edges.append(row)
        return {"nodes": nodes, "edges": edges, "event_count": self.connection.execute("SELECT COUNT(*) FROM network_events").fetchone()[0], "edge_limit": 1000}

    def public_vulnerability_for_finding(self, finding_id: str) -> dict[str, Any] | None:
        """Return only public intelligence columns; no local asset/finding fields."""
        row = self.connection.execute("""SELECT v.cve_id,v.summary,v.published,v.modified,v.severity,v.cvss,v.kev,
            v.exploitation_metadata,v.mitigation,v.affected_products,v.source,v.source_url,v.references_json,v.synthetic
            FROM findings f JOIN vulnerabilities v USING(cve_id) WHERE f.finding_id=?""", (finding_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["affected_products"] = json.loads(result["affected_products"])
        result["references"] = json.loads(result.pop("references_json"))
        return result

    def save_ai_remediation(self, finding_id: str, model: str, guidance: dict[str, Any], source_urls: list[str]) -> None:
        if not self.connection.execute("SELECT 1 FROM findings WHERE finding_id=?", (finding_id,)).fetchone():
            raise ValueError("Finding not found")
        self.connection.execute("""INSERT INTO ai_remediations VALUES (?,?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET
            model=excluded.model,guidance_json=excluded.guidance_json,source_urls_json=excluded.source_urls_json,generated_at=excluded.generated_at""",
            (finding_id, model, json.dumps(guidance), json.dumps(source_urls), utc_now()))
        self.connection.commit()

    def get_ai_remediation(self, finding_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM ai_remediations WHERE finding_id=?", (finding_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["guidance"] = json.loads(result.pop("guidance_json"))
        result["source_urls"] = json.loads(result.pop("source_urls_json"))
        return result

    def create_remediation_plan(self, finding_id: str, provider: str, model: str, plan: dict[str, Any], source_urls: list[str]) -> dict[str, Any]:
        if not self.connection.execute("SELECT 1 FROM findings WHERE finding_id=?", (finding_id,)).fetchone():
            raise ValueError("Finding not found")
        existing = self.connection.execute("SELECT plan_id,status FROM remediation_plans WHERE finding_id=?", (finding_id,)).fetchone()
        now = utc_now()
        if existing:
            plan_id = existing["plan_id"]
            self.connection.execute("UPDATE remediation_plans SET provider=?,model=?,plan_json=?,source_urls_json=?,status='Recommended',reviewer='',change_notes='',verification_evidence='',updated_at=? WHERE plan_id=?", (provider, model, json.dumps(plan), json.dumps(source_urls), now, plan_id))
            self.connection.execute("INSERT INTO remediation_plan_events VALUES (?,?,?,?,?,?,?)", (str(uuid.uuid4()), plan_id, existing["status"], "Recommended", "system", "Plan regenerated; prior review and verification were cleared.", now))
        else:
            plan_id = str(uuid.uuid4())
            self.connection.execute("INSERT INTO remediation_plans VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (plan_id, finding_id, provider, model, json.dumps(plan), json.dumps(source_urls), "Recommended", "", "", "", now, now))
            self.connection.execute("INSERT INTO remediation_plan_events VALUES (?,?,?,?,?,?,?)", (str(uuid.uuid4()), plan_id, "New", "Recommended", "system", "Plan generated; no operational change was made.", now))
        self.connection.commit()
        return self.get_remediation_plan(finding_id)  # type: ignore[return-value]

    def get_remediation_plan(self, finding_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM remediation_plans WHERE finding_id=?", (finding_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["plan"] = json.loads(result.pop("plan_json"))
        result["source_urls"] = json.loads(result.pop("source_urls_json"))
        result["history"] = [dict(item) for item in self.connection.execute("SELECT old_status,new_status,actor,notes,created_at FROM remediation_plan_events WHERE plan_id=? ORDER BY created_at", (result["plan_id"],))]
        return result

    def update_remediation_plan(self, finding_id: str, status: str, *, reviewer: str = "", change_notes: str = "", verification_evidence: str = "") -> dict[str, Any]:
        transitions = {
            "Recommended": {"Under Review", "Rejected", "Deferred", "Needs More Evidence"},
            "Under Review": {"Recommended", "Approved", "Rejected", "Deferred", "Needs More Evidence"},
            "Approved": {"Under Review", "Implemented", "Rejected", "Deferred"},
            "Implemented": {"Under Review", "Verified", "Deferred"},
            "Rejected": {"Recommended", "Under Review"},
            "Deferred": {"Recommended", "Under Review"},
            "Needs More Evidence": {"Recommended", "Under Review"},
            "Verified": {"Under Review"},
        }
        row = self.connection.execute("SELECT plan_id,status FROM remediation_plans WHERE finding_id=?", (finding_id,)).fetchone()
        if not row:
            raise ValueError("Remediation plan not found")
        if status not in transitions.get(row["status"], set()):
            raise ValueError(f"Invalid remediation transition: {row['status']} → {status}")
        if status == "Approved" and not reviewer.strip():
            raise ValueError("Reviewer is required for approval")
        if status == "Verified" and not verification_evidence.strip():
            raise ValueError("Verification evidence is required before marking a plan verified")
        now = utc_now()
        self.connection.execute("UPDATE remediation_plans SET status=?,reviewer=CASE WHEN ?!='' THEN ? ELSE reviewer END,change_notes=CASE WHEN ?!='' THEN ? ELSE change_notes END,verification_evidence=CASE WHEN ?='Under Review' THEN '' WHEN ?!='' THEN ? ELSE verification_evidence END,updated_at=? WHERE plan_id=?", (status, reviewer.strip(), reviewer.strip(), change_notes.strip(), change_notes.strip(), status, verification_evidence.strip(), verification_evidence.strip(), now, row["plan_id"]))
        self.connection.execute("INSERT INTO remediation_plan_events VALUES (?,?,?,?,?,?,?)", (str(uuid.uuid4()), row["plan_id"], row["status"], status, reviewer.strip(), change_notes.strip() or verification_evidence.strip(), now))
        self.connection.commit()
        return self.get_remediation_plan(finding_id)  # type: ignore[return-value]

    def observe_ip(self, ip: str, timestamp: str) -> None:
        """Track a private observed endpoint without inferring device identity."""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return
        if not address.is_private:
            return
        existing = self.connection.execute("SELECT asset_id FROM assets WHERE ip_address=? ORDER BY verified DESC, identity_confidence DESC LIMIT 1", (ip,)).fetchone()
        if existing:
            self.connection.execute("UPDATE assets SET last_seen=CASE WHEN last_seen='' OR last_seen<? THEN ? ELSE last_seen END,updated_at=? WHERE asset_id=?", (timestamp, timestamp, utc_now(), existing["asset_id"]))
            return
        values = (str(uuid.uuid5(uuid.NAMESPACE_URL, f"phylax-observed:{ip}")), ip, "", "", "unknown", "", "", "", "", "unknown", "medium", "zeek_passive", "low", timestamp, "Passive observation only; product, model, and firmware were not inferred.", 0, utc_now())
        self.connection.execute("INSERT OR IGNORE INTO assets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values)

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
                asset_id = row.get("asset_id") or str(uuid.uuid5(uuid.NAMESPACE_URL, f"phylax:{ip}:{row.get('mac_address', '')}"))
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
                normalized.append({"vendor": str(p["vendor"]), "product": str(p["product"]), "versions": [str(x) for x in p.get("versions", [])], "conditions_unresolved": bool(p.get("conditions_unresolved", False))})
            previous = self.connection.execute("SELECT summary,modified,severity,affected_products FROM vulnerabilities WHERE cve_id=?", (cve,)).fetchone()
            values = (cve, record["summary"], record.get("published", ""), record.get("modified", ""), record.get("severity", ""), record.get("cvss"), record.get("source", "offline-fixture"), record.get("source_url", ""), int(bool(record.get("kev", False))), str(record.get("exploitation_metadata", "")), str(record.get("mitigation", "")), json.dumps(normalized), utc_now(), int(bool(record.get("synthetic", data.get("synthetic", True)))), json.dumps(record.get("references", ([record.get("source_url")] if record.get("source_url") else []))))
            self.connection.execute("""INSERT INTO vulnerabilities(cve_id,summary,published,modified,severity,cvss,source,source_url,kev,exploitation_metadata,mitigation,affected_products,retrieved_at,synthetic,references_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(cve_id) DO UPDATE SET summary=excluded.summary,published=excluded.published,modified=excluded.modified,severity=excluded.severity,cvss=excluded.cvss,source=excluded.source,source_url=excluded.source_url,kev=excluded.kev,exploitation_metadata=excluded.exploitation_metadata,mitigation=excluded.mitigation,affected_products=excluded.affected_products,retrieved_at=excluded.retrieved_at,synthetic=excluded.synthetic,references_json=excluded.references_json""", values)
            if not previous or any((previous[field] or "") != value for field, value in (("summary", record["summary"]), ("modified", record.get("modified", "")), ("severity", record.get("severity", "")), ("affected_products", json.dumps(normalized)))):
                self._record_intelligence_change(cve, "new" if not previous else "updated", record.get("source", "offline-fixture"), record.get("modified", ""), record["summary"])
            ingested.append(cve)
        self.connection.commit()
        return {"ingested": ingested, "retrieved_at": utc_now()}

    def ingest_normalized(self, records: list[dict[str, Any]]) -> int:
        """Persist normalized adapter records; merge KEV metadata without losing NVD evidence."""
        count = 0
        for record in records:
            cve = str(record.get("cve_id", "")).upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
                continue
            existing = self.connection.execute("SELECT * FROM vulnerabilities WHERE cve_id=?", (cve,)).fetchone()
            if record.get("source") == "CISA KEV" and existing:
                kev_changed = not existing["kev"] or existing["exploitation_metadata"] != record.get("exploitation_metadata", "") or (record.get("mitigation") and existing["mitigation"] != record.get("mitigation"))
                self.connection.execute("UPDATE vulnerabilities SET kev=1,exploitation_metadata=?,mitigation=CASE WHEN ?!='' THEN ? ELSE mitigation END,retrieved_at=? WHERE cve_id=?", (record.get("exploitation_metadata", ""), record.get("mitigation", ""), record.get("mitigation", ""), record.get("retrieved_at") or utc_now(), cve))
                if kev_changed:
                    self._record_intelligence_change(cve, "updated" if existing["kev"] else "new_kev", "CISA KEV", record.get("modified", ""), record.get("summary", cve))
            else:
                products = record.get("affected_products", [])
                references = record.get("references") or ([record.get("source_url")] if record.get("source_url") else [])
                values = (cve, record.get("summary", "") or cve, record.get("published", ""), record.get("modified", ""), record.get("severity", ""), record.get("cvss"), record.get("source", "unknown"), record.get("source_url", ""), int(bool(record.get("kev"))), record.get("exploitation_metadata", ""), record.get("mitigation", ""), json.dumps(products), record.get("retrieved_at") or utc_now(), int(bool(record.get("synthetic", False))), json.dumps(references))
                materially_changed = not existing or any((existing[old] or "") != (current or "") for old, current in (("summary", record.get("summary", "") or cve), ("published", record.get("published", "")), ("modified", record.get("modified", "")), ("severity", record.get("severity", "")), ("cvss", record.get("cvss")), ("source", record.get("source", "unknown")), ("source_url", record.get("source_url", "")), ("affected_products", json.dumps(products)), ("references_json", json.dumps(references))))
                self.connection.execute("""INSERT INTO vulnerabilities(cve_id,summary,published,modified,severity,cvss,source,source_url,kev,exploitation_metadata,mitigation,affected_products,retrieved_at,synthetic,references_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET summary=excluded.summary,published=CASE WHEN excluded.published!='' THEN excluded.published ELSE vulnerabilities.published END,modified=CASE WHEN excluded.modified!='' THEN excluded.modified ELSE vulnerabilities.modified END,severity=CASE WHEN excluded.severity!='' THEN excluded.severity ELSE vulnerabilities.severity END,cvss=COALESCE(excluded.cvss,vulnerabilities.cvss),source=excluded.source,source_url=CASE WHEN excluded.source_url!='' THEN excluded.source_url ELSE vulnerabilities.source_url END,kev=MAX(vulnerabilities.kev,excluded.kev),exploitation_metadata=CASE WHEN excluded.exploitation_metadata!='' THEN excluded.exploitation_metadata ELSE vulnerabilities.exploitation_metadata END,mitigation=CASE WHEN excluded.mitigation!='' THEN excluded.mitigation ELSE vulnerabilities.mitigation END,affected_products=CASE WHEN excluded.affected_products!='[]' THEN excluded.affected_products ELSE vulnerabilities.affected_products END,retrieved_at=excluded.retrieved_at,synthetic=excluded.synthetic,references_json=CASE WHEN excluded.references_json!='[]' THEN excluded.references_json ELSE vulnerabilities.references_json END""", values)
                if materially_changed:
                    self._record_intelligence_change(cve, "new" if not existing else "updated", record.get("source", "unknown"), record.get("modified", ""), record.get("summary", cve))
            count += 1
        self.connection.commit()
        return count

    def _record_intelligence_change(self, cve: str, change_type: str, source: str, source_modified: str, summary: str) -> None:
        changed_at = source_modified or utc_now()
        change_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"phylax-intel:{cve}:{change_type}:{changed_at}"))
        self.connection.execute("INSERT OR IGNORE INTO intelligence_changes VALUES (?,?,?,?,?,?)", (change_id, cve, source, change_type, changed_at, str(summary)[:1000]))

    def save_ics_advisories(self, records: list[dict[str, str]]) -> int:
        for record in records:
            if not record.get("advisory_id") or not record.get("title"):
                continue
            self.connection.execute("""INSERT INTO ics_advisories VALUES (?,?,?,?,?,?,?) ON CONFLICT(advisory_id) DO UPDATE SET title=excluded.title,link=excluded.link,published=excluded.published,summary=excluded.summary,retrieved_at=excluded.retrieved_at""", (record["advisory_id"], record["title"], record.get("link", ""), record.get("published", ""), record.get("summary", ""), record.get("source", "CISA ICS advisories RSS"), record.get("retrieved_at", utc_now())))
        self.connection.commit()
        return len(records)

    def set_source_health(self, source: str, health: str, *, records: int = 0, message: str = "", attempted_at: str | None = None) -> None:
        attempted_at = attempted_at or utc_now()
        self.connection.execute("""INSERT INTO intelligence_sources(source,health,last_attempt_at,last_success_at,record_count,message) VALUES(?,?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET health=excluded.health,last_attempt_at=excluded.last_attempt_at,last_success_at=CASE WHEN excluded.health='healthy' THEN excluded.last_success_at ELSE intelligence_sources.last_success_at END,record_count=CASE WHEN excluded.health='healthy' THEN excluded.record_count ELSE intelligence_sources.record_count END,message=excluded.message""", (source, health, attempted_at, attempted_at if health == "healthy" else "", records, message[:500]))
        self.connection.commit()

    def sync_checkpoint(self, source: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM sync_checkpoints WHERE source=?", (source,)).fetchone()
        return dict(row) if row else None

    def save_sync_checkpoint(self, source: str, window_start: str, window_end: str, next_start_index: int, page_size: int, total_results: int) -> None:
        self.connection.execute("""INSERT INTO sync_checkpoints VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(source) DO UPDATE SET window_start=excluded.window_start,window_end=excluded.window_end,
            next_start_index=excluded.next_start_index,page_size=excluded.page_size,total_results=excluded.total_results,updated_at=excluded.updated_at""",
            (source, window_start, window_end, next_start_index, page_size, total_results, utc_now()))
        self.connection.commit()

    def clear_sync_checkpoint(self, source: str) -> None:
        self.connection.execute("DELETE FROM sync_checkpoints WHERE source=?", (source,))
        self.connection.commit()

    def source_health(self) -> list[dict[str, Any]]:
        rows = [dict(row) for row in self.connection.execute("SELECT * FROM intelligence_sources ORDER BY source")]
        now = datetime.now(timezone.utc)
        for row in rows:
            if row["health"] == "healthy" and row["last_success_at"]:
                try:
                    checked = datetime.fromisoformat(row["last_success_at"].replace("Z", "+00:00"))
                    if (now - checked).total_seconds() > 86400:
                        row["health"] = "stale"
                except ValueError:
                    row["health"] = "unknown"
        return rows

    def correlate(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        assets = self.assets()
        vulns = [dict(r) for r in self.connection.execute("SELECT * FROM vulnerabilities")]
        for asset in assets:
            if not asset["vendor"].strip() or not asset["product"].strip():
                # Incomplete inventory identity is tracked separately; do not fan it out
                # into one meaningless NEEDS_REVIEW row per CVE.
                self.connection.execute("DELETE FROM findings WHERE asset_id=?", (asset["asset_id"],))
                continue
            for vuln in vulns:
                affected = json.loads(vuln["affected_products"])
                product_match = next((p for p in affected if _normalized(p["vendor"]) == _normalized(asset["vendor"]) and _normalized(p["product"]) == _normalized(asset["product"])), None)
                if product_match is None:
                    # Do not create unrelated manufacturer-wide findings.
                    self.connection.execute("DELETE FROM findings WHERE asset_id=? AND cve_id=?", (asset["asset_id"], vuln["cve_id"]))
                    continue
                elif product_match.get("conditions_unresolved"):
                    status, evidence, missing = "NEEDS_REVIEW", [f"Exact vendor/product identity appears in source conditions: {product_match['vendor']} {product_match['product']}"], ["source configuration prerequisites are not evaluated by this matcher"]
                elif asset["identity_confidence"] == "low":
                    status, evidence, missing = "NEEDS_REVIEW", [f"Candidate product matches source: {product_match['vendor']} {product_match['product']}"], ["asset identity confidence is low; verify vendor and product"]
                elif not asset["version"]:
                    status, evidence = "POTENTIAL_MATCH", [f"Candidate vendor/product identity matches source: {product_match['vendor']} {product_match['product']}"]
                    missing = ["asset version; source version applicability cannot be evaluated"]
                    if not product_match.get("versions") and not product_match.get("version_ranges"):
                        missing.append("source affected-version data")
                    if asset["identity_confidence"] != "high" or not asset["verified"]:
                        missing.append("asset identity has not been confirmed at high confidence")
                else:
                    version_match = _version_applicability(asset["version"], product_match)
                    if version_match is None:
                        status, evidence, missing = "NEEDS_REVIEW", [f"Exact vendor/product identity matches source: {product_match['vendor']} {product_match['product']}"], [f"source version semantics cannot be compared safely with asset version {asset['version']}"]
                    elif version_match and (asset["identity_confidence"] != "high" or not asset["verified"]):
                        status, evidence, missing = "POTENTIAL_MATCH", [f"Candidate vendor/product/version matches source: {product_match['vendor']} {product_match['product']} {asset['version']}"], ["asset identity has not been confirmed at high confidence"]
                    elif version_match:
                        status, evidence, missing = "CONFIRMED_MATCH", [f"Exact vendor/product match: {product_match['vendor']} {product_match['product']}", f"Asset version {asset['version']} matches source-defined affected-version data"], []
                    elif asset["identity_confidence"] != "high" or not asset["verified"]:
                        status, evidence, missing = "NEEDS_REVIEW", [f"Candidate vendor/product matches source: {product_match['vendor']} {product_match['product']}"], ["asset identity must be confirmed before excluding applicability"]
                    else:
                        status, evidence, missing = "NO_MATCH_TO_THIS_ADVISORY", [f"Exact vendor/product match, but asset version {asset['version']} is outside source-defined affected versions"], []
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
        network_alerts = [dict(r) for r in self.connection.execute("""SELECT a.*,e.event_ref,e.timestamp AS event_timestamp,e.source_ip,e.destination_ip,e.source_file,asset.asset_id AS destination_asset_id,asset.hostname AS destination_hostname FROM network_alerts a JOIN network_events e USING(event_id) LEFT JOIN assets asset ON asset.ip_address=e.destination_ip ORDER BY a.created_at DESC""")]
        identity_review_assets = [dict(r) for r in self.connection.execute("""SELECT asset_id,ip_address,hostname,asset_type,vendor,product,version,identity_confidence,verified,identification_source
            FROM assets WHERE TRIM(vendor)='' OR TRIM(product)='' OR identity_confidence!='high' OR verified=0 ORDER BY ip_address,asset_id""")]
        remediation_plans = []
        plan_rows = self.connection.execute("""SELECT p.finding_id,f.cve_id,f.asset_id,f.status AS finding_status,f.priority,a.ip_address,a.hostname
            FROM remediation_plans p JOIN findings f USING(finding_id) JOIN assets a USING(asset_id) ORDER BY p.updated_at DESC""")
        for row in plan_rows:
            plan = self.get_remediation_plan(row["finding_id"])
            if plan:
                remediation_plans.append(plan | {"cve_id": row["cve_id"], "asset_id": row["asset_id"], "ip_address": row["ip_address"], "hostname": row["hostname"], "finding_status": row["finding_status"], "priority": row["priority"]})
        stale_sources = sum(1 for item in self.source_health() if item["health"] == "stale")
        communication_relationships = self.connection.execute("""SELECT COUNT(*) FROM (SELECT 1 FROM network_events GROUP BY source_ip,source_port,destination_ip,destination_port,protocol,operation,event_type,source_file)""").fetchone()[0]
        return {
            "assets": self.connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0],
            "assets_needing_identity_review": len(identity_review_assets),
            "identity_review_assets": identity_review_assets,
            "confirmed_assets": self.connection.execute("SELECT COUNT(DISTINCT asset_id) FROM findings WHERE status='CONFIRMED_MATCH'").fetchone()[0],
            "potential_assets": self.connection.execute("SELECT COUNT(DISTINCT asset_id) FROM findings WHERE status='POTENTIAL_MATCH'").fetchone()[0],
            "kev_findings": self.connection.execute("SELECT COUNT(*) FROM findings f JOIN vulnerabilities v USING(cve_id) WHERE v.kev=1 AND f.status IN ('CONFIRMED_MATCH','POTENTIAL_MATCH')").fetchone()[0],
            "critical_exposed_assets": self.connection.execute("SELECT COUNT(DISTINCT f.asset_id) FROM findings f JOIN assets a USING(asset_id) WHERE a.criticality='critical' AND f.status IN ('CONFIRMED_MATCH','POTENTIAL_MATCH')").fetchone()[0],
            "unacknowledged_alerts": self.connection.execute("SELECT (SELECT COUNT(*) FROM alerts WHERE acknowledged=0)+(SELECT COUNT(*) FROM network_alerts WHERE acknowledged=0)").fetchone()[0],
            "findings": [dict(r) for r in self.connection.execute("""SELECT f.*,a.ip_address,a.hostname,a.vendor,a.product,a.version,a.criticality,a.identity_confidence,a.zone,v.summary,v.severity,v.kev,v.source,v.source_url,v.references_json,v.published,v.modified,v.mitigation,v.synthetic FROM findings f JOIN assets a USING(asset_id) JOIN vulnerabilities v USING(cve_id) ORDER BY CASE f.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, f.updated_at DESC""")],
            "alerts": [dict(r) for r in self.connection.execute("SELECT * FROM alerts ORDER BY created_at DESC")] + network_alerts,
            "network_alerts": network_alerts,
            "network_events": self.connection.execute("SELECT COUNT(*) FROM network_events").fetchone()[0],
            "communication_relationships": communication_relationships,
            "stale_sources": stale_sources,
            "source_health": self.source_health(),
            "recent_intelligence": [dict(r) for r in self.connection.execute("SELECT * FROM intelligence_changes ORDER BY changed_at DESC LIMIT 10")],
            "remediation_plans": remediation_plans,
        }

    def acknowledge(self, alert_id: str) -> bool:
        cur = self.connection.execute("UPDATE alerts SET acknowledged=1,updated_at=? WHERE alert_id=?", (utc_now(), alert_id))
        network_cur = self.connection.execute("UPDATE network_alerts SET acknowledged=1,updated_at=? WHERE alert_id=?", (utc_now(), alert_id))
        self.connection.commit()
        return cur.rowcount == 1 or network_cur.rowcount == 1

    def report(self, format: str = "json") -> str:
        data = self.dashboard()
        findings = []
        for item in data["findings"]:
            row = dict(item)
            row["references"] = json.loads(row.pop("references_json", "[]"))
            findings.append(row)
        payload = {"generated_at": utc_now(), "scope": "local inventory and locally stored intelligence", "known_limitations": ["No active scanning or device control is performed.", "Version matching uses exact source versions and numeric dotted ranges only; other version syntax requires review.", "Assets with incomplete or unverified identity are listed separately and are not treated as safe or matched to every CVE.", "Attack-surface relationships reflect imported observations only; no reachability or firewall permission is inferred.", "Remediation plans are recommendations; approval and verification are separate recorded states.", "A missing match does not establish that an asset is safe.", "A vulnerability finding does not establish compromise."], "findings": findings, "asset_identity_reviews": data["identity_review_assets"], "network_alerts": data["network_alerts"], "remediation_plans": data["remediation_plans"]}
        if format == "json":
            return json.dumps(payload, indent=2)
        if format == "csv":
            from io import StringIO
            out = StringIO()
            rows = payload["findings"]
            columns = ["record_type", "asset_id", "ip_address", "hostname", "vendor", "product", "version", "cve_id", "status", "priority", "severity", "kev", "summary", "evidence", "missing_evidence", "source_url", "references", "mitigation", "rule_id", "alert_id", "event_ref", "timestamp", "source_ip", "destination_ip", "policy_evidence", "remediation_status", "provider", "model", "reviewer", "change_notes", "verification_evidence"]
            writer = csv.DictWriter(out, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({**row, "record_type": "vulnerability_finding", "evidence": "; ".join(json.loads(row["evidence"])), "missing_evidence": "; ".join(json.loads(row["missing_evidence"])), "references": "; ".join(row["references"])})
            for row in data["identity_review_assets"]:
                missing = [name for name, value in (("vendor", row["vendor"]), ("product", row["product"]), ("high identity confidence", row["identity_confidence"] == "high"), ("operator verification", row["verified"])) if not value]
                writer.writerow({**row, "record_type": "asset_identity_review", "status": "NEEDS_REVIEW", "summary": "Asset identity needs review; no CVE applicability conclusion was made.", "missing_evidence": "; ".join(missing)})
            for row in data["network_alerts"]:
                writer.writerow({"record_type": "network_alert", "severity": row["severity"], "rule_id": row["rule_id"], "alert_id": row["alert_id"], "event_ref": row["event_ref"], "timestamp": row["event_timestamp"], "source_ip": row["source_ip"], "destination_ip": row["destination_ip"], "summary": row["explanation"], "policy_evidence": row["policy_evidence"]})
            for row in data["remediation_plans"]:
                writer.writerow({"record_type": "remediation_plan", "asset_id": row["asset_id"], "ip_address": row["ip_address"], "hostname": row["hostname"], "cve_id": row["cve_id"], "status": row["finding_status"], "priority": row["priority"], "remediation_status": row["status"], "provider": row["provider"], "model": row["model"], "reviewer": row["reviewer"], "change_notes": row["change_notes"], "verification_evidence": row["verification_evidence"], "summary": row["plan"]["finding_summary"], "references": "; ".join(row["source_urls"])})
            return out.getvalue()
        raise ValueError("format must be json or csv")


def read_json_limited(raw: bytes, max_bytes: int = 5_000_000) -> dict[str, Any]:
    if len(raw) > max_bytes:
        raise ValueError(f"Input exceeds {max_bytes} byte limit")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("JSON input must be an object")
    return parsed
