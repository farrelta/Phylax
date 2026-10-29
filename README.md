# Phylax

Phylax is a local-first, passive IT/OT cybersecurity decision-support MVP for the Kartika Cyber Hackathon 2026. It combines operator-supplied inventory with locally loaded vulnerability intelligence and explains the evidence behind each applicability assessment. It never scans, writes to, isolates, or otherwise controls OT devices.

## Current implementation

The repository was empty apart from its initial README, so the first milestone is a dependency-free vertical slice using Python's standard library and SQLite:

- CSV asset import/export with row-level validation, retained unknown identity, verification/source/confidence fields, and repeatable IDs for rows without supplied IDs.
- Local JSON vulnerability fixture ingestion with CVE-ID validation, source provenance, retrieval time, KEV metadata, mitigation text, affected products, deduplication, and synthetic-data marking.
- Conservative correlation: normalized vendor and product must match exactly. A confirmed match requires the asset's version string to exactly equal a source-listed affected version. No arbitrary fuzzy match or version-range guess is made.
- Four applicability states: `CONFIRMED_MATCH`, `POTENTIAL_MATCH`, `NO_MATCH_TO_THIS_ADVISORY`, and `NEEDS_REVIEW`. Incomplete identities remain uncertain; unrelated products do not create findings.
- Stable findings and deduplicated exposure alerts, acknowledgement, visible evidence, and JSON/CSV exports.
- A small loopback-only dashboard, CLI, local SQLite persistence, and synthetic demonstration data.

This is not yet the full requested platform. NVD/CISA live synchronization, source-health and stale-feed tracking, Zeek/ICSNPP ingestion, network-policy rules, PCAP processing, audit history, report Markdown, database migrations, multi-user access control, and production deployment hardening remain incomplete. The dashboard shows locally stored data only, so its counts are calculated from actual records rather than demo constants.

## Requirements and run

Python 3.10 or newer; no third-party packages are required.

```bash
python3 -m sentinelot --db data/sentinelot.db serve
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). The server refuses non-loopback bind addresses. The database is created at `data/sentinelot.db` by default; pass `--db /path/to/file.sqlite` to choose another location. Keep the database and any uploaded inventory on a trusted local machine.

CLI workflow:

```bash
python3 -m sentinelot --db data/sentinelot.db import-assets examples/assets.csv
python3 -m sentinelot --db data/sentinelot.db load-fixture examples/vulnerability-fixture.json
python3 -m sentinelot --db data/sentinelot.db correlate
python3 -m sentinelot --db data/sentinelot.db export-report --format json --output report.json
```

The dashboard supports those same steps and also provides CSV reports and asset export. CSV fields are `asset_id`, `ip_address`, `mac_address`, `hostname`, `asset_type`, `vendor`, `product`, `version`, `operating_system`, `zone`, `criticality`, `identification_source`, `identity_confidence`, `last_seen`, `notes`, and `verified`. Only `ip_address` is required. Unknown metadata is left blank or marked `unknown`; an IP address alone is never used to infer a model or firmware.

## Controlled demonstration

`examples/assets.csv` contains four synthetic assets. `examples/vulnerability-fixture.json` is fictional training data, labeled synthetic in the file, dashboard, and generated report. It uses a reserved future-style CVE identifier solely to exercise the data flow; it is not a real advisory, exploit, KEV entry, or mitigation. Never use this fixture to make operational decisions.

1. Start the dashboard and import `examples/assets.csv`.
2. Load `examples/vulnerability-fixture.json`.
3. Run correlation. The demo PLC should be a confirmed match based on exact listed version evidence. The demo HMI should be potential because the asset version is absent. The workstation should require review because product identity is unknown. The historian has no match to this fixture.
4. Review the separate severity, urgency, KEV, and applicability fields; acknowledge an alert and export JSON or CSV.
5. Stop internet connectivity: this workflow remains available because it uses only local data.

No PCAP or real industrial device is required for this MVP demonstration.

## Architecture and matching rules

```text
CSV inventory ─┐
               ├── SQLite store ── exact evidence correlation ── findings/alerts ── dashboard/reports
JSON fixture ──┘
```

`sentinelot/core.py` contains SQLite persistence, import/export, fixture normalization, correlation, prioritization, and reporting. `sentinelot/web.py` serves the local dashboard; `sentinelot/__main__.py` exposes CLI operations.

Priority is a transparent rule-based urgency indicator, independent of severity and applicability: KEV adds 3 points; critical/high/medium source severity adds 3/2/1; critical/high/medium asset criticality adds 3/2/1; confirmed applicability adds 2. Scores map to critical (8+), high (6–7), medium (3–5), or low (0–2). Unknown values add no points. This local prioritization does not imply compromise or an attack.

The first version supports explicit exact-version lists only. Source records that specify ranges or configuration prerequisites are not silently interpreted. A match is not proof of compromise; no match is not proof an asset is safe. KEV membership describes the catalog record, not activity on the local network.

## Security and data handling

- No active discovery, packet transmission to OT, automated response, patching, isolation, controller write, or firewall changes are implemented.
- The dashboard binds only to loopback and does not expose an API for public deployment. Do not put it behind a public interface without adding authentication, authorization, TLS, and deployment review.
- Uploads have a 5 MB cap; fixture JSON is validated before ingestion; CSV values are stored as data, not executed. Imported content should still be treated as untrusted.
- No inventory data is sent to external services. There are no credentials or API keys in this MVP.
- Timestamps are stored as UTC ISO 8601. UI timezone conversion is not implemented yet.

## Tests

Run the deterministic local test suite (no network access required):

```bash
python3 -m unittest discover -s tests -v
```

It covers CSV validation and round-trip export, exact confirmed and incomplete matching, unrelated-product false-match avoidance, alert acknowledgement, report export, malformed fixture IDs, and duplicate record upsert. Live feeds and network monitoring do not yet exist and therefore are not claimed as tested features.

## Remaining work and known limits

The planned next milestones are documented source adapters for NVD, CISA KEV, and structured ICS advisories; incremental sync/cache health; richer product identifiers and source-defined version-range evaluation; re-evaluation on changes; Zeek/Modbus offline analysis and passive policy rules; richer asset/event inventory; audit logging; and broader integration/security tests. The current demo runs on Python plus SQLite, but no benchmark dataset or machine-specific performance measurements have been collected. It should be treated as a hackathon MVP, not a production OT security control.
