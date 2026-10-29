# Phylax

Phylax is a local-first, passive IT/OT cybersecurity decision-support MVP for the Kartika Cyber Hackathon 2026. It combines operator-supplied inventory with locally loaded vulnerability intelligence and explains the evidence behind each applicability assessment. It never scans, writes to, isolates, or otherwise controls OT devices.

## Current implementation

The current implementation is a dependency-free Python/SQLite MVP:

- CSV asset import/export with row-level validation, retained unknown identity, verification/source/confidence fields, and repeatable IDs for rows without supplied IDs.
- Local JSON vulnerability fixture ingestion with CVE-ID validation, source provenance, retrieval time, KEV metadata, mitigation text, affected products, deduplication, and synthetic-data marking.
- Conservative correlation: normalized vendor and product must match exactly. A confirmed match requires the asset's version string to exactly equal a source-listed affected version. No arbitrary fuzzy match or version-range guess is made.
- Four applicability states: `CONFIRMED_MATCH`, `POTENTIAL_MATCH`, `NO_MATCH_TO_THIS_ADVISORY`, and `NEEDS_REVIEW`. Incomplete identities remain uncertain; unrelated products do not create findings.
- Inventory gaps are surfaced as asset identity reviews rather than one `NEEDS_REVIEW` row per CVE. Low-confidence or unverified identities cannot produce confirmed matches, and stale findings are removed when an asset's product identity changes.
- Stable findings and deduplicated exposure alerts, acknowledgement, visible evidence, and JSON/CSV exports.
- NVD CVE API 2.0, CISA KEV JSON, and CISA ICS advisory RSS adapters with bounded HTTP responses, timeouts, retry on transient errors, pagination, local cache, per-source health, change tracking, resumable sync, and manual sync. NVD routine sync uses a one-day initial window and a one-day overlap from the last successful sync; broader windows are explicit and capped at 120 days. It does not download the full historical NVD corpus.
- CISA KEV metadata merges into NVD CVE records without replacing NVD product evidence. KEV-only product records carry no version range, so cannot produce a confirmed version match. ICS advisories are stored with their references; RSS text is not converted into invented affected-product ranges.
- Streaming Zeek JSON Lines and standard TSV log parsing for connection and Modbus logs. Imported observations and event references are stored locally and deduplicated. Private observed IPs can add/update unknown, low-confidence inventory entries; no model or firmware is inferred. Rules flag unauthorized Modbus writers, communications outside an explicit protected-asset allowlist, and Modbus writes outside configured UTC maintenance windows. Missing evidence yields diagnostics instead of an alert.
- A small loopback-only dashboard, CLI, local SQLite persistence, network policy example, and synthetic demonstration data.

Still incomplete: direct PCAP processing (Zeek must be run separately to create logs), automated Zeek installation or execution, live capture, a dedicated ICSNPP installer, an advisory detail page, EPSS, a full CVE-history backfill, audit history, Markdown reports, authentication/multi-user controls, and production deployment hardening. The dashboard shows locally stored data only, so its counts are calculated from actual records rather than demo constants.

## Requirements and run

Python 3.10 or newer; no third-party packages are required.

```bash
python3 -m phylax --db data/phylax.db serve
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). The server refuses non-loopback bind addresses. The database is created at `data/phylax.db` by default; pass `--db /path/to/file.sqlite` to choose another location. Keep the database and any uploaded inventory on a trusted local machine.

CLI workflow:

```bash
python3 -m phylax --db data/phylax.db import-assets examples/assets.csv
python3 -m phylax --db data/phylax.db load-fixture examples/vulnerability-fixture.json
python3 -m phylax --db data/phylax.db correlate
python3 -m phylax --db data/phylax.db export-report --format json --output report.json
python3 -m phylax --db data/phylax.db sync-feeds
python3 -m phylax --db data/phylax.db analyze-zeek examples/conn.log --policy examples/network-policy.json
python3 -m phylax --db data/phylax.db analyze-zeek examples/modbus.log --kind modbus --policy examples/network-policy.json
```

Feed synchronization requires internet access. It can be triggered from the dashboard or CLI; offline inventory, cached records, log analysis, correlation, and reports work without it. Set `NVD_API_KEY` in the environment to use an NVD API key; no key is required. Feed health displays the last success and marks data stale after 24 hours. A failed source does not delete its cached records.

`sync-feeds` contacts three public sources and stores their normalized results in the local SQLite database: (1) NVD CVE API 2.0, using an incremental modified-date window; (2) the CISA KEV JSON catalog, which is retrieved as a complete catalog and merged into matching CVE records as observed-exploitation metadata; and (3) CISA ICS advisory RSS, which is saved as advisory entries and references without inventing affected-product/version ranges from advisory text. It then re-runs local asset correlation against the stored intelligence. It does not scan assets, contact devices, upload inventory, prove exploitation on your network, or download the complete NVD historical corpus. Each source is handled independently, so a failed feed leaves its cache intact and the other sources continue. The CLI writes UTC progress lines to stderr, including NVD page progress, each source's result, and the final local correlation step; a final per-source summary is written to stdout.

Routine NVD sync requests only the prior 24 hours on a first run, then changes since the last successful sync with a 24-hour overlap. Each NVD page is saved to SQLite before fetching the next page, with a durable checkpoint; rerunning after interruption resumes the same fixed query window at the next page. Re-fetching a page after a crash between its record write and checkpoint write is safe because CVEs are upserted by ID. For a one-time wider NVD last-modified query, use `sync-feeds --backfill-days 30` (or another value up to 120). Backfill still uses NVD's modified-date window and is not an all-history download. If an NVD checkpoint exists, sync resumes that window first, regardless of a newly supplied backfill option.

The dashboard has overview, paginated asset inventory, paginated threat-intelligence, and paginated passive network views. It also provides CSV reports, asset export, and source synchronization. CSV fields are `asset_id`, `ip_address`, `mac_address`, `hostname`, `asset_type`, `vendor`, `product`, `version`, `operating_system`, `zone`, `criticality`, `identification_source`, `identity_confidence`, `last_seen`, `notes`, and `verified`. Only `ip_address` is required. Unknown metadata is left blank or marked `unknown`; an IP address alone is never used to infer a model or firmware.

## Controlled demonstration

`examples/assets.csv` contains four synthetic assets. `examples/vulnerability-fixture.json` is fictional training data, labeled synthetic in the file, dashboard, and generated report. It uses a reserved future-style CVE identifier solely to exercise the data flow; it is not a real advisory, exploit, KEV entry, or mitigation. Never use this fixture to make operational decisions.

1. Start the dashboard and import `examples/assets.csv`.
2. Load `examples/vulnerability-fixture.json`.
3. Run correlation. The demo PLC should be a confirmed match based on exact listed version evidence. The demo HMI should be potential because the asset version is absent. The workstation should require review because product identity is unknown. The historian has no match to this fixture.
4. Review the separate severity, urgency, KEV, and applicability fields; acknowledge an alert and export JSON or CSV.
5. Stop internet connectivity: this workflow remains available because it uses only local data.

The sample Zeek logs use documentation-only IP ranges and fictional events. Analyze them with the CLI examples above or use the dashboard upload form, providing `examples/network-policy.json` as the optional policy file. The Modbus sample generates a benign read and a prohibited write alert. These are synthetic training records, not a real incident. No PCAP or real industrial device is required for this MVP demonstration.

To analyze a PCAP, run Zeek yourself in an isolated output directory, then import the resulting `conn.log` and optional Modbus logs. For example, `zeek -Cr /path/to/capture.pcap` creates standard Zeek logs. If the [CISA ICSNPP-Modbus extension](https://github.com/cisagov/icsnpp-modbus) is installed, its documented package invocation can produce additional detailed Modbus logs. Phylax does not install or execute Zeek and does not read or transmit live traffic. It recognizes ICSNPP's `source_h`, `source_p`, `destination_h`, `destination_p`, `func`, and `request_response` fields; response records are retained but excluded from write detections.

## Architecture and matching rules

```text
CSV inventory ─┐
NVD / KEV / ICS RSS ─┼── SQLite store ── correlation ── findings/alerts ── dashboard/reports
Zeek conn/Modbus ────┘                 └── passive policy detections
JSON fixture ────────┘
```

`phylax/core.py` contains SQLite persistence, import/export, correlation, prioritization, and reporting. `phylax/feeds.py` normalizes the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities), [CISA KEV JSON catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), and [CISA ICS advisories RSS](https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml). `phylax/monitoring.py` parses Zeek logs and evaluates explicit policy. Zeek `conn.log` fields follow the [official Zeek connection log reference](https://docs.zeek.org/en/current/reference/logs/conn.html); Modbus fields follow the [CISA ICSNPP-Modbus documentation](https://github.com/cisagov/icsnpp-modbus). `phylax/web.py` serves the local dashboard; `phylax/__main__.py` exposes CLI operations.

Priority is a transparent rule-based urgency indicator, independent of severity and applicability: KEV adds 3 points; critical/high/medium source severity adds 3/2/1; critical/high/medium asset criticality adds 3/2/1; confirmed applicability adds 2. Scores map to critical (8+), high (6–7), medium (3–5), or low (0–2). Unknown values add no points. This local prioritization does not imply compromise or an attack.

The correlation engine supports explicit exact-version lists only. NVD version ranges and configuration prerequisites are not evaluated; affected products with range semantics or conditional configurations become `NEEDS_REVIEW`. Assets without vendor/product identity are reported as inventory coverage gaps and are not treated as safe or matched against every CVE. Low-confidence or unverified asset identity cannot yield a confirmed match. A match is not proof of compromise; no match is not proof an asset is safe. KEV membership describes the catalog record, not activity on the local network. Zeek connection service labels alone do not count as decoded Modbus function codes. The Modbus parser accepts JSON Lines or TSV fields such as `func`, `function`, or `function_code`; confirm the log version and output before relying on it. It does not cover every OT protocol or all Modbus-specific functions.

The network policy uses `protected_assets`, `allowed_communications`, `authorized_writers`, and `maintenance_windows_utc`. Maintenance day numbers follow Python's weekday convention (Monday `0` to Sunday `6`); times are UTC in `HH:MM`. An unexpected-communication rule evaluates only protected destinations with a configured communication policy. A write with no configured controller policy produces a diagnostic instead of an unauthorized-writer alert.

## Security and data handling

- No active discovery, packet transmission to OT, automated response, patching, isolation, controller write, or firewall changes are implemented.
- The dashboard binds only to loopback and does not expose an API for public deployment. Do not put it behind a public interface without adding authentication, authorization, TLS, and deployment review.
- Uploads have a 5 MB cap; fixture JSON is validated before ingestion; CSV values are stored as data, not executed. Imported content should still be treated as untrusted.
- No inventory data is sent to external services. `NVD_API_KEY` is an optional environment variable used only as a header for NVD requests.
- Timestamps are stored as UTC ISO 8601. UI timezone conversion is not implemented yet.

## Tests

Run the deterministic local test suite (no network access required):

```bash
python3 -m unittest discover -s tests -v
```

It covers CSV validation and round-trip export, exact confirmed and incomplete matching, unrelated-product false-match avoidance, alert acknowledgement, report export, malformed fixture IDs, duplicate upsert, mocked feed pagination/normalization/merging and change detection, advisory preservation, Zeek JSON/TSV and ICSNPP field parsing, event deduplication, missing-data handling, observed-asset confidence, and all three policy detections. Network tests use local fixtures and never open a socket.

## Remaining work and known limits

The next milestones are source-defined version-range evaluation, CPE-aware identity matching, complete source history/backfill controls, expanded ICSNPP field coverage, direct PCAP orchestration, audit logging, and broader integration/security review. The NVD source is intentionally a recent-change sync (30 days initially, then from last success with a one-day overlap), so older CVEs may be absent until broader backfill is added. The current demo runs on Python plus SQLite, but no benchmark dataset or machine-specific performance measurements have been collected. Treat it as a hackathon MVP, not a production OT security control.
