# Phylax

Phylax is a local-first, passive IT/OT cybersecurity decision-support MVP for the Kartika Cyber Hackathon 2026. It combines operator-supplied inventory with locally loaded vulnerability intelligence and explains the evidence behind each applicability assessment. It never scans, writes to, isolates, or otherwise controls OT devices.

## Current implementation

The current implementation is a dependency-free Python/SQLite MVP:

- CSV asset import/export with row-level validation, retained unknown identity, verification/source/confidence fields, and repeatable IDs for rows without supplied IDs.
- Local JSON vulnerability fixture ingestion with CVE-ID validation, source provenance, retrieval time, KEV metadata, mitigation text, affected products, deduplication, and synthetic-data marking.
- Conservative correlation: normalized vendor and product must match exactly. Confirmed matches require high-confidence, operator-verified identity and either an exact source-listed version or a numeric dotted version inside explicit NVD bounds. Unsupported version syntax remains review-only; no arbitrary fuzzy or semantic-version guess is made.
- Four applicability states: `CONFIRMED_MATCH`, `POTENTIAL_MATCH`, `NO_MATCH_TO_THIS_ADVISORY`, and `NEEDS_REVIEW`. Incomplete identities remain uncertain; unrelated products do not create findings.
- Inventory gaps are surfaced as asset identity reviews rather than one `NEEDS_REVIEW` row per CVE. Low-confidence or unverified identities cannot produce confirmed matches, and stale findings are removed when an asset's product identity changes.
- Stable findings and deduplicated exposure alerts, acknowledgement, visible evidence, and JSON/CSV exports.
- NVD CVE API 2.0, CISA KEV JSON, and CISA ICS advisory RSS adapters with bounded HTTP responses, timeouts, retry on transient errors, pagination, local cache, per-source health, change tracking, resumable sync, and manual sync. NVD routine sync uses a one-day initial window and a one-day overlap from the last successful sync; broader windows are explicit and capped at 120 days. It does not download the full historical NVD corpus.
- CISA KEV metadata merges into NVD CVE records without replacing NVD product evidence. KEV-only product records carry no version range, so cannot produce a confirmed version match. ICS advisories are stored with their references; RSS text is not converted into invented affected-product ranges.
- Streaming Zeek JSON Lines and standard TSV log parsing for connection and Modbus logs. Imported observations and event references are stored locally and deduplicated. Private observed IPs can add/update unknown, low-confidence inventory entries; no model or firmware is inferred. Rules flag unauthorized Modbus writers, communications outside an explicit protected-asset allowlist, and Modbus writes outside configured UTC maintenance windows. Missing evidence yields diagnostics instead of an alert.
- A small loopback-only dashboard, CLI, and local SQLite persistence. The application database starts without demo assets or fictional CVEs; deterministic synthetic records are confined to automated-test fixtures.

Still incomplete: direct PCAP processing (Zeek must be run separately to create logs), automated Zeek installation or execution, live capture, a dedicated ICSNPP installer, an advisory detail page, EPSS, a full CVE-history backfill, audit history, Markdown reports, authentication/multi-user controls, and production deployment hardening. The dashboard shows locally stored data only, so its counts are calculated from actual records rather than demo constants.

## Requirements and run

Python 3.10 or newer; no third-party packages are required.

```bash
python3 -m phylax --db data/phylax.db serve
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). The server refuses non-loopback bind addresses. The database is created at `data/phylax.db` by default; pass `--db /path/to/file.sqlite` to choose another location. Keep the database and any uploaded inventory on a trusted local machine.

CLI workflow:

```bash
python3 -m phylax --db data/phylax.db import-assets /path/to/your-assets.csv
python3 -m phylax --db data/phylax.db load-fixture /path/to/public-vulnerability-records.json
python3 -m phylax --db data/phylax.db correlate
python3 -m phylax --db data/phylax.db export-report --format json --output report.json
python3 -m phylax --db data/phylax.db sync-feeds
python3 -m phylax --db data/phylax.db analyze-zeek /path/to/conn.log --policy /path/to/network-policy.json
python3 -m phylax --db data/phylax.db analyze-zeek /path/to/modbus.log --kind modbus --policy /path/to/network-policy.json
```

Feed synchronization requires internet access. It can be triggered from the dashboard or CLI; offline inventory, cached records, log analysis, correlation, and reports work without it. Set `NVD_API_KEY` in the environment to use an NVD API key; no key is required. Feed health displays the last success and marks data stale after 24 hours. A failed source does not delete its cached records.

`sync-feeds` contacts three public sources and stores their normalized results in the local SQLite database: (1) NVD CVE API 2.0, using an incremental modified-date window; (2) the CISA KEV JSON catalog, which is retrieved as a complete catalog and merged into matching CVE records as observed-exploitation metadata; and (3) CISA ICS advisory RSS, which is saved as advisory entries and references without inventing affected-product/version ranges from advisory text. It then re-runs local asset correlation against the stored intelligence. It does not scan assets, contact devices, upload inventory, prove exploitation on your network, or download the complete NVD historical corpus. Each source is handled independently, so a failed feed leaves its cache intact and the other sources continue. The CLI writes UTC progress lines to stderr, including NVD page progress, each source's result, and the final local correlation step; a final per-source summary is written to stdout.

Routine NVD sync requests only the prior 24 hours on a first run, then changes since the last successful sync with a 24-hour overlap. Each NVD page is saved to SQLite before fetching the next page, with a durable checkpoint; rerunning after interruption resumes the same fixed query window at the next page. Re-fetching a page after a crash between its record write and checkpoint write is safe because CVEs are upserted by ID. For a one-time wider NVD last-modified query, use `sync-feeds --backfill-days 30` (or another value up to 120). Backfill still uses NVD's modified-date window and is not an all-history download. If an NVD checkpoint exists, sync resumes that window first, regardless of a newly supplied backfill option.

The dashboard has overview, paginated asset inventory, paginated threat-intelligence, and paginated passive network views. It also provides CSV reports, asset export, and source synchronization. CSV fields are `asset_id`, `ip_address`, `mac_address`, `hostname`, `asset_type`, `vendor`, `product`, `version`, `operating_system`, `zone`, `criticality`, `identification_source`, `identity_confidence`, `last_seen`, `notes`, and `verified`. Only `ip_address` is required. Unknown metadata is left blank or marked `unknown`; an IP address alone is never used to infer a model or firmware.

## Testing hosted AI with a real advisory

The application database is not seeded with demo inventory or fictional CVEs. To exercise hosted guidance without using production inventory, prepare a separate test database from a real NVD record already stored locally:

```bash
python3 scripts/prepare_ai_test_data.py
python3 -m phylax --db data/phylax-ai-test.db serve
```

Open the dashboard and generate a plan for `CVE-2026-0322`. The advisory is copied from the local NVD cache and retains its source-provided PAN-OS version range. The test database contains one explicitly labeled simulated lab asset at documentation-only IP `192.0.2.50`; it is not a real device and must not be imported into production inventory. The script makes no network requests and does not call the model. Hosted AI runs only after you click **Generate remediation plan**. To use another current advisory, pass its CVE ID with `--cve`; the script refuses records that are synthetic or do not contain the expected affected-version evidence.

Automated-test data is isolated under `tests/fixtures/`; the application never loads it automatically. These fixtures exist only to keep unit and integration tests deterministic.

For offline network-parser tests, the test-only Zeek logs use documentation-only IP ranges and fictional events. To analyze operational captures, use logs generated from an authorized PCAP or environment as described below. No PCAP or real industrial device is included in the test data.

To analyze a PCAP, run Zeek yourself in an isolated output directory, then import the resulting `conn.log` and optional Modbus logs. For example, `zeek -Cr /path/to/capture.pcap` creates standard Zeek logs. If the [CISA ICSNPP-Modbus extension](https://github.com/cisagov/icsnpp-modbus) is installed, its documented package invocation can produce additional detailed Modbus logs. Phylax does not install or execute Zeek and does not read or transmit live traffic. It recognizes ICSNPP's `source_h`, `source_p`, `destination_h`, `destination_p`, `func`, and `request_response` fields; response records are retained but excluded from write detections.

## Architecture and matching rules

```text
CSV inventory ─┐
NVD / KEV / ICS RSS ─┼── SQLite store ── correlation ── findings/alerts ── dashboard/reports
Zeek conn/Modbus ────┘                 └── passive policy detections
Local public-record import ─┘
```

`phylax/core.py` contains SQLite persistence, import/export, correlation, prioritization, and reporting. `phylax/feeds.py` normalizes the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities), [CISA KEV JSON catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), and [CISA ICS advisories RSS](https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml). `phylax/monitoring.py` parses Zeek logs and evaluates explicit policy. Zeek `conn.log` fields follow the [official Zeek connection log reference](https://docs.zeek.org/en/current/reference/logs/conn.html); Modbus fields follow the [CISA ICSNPP-Modbus documentation](https://github.com/cisagov/icsnpp-modbus). `phylax/web.py` serves the local dashboard; `phylax/__main__.py` exposes CLI operations.

The **Attack surface** view joins inventory rows with grouped Zeek events already stored locally. It reports observed peers, ports, protocols, operations, timestamps, zones, criticality, identity confidence, and inventory-only assets, with a bounded topology diagram and event references. It does not discover hosts or capture live traffic. Imported logs define the observed surface: unseen traffic is not evidence that no communication or device exists. A recorded connection does not prove firewall reachability beyond that observation; unknown peers, protocol metadata, and trust boundaries remain explicitly unknown.

## Optional AI remediation guidance

Hosted AI is disabled unless a provider, API key, and model are configured. Phylax includes presets for Gemini, Groq, and OpenRouter, plus a custom OpenAI-compatible endpoint. Requests time out after 90 seconds by default; `PHYLAX_AI_TIMEOUT_SECONDS` can be set from 5 to 180. Gemini requests use its low thinking level for this short guidance task. Free-tier eligibility and quotas vary by account and model and can change; check the provider console before relying on a free quota.

```bash
# Choose one: gemini, groq, openrouter, or custom
export PHYLAX_AI_PROVIDER="openrouter"
export OPENROUTER_API_KEY="your-key"
# Optional: defaults to OpenRouter's free-model router
# export PHYLAX_AI_MODEL="openrouter/free"
python3 -m phylax --db data/phylax.db serve
```

You can copy [`.env.example`](.env.example) to `.env` in the project directory and fill in your provider settings. Phylax reads the supported AI settings from that file when running from the project directory; simple `KEY=value` lines and quoted values are supported. Existing process environment values take precedence. The file is parsed as data and never executed. Keep real credentials out of Git; `.env` is ignored by Git.

For Gemini, set `PHYLAX_AI_PROVIDER=gemini`, `GEMINI_API_KEY`, and `PHYLAX_AI_MODEL` to a model enabled for your account. For Groq, use `PHYLAX_AI_PROVIDER=groq`, `GROQ_API_KEY`, and an active model ID. For OpenRouter, use `PHYLAX_AI_PROVIDER=openrouter`, `OPENROUTER_API_KEY`, and optionally `PHYLAX_AI_MODEL`; its `openrouter/free` router selects an available free model. Alternatively, set `PHYLAX_AI_PROVIDER=custom` with `PHYLAX_AI_BASE_URL`, `PHYLAX_AI_MODEL`, and `PHYLAX_AI_API_KEY`. The presets use documented OpenAI-compatible Chat Completions endpoints: [Gemini](https://ai.google.dev/gemini-api/docs/openai/), [Groq](https://console.groq.com/docs/openai), and [OpenRouter](https://openrouter.ai/docs/api-reference/overview).

The overview offers a per-finding **Generate remediation plan** action; opening pages or syncing feeds never calls a model. HTTPS is required except for loopback development endpoints. Phylax sends an allowlisted public vulnerability record (CVE/advisory text, source metadata, public affected-product data, severity/KEV metadata, mitigation text, and source URLs). It does **not** send asset IPs, hostnames, inventory records, local findings, policies, network events, or local risk context. Synthetic fixtures are blocked from hosted requests. Provider data practices differ: Gemini's free tier may use submitted content to improve its products ([pricing and data-use notice](https://ai.google.dev/gemini-api/docs/pricing)); OpenRouter forwards prompts to the selected model provider, whose terms can differ ([privacy policy](https://openrouter.ai/privacy)); Groq's API terms state customer inputs are not used for model training without permission ([service terms](https://console.groq.com/docs/legal)). Review current provider and model terms before enabling hosted AI.

Generating a remediation plan uses a deterministic local template when AI is disabled, the record is synthetic, or the provider fails validation or times out. With a hosted provider, its optional supplement is limited to the public vulnerability record; local asset evidence, applicability details, priority, and network context remain on the Phylax host. Advisory text is treated as untrusted input. Returned citations must exactly match source URLs supplied with the public record.

Plans store evidence, uncertainty, priority explanation, source references, preferred source-provided mitigation when present, compensating-control review suggestions, operational considerations, preconditions, validation, rollback, and post-change verification criteria. Plans move through `Recommended`, `Under Review`, `Approved`, `Implemented`, and `Verified`, with `Rejected`, `Deferred`, and `Needs More Evidence` alternatives. Approval requires a named reviewer; verification requires recorded evidence. A generated plan or approval does not mark a finding remediated. AI output cannot update applicability, severity, priority, acknowledgement, or perform device actions.

Priority is a transparent rule-based urgency indicator, independent of severity and applicability: KEV adds 3 points; critical/high/medium source severity adds 3/2/1; critical/high/medium asset criticality adds 3/2/1; confirmed applicability adds 2. Scores map to critical (8+), high (6–7), medium (3–5), or low (0–2). Unknown values add no points. This local prioritization does not imply compromise or an attack.

The correlation engine evaluates exact source-listed versions and NVD numeric dotted version bounds, including inclusive and exclusive boundaries. It does not infer semantics for alphanumeric or vendor-specific version strings; those findings become `NEEDS_REVIEW`. NVD configuration prerequisites are not evaluated, so conditional products remain `NEEDS_REVIEW`. Assets without vendor/product identity are reported as inventory coverage gaps and are not treated as safe or matched against every CVE. Low-confidence or unverified asset identity cannot yield a confirmed match. A match is not proof of compromise; no match is not proof an asset is safe. KEV membership describes the catalog record, not activity on the local network. Zeek connection service labels alone do not count as decoded Modbus function codes. The Modbus parser accepts JSON Lines or TSV fields such as `func`, `function`, or `function_code`; confirm the log version and output before relying on it. It does not cover every OT protocol or all Modbus-specific functions.

The network policy uses `protected_assets`, `allowed_communications`, `authorized_writers`, and `maintenance_windows_utc`. Maintenance day numbers follow Python's weekday convention (Monday `0` to Sunday `6`); times are UTC in `HH:MM`. An unexpected-communication rule evaluates only protected destinations with a configured communication policy. A write with no configured controller policy produces a diagnostic instead of an unauthorized-writer alert.

## Security and data handling

- No active discovery, packet transmission to OT, automated response, patching, isolation, controller write, or firewall changes are implemented.
- The dashboard binds only to loopback and does not expose an API for public deployment. Do not put it behind a public interface without adding authentication, authorization, TLS, and deployment review.
- Uploads have a 5 MB cap; fixture JSON is validated before ingestion; CSV values are stored as data, not executed. Imported content should still be treated as untrusted.
- No inventory data is sent to intelligence services. `NVD_API_KEY` is an optional environment variable used only as a header for NVD requests. If optional AI is enabled, only the public vulnerability data described above is sent to the configured model provider.
- Timestamps are stored as UTC ISO 8601. UI timezone conversion is not implemented yet.

## Tests

Run the deterministic local test suite (no network access required):

```bash
python3 -m unittest discover -s tests -v
```

It covers CSV validation and round-trip export, exact confirmed and incomplete matching, unrelated-product false-match avoidance, alert acknowledgement, report export, malformed fixture IDs, duplicate upsert, mocked feed pagination/normalization/merging and change detection, advisory preservation, Zeek JSON/TSV and ICSNPP field parsing, event deduplication, missing-data handling, observed-asset confidence, all three policy detections, passive surface joins/topology and unknown peers, mocked AI privacy/provider failures/citation validation, and remediation lifecycle approval/verification rules. Network tests use local fixtures and never open a socket.

## Remaining work and known limits

Known gaps include automated evidence-based attack-path hypotheses, trust-boundary configuration and persistence, vendor-document retrieval/RAG, remediation-plan content revision history beyond lifecycle events, manual-entry UI (CSV import is available), durable asset-history tracking, CPE-first identity matching, broader source-history/backfill controls, expanded ICSNPP field coverage, direct PCAP orchestration, and broader integration/security review. The current priority rule does not yet include observed network exposure or zone, though both are shown separately. Hosted AI currently receives public advisory data only; it cannot tailor advice using local topology or asset context. Routine NVD sync is incremental; a wider modified-date window is explicitly requested and capped at 120 days, so older CVEs may still be absent. The current demo runs on Python plus SQLite, but no benchmark dataset or machine-specific performance measurements have been collected. Treat it as a hackathon MVP, not a production OT security control.
