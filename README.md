# Phylax

Phylax is a lightweight, local IT/OT cybersecurity decision-support platform for the Kartika Cyber Hackathon 2026. It combines inventory, public vulnerability intelligence, passive Zeek observations, explainable findings, and optional hosted remediation guidance.

Active discovery is disabled unless an operator grants permission to an individual supporting IT host or network management IP. OT control endpoints stay passive-only. Phylax performs no device writes, automatic patching, isolation, firewall changes, or autonomous response. A vulnerability match does not establish compromise; absence of a match does not establish safety.

## Install and run

Python 3.12 or newer is recommended (verified here with host Python 3.14.7 and lab Python 3.13.5). The application and offline tests use Python's standard library; no pip dependencies are required.

```bash
python3 -m phylax --db data/phylax.db serve
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). The server accepts loopback binds only. Inventory, cached intelligence, correlation, log analysis, and reports remain available offline. Hosted AI and public feed requests require connectivity.

An existing database receives additive schema upgrades. The asset-intelligence release writes `<database>.pre-asset-intelligence.sqlite` before its versioned migration; it preserves existing IDs and adds separate context, observation, approval, software, queue, and checkpoint records. Stop dashboard and workers before the first upgrade. Device management approval, inventory verification and active-scan permission remain independent. Before the first hardening migration, Phylax writes `<database>.pre-hardening.sqlite` using SQLite backup. Migration creates an indexed product lookup, source snapshots, policy versions, diagnostics, audit history, and archived plans. Old NVD records that did not retain full CPE conditions become `NEEDS_REVIEW` until refreshed. Missing evidence is never reconstructed from device IPs or product names. Keep backups and the database on a trusted local filesystem.

After upgrading, restart the server and reload existing browser forms; stale form tokens are rejected.

If a form reports **Cross-origin request denied**, open the dashboard directly in
a regular browser tab using the address printed by `serve`, then reload it.
Origin checks compare the normalized hostname and port. `localhost`,
`127.0.0.1` and `[::1]` remain distinct origins; opaque (`Origin: null`),
embedded and mismatched origins are rejected. A denied `/sync` request has not
started feed synchronization. Do not disable the origin or CSRF checks to work
around the error.
Responses use `Referrer-Policy: same-origin`: same-origin form submissions retain
their origin, while external destinations receive no referrer. A previously open
page can still carry the old policy; reload it after restarting the server.

## Operator workflows

See the [offline workflow atlas](docs/workflows/index.html) for 14 diagrams covering the current application paths, decisions and recovery behavior, or read the [Mermaid version](docs/workflows/WORKFLOWS.md).

The primary navigation has seven pages: **Overview, Assets, Monitoring, Intelligence, Triage, Reports and Settings**. Assets contains inventory, approvals, approved IT discovery, software, changes and operational context. Monitoring contains events and the passive attack surface. Triage contains alerts and remediation plans; Settings contains sources/collectors, network policy and the glossary. Existing page URLs remain available. Findings, alert streams, inventory, intelligence, network events, and remediation plans use bounded pages. Counts come from all stored records, regardless of the displayed page.

Monitoring → Attack surface uses the minimalist topology: observed endpoints are grouped by inventory zone, with directed communication and dashed confirmed process support. Select a node for identity, timestamps, applicability and source evidence. Search highlights matching observed endpoints; zoom and process visibility use local GET navigation. On narrow screens, scroll inside the diagram to explore and read the detail panel below. Inventory without observed traffic remains in a separate expandable list. The diagram shows at most 24 observed endpoints, 60 directed connections and 12 process nodes, with visible omission counts; colliding port/protocol labels are suppressed with an explicit count and remain inspectable through evidence links. Full stored relationship tables remain available. Zone groups do not establish trust boundaries or reachability. See [topology verification](verification/2026-11-06-topology/README.md).

Overview summarizes alerts and links to Triage for acknowledgement. A finding with a saved plan shows its status and **Review plan**; lifecycle review and regeneration happen on the focused remediation page. Regeneration archives the prior plan and clears its review state. Imports reassess findings automatically. Manual correlation remains available under **Settings → Advanced assessment tools** and through the CLI.

Triage starts with compact summaries; expand **Inspect alert** to review evidence,
policy, context and acknowledgement. A selected vulnerability opens a stacked
case view with applicability, missing evidence and its plan action together on
narrow screens. Original-event pages distinguish normalized records and imported
payloads, with a return to the selected case or topology filters. Remediation
separates the current finding from the plan's generation-time evidence and offers
**Review plan** before the supporting sections. Inventory groups identity,
verification and operational classification, and the overview's identity-review
link opens a matching inventory filter. See the
[critique fixes and verification](verification/2026-11-06-critique-fixes/README.md).

Unused legacy AI persistence methods were removed; the `ai_remediations` table and its existing records are retained. Current guidance uses `remediation_plans`. The old POST `/ack` endpoint is retired; use the protected `/triage/ack` workflow. Reload previously opened forms after restarting the dashboard.

Public sync and hosted guidance run in a bounded background queue with progress pages that refresh automatically. Each worker owns a separate SQLite connection. Job progress is process-local; queued UI jobs do not survive restart. NVD page checkpoints do survive restart.

```bash
python3 -m phylax --db data/phylax.db import-assets /path/to/assets.csv
python3 -m phylax --db data/phylax.db load-fixture /path/to/public-records.json
python3 -m phylax --db data/phylax.db correlate
python3 -m phylax --db data/phylax.db export-report --format json --output report.json
python3 -m phylax --db data/phylax.db export-report --format csv --output report.csv
python3 -m phylax --db data/phylax.db export-report --format markdown --output report.md
```

Asset and intelligence imports automatically reevaluate relevant findings. Exposure alerts are deduplicated. Changed supporting evidence invalidates prior remediation review, preserves an archived plan snapshot, and requires review again. Removing a product association archives its plan before deleting the obsolete finding. Acknowledgement remains separate from remediation.

Asset CSV fields: `asset_id`, `ip_address`, `mac_address`, `hostname`, `asset_type`, `vendor`, `product`, `version`, `operating_system`, `zone`, `criticality`, `identification_source`, `identity_confidence`, `last_seen`, `notes`, `verified`. Only IP is required. MAC and enumeration values are validated; supplied last-seen timestamps require an explicit timezone and are normalized to UTC. CSV imports retain valid rows and report malformed rows. Unknown passive peers can be reconciled with a manual identity only when there is one unverified identity-free passive record at that IP. Competing manual identities are not silently merged.

Public-record JSON has a `vulnerabilities` array. Records need `cve_id` and `summary`; affected products need `vendor` and `product`. Exact `versions`, inclusive/exclusive `version_ranges`, complete `cpe_names`, and uncertainty flags are preserved through the same validator as live ingestion. A range uses `start_including`, `start_excluding`, `end_including`, and `end_excluding`. Unknown constraints must remain explicit. Imports are validated before mutation and are atomic. Imported records default to synthetic unless explicitly labeled otherwise, and never acquire trusted-public hosted eligibility merely from an uploaded flag.

## Intelligence sync and provenance

**Intelligence → CVEs** (`/intelligence`) and **Intelligence → CISA ICS advisories** (`/intelligence/ics`) are separate pages. Each has its own search, count and pagination; ICS advisories no longer appear below the CVE table. The existing Sync public sources action still synchronizes all configured sources.

CISA ICS advisory summaries show a compact plain-text excerpt (up to 320 characters plus an ellipsis), preferring the source Summary section. **Read full advisory text** expands the complete readable text in a bounded scroll region. Stored source HTML is retained unchanged; existing cached records need no new synchronization.

```bash
export NVD_API_KEY='optional-nvd-key'
python3 -m phylax --db data/phylax.db sync-feeds
python3 -m phylax --db data/phylax.db sync-feeds --backfill-days 30
python3 -m phylax --db data/phylax.db refresh-cve CVE-2026-0322
```

The adapters use the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities), [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), and [CISA ICS RSS](https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml). Their data is cached locally. Feed bodies have size bounds and timeouts, transient failures have bounded retries, and failures preserve cached data. CLI sync prints timestamped progress. Source health retains the last success and becomes stale after 24 hours; viewing a page performs no connectivity probe.

Routine NVD sync starts with the previous day, then uses the last successful window with a one-day overlap. Each fetched page is persisted with a fixed-window checkpoint. An interrupted operation resumes that window from its saved page; replaying a page is safe. `--backfill-days` explicitly requests a wider last-modified window, from 1 to 120 days. A pending checkpoint takes precedence. This is not a complete historical download. `refresh-cve` refreshes one public CVE without sending inventory or network context.

Source snapshots preserve per-source retrieval time and public-feed provenance. KEV membership and catalog required actions remain distinct from vendor fixes and version evidence. KEV does not supply affected-version ranges. ICS RSS entries retain advisory text and references without invented version conditions. Source sync outcomes and significant configuration changes have local audit records. Additional structured sources implement the `IntelligenceAdapter` contract in `phylax/adapters.py`; correlation consumes shared validated records.

Only AI settings are automatically loaded from project `.env`; export `NVD_API_KEY` in the server/CLI environment for NVD requests.

## Applicability and urgency

- `CONFIRMED_MATCH`: verified high-confidence product identity and supported source version evidence, with no unresolved conditions.
- `POTENTIAL_MATCH`: relevant product identity with incomplete version/identity evidence.
- `NO_MATCH_TO_THIS_ADVISORY`: supported evidence excludes the version for this advisory.
- `NEEDS_REVIEW`: unsupported CPE/platform/update constraints, configuration prerequisites, version semantics, or insufficient identity confidence.

Full CPE names and source version bounds are retained with match evidence. Unsupported update, edition, language, target software, and architecture conditions force review. The matcher supports exact source-listed version strings and plain numeric dotted ranges. It does not guess vendor-specific version ordering. Assets without vendor/product identity appear as identity reviews rather than being declared safe or matched against every CVE.

Priority rule version 2 adds: KEV +3; critical/high/medium severity +3/+2/+1; critical/high/medium asset criticality +3/+2/+1; confirmed applicability +2; known DMZ placement +1. Critical is 8+, high 6–7, medium 3–5, low 0–2. Non-applicable or review-only findings have no urgency score. Unknown source severity contributes no invented score and is shown as uncertainty. CVSS, applicability, identity confidence, and urgency remain separate. Observed reachability and verified vendor-fix availability are not inferred; their limitations are visible. Inputs and points are shown directly with findings and exported reports.

## Passive monitoring and policies

```bash
python3 -m phylax --db data/phylax.db analyze-zeek /path/to/conn.log
python3 -m phylax --db data/phylax.db analyze-zeek /path/to/modbus.log --kind modbus --policy /path/to/policy.json
python3 -m phylax --db data/phylax.db apply-policy /path/to/policy.json
```

JSON Lines and standard Zeek TSV are streamed with a 500 MB CLI log limit; web uploads have a 5 MB cap. Zeek connection service labels alone are not decoded Modbus operations. Supported ICSNPP fields include `source_h`, `source_p`, `destination_h`, `destination_p`, `func`, and `request_response`. Zeek's built-in Modbus `pdu_type=RESP` and explicit ICSNPP response records are retained but excluded from writer/maintenance detections. Numeric write functions 5, 6, 15, 16, 21, 22, and 23 and their supported names are recognized; other OT protocols and unsupported operations are not claimed as covered.

Rules evaluate unauthorized writers, communications that violate a protected-destination allowlist, and writes outside configured maintenance restrictions. Policies use `protected_assets`, `allowed_communications`, `authorized_writers`, and `maintenance_windows_utc`. Times are UTC `HH:MM`; days are Monday 0 through Sunday 6. Overnight windows belong to their start day, and end times are exclusive. Equal start/end is empty. Omitting a policy section leaves that rule unconfigured; an explicit empty maintenance-window array means no approved write period.

Missing fields or unsupported operations produce diagnostics instead of fabricated violations. Policy versions are immutable hashes. Reimporting an existing event reevaluates it without duplicating storage; `apply-policy` or the Network Policy page reevaluates all stored events. Cleared violations are retained as resolved history and excluded from active alert counts. Diagnostics are persisted, with bounded import-message samples. The latest configured policy is reused on later log imports.

The attack surface is inventory plus imported observations: timestamps, peers, ports, protocols, operations, confidence, and visibility gaps. Unknown peers remain unknown. At most 1,000 grouped relationships are shown, with a smaller topology diagram. Unseen traffic is not evidence of absence; recorded communication does not establish firewall permission or live reachability.

## Offline PCAP analysis with Zeek

Phylax invokes Zeek only with offline `-r` input, fixed arguments, a temporary directory and a timeout. No protocol decoder or live capture is implemented. Use a locally installed Zeek executable, or an already installed Zeek Docker image:

```bash
python3 -m phylax --db data/phylax.db analyze-pcap /path/to/capture.pcap --policy /path/to/policy.json
python3 -m phylax --db data/phylax.db analyze-pcap /path/to/capture.pcap --docker-image zeek/zeek:YOUR_INSTALLED_VERSION --policy /path/to/policy.json
```

Docker analysis uses `--pull=never`, `--network=none`, no capabilities, a read-only root filesystem, a non-root user, and CPU/memory/process bounds. Image installation is a separate operator action; prefer a digest for reproducibility. The runner reports missing executables, Docker/Zeek failures, timeouts, and missing supported logs. It imports `conn.log` and `modbus.log` when produced, retains a capture SHA-256 in evidence references, and deduplicates completed capture imports by digest. Duplicate capture analysis with a supplied policy reevaluates stored events. Installed ICSNPP packages can supply richer logs; this runner does not install or certify that extension. See [Zeek invocation](https://docs.zeek.org/en/stable/quickstart.html) and [ICSNPP-Modbus](https://github.com/cisagov/icsnpp-modbus).

Generate reproducible captures in a separate test directory:

```bash
python3 scripts/generate_passive_demo.py --output-dir data/passive-demo
python3 -m phylax --db data/passive-demo.db analyze-pcap data/passive-demo/synthetic-benign-read.pcap --docker-image zeek/zeek:YOUR_INSTALLED_VERSION --policy data/passive-demo/policy.json
python3 -m phylax --db data/passive-demo.db analyze-pcap data/passive-demo/synthetic-unauthorized-write.pcap --docker-image zeek/zeek:YOUR_INSTALLED_VERSION --policy data/passive-demo/policy.json
```

These files are explicitly **synthetic offline test traffic**, use documentation IPs, and were never transmitted. They are not operational incidents. Do not put them into production inventory. The generator has no socket code.

### Verified Docker rehearsal

On **2026-10-31 (Asia/Jakarta)**, both captures were successfully analyzed with the installed **Zeek 9.0.1** image and Docker 28.5.2. The container used the restrictions above, including disabled networking. The initial run revealed that `pdu_type=RESP` needed to be excluded from write detections; this was corrected and covered by regression tests using the actual generated logs.

| Capture | Packets / bytes | Stored events | Active alerts | Measured analysis time |
|---|---|---|---|---|
| Synthetic benign read | 7 / 537 | 1 connection + 2 Modbus PDUs | 0 | 0.576 seconds |
| Synthetic unauthorized write | 7 / 538 | 1 connection + 2 Modbus PDUs | 3 | 0.575 seconds |

The three write-capture alerts are unexpected communication, unauthorized Modbus writer, and write outside maintenance window. Each references its event, capture SHA-256 and policy evidence. Duplicate replay retained six total events and three alerts. JSON, CSV and Markdown reports were generated. The production databases were not used.

Host: Intel Core i7-13650HX, 20 logical CPUs, 7.57 GiB RAM visible to WSL2, Linux 6.6.114.1, Python 3.14.7. Container limits were one CPU and 512 MiB. These are single tiny-capture measurements, not throughput guarantees. The built-in Zeek Modbus analyzer was verified; the separate ICSNPP extension was not installed or certified in this rehearsal.

Repeat all checks and export reports into a **new** isolated directory (the image must already be installed):

```bash
python3 scripts/verify_zeek_demo.py --output-dir data/zeek-rehearsal --docker-image zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0
```

The command refuses an existing output directory and writes `verification.db`, generated captures, `verification.json`, and all three report formats. Recorded results and actual log fixtures are in [the synthetic Zeek fixture directory](tests/fixtures/synthetic_zeek9_README.md).

## Asset intelligence and approved IT discovery

All new state is local SQLite data. The new pages reuse the existing theme and
CSRF/Host/Origin protections. Typed operator names record decisions but are not
multi-user authentication.

### Three independent decisions

1. **Inventory verification:** confirm product/version evidence for applicability.
2. **Device management approval:** explicitly approve or block an IP, MAC, or pair
   within a monitored subnet. Existing inventory is not automatically approved.
3. **Scan permission:** separately permit specific TCP ports on a supporting IT
   server in IT/DMZ or a network management interface.

PLCs, RTUs, HMIs, engineering workstations, unknown devices and automatically
observed-only records cannot be granted active scan permission. No result creates
additional scan targets or permissions. Literal IPv4 targets only; no CIDRs,
hostname resolution, raw Nmap arguments, scripts, UDP or OS fingerprinting.
Nmap is an optional external executable (`/usr/bin/nmap` or `/usr/local/bin/nmap`).

```bash
python3 -m phylax --db data/phylax.db monitor-subnet "Approved lab" 192.0.2.0/24
python3 -m phylax --db data/phylax.db device-decision --subnet-id SUBNET_ID --ip 192.0.2.10 --actor "Operator" --note "Approved inventory review"
python3 -m phylax --db data/phylax.db scan-target save --asset-id ASSET_ID --ports 80 443 --identify --permit --actor "Operator" --note "Individually authorized supporting IT target"
python3 -m phylax --db data/phylax.db scan --target TARGET_ID
python3 -m phylax --db data/phylax.db worker --once
python3 -m phylax --db data/phylax.db scan-target schedule TARGET_ID --interval-minutes 60
python3 -m phylax --db data/phylax.db worker
```

Replace placeholders with IDs from the preceding command or the dashboard.
The command examples do not authorize any real target. Select and review your
own permitted inventory entry first. The isolated demo starts with scanning disabled.

At most 32 selected TCP ports are checked using unprivileged connect scanning,
one run per database at a time. Nmap has a 30-second host timeout, one retry and
constrained pacing; whole execution is bounded to 180 seconds. Optional HTTP(S)
header requests and SSH banners are limited to standard ports 22, 80, 443, 8080,
and 8443, with three-second deadlines and 4 KB responses. HTTP redirects and
authentication are disabled; TLS validation failures stay explicit. A header is
unverified evidence, never a confirmed installed version.

Schedules are opt-in, default to 60 minutes, and require at least 15 minutes.
Permission revisions cancel queued requests and stop running work at its next
cancellation check. A worker lease prevents overlapping workers on one database;
expired executions become interrupted and are not replayed. Missed schedule
intervals are skipped. Use the discovery page or `scan --cancel RUN_ID` to cancel,
`scan --status RUN_ID` to inspect, and `scan-target revoke TARGET_ID --actor NAME
--note REASON` to revoke permission. The worker is separate from passive ingestion.

### Passive observations, changes and software

```bash
python3 -m phylax --db data/phylax.db analyze-zeek /path/to/dhcp.log --kind dhcp
python3 -m phylax --db data/phylax.db analyze-zeek /path/to/software.log --kind software
python3 -m phylax --db data/phylax.db watch-zeek --directory /path/to/finalized-logs --interval-seconds 30
```

The watcher never starts capture. Use a separately managed Zeek sensor/TAP/SPAN
setup and a finalized, uncompressed log directory. Two stable polls precede
snapshot ingestion; files changing during import roll back. Hash checkpoints
survive restart; malformed unchanged content is retained as a visible failure
rather than repeatedly imported. Symlinks are skipped, file size is capped at
500 MB, and polling considers at most 1,000 directory entries. Archive older
files elsewhere. Poll intervals are 1–60 seconds; collector heartbeats become
stale after 180 seconds. Stopped/failed collection is distinct from device inactivity.

DHCP supplies MAC evidence opportunistically. Requested addresses alone do not
establish an assigned endpoint. Observations preserve raw evidence and observation
versus ingestion time. New services, IP/MAC associations and software-version
changes appear in the timeline. Historical imports retain their original time.
Neither MAC nor hostname silently merges inventory identities. Unapproved endpoints
produce a deduplicated **unmanaged—needs review** alert within configured subnets;
only explicit block decisions establish **unauthorized** status.

Software components remain separate from hardware/firmware. Exact mappings are
operator editable (Apache maps to `apache:http_server`); fuzzy matching is not used.
Verify/retire components on the Software Evidence page. New versions invalidate
prior verification, and competing active versions require review. Multiple components
contribute evidence to one stable asset/CVE finding. Unknown or unverified versions
cannot create a confirmed match. Source conflicts remain explicit.

### Operational context, topology and urgency

Use Operational Context for ownership, location, lifecycle, tags, criticality
rationale, and confirmed process support. Solid topology edges are observed
communications; dashed amber edges are operator-confirmed process links. These
relationships do not prove actual disruption or automatically raise criticality.
Filters cover subnet, zone, approval state, time, criticality and focused endpoint;
ephemeral source ports are aggregated. The graph shows at most 24 assets and 12
processes, the asset table is paged, and relationships are limited to 1,000 groups.
Original event evidence remains linked. Unseen traffic is not evidence of absence.

Unified Triage preserves source severity, applicability and acknowledgement.
Network urgency uses rule `network-1`: severity low/medium/high/critical contributes
0/1/2/3, relevant asset criticality contributes 0/1/2/3, and an explicitly protected
destination contributes 1. Critical is 6+, high 4–5, medium 2–3, low 0–1. Missing
criticality contributes zero and stays unknown; an automatically assigned inventory
default is not verified operational criticality. Vulnerability priority version 2
is unchanged. Reports include component assessments, management status, changes,
process context and priority factors. Neither scoring nor acknowledgement executes
remediation or grants permission.

### Selected structured CISA advisories

Configure at most 25 official CSAF 2.0 document URLs through Sources/Settings or:

```bash
python3 -m phylax --db data/phylax.db csaf-source https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2024/icsa-24-004-01.json
python3 -m phylax --db data/phylax.db sync-csaf
```

Ordinary `sync-feeds` also checks configured documents. Requests use HTTPS,
conditional ETags, a ten-second timeout, no redirects and a 2 MB body limit.
Documents and provenance are cached locally. Supported identities use exact CPE
2.3 or structured vendor/product labels; explicit affected/fixed statuses are
preserved. Prose ranges, configuration prerequisites, unsupported identifiers and
relationships remain for review. Unlisted versions are not declared unaffected.
Advisories without CVEs are retained. This is not a full-archive download or a
complete CSAF implementation, and detached signatures are not verified.

## Optional hosted remediation guidance

Copy `.env.example` to `.env` in the project directory and configure one provider. Existing shell variables take precedence. The file is parsed as data, never executed. Restart the server after edits.

```dotenv
PHYLAX_AI_PROVIDER=gemini
GEMINI_API_KEY=your-key
PHYLAX_AI_MODEL=your-enabled-model
PHYLAX_AI_TIMEOUT_SECONDS=120
```

Supported presets: Gemini (`GEMINI_API_KEY`), Groq (`GROQ_API_KEY`), and OpenRouter (`OPENROUTER_API_KEY`, optional model defaults to `openrouter/free`). A custom compatible endpoint uses `PHYLAX_AI_PROVIDER=custom`, `PHYLAX_AI_BASE_URL`, `PHYLAX_AI_MODEL`, and `PHYLAX_AI_API_KEY`. HTTPS is required except for loopback development endpoints. Timeout defaults to 90 seconds and accepts 5–180. Free quotas and data-use terms vary by provider/account; inspect their current terms before relying on free availability.

Generation occurs only after an operator requests a plan. Only trusted public-feed snapshots are sent, through an explicit public-field allowlist. Local asset identifiers, inventory, events, policies and risk context remain on the host. Imported/local replacements cannot overwrite the outbound trusted snapshot. Old caches need an official CVE refresh before hosted eligibility. Synthetic fixtures never call a hosted model.

Output is validated for shape and exact supplied citation URLs; common executable-command syntax is rejected. These checks do not prove semantic correctness or factual support. The UI labels model output AI-generated and unverified. Missing vendor guidance stays explicit; CISA required action is distinguished from a verified vendor fix. Actual returned model identity, requested model, generation time, supplied references and the cited subset are retained. Provider failures keep an existing hosted plan rather than overwriting it with fallback output. Changes to findings during generation require a retry.

Plans have manual review/approval/implementation/verification states. Named approval and recorded verification evidence are required. Regeneration archives previous contents and clears prior review. Plan state never changes applicability, severity, urgency, or alert acknowledgement; no plan is executed by Phylax.

For an isolated real-advisory workflow, first refresh public evidence, then prepare a new test database:

```bash
python3 -m phylax --db data/phylax.db refresh-cve CVE-2026-0322
python3 scripts/prepare_ai_test_data.py --output-db data/phylax-ai-test-new.db
python3 -m phylax --db data/phylax-ai-test-new.db serve
```

The advisory is real cached public data; the asset is an explicitly simulated PAN-OS lab identity at a documentation IP. Applicability follows current source conditions and can remain `NEEDS_REVIEW`. Hosted guidance is generic to the advisory in every case. The preparation script refuses existing output databases and never sends packets or calls a model.

## Reports, audit and security boundaries

JSON, CSV and Markdown distinguish confirmed/potential/review-only findings and include generation time, identity confidence, evidence, missing data, severity, priority factors, source provenance, next steps and limitations. JSON uses native arrays/objects for evidence. CSV includes a metadata record even with no findings and neutralizes common spreadsheet formula prefixes. Inventory CSV also neutralizes formulas, so an unsafe leading formula character may be prefixed with an apostrophe on export.

Audit records cover source outcomes, imports, acknowledgements, policy revisions/reevaluations and plan generation. Archived plans preserve contents that preceded regeneration or evidence invalidation. There is no multi-user identity provider or complete immutable forensic audit service.

The dashboard validates Host/Origin and form tokens; responses include CSP, frame restrictions, no-store, and nosniff headers. The database remains local. Do not publish the dashboard through a proxy without authentication, authorization, TLS and deployment review. Raw PCAPs are temporary inputs, not public download endpoints. Imported advisory text is untrusted and never executed. Secrets are environment values, are excluded from reports/configuration pages, and are redacted from provider-error text.

## Tests and implementation status

For hands-on acceptance checks with expected results and isolated fixtures, follow
the [full manual testing checklist](MANUAL_TESTING.md).

```bash
python3 -m unittest discover -s tests -v
```

The suite is offline: provider/feed responses and Zeek execution are mocked, with additional parser fixtures generated by real Zeek 9.0.1. **160 tests pass** after the operator-workflow, technical UI, simplification, topology and critique fixes. Coverage includes the original vertical slice, MVP-review regressions, policy history, HTTP plan persistence, privacy, CSRF, source snapshots, migrations, reports, jobs, parsing boundaries, context edit conflicts, discovery affordances, triage filters and contextual actions. The UI regressions also cover retained invalid input, labeled remediation transitions, uncertain KEV status, batched triage reads and paginated eligible asset selection. Synthetic test fixtures live under `tests/fixtures/`; the demo generator creates explicitly labeled captures only on operator request. They are never auto-loaded into operational data.

See the [simplification verification](verification/2026-11-06-simplification/README.md) for the consolidated workflows and responsive checks.

See the [November 6 UI refinement verification](verification/2026-11-06-refinement/README.md) for browser evidence, contrast checks and measured query improvements. Restart the dashboard to load these changes. No database migration is required. Triage still ranks matching alert metadata globally using the existing deterministic rules; complete context and evidence are loaded only for the requested page. This is not a capacity guarantee for arbitrarily large histories.

Operational Context loads the selected record before editing and rejects stale
updates. Discovery offers eligible supporting IT assets and separates permission
from queueing. Unified Triage presents observations, configured policy, ownership,
process support and score factors before the original raw record; category,
urgency, acknowledgement and text filters preserve their scope after review.
Software review and decision revocation are bound to their records. Narrow
screens use collapsed native navigation; advanced setup and topology filters
remain available through disclosures. Restart the dashboard and reload old forms
after upgrading these views.

See [release implementation and verification](RELEASE_NOTES.md) for measured checks, migration/rollback, limits and remaining submission activities, and [the fictional support-site lab](demo/README.md) for the full demonstration. Offline replay and live externally managed Zeek collection have been verified. Separate ICSNPP validation, broader version semantics, evaluated configuration prerequisites, stronger semantic AI validation and multi-user deployment remain outside this release. EPSS, RAG and automatic attack paths are optional future work.

### Passive attack-surface navigation

Find locates all known inventory assets and peers from stored communication events within the current asset filters, including inventory-only assets and older peers outside the relationship listing. It selects details without inventing observed communication. A zero-result search leaves no unrelated endpoint selected. On narrow screens, selected details precede the scrollable graph; Reset zoom restores readable natural-size labels.

Observation existence and first/last communication timestamps use the complete selected observation period. “Inventory only” means no imported communication across all stored times; previously observed endpoints outside the period remain distinct. Event totals describe the time window before asset/focus filters. Relationships are filtered before retaining the 1,000 most recent groups; counts and truncation are explicit. The diagram separately caps endpoints (24), connections (60), and process nodes (12). Find and endpoint focus expose evidence beyond those diagram limits. Each listed relationship opens its original event evidence and returns to the current view. Unseen traffic still does not establish absence or safety.
