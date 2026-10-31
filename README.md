# Phylax

Phylax is a lightweight, local IT/OT cybersecurity decision-support platform for the Kartika Cyber Hackathon 2026. It combines inventory, public vulnerability intelligence, passive Zeek observations, explainable findings, and optional hosted remediation guidance.

It performs no active discovery, device writes, automatic patching, isolation, firewall changes, or autonomous response. A vulnerability match does not establish compromise; absence of a match does not establish safety.

## Install and run

Python 3.10 or newer. The application and offline tests use Python's standard library; no pip dependencies are required.

```bash
python3 -m phylax --db data/phylax.db serve
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). The server accepts loopback binds only. Inventory, cached intelligence, correlation, log analysis, and reports remain available offline. Hosted AI and public feed requests require connectivity.

An existing database receives additive schema upgrades. Before the first hardening migration, Phylax writes `<database>.pre-hardening.sqlite` using SQLite backup. Migration creates an indexed product lookup, source snapshots, policy versions, diagnostics, audit history, and archived plans. Old NVD records that did not retain full CPE conditions become `NEEDS_REVIEW` until refreshed. Missing evidence is never reconstructed from device IPs or product names. Keep backups and the database on a trusted local filesystem.

After upgrading, restart the server and reload existing browser forms; stale form tokens are rejected.

## Operator workflows

The overview links to inventory, manual asset add/edit, attack surface, intelligence, network events, remediation plans, network policy, settings/source health, and reports. Findings, alert streams, inventory, intelligence, network events, and remediation plans use bounded pages. Counts come from all stored records, regardless of the displayed page.

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

```bash
python3 -m unittest discover -s tests -v
```

The suite is offline: provider/feed responses and Zeek execution are mocked, with additional parser fixtures generated by real Zeek 9.0.1. **67 tests pass** after the Docker rehearsal fix. It covers the original vertical slice plus the reproduced MVP-review failures, policy history, current HTTP plan persistence, privacy, CSRF, source snapshots, migration backup, reports, jobs and parsing boundaries. Synthetic test fixtures live under `tests/fixtures/`; the demo generator creates explicitly labeled captures only on operator request. They are never auto-loaded into operational data.

The full [MVP evaluation](docs/MVP_EVALUATION.md) is a historical before-fix assessment. See [hardening results](docs/HARDENING_RESULTS.md) for implemented fixes, verification, performance measurements and remaining limits. Actual offline Zeek connection/Modbus capture rehearsal now passes. Outstanding work includes separate ICSNPP validation, broader version semantics, evaluated configuration prerequisites, stronger semantic AI validation, fresh hardware/deployment validation, and multi-user controls. Live capture, EPSS, RAG and automatic attack paths remain optional future work.
