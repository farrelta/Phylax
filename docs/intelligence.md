# Intelligence, applicability, and priority

[Documentation index](README.md)

## Supported sources

| Source | Stored contribution | Boundary |
|---|---|---|
| NVD CVE API 2.0 | CVEs, severity, references, CPE/version conditions | Unsupported conditions require review |
| CISA KEV JSON | Known-exploitation membership, catalog dates/actions | Does not provide affected-version proof or prove a local attack |
| CISA ICS RSS | Advisory text and references | Does not invent structured affected versions |
| Configured CISA CSAF documents | Supported product identities, affected/fixed statuses, advisory records | Selected official URLs, not a complete archive or CSAF implementation |

Official source references: [NVD API](https://nvd.nist.gov/developers/vulnerabilities), [KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json), [ICS RSS](https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml), [CISA CSAF repository](https://github.com/cisagov/CSAF).

CVEs and CISA ICS advisories have separate Intelligence pages with independent search and pagination. ICS previews use bounded readable text; full advisory text is available through a disclosure. Source HTML remains untrusted.

## Synchronize and resume

```bash
python3 -m phylax --db data/phylax.db sync-feeds
python3 -m phylax --db data/phylax.db sync-feeds --backfill-days 30
python3 -m phylax --db data/phylax.db refresh-cve CVE-2026-0322
```

- Normal NVD synchronization starts with the previous day, then uses the last successful window with a one-day overlap.
- Each fetched page is stored with a fixed-window checkpoint. Cancellation resumes from the saved page on the next run; a replayed page is deduplicated safely.
- `--backfill-days` requests a wider **last-modified** window of 1–120 days. An unfinished checkpoint takes precedence. This is not a complete historical download.
- KEV refreshes its catalog, ICS RSS refreshes available entries, and configured CSAF documents use conditional retrieval.
- CLI progress is timestamped. Duration depends on window size, pages, rate limits, and source response times; no fixed completion time is guaranteed.

Feed failures are independent and preserve cached records. Source health retains last success and becomes stale after 24 hours. Reading a page performs no connectivity probe. Refreshing a CVE sends its identifier, not inventory or network context. Configure the optional NVD key as described in [setup](setup.md#feed-key).

Configure at most 25 official CSAF document URLs:

```bash
python3 -m phylax --db data/phylax.db csaf-source https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2024/icsa-24-004-01.json
python3 -m phylax --db data/phylax.db sync-csaf
```

The adapter uses ETags, HTTPS without redirects, a 10-second timeout, and a 2 MB body limit. It preserves unsupported conditions for review, retains advisories without CVEs, and does not verify detached signatures. `sync-feeds` also checks configured documents.

## Offline intelligence imports

```bash
python3 -m phylax --db data/phylax.db load-fixture /path/to/records.json
```

The JSON contains a `vulnerabilities` array. Records require `cve_id` and `summary`; affected products require `vendor` and `product`. Supported evidence includes exact `versions`, `excluded_versions`, `cpe_names`, and `version_ranges` with `start_including`, `start_excluding`, `end_including`, or `end_excluding`. Uncertain semantics and prerequisites must remain explicit. See the [synthetic software fixture](../demo/manual-fixtures/software-advisory.json) for a complete labeled example.

Payloads are validated before atomic mutation. Imports default to synthetic unless explicitly labeled otherwise; an uploaded flag does not establish trusted public provenance or hosted-AI eligibility. Never present a synthetic CVE as a real advisory.

## Applicability states

| Status | Meaning |
|---|---|
| `CONFIRMED_MATCH` | Verified high-confidence identity and supported affected-version evidence, with no unresolved conditions |
| `POTENTIAL_MATCH` | Relevant product, but version or identity evidence is incomplete |
| `NO_MATCH_TO_THIS_ADVISORY` | Supported evidence excludes this advisory for the verified identity/version |
| `NEEDS_REVIEW` | Identity, configuration, conflicting evidence, or version conditions cannot be evaluated reliably |

Product matching uses exact normalized identifiers, not fuzzy similarity or vendor-only matching. The engine supports exact version strings and plain numeric dotted ranges. Unsupported CPE attributes, vendor-specific ordering, and configuration prerequisites require review. Competing active software versions and contradictory affected/excluded source evidence remain explicit. Findings preserve component-level evidence; imports trigger reassessment.

An excluded assessment applies to that advisory only. No match is not a safety verdict; a match is not proof of compromise.

## Deterministic urgency

Vulnerability priority rule **2** applies to confirmed and potential matches:

| Input | Points |
|---|---|
| KEV membership | +3 |
| Source severity critical / high / medium | +3 / +2 / +1 |
| Asset criticality critical / high / medium | +3 / +2 / +1 |
| Confirmed applicability | +2 |
| Known DMZ placement | +1 |
| Verified vendor fix | Unknown; +0, explicitly disclosed |

Thresholds: critical ≥8; high 6–7; medium 3–5; low 0–2. Review-only and excluded assessments have no applicability urgency score. Unknown severity adds no invented CVSS or exploit probability.

Network rule **network-1** adds severity low/medium/high/critical (0/1/2/3), relevant asset criticality (0/1/2/3), and explicitly protected destination (+1). Critical ≥6; high 4–5; medium 2–3; low 0–1. Communication/write alerts use destination criticality; unmanaged-endpoint alerts use endpoint criticality. Unknown criticality contributes zero and remains visible.

Process context does not silently raise criticality. Recalculation preserves acknowledgement. KEV, CVSS, and urgency are evidence for prioritization, not proof of active exploitation on the local device.
