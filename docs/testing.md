# Testing and demonstration

[Documentation index](README.md)

## Offline automated suite

```bash
python3 -m unittest discover -s tests -v
```

No internet, Docker daemon, real device, or hosted model is needed. Feed/provider responses and external process execution are mocked. Coverage includes CSV validation, migration preservation, applicability and source conflicts, software evidence, approvals, scanning boundaries/recovery, Zeek parsing, policy rules, watcher checkpoints, AI privacy/citations, reports, request protections, and topology visibility/search.

## Smallest isolated demonstration

Run from the repository root, using a new directory:

```bash
python3 scripts/prepare_release_demo.py --output-dir data/first-demo
python3 -m phylax --db data/first-demo/phylax-demo.db serve
```

Preparation creates six synthetic inventory entries, four explicit applicability cases, a passive policy, process context, a disabled IT scan target, and replay captures. It performs no device probes, feed requests, or hosted-model calls. Existing output directories are refused. The fictional `CVE-2099-99999` is synthetic, not a public CVE. All site identities describe a fictional TNI AD support facility with no real infrastructure or endorsement.

Use the Overview to inspect confirmed, potential, excluded, and review-required assessments. Export a report and verify that synthetic labels, missing evidence, and applicability remain explicit. This initial workflow does not require Zeek or Nmap.

## Feature acceptance checklist

Use the [full manual checklist](manual-testing.md) for steps and expected outcomes. Record `ID | Pass/Fail/Blocked | Actual evidence | Notes`. Core acceptance areas:

| Area | Required observation |
|---|---|
| Inventory | Valid/invalid CSV, unknown version, duplicate identity, safe export |
| Approvals/context | Unmanaged review, explicit block, revocation, stale-edit protection, independent scan permission |
| Software | Exact mapping, verification, changed/competing versions, reassessment |
| Intelligence | Incremental sync, saved-page resume, offline fixture, source health and stale status |
| Applicability | All four states, excluded/fixed versions, missing prerequisites, preserved source evidence |
| Monitoring | Benign read, authorized/unauthorized write, unexpected peer, maintenance boundary, missing metadata |
| Watcher | Rotation, two stable polls, changed/malformed inputs, deduplication and collector inactivity |
| Discovery | Eligible IT target only, explicit ports/permission, queue/worker, cancellation, schedule/restart/revocation |
| Topology | All-known Find, unknown/inventory-only detail, zero results, accurate caps, row evidence and mobile details first |
| Triage/reports | Distinct severity/confidence/urgency, acknowledgement preserved, complete JSON/CSV/Markdown |
| AI | Disabled/synthetic behavior, public-only payload, provider failure/citations, saved plan and manual review |
| Offline/upgrade | Stored access, local replay, backups, preserved IDs/counts and integrity |

## Optional live and replay lab

The [isolated lab guide](../demo/README.md) contains pinned build inputs, Docker networking, collector rotation, one permitted IT target, a simulator-only policy violation, offline replay, and shutdown instructions. Live operation needs Docker Engine/Compose; approved discovery also needs Nmap. Verify `172.30.77.0/24` does not overlap your environment before starting the lab.

For replay, install the chosen Zeek image separately, then use a fresh output directory:

```bash
python3 scripts/verify_release_replay.py --output-dir data/release-replay --docker-image zeek/zeek:YOUR_INSTALLED_VERSION
```

This is a real isolated Docker integration check, separate from the mocked offline suite. It analyzes generated PCAPs, checks findings/alerts/deduplication, and exports reports. Do not mix live and replay databases when asserting exact counts. The lab driver can issue a simulator write; Phylax itself cannot issue controller writes.

## Optional real-advisory AI exercise

```bash
python3 -m phylax --db data/phylax.db refresh-cve CVE-2026-0322
python3 scripts/prepare_ai_test_data.py --source-db data/phylax.db --output-db data/ai-exercise.db
python3 -m phylax --db data/ai-exercise.db serve
```

The source database must contain the trusted public advisory. The output database must be new. The script creates a clearly simulated lab asset, does not scan, and does not call a model. Applicability can remain uncertain. Hosted generation is a separate operator action requiring provider configuration and current public eligibility; provider availability must not determine whether the offline demonstration succeeds.

## Rehearsal record

Record date/time, code revision, OS/CPU/RAM, Python/Zeek/Docker/Nmap versions, image digest, dataset size, processing time, expected versus actual counts, and limitations. Verify ingestion within the intended rehearsal latency after finalized log rotation; do not turn a tiny replay timing into a production throughput claim. Never record API keys or real operational metadata in a public submission.
